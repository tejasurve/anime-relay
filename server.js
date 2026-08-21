/**
 * mkissa API relay for Railway / Node hosts.
 *
 * Beyond plain forwarding, this repairs the `x-aa-boot` header on bootstrap
 * requests. Upstream ships the boot-token shape (HMAC prefix, payload field
 * order, separator) as parameters in its JS bundle and rotates them every few
 * days; a released mobile app has those baked in and cannot follow. So the
 * relay derives the current build id, mask and parameters from the live bundle
 * and re-signs the header, which turns "ship a new app build" into "nothing".
 *
 * What it deliberately does NOT change is the build id the client asked for.
 * The client derives its AES key as `partB XOR mask`, so if the relay signed
 * for a different build the returned `partB` would pair with a mask the client
 * does not have, and every signed query would fail with AA_CRYPTO_STALE. When
 * the client is on a stale build the mismatch is surfaced in a response header
 * instead of being silently papered over.
 */
const crypto = require("crypto");
const express = require("express");
const vm = require("vm");

const app = express();
const PORT = process.env.PORT || 3000;
const UPSTREAM = process.env.UPSTREAM || "https://api.mkissa.net";
const SITE = process.env.SITE || "https://mkissa.to";
const BOOTSTRAP_PATH = "/client-crypto/v1/bootstrap";
const MATERIAL_TTL_MS = 30 * 60 * 1000;
const EPOCH_LENGTHS_MS = [604800000, 259200000];

const UA =
  process.env.RELAY_UA ||
  "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 " +
    "(KHTML, like Gecko) Chrome/148.0.0.0 Safari/537.36";

const DEFAULT_HEADERS = {
  accept: "*/*",
  "accept-language": "en-GB,en-US;q=0.9,en;q=0.8",
  origin: SITE,
  referer: `${SITE}/`,
  "user-agent": UA,
};

const PASSTHROUGH = [
  "x-build-id",
  "x-aa-boot",
  "origin",
  "referer",
  "user-agent",
  "accept",
  "accept-language",
  "content-type",
];

// ── Bundle-derived signing material ─────────────────────────────────────────

let cached = null; // { buildId, maskHex, params, at }
let inflight = null;

async function get(url) {
  const res = await fetch(url, {
    headers: { "user-agent": UA, referer: `${SITE}/` },
  });
  if (!res.ok) throw new Error(`GET ${url} -> HTTP ${res.status}`);
  return res.text();
}

function balancedBody(src, from) {
  const open = src.indexOf("{", from);
  let depth = 0;
  let quote = null;
  for (let i = open; i < src.length; i++) {
    const c = src[i];
    if (src[i - 1] === "\\") continue;
    if (quote) {
      if (c === quote) quote = null;
      continue;
    }
    if (c === '"' || c === "'" || c === "`") {
      quote = c;
      continue;
    }
    if (c === "{") depth++;
    else if (c === "}" && --depth === 0) return src.slice(from, i + 1);
  }
  throw new Error("unbalanced braces");
}

function statement(src, from) {
  let depth = 0;
  let quote = null;
  for (let i = from; i < src.length; i++) {
    const c = src[i];
    if (src[i - 1] === "\\") continue;
    if (quote) {
      if (c === quote) quote = null;
      continue;
    }
    if (c === '"' || c === "'" || c === "`") {
      quote = c;
      continue;
    }
    if ("([{".includes(c)) depth++;
    else if (")]}".includes(c)) depth--;
    else if (c === ";" && depth === 0) return src.slice(from, i + 1);
  }
  throw new Error("no statement end");
}

const RESERVED = new Set([
  "function", "return", "const", "let", "var", "if", "else", "for", "while",
  "try", "catch", "typeof", "new", "this", "true", "false", "null", "undefined",
  "String", "Number", "Array", "Object", "Math", "JSON", "Uint8Array", "atob",
  "btoa", "TextEncoder", "Promise", "Error", "Date", "parseInt", "parseFloat",
  "Symbol", "Proxy", "Reflect", "of", "in", "await", "async", "delete", "void",
]);

function findDecl(src, name, lo, hi) {
  const esc = name.replace(/\$/g, "\\$");
  const inRange = (i) => i >= lo && i < hi;
  for (const fn of src.matchAll(new RegExp(`function\\s+${esc}\\s*\\(`, "g"))) {
    if (inRange(fn.index)) {
      return { at: fn.index, code: balancedBody(src, fn.index) };
    }
  }
  const asn = [
    ...src.matchAll(new RegExp(`(^|[,;{(\\s])${esc}\\s*=(?!=)`, "g")),
  ].find((m) => inRange(m.index));
  if (!asn) return null;
  const at = asn.index + asn[0].indexOf(name);
  const kw = Math.max(
    src.lastIndexOf("const ", at),
    src.lastIndexOf("let ", at),
    src.lastIndexOf("var ", at)
  );
  if (kw === -1) return null;
  return { at: kw, code: statement(src, kw) };
}

/// Slice the aa-crypto module out of `src` and replay it to recover the build
/// id, mask and boot-token parameters. Mirrors tools/aa_extract_build.js.
function extractMaterial(src) {
  let maskFn = null;
  let buildVar = null;
  for (const m of src.matchAll(
    /function\s+([A-Za-z_$][\w$]*)\s*\(\s*[A-Za-z_$][\w$]*\s*=\s*([A-Za-z_$][\w$]*)\s*\)/g
  )) {
    let body;
    try {
      body = balancedBody(src, m.index);
    } catch {
      continue;
    }
    if (
      body.includes("new Uint8Array(") &&
      /return\s+\w+\s*\^\s*\w+/.test(body)
    ) {
      maskFn = m[1];
      buildVar = m[2];
      break;
    }
  }
  if (!maskFn) throw new Error("mask builder not found in bundle");

  const at = src.indexOf(`function ${maskFn}(`);
  const lo = Math.max(0, at - 25000);
  const hi = Math.min(src.length, at + 25000);

  const seen = new Map();
  const queue = [maskFn, buildVar];
  while (queue.length) {
    const name = queue.shift();
    if (seen.has(name) || RESERVED.has(name)) continue;
    let decl;
    try {
      decl = findDecl(src, name, lo, hi);
    } catch {
      continue;
    }
    if (!decl) continue;
    seen.set(name, decl);
    for (const t of decl.code.matchAll(/[A-Za-z_$][\w$]{1,}/g)) {
      if (!seen.has(t[0]) && !RESERVED.has(t[0])) queue.push(t[0]);
    }
  }

  const rotators = [];
  for (const m of src.matchAll(/\(function\([a-z],[a-z]\)\{/g)) {
    let stmt;
    try {
      stmt = statement(src, m.index);
    } catch {
      continue;
    }
    const tail = /\)\(\s*([A-Za-z_$][\w$]*)\s*,/.exec(stmt.slice(-120));
    if (tail && seen.has(tail[1])) rotators.push({ at: m.index, code: stmt });
  }

  const byOffset = new Map();
  for (const d of [...seen.values(), ...rotators]) byOffset.set(d.at, d);
  const code = [...byOffset.values()]
    .sort((a, b) => a.at - b.at)
    .map((d) => d.code)
    .join("\n");

  const sandbox = {
    atob: (s) => Buffer.from(s, "base64").toString("binary"),
    btoa: (s) => Buffer.from(s, "binary").toString("base64"),
    TextEncoder, Uint8Array, Array, String, Number, Math, JSON, Date, Error,
    Symbol, parseInt, Function, console,
  };
  sandbox.globalThis = sandbox;
  sandbox.window = sandbox;
  vm.createContext(sandbox);
  new vm.Script(
    `${code}\n;globalThis.__mask=Array.from(${maskFn}()||[]);` +
      `globalThis.__build=String(${buildVar}||"");`
  ).runInContext(sandbox, { timeout: 15000 });

  const mask = sandbox.__mask;
  const buildId = sandbox.__build;
  if (!mask || mask.length !== 32) throw new Error("mask builder gave no bytes");
  if (!/^\d{1,4}$/.test(buildId)) throw new Error(`bad build id ${buildId}`);

  let params = null;
  for (const name of seen.keys()) {
    for (const expr of [name, `${name}()`]) {
      try {
        const v = vm.runInContext(expr, sandbox);
        if (v && typeof v === "object" && typeof v.bootPrefix === "string") {
          params = v;
        }
      } catch {
        /* not the params object */
      }
      if (params) break;
    }
    if (params) break;
  }

  return {
    buildId,
    maskHex: Buffer.from(mask).toString("hex"),
    params: {
      bootPrefix: params?.bootPrefix ?? "aa-boot:",
      join: params?.join ?? ":",
      parts: params?.parts ?? ["buildId", "group", "host", "epoch", "lane"],
    },
  };
}

async function fetchMaterial() {
  const home = await get(`${SITE}/`);
  const entries = [
    ...new Set(
      [
        ...home.matchAll(
          /https?:\/\/[^"']+\/_app\/immutable\/entry\/(?:app|start)\.[A-Za-z0-9_-]+\.js/g
        ),
      ].map((m) => m[0])
    ),
  ];
  if (!entries.length) throw new Error("no entry bundle on homepage");
  const base = entries[0].slice(
    0,
    entries[0].indexOf("/immutable/") + "/immutable/".length
  );

  const names = new Set();
  for (const entry of entries) {
    const js = await get(entry);
    for (const m of js.matchAll(/chunks\/[A-Za-z0-9_-]+\.js/g)) names.add(m[0]);
  }
  for (const name of names) {
    let js;
    try {
      js = await get(base + name);
    } catch {
      continue;
    }
    if (js.includes("client-crypto/v1/bootstrap")) return extractMaterial(js);
  }
  throw new Error("crypto chunk not found");
}

function material({ force = false } = {}) {
  const fresh = cached && Date.now() - cached.at < MATERIAL_TTL_MS;
  if (fresh && !force) return Promise.resolve(cached);
  if (inflight) return inflight;
  inflight = fetchMaterial()
    .then((m) => {
      cached = { ...m, at: Date.now() };
      console.log(
        `crypto material: build ${m.buildId}, prefix ${m.params.bootPrefix}, ` +
          `payload ${m.params.parts.join(m.params.join)}`
      );
      return cached;
    })
    .catch((err) => {
      console.error("material refresh failed:", err.message);
      if (cached) return cached; // stale beats nothing
      throw err;
    })
    .finally(() => {
      inflight = null;
    });
  return inflight;
}

// ── Boot token ──────────────────────────────────────────────────────────────

function keyGroupForHost(host) {
  const h = (host || "").toLowerCase();
  if (h.startsWith("192.168.")) return "mirror";
  if (h === "youtu-chan.com" || h === "isekai2nd.com") return "mirror";
  return "mkissa";
}

function bootToken({ maskHex, params, buildId, epoch, lane, host }) {
  const inner = crypto
    .createHmac("sha256", Buffer.from(maskHex, "hex"))
    .update(params.bootPrefix + buildId)
    .digest();
  const values = {
    epoch: String(epoch),
    group: keyGroupForHost(host),
    host,
    buildId,
    lane,
  };
  const payload = params.parts.map((p) => values[p] ?? "").join(params.join);
  return crypto.createHmac("sha256", inner).update(payload).digest("hex");
}

function epochCandidates(now = Date.now()) {
  const out = [];
  for (const len of EPOCH_LENGTHS_MS) {
    const cur = Math.floor(now / len);
    out.push(cur, cur - 1, cur + 1);
  }
  return [...new Set(out)];
}

/// Bootstrap needs a token the client cannot compute, so sign it here and walk
/// the epoch candidates until upstream stops saying `invalid_boot_token`.
async function proxyBootstrap(req, res) {
  const url = new URL(UPSTREAM + req.originalUrl);
  const lane = url.searchParams.get("k") || "k7";
  const clientBuild =
    url.searchParams.get("buildId") || req.headers["x-build-id"] || "";
  const host = new URL(SITE).hostname.replace(/^www\./, "");

  // A client that sends no `k` predates per-lane seeds, and one seed cannot
  // serve both episode and chapterPages. Log it: no proxy can fix that shape,
  // so it is the signal that the installed app genuinely needs a new release.
  console.log(
    `bootstrap: build=${clientBuild || "-"} lane=${
      url.searchParams.get("k") || "MISSING"
    } clientToken=${req.headers["x-aa-boot"] ? "yes" : "MISSING"}`
  );

  let mat;
  try {
    mat = await material();
  } catch (err) {
    return res.status(502).json({ error: "material_unavailable", detail: String(err) });
  }

  // Sign for the build the client will pair the response with; if that is not
  // the build now live we have no matching mask, so fall back to the current
  // one and flag it rather than silently mismatching.
  const buildId = clientBuild || mat.buildId;
  const buildMismatch = clientBuild && clientBuild !== mat.buildId;
  const signBuild = buildMismatch ? mat.buildId : buildId;

  let last = null;
  for (let attempt = 0; attempt < 2; attempt++) {
    for (const epoch of epochCandidates()) {
      url.searchParams.set("buildId", signBuild);
      const upstream = await fetch(url, {
        headers: {
          ...DEFAULT_HEADERS,
          "x-build-id": signBuild,
          "x-aa-boot": bootToken({
            maskHex: mat.maskHex,
            params: mat.params,
            buildId: signBuild,
            epoch,
            lane,
            host,
          }),
        },
      });
      const body = await upstream.text();
      last = { status: upstream.status, body };
      if (!body.includes("invalid_boot_token")) {
        res.status(upstream.status);
        res.setHeader("content-type", upstream.headers.get("content-type") || "application/json");
        res.setHeader("access-control-allow-origin", "*");
        res.setHeader("x-relay-signed-build", signBuild);
        if (buildMismatch) res.setHeader("x-relay-build-mismatch", clientBuild);
        return res.send(body);
      }
    }
    // Every epoch rejected — the parameters probably rotated mid-session.
    if (attempt === 0) {
      console.log("all epochs rejected; refreshing crypto material");
      try {
        mat = await material({ force: true });
      } catch {
        break;
      }
    }
  }

  res.status(last ? last.status : 502);
  res.setHeader("access-control-allow-origin", "*");
  res.setHeader("x-relay-signed-build", signBuild);
  res.send(last ? last.body : JSON.stringify({ error: "bootstrap_failed" }));
}

app.use(express.raw({ type: "*/*" }));

app.get("/healthz", async (_req, res) => {
  try {
    const m = await material();
    res.json({ ok: true, buildId: m.buildId, params: m.params });
  } catch (err) {
    res.status(503).json({ ok: false, detail: String(err) });
  }
});

// `app.use` rather than `app.all("*")`: the wildcard string is rejected by
// Express 5's path parser, and this file has to run on whatever the host has.
app.use(async (req, res) => {
  if (req.path === "/") return res.send("allanime relay: ok");

  if (req.path === BOOTSTRAP_PATH && req.method === "GET") {
    try {
      return await proxyBootstrap(req, res);
    } catch (err) {
      console.error("Bootstrap relay error:", err);
      return res.status(502).json({ error: "bootstrap_relay_failed", detail: String(err) });
    }
  }

  const target = `${UPSTREAM}${req.originalUrl}`;
  const headers = { ...DEFAULT_HEADERS };
  for (const name of PASSTHROUGH) {
    const v = req.headers[name];
    if (typeof v === "string" && v.length) headers[name] = v;
  }

  try {
    const upstream = await fetch(target, {
      method: req.method,
      headers,
      body: req.method === "GET" || req.method === "HEAD" ? undefined : req.body,
      redirect: "follow",
    });
    res.status(upstream.status);
    const ct = upstream.headers.get("content-type");
    if (ct) res.setHeader("content-type", ct);
    res.setHeader("access-control-allow-origin", "*");
    res.send(Buffer.from(await upstream.arrayBuffer()));
  } catch (err) {
    console.error("Relay Error:", err);
    res.status(502).json({ error: "relay_fetch_failed", detail: String(err) });
  }
});

app.listen(PORT, () => {
  console.log(`Relay listening on port ${PORT} -> ${UPSTREAM}`);
  material().catch(() => {});
});
