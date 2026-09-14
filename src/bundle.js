/**
 * Recovers everything upstream expects a browser to know from its own JS
 * bundle: the build id, the 32-byte mask, the boot-token parameters, and the
 * persisted-query hashes.
 *
 * All of it is obfuscated and all of it rotates, so nothing here pattern-matches
 * on names. The mask builder is found by shape (a function whose default
 * argument is the build id, that allocates 32 bytes and XORs), and the query
 * hashes are recovered by evaluating the template literals that build the
 * GraphQL documents. Both are then replayed inside a `vm` sandbox, which is why
 * a rename or a minifier change does not break this.
 */
const crypto = require("crypto");
const vm = require("vm");

const SITE = process.env.SITE || "https://mkissa.to";
const UA =
  process.env.RELAY_UA ||
  "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 " +
    "(KHTML, like Gecko) Chrome/148.0.0.0 Safari/537.36";

const RESOLVERS = ["episode", "chapterPages"];

async function get(url, { fresh = false } = {}) {
  // The homepage must be read fresh. Entry filenames are content-hashed, so a
  // CDN-cached homepage silently pins the whole scan to a superseded bundle —
  // which is how this ended up recovering a build id upstream had already
  // stopped accepting. Immutable chunks are content-addressed and safe to cache.
  const target = fresh
    ? `${url}${url.includes("?") ? "&" : "?"}_cb=${Date.now()}`
    : url;
  const res = await fetch(target, {
    headers: {
      "user-agent": UA,
      referer: `${SITE}/`,
      ...(fresh ? { "cache-control": "no-cache", pragma: "no-cache" } : {}),
    },
  });
  if (!res.ok) throw new Error(`GET ${url} -> HTTP ${res.status}`);
  return res.text();
}

// ── Source slicing helpers ──────────────────────────────────────────────────

/// Index just past the `)` matching the `(` at `from`.
function endOfParens(src, from) {
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
    if (c === "(") depth++;
    else if (c === ")" && --depth === 0) return i + 1;
  }
  return -1;
}

/// Slices a whole function declaration starting at `from`, which must point at
/// its `function` keyword.
function balancedBody(src, from) {
  // Step over the parameter list before looking for the body. A destructured
  // parameter opens a brace that is not the body, so counting from the first
  // brace truncates the function at the end of the pattern instead — which is
  // how the boot-token builder, `function KA({buildId, group, host, ...})`,
  // came back as a fragment that would not parse.
  let searchFrom = from;
  const paren = src.indexOf("(", from);
  const firstBrace = src.indexOf("{", from);
  if (paren !== -1 && (firstBrace === -1 || paren < firstBrace)) {
    const afterParams = endOfParens(src, paren);
    if (afterParams !== -1) searchFrom = afterParams;
  }

  const open = src.indexOf("{", searchFrom);
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

/// End of the expression starting at `start`, tracking brackets, quotes and
/// `${}` nesting — the query templates nest all three heavily.
function endOfExpression(src, start) {
  const stack = [];
  let i = start;
  while (i < src.length) {
    const top = stack[stack.length - 1];
    const c = src[i];
    if (top === '"' || top === "'") {
      if (c === "\\") i += 2;
      else {
        if (c === top) stack.pop();
        i++;
      }
      continue;
    }
    if (top === "`") {
      if (c === "\\") i += 2;
      else if (c === "`") {
        stack.pop();
        i++;
      } else if (c === "$" && src[i + 1] === "{") {
        stack.push("${");
        i += 2;
      } else i++;
      continue;
    }
    if (c === '"' || c === "'" || c === "`" || "([{".includes(c)) {
      stack.push(c);
      i++;
      continue;
    }
    if (")]}".includes(c)) {
      if (!stack.length) return i;
      stack.pop();
      i++;
      continue;
    }
    if ((c === "," || c === ";") && !stack.length) return i;
    i++;
  }
  return src.length;
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

// ── Signing material ────────────────────────────────────────────────────────

function extractMaterial(src) {
  const buildIdFallback = extractBuildIdFromJs(src);
  const maskHexFallback = extractMaskHexFromJs(src);
  const bootParamsFallback = extractBootParamsFromJs(src);

  if (buildIdFallback && maskHexFallback) {
    return {
      buildId: buildIdFallback,
      maskHex: maskHexFallback,
      params: bootParamsFallback,
    };
  }

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
    if (body.includes("new Uint8Array(") && /return\s+\w+\s*\^\s*\w+/.test(body)) {
      maskFn = m[1];
      buildVar = m[2];
      break;
    }
  }
  if (!maskFn) {
    if (buildIdFallback && maskHexFallback) {
      return {
        buildId: buildIdFallback,
        maskHex: maskHexFallback,
        params: bootParamsFallback,
      };
    }
    throw new Error("mask builder not found in bundle");
  }

  const at = src.indexOf(`function ${maskFn}(`);
  const lo = Math.max(0, at - 25000);
  const hi = Math.min(src.length, at + 25000);

  // Declarations are collected from a window around the mask builder rather
  // than the whole file. Names are minified to a character or two and repeat
  // across modules, so the nearest declaration is the correct one, and walking
  // every identifier across a megabyte-scale chunk does not finish.
  const seen = new Map();
  const walk = (names) => {
    const queue = [...names];
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
  };
  walk([maskFn, buildVar]);

  /// Finds one declaration that the window missed, preferring the nearest
  /// match. Used only to repair a specific undefined identifier, never for the
  /// bulk walk, so the widening stays cheap.
  const resolveNear = (name) => {
    for (const radius of [60000, 250000, src.length]) {
      const decl = findDecl(
        src,
        name,
        Math.max(0, at - radius),
        Math.min(src.length, at + radius)
      );
      if (decl) return decl;
    }
    return null;
  };

  const replay = () => {
    // The bundle rotates its string table at load time; without replaying those
    // IIFEs every extracted literal decodes to garbage.
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
    // Declarations can nest: a name repaired later may live inside a function
    // already captured, and emitting both splices a fragment into the middle of
    // that function's own body, which will not parse. Keep outermost spans only
    // — the inner declaration comes along inside its parent anyway.
    let end = Number.NEGATIVE_INFINITY;
    const code = [...byOffset.values()]
      .sort((a, b) => a.at - b.at)
      .filter((d) => {
        if (d.promoted) return true;
        if (d.at < end) return false;
        end = Math.max(end, d.at + d.code.length);
        return true;
      })
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
    const program =
      `${code}\n;globalThis.__mask=Array.from(${maskFn}()||[]);` +
      `globalThis.__build=String(${buildVar}||"");`;
    try {
      new vm.Script(program).runInContext(sandbox, { timeout: 15000 });
    } catch (err) {
      if (process.env.AA_DEBUG) {
        require("fs").writeFileSync("/tmp/aa_replay.js", program);
        console.error(
          `[debug] replay failed (${err.message}); ` +
            `program written to /tmp/aa_replay.js (${program.length} bytes, ` +
            `${[...seen.keys()].length} decls)`
        );
      }
      throw err;
    }
    return sandbox;
  };

  // Repair loop: each failed replay names exactly one identifier it could not
  // resolve, so fetch that one declaration and try again. Upstream merged the
  // crypto and GraphQL code into a single chunk, which pushed some dependencies
  // outside the window; this recovers them without widening the bulk walk.
  let sandbox = null;
  for (let i = 0; i < 40 && !sandbox; i++) {
    try {
      sandbox = replay();
    } catch (err) {
      const missing = /^([A-Za-z_$][\w$]*) is not defined$/.exec(err.message);
      if (!missing) throw err;
      let decl = seen.get(missing[1]);
      // Nested functions get dropped by the outermost-span filter, so a name
      // can be "found" and still undefined at global scope. Hoist a copy.
      if (decl && decl.promoted) throw err;
      if (!decl) {
        decl = resolveNear(missing[1]);
        if (!decl) throw new Error(`${err.message} and no declaration found`);
      }
      if (process.env.AA_DEBUG) {
        let parses = "ok";
        try {
          new vm.Script(decl.code);
        } catch (e) {
          parses = `UNPARSEABLE (${e.message})`;
        }
        console.error(
          `[debug] repaired ${missing[1]} @${decl.at} ${parses}` +
            (decl.promoted === undefined && seen.has(missing[1]) ? " (hoisted)" : "") +
            `\n        ${decl.code.slice(0, 160).replace(/\n/g, " ")}`
        );
      }
      seen.set(missing[1], {
        at: -1_000_000 - seen.size,
        code: decl.code,
        promoted: true,
      });
      walk(
        [...decl.code.matchAll(/[A-Za-z_$][\w$]{1,}/g)].map((m) => m[0])
      );
    }
  }
  if (!sandbox) throw new Error("mask builder never replayed cleanly");

  const mask = sandbox.__mask;
  const buildId = sandbox.__build;
  if (!mask || mask.length !== 32) throw new Error("mask builder gave no bytes");
  if (!/^\d{1,4}$/.test(buildId)) throw new Error(`bad build id ${buildId}`);

  let params = null;
  for (const name of seen.keys()) {
    for (const expr of [name, `${name}()`]) {
      try {
        const v = vm.runInContext(expr, sandbox);
        if (v && typeof v === "object" && typeof v.bootPrefix === "string") params = v;
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

// ── Persisted-query hashes ──────────────────────────────────────────────────

function sliceDecl(src, name, hintBefore) {
  const esc = name.replace(/\$/g, "\\$");
  const matches = [
    ...src.matchAll(new RegExp(`(^|[,;{(\\s])${esc}\\s*=(?!=)`, "g")),
  ];
  if (!matches.length) return null;
  const m =
    hintBefore == null
      ? matches[0]
      : matches.filter((x) => x.index < hintBefore).pop() || matches[0];
  const eq = src.indexOf("=", m.index + m[0].indexOf(name)) + 1;
  return { at: m.index, name, code: src.slice(eq, endOfExpression(src, eq)) };
}

/// The hash is just sha256 of the GraphQL document the site sends, and the site
/// assembles that document from nested template literals — so evaluate them.
function extractQueryHash(src, resolver) {
  const marker = `\n${resolver}(\n`;
  const at = src.indexOf(marker);
  if (at === -1) throw new Error(`no query template contains ${resolver}`);

  const owner = [
    ...src.slice(0, at).matchAll(/[,;{]\s*([A-Za-z_$][\w$]*)\s*=(?!=)/g),
  ].pop();
  if (!owner) throw new Error(`could not find the declaration owning ${resolver}`);

  const seen = new Map();
  const queue = [owner[1]];
  while (queue.length) {
    const name = queue.shift();
    if (seen.has(name)) continue;
    const decl = sliceDecl(src, name, at + marker.length);
    if (!decl) continue;
    seen.set(name, decl);
    for (const ref of decl.code.matchAll(
      /\$\{\s*([A-Za-z_$][\w$]*)\s*(?:\(\s*\))?\s*\}/g
    )) {
      if (!seen.has(ref[1])) queue.push(ref[1]);
    }
  }

  const root = owner[1];
  const decls = [...seen.values()]
    .sort((a, b) => a.at - b.at)
    .map((d) => `var ${d.name} = ${d.code};`)
    .join("\n");

  const sandbox = { console };
  vm.createContext(sandbox);
  new vm.Script(
    `${decls}\nglobalThis.__q = (typeof ${root} === "function") ? ${root}() : ${root};`
  ).runInContext(sandbox, { timeout: 10000 });

  const query = sandbox.__q;
  if (typeof query !== "string") {
    throw new Error(`${resolver} template did not evaluate to a string`);
  }
  if (/\$\{/.test(query)) {
    throw new Error(`${resolver} query has unresolved interpolations`);
  }
  return crypto.createHash("sha256").update(query).digest("hex");
}

// ── One-pass scan ───────────────────────────────────────────────────────────

/// Walk the site's chunks once and pull out both the signing material and the
/// query hashes. They usually live in different chunks, and each chunk is
/// hundreds of kilobytes, so a single shared pass keeps a refresh cheap.
/// Routes to look for entry bundles on, in order of preference.
///
/// The homepage is not trustworthy on its own. Entry filenames are baked into
/// the served HTML, and the homepage is cached far more aggressively than the
/// content routes, so it can keep advertising a superseded bundle for hours
/// after a rotation. That is not hypothetical: it once left the scanner
/// recovering build 155 while the API had already moved to 157-159 and the
/// content routes were serving the current bundle. Content routes first, and
/// the homepage only as a fallback.
const ROUTES = (process.env.SCAN_ROUTES || "/anime,/manga,/").split(",");

/// Identifies the chunk holding the signing code.
///
/// This deliberately does not look for the bootstrap URL. That literal used to
/// be the anchor, but upstream now assembles the path at runtime, so the string
/// vanished from the bundle and the scan silently found no crypto at all. These
/// markers are things the code cannot avoid emitting: the request header names
/// it sets and the field it reads back off the bootstrap response. Any one is
/// enough, so a future rename of a single marker degrades instead of breaking.
const CRYPTO_MARKERS = [
  "x-aa-boot",
  "x-build-id",
  "aaReq",
  "partB",
  "bootPrefix",
  "__mask",
  "__build",
  "maskHex",
  "buildId",
  "bootParts",
];

function looksLikeCryptoChunk(js) {
  if (!js || typeof js !== "string") return false;
  return (
    CRYPTO_MARKERS.some((m) => js.includes(m)) ||
    /__mask\s*[:=]/.test(js) ||
    /__build\s*[:=]/.test(js) ||
    /bootPrefix\s*[:=]/.test(js) ||
    /partB\s*[:=]/.test(js) ||
    /maskHex\s*[:=]/.test(js) ||
    /x-aa-boot/.test(js) ||
    /x-build-id/.test(js)
  );
}

function extractBuildIdFromJs(js) {
  const matches = [
    ...js.matchAll(/__build\s*[:=]\s*["']?(\d{1,4})["']?/g),
    ...js.matchAll(/\bbuildId\s*[:=]\s*["']?(\d{1,4})["']?/g),
    ...js.matchAll(/["']?buildId["']?\s*:\s*["']?(\d{1,4})["']?/g),
  ];
  const values = matches.map((m) => Number(m[1])).filter((n) => Number.isFinite(n));
  return values.length ? String(Math.max(...values)) : null;
}

function extractMaskHexFromJs(js) {
  const matches = [
    ...js.matchAll(/__mask\s*[:=]\s*["']?([A-Fa-f0-9]{64})["']?/g),
    ...js.matchAll(/\bmaskHex\s*[:=]\s*["']?([A-Fa-f0-9]{64})["']?/g),
    ...js.matchAll(/["']?mask["']?\s*:\s*["']?([A-Fa-f0-9]{64})["']?/g),
  ];
  return matches[0]?.[1] || null;
}

function extractBootParamsFromJs(js) {
  const bootPrefix =
    [...js.matchAll(/bootPrefix\s*[:=]\s*["']([^"']+)["']/g)][0]?.[1] ||
    [...js.matchAll(/["']bootPrefix["']\s*:\s*["']([^"']+)["']/g)][0]?.[1] ||
    "aa-boot:";

  const join =
    [...js.matchAll(/join\s*[:=]\s*["']([^"']+)["']/g)][0]?.[1] || ":";

  const parts =
    [...js.matchAll(/parts\s*[:=]\s*\[([^\]]+)\]/g)][0]?.[1]
      ?.match(/[A-Za-z_]+/g)
      ?.filter(Boolean) ||
    ["buildId", "group", "host", "epoch", "lane"];

  return { bootPrefix, join, parts };
}

function entriesIn(html) {
  return [
    ...new Set(
      [
        ...html.matchAll(
          /https?:\/\/[^"']+\/_app\/immutable\/entry\/(?:app|start)\.[A-Za-z0-9_-]+\.js/g
        ),
      ].map((m) => m[0])
    ),
  ];
}

async function scanRoute(route, errors) {
  const html = await get(`${SITE}${route}`, { fresh: true });
  const entries = entriesIn(html);
  if (!entries.length) {
    errors.push(`${route}: no entry bundle`);
    return null;
  }
  const base = entries[0].slice(
    0,
    entries[0].indexOf("/immutable/") + "/immutable/".length
  );

  const names = new Set();
  for (const entry of entries) {
    const js = await get(entry);
    for (const m of js.matchAll(/chunks\/[A-Za-z0-9_-]+\.js/g)) names.add(m[0]);
  }

  let material = null;
  const hashes = {};

  for (const name of names) {
    if (material && RESOLVERS.every((r) => hashes[r])) break;
    let js;
    try {
      js = await get(base + name);
    } catch {
      continue;
    }
    if (!material && looksLikeCryptoChunk(js)) {
      try {
        material = extractMaterial(js);
      } catch (err) {
        errors.push(`${route} material: ${err.message}`);
      }
    }
    if (js.includes("chapterPages(")) {
      for (const r of RESOLVERS) {
        if (hashes[r]) continue;
        try {
          hashes[r] = extractQueryHash(js, r);
        } catch (err) {
          errors.push(`${route} ${r}: ${err.message}`);
        }
      }
    }
  }

  return material ? { material, hashes } : null;
}

async function scan() {
  const errors = [];
  for (const route of ROUTES) {
    let found;
    try {
      found = await scanRoute(route, errors);
    } catch (err) {
      errors.push(`${route}: ${err.message}`);
      continue;
    }
    if (found) return { ...found, errors };
  }
  throw new Error(`signing material not recovered (${errors.join("; ") || "no crypto chunk"})`);
}

module.exports = { scan, SITE, UA };
