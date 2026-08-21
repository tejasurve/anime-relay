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

async function get(url) {
  const res = await fetch(url, {
    headers: { "user-agent": UA, referer: `${SITE}/` },
  });
  if (!res.ok) throw new Error(`GET ${url} -> HTTP ${res.status}`);
  return res.text();
}

// ── Source slicing helpers ──────────────────────────────────────────────────

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
async function scan() {
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

  let material = null;
  const hashes = {};
  const errors = [];

  for (const name of names) {
    if (material && RESOLVERS.every((r) => hashes[r])) break;
    let js;
    try {
      js = await get(base + name);
    } catch {
      continue;
    }
    if (!material && js.includes("client-crypto/v1/bootstrap")) {
      try {
        material = extractMaterial(js);
      } catch (err) {
        errors.push(`material: ${err.message}`);
      }
    }
    if (js.includes("chapterPages(")) {
      for (const r of RESOLVERS) {
        if (hashes[r]) continue;
        try {
          hashes[r] = extractQueryHash(js, r);
        } catch (err) {
          errors.push(`${r}: ${err.message}`);
        }
      }
    }
  }

  if (!material) {
    throw new Error(`signing material not recovered (${errors.join("; ") || "no crypto chunk"})`);
  }
  return { material, hashes, errors };
}

module.exports = { scan, SITE, UA };
