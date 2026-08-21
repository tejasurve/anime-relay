/**
 * Talks to the protected resolvers on the app's behalf.
 *
 * The app used to do this itself, which meant every upstream rotation — build
 * id, mask, boot-token shape, persisted-query hash — needed either a Remote
 * Config edit or a store release. Here the same failures are recoverable in
 * process: a stale hash triggers a bundle rescan, stale crypto triggers a
 * re-bootstrap, and both retry once before the caller ever sees an error.
 */
const { scan, SITE } = require("./bundle");
const {
  bootToken,
  signAaReq,
  decodeB7,
  epochCandidates,
  currentTs,
} = require("./aacrypto");

const UPSTREAM = process.env.UPSTREAM || "https://api.mkissa.net";
const UA =
  process.env.RELAY_UA ||
  "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 " +
    "(KHTML, like Gecko) Chrome/148.0.0.0 Safari/537.36";

const MATERIAL_TTL_MS = 30 * 60 * 1000;
/// Re-bootstrap slightly before upstream rotates so a request never straddles it.
const BOOT_SKEW_MS = 5 * 60 * 1000;
const RESPONSE_TTL_MS = Number(process.env.RESPONSE_TTL_MS || 15 * 60 * 1000);
const RESPONSE_MAX_ENTRIES = 300;

/// How long to stop calling a lane after upstream demands a captcha.
///
/// That gate is per egress IP and sticky for at least an hour, and this process
/// has exactly one IP for every user. Retrying into it cannot succeed and only
/// deepens the block, so the lane is parked and the error returned immediately —
/// which also lets an app with a direct-host fallback try from its own IP.
const CAPTCHA_COOLDOWN_MS = Number(process.env.CAPTCHA_COOLDOWN_MS || 15 * 60 * 1000);

const LANES = { episode: "k7", chapterPages: "k9" };

const state = {
  material: null, // { buildId, maskHex, params }
  hashes: {}, // resolver -> sha256
  scannedAt: 0,
  boot: new Map(), // lane -> { partB, epoch, switchAt, at }
  captcha: new Map(), // lane -> unix ms until which the lane is parked
  lastError: null,
};

let scanInflight = null;
const bootInflight = new Map();
const responseCache = new Map(); // key -> { at, value }
const queryInflight = new Map();

function host() {
  return new URL(SITE).hostname.replace(/^www\./, "");
}

function baseHeaders() {
  return {
    accept: "*/*",
    "accept-language": "en-GB,en-US;q=0.9,en;q=0.8",
    origin: SITE,
    referer: `${SITE}/`,
    "user-agent": UA,
  };
}

// ── Bundle-derived state ────────────────────────────────────────────────────

async function refresh({ force = false } = {}) {
  const fresh = state.material && Date.now() - state.scannedAt < MATERIAL_TTL_MS;
  if (fresh && !force) return state;
  if (scanInflight) return scanInflight;

  scanInflight = scan()
    .then(({ material, hashes, errors }) => {
      const before = state.material;
      state.material = material;
      // Keep a previously good hash if this pass could not recover it.
      state.hashes = { ...state.hashes, ...hashes };
      state.scannedAt = Date.now();
      state.lastError = errors.length ? errors.join("; ") : null;

      if (!before || before.buildId !== material.buildId) {
        // The mask is build-bound, so any cached seed is now unusable.
        state.boot.clear();
        console.log(
          `[scan] build ${material.buildId} mask ${material.maskHex.slice(0, 12)}… ` +
            `boot ${material.params.bootPrefix}${material.params.parts.join(material.params.join)}`
        );
      }
      for (const [resolver, hash] of Object.entries(hashes)) {
        console.log(`[scan] ${resolver} hash ${hash}`);
      }
      if (errors.length) console.warn(`[scan] partial: ${errors.join("; ")}`);
      return state;
    })
    .catch((err) => {
      state.lastError = err.message;
      console.error(`[scan] failed: ${err.message}`);
      if (state.material) return state; // stale beats nothing
      throw err;
    })
    .finally(() => {
      scanInflight = null;
    });

  return scanInflight;
}

// ── Bootstrap ───────────────────────────────────────────────────────────────

async function fetchBootstrap(lane) {
  const { material } = await refresh();
  const url = new URL(`${UPSTREAM}/client-crypto/v1/bootstrap`);
  url.searchParams.set("buildId", material.buildId);
  url.searchParams.set("k", lane);

  let last = null;
  for (const epoch of epochCandidates()) {
    const res = await fetch(url, {
      headers: {
        ...baseHeaders(),
        "x-build-id": material.buildId,
        "x-aa-boot": bootToken({
          maskHex: material.maskHex,
          params: material.params,
          buildId: material.buildId,
          epoch,
          lane,
          host: host(),
        }),
      },
    });
    const text = await res.text();
    last = text;
    if (text.includes("invalid_boot_token")) continue;

    let body;
    try {
      body = JSON.parse(text);
    } catch {
      continue;
    }
    if (!body.partB) continue;
    return {
      partB: body.partB,
      epoch: body.epoch,
      switchAt: body.switchAt || 0,
      at: Date.now(),
      // Kept verbatim so the bootstrap endpoint can answer older clients from
      // cache with the exact body upstream would have sent.
      raw: body,
    };
  }
  throw new Error(`bootstrap rejected for ${lane}: ${String(last).slice(0, 120)}`);
}

async function getBootstrap(lane, { force = false } = {}) {
  const cached = state.boot.get(lane);
  const valid =
    cached && (!cached.switchAt || Date.now() < cached.switchAt - BOOT_SKEW_MS);
  if (valid && !force) return cached;
  if (bootInflight.has(lane)) return bootInflight.get(lane);

  const p = fetchBootstrap(lane)
    .then((boot) => {
      state.boot.set(lane, boot);
      console.log(`[boot] ${lane} epoch ${boot.epoch}`);
      return boot;
    })
    .finally(() => bootInflight.delete(lane));

  bootInflight.set(lane, p);
  return p;
}

// ── Signed query ────────────────────────────────────────────────────────────

function errorMessage(body) {
  if (!body || !Array.isArray(body.errors) || !body.errors.length) return null;
  return String(body.errors[0].message || "");
}

async function callUpstream({ resolver, lane, variables }) {
  const { material, hashes } = await refresh();
  const queryHash = hashes[resolver];
  if (!queryHash) throw new Error(`no persisted-query hash known for ${resolver}`);

  const boot = await getBootstrap(lane);
  const extensions = {
    persistedQuery: { version: 1, sha256Hash: queryHash },
    k: lane,
    aaReq: signAaReq({
      partB: boot.partB,
      maskHex: material.maskHex,
      buildId: material.buildId,
      epoch: boot.epoch,
      queryHash,
      lane,
      ts: currentTs(),
    }),
  };

  const url =
    `${UPSTREAM}/api?variables=${encodeURIComponent(JSON.stringify(variables))}` +
    `&extensions=${encodeURIComponent(JSON.stringify(extensions))}`;

  const res = await fetch(url, {
    headers: { ...baseHeaders(), "x-build-id": material.buildId },
  });
  const text = await res.text();
  let body;
  try {
    body = JSON.parse(text);
  } catch {
    throw new Error(`upstream returned non-JSON (HTTP ${res.status})`);
  }

  const message = errorMessage(body);
  if (message) return { error: message, status: res.status };

  let data = body.data;
  if (data && data._m === "b7" && typeof data.tobeparsed === "string") {
    data = decodeB7(data.tobeparsed, {
      partB: boot.partB,
      maskHex: material.maskHex,
    });
  }
  return { data };
}

/// Runs a protected resolver, healing the two failures that used to require a
/// config edit or an app release. NEED_CAPTCHA is deliberately not retried:
/// it is egress reputation, so hammering it makes matters worse.
async function runQuery({ resolver, variables }) {
  const lane = LANES[resolver];
  if (!lane) throw new Error(`unsupported resolver ${resolver}`);

  const parkedUntil = state.captcha.get(lane) || 0;
  if (Date.now() < parkedUntil) {
    throw Object.assign(new Error("NEED_CAPTCHA"), { upstream: true, parked: true });
  }

  let result = await callUpstream({ resolver, lane, variables });

  if (result.error && /PersistedQueryNotFound|PERSISTED_QUERY_NOT_FOUND/i.test(result.error)) {
    console.warn(`[heal] ${resolver} hash stale — rescanning bundle`);
    await refresh({ force: true });
    result = await callUpstream({ resolver, lane, variables });
  } else if (result.error && /AA_CRYPTO|invalid_boot_token|STALE/i.test(result.error)) {
    console.warn(`[heal] ${resolver} crypto stale — re-bootstrapping`);
    await refresh({ force: true });
    await getBootstrap(lane, { force: true });
    result = await callUpstream({ resolver, lane, variables });
  }

  if (result.error) {
    if (/NEED_CAPTCHA/i.test(result.error)) {
      state.captcha.set(lane, Date.now() + CAPTCHA_COOLDOWN_MS);
      console.warn(
        `[captcha] ${lane} parked for ${Math.round(CAPTCHA_COOLDOWN_MS / 60000)} min`
      );
    }
    throw Object.assign(new Error(result.error), { upstream: true });
  }
  state.captcha.delete(lane);
  return result.data;
}

// ── Cache ───────────────────────────────────────────────────────────────────

function cacheKey(resolver, variables) {
  return `${resolver}:${JSON.stringify(variables)}`;
}

/// Identical requests are common (retries, several users on a new episode) and
/// every extra upstream call spends egress reputation, so serve a short cache
/// and collapse concurrent duplicates into one call.
async function query({ resolver, variables }) {
  const key = cacheKey(resolver, variables);
  const hit = responseCache.get(key);
  if (hit && Date.now() - hit.at < RESPONSE_TTL_MS) return hit.value;
  if (queryInflight.has(key)) return queryInflight.get(key);

  const p = runQuery({ resolver, variables })
    .then((data) => {
      if (responseCache.size >= RESPONSE_MAX_ENTRIES) {
        responseCache.delete(responseCache.keys().next().value);
      }
      responseCache.set(key, { at: Date.now(), value: data });
      return data;
    })
    .finally(() => queryInflight.delete(key));

  queryInflight.set(key, p);
  return p;
}

module.exports = {
  refresh,
  getBootstrap,
  query,
  runQuery, // uncached — used by the verifier so a probe is always a real call
  state,
  LANES,
  UPSTREAM,
  baseHeaders,
  host,
};
