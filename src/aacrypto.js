/**
 * The aa-crypto primitives upstream uses: the bootstrap boot token, the `aaReq`
 * request signature, and the `b7` response envelope.
 *
 * The AES key is never transmitted. Upstream returns half of it (`partB`) from
 * the bootstrap endpoint and the other half is the mask baked into the bundle,
 * so the key is `partB XOR mask` and both sides derive it independently.
 */
const crypto = require("crypto");

const B7_STATIC_KEY = process.env.B7_KEY || "Xot36i3lK3";

/// Signatures are bucketed to 5 minutes so a request stays valid briefly.
const TS_BUCKET_MS = 5 * 60 * 1000;

const EPOCH_LENGTHS_MS = [604800000, 259200000];

function epochCandidates(now = Date.now()) {
  const out = [];
  for (const len of EPOCH_LENGTHS_MS) {
    const cur = Math.floor(now / len);
    out.push(cur, cur - 1, cur + 1);
  }
  return [...new Set(out)];
}

function keyGroupForHost(host) {
  const h = (host || "").toLowerCase();
  if (h.startsWith("192.168.")) return "mirror";
  if (h === "youtu-chan.com" || h === "isekai2nd.com") return "mirror";
  return "mkissa";
}

/// HMAC chain: the mask keys an inner digest over `prefix + buildId`, and that
/// digest keys the outer digest over the parameter payload. Prefix, separator
/// and field order all come from the bundle because upstream rotates them.
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

function deriveKey(partB, maskHex) {
  const raw = Buffer.from(partB, "base64");
  const mask = Buffer.from(maskHex, "hex");
  const key = Buffer.alloc(32);
  for (let i = 0; i < 32; i++) key[i] = raw[i] ^ mask[i % mask.length];
  return key;
}

function currentTs(now = Date.now()) {
  return Math.floor(now / TS_BUCKET_MS) * TS_BUCKET_MS;
}

/// The IV is derived from the same fields the plaintext carries, so a replayed
/// signature cannot be re-pointed at a different query or lane.
function signAaReq({ partB, maskHex, buildId, epoch, queryHash, lane, ts }) {
  const key = deriveKey(partB, maskHex);
  const plaintext = JSON.stringify({
    v: 1,
    ts,
    epoch,
    buildId,
    qh: queryHash,
    k: lane,
  });
  const iv = crypto
    .createHash("sha256")
    .update(`${epoch}:${buildId}:${queryHash}:${ts}:${lane}`)
    .digest()
    .subarray(0, 12);
  const cipher = crypto.createCipheriv("aes-256-gcm", key, iv);
  const ct = Buffer.concat([cipher.update(plaintext, "utf8"), cipher.final()]);
  return Buffer.concat([
    Buffer.from([1]),
    iv,
    ct,
    cipher.getAuthTag(),
  ]).toString("base64");
}

/// Responses come back AES-GCM sealed under either the bootstrap key or a
/// static key derived from the build. Try both rather than guessing.
function decodeB7(tobeparsed, { partB, maskHex } = {}) {
  const blob = Buffer.from(tobeparsed, "base64");
  if (blob.length < 29) throw new Error(`b7 payload too short (${blob.length}B)`);
  const version = blob[0];
  const iv = blob.subarray(1, 13);
  const ct = blob.subarray(13, blob.length - 16);
  const tag = blob.subarray(blob.length - 16);

  const keys = [];
  if (partB && maskHex) keys.push(deriveKey(partB, maskHex));
  keys.push(
    crypto.createHash("sha256").update(`${B7_STATIC_KEY}:v${version}`).digest()
  );

  let lastError;
  for (const key of keys) {
    try {
      const d = crypto.createDecipheriv("aes-256-gcm", key, iv);
      d.setAuthTag(tag);
      return JSON.parse(
        Buffer.concat([d.update(ct), d.final()]).toString("utf8")
      );
    } catch (err) {
      lastError = err;
    }
  }
  throw new Error(`b7 decode failed: ${lastError && lastError.message}`);
}

module.exports = {
  bootToken,
  deriveKey,
  signAaReq,
  decodeB7,
  epochCandidates,
  keyGroupForHost,
  currentTs,
};
