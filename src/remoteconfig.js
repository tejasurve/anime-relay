/**
 * Publishes verified signing material into Firebase Remote Config.
 *
 * This is what removes the manual step. Upstream rotates its build id, mask,
 * boot-token parameters and query hashes every few days; the app reads those
 * from Remote Config, so as long as a human has to paste them in, content
 * breaks until someone notices. The verifier already recovers and proves the
 * values, so it may as well publish them.
 *
 * Two things worth knowing about the shape here. The app keeps its entire
 * config in ONE parameter (`my_android_configs`) as a JSON string, so this is a
 * read-modify-write inside that string rather than a field update — every other
 * setting in it must survive untouched. And the write is guarded by the
 * template ETag, so a concurrent edit in the Firebase console fails the request
 * instead of being silently overwritten.
 */
const crypto = require("crypto");

const PARAM = process.env.RC_PARAM_NAME || "my_android_configs";
const SCOPE = "https://www.googleapis.com/auth/firebase.remoteconfig";
const TOKEN_URL = "https://oauth2.googleapis.com/token";

/// Only these keys are ever written. Anything else in the app's config is the
/// owner's to manage, and a bug here must not be able to touch it.
const MANAGED_KEYS = [
  "anime_episode_info",
  "manga_pages",
  "aa_build_id",
  "aa_mask",
  "aa_boot_prefix",
  "aa_boot_join",
  "aa_boot_parts",
];

function serviceAccount() {
  const b64 = process.env.FIREBASE_SERVICE_ACCOUNT_B64;
  const raw = b64
    ? Buffer.from(b64, "base64").toString("utf8")
    : process.env.FIREBASE_SERVICE_ACCOUNT;
  if (!raw) return null;
  let sa;
  try {
    sa = JSON.parse(raw);
  } catch (err) {
    throw new Error(`FIREBASE_SERVICE_ACCOUNT is not valid JSON: ${err.message}`);
  }
  if (!sa.client_email || !sa.private_key || !sa.project_id) {
    throw new Error("service account missing client_email/private_key/project_id");
  }
  return sa;
}

function isConfigured() {
  try {
    return Boolean(serviceAccount());
  } catch {
    return false;
  }
}

const b64url = (buf) =>
  Buffer.from(buf)
    .toString("base64")
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=+$/, "");

let tokenCache = null; // { token, expiresAt }

/// Service-account OAuth: sign a JWT asserting the scope, exchange it for an
/// access token. Done by hand to avoid pulling in googleapis for one call.
async function accessToken() {
  if (tokenCache && Date.now() < tokenCache.expiresAt - 60_000) {
    return tokenCache.token;
  }
  const sa = serviceAccount();
  if (!sa) throw new Error("no service account configured");

  const now = Math.floor(Date.now() / 1000);
  const header = b64url(JSON.stringify({ alg: "RS256", typ: "JWT" }));
  const claims = b64url(
    JSON.stringify({
      iss: sa.client_email,
      scope: SCOPE,
      aud: sa.token_uri || TOKEN_URL,
      iat: now,
      exp: now + 3600,
    })
  );
  const signature = b64url(
    crypto
      .createSign("RSA-SHA256")
      .update(`${header}.${claims}`)
      .sign(sa.private_key)
  );
  const assertion = `${header}.${claims}.${signature}`;

  const res = await fetch(sa.token_uri || TOKEN_URL, {
    method: "POST",
    headers: { "content-type": "application/x-www-form-urlencoded" },
    body: new URLSearchParams({
      grant_type: "urn:ietf:params:oauth:grant-type:jwt-bearer",
      assertion,
    }),
  });
  const body = await res.json();
  if (!res.ok || !body.access_token) {
    throw new Error(`token exchange failed (HTTP ${res.status}): ${JSON.stringify(body)}`);
  }
  tokenCache = {
    token: body.access_token,
    expiresAt: Date.now() + (body.expires_in || 3600) * 1000,
  };
  return tokenCache.token;
}

function templateUrl(projectId) {
  return `https://firebaseremoteconfig.googleapis.com/v1/projects/${projectId}/remoteConfig`;
}

async function fetchTemplate() {
  const sa = serviceAccount();
  const token = await accessToken();
  const res = await fetch(templateUrl(sa.project_id), {
    headers: { authorization: `Bearer ${token}` },
  });
  const text = await res.text();
  if (!res.ok) throw new Error(`template fetch failed (HTTP ${res.status}): ${text.slice(0, 200)}`);
  const etag = res.headers.get("etag");
  if (!etag) throw new Error("template response carried no ETag");
  return { template: JSON.parse(text), etag };
}

async function putTemplate(template, etag) {
  const sa = serviceAccount();
  const token = await accessToken();
  const res = await fetch(templateUrl(sa.project_id), {
    method: "PUT",
    headers: {
      authorization: `Bearer ${token}`,
      "content-type": "application/json; UTF-8",
      "if-match": etag,
    },
    body: JSON.stringify(template),
  });
  const text = await res.text();
  if (!res.ok) {
    // 409 means someone edited the template between our read and write.
    throw new Error(`template publish failed (HTTP ${res.status}): ${text.slice(0, 300)}`);
  }
  return JSON.parse(text);
}

/// Rewrites the managed keys inside one JSON-string config value, returning the
/// new string and a description of what changed. Returns null when nothing did.
function applyToConfigString(jsonString, values, label) {
  let config;
  try {
    config = JSON.parse(jsonString);
  } catch (err) {
    throw new Error(`${label} is not valid JSON: ${err.message}`);
  }
  const hashes = config.third_party_api_hashes;
  if (!hashes || typeof hashes !== "object") {
    throw new Error(`${label} has no third_party_api_hashes object`);
  }

  const changes = [];
  for (const key of MANAGED_KEYS) {
    const next = values[key];
    if (next === undefined) continue;
    const prev = hashes[key];
    if (String(prev ?? "") === String(next)) continue;
    changes.push({ key, from: prev ?? "(absent)", to: next });
    hashes[key] = next;
  }
  if (!changes.length) return null;

  // Preserve the original formatting style: these templates are hand-edited in
  // the console, so keep it readable rather than minified.
  return { value: JSON.stringify(config, null, 2), changes };
}

/**
 * Writes `values` into every copy of the app config in the template — the
 * default plus any conditional variants, since a device on a condition needs
 * current crypto just as much as one on the default.
 *
 * Set `dryRun` to compute the diff without publishing.
 */
async function publish(values, { dryRun = false } = {}) {
  const { template, etag } = await fetchTemplate();
  const param = template.parameters && template.parameters[PARAM];
  if (!param) {
    throw new Error(`Remote Config has no parameter named "${PARAM}"`);
  }

  const allChanges = [];

  if (param.defaultValue && typeof param.defaultValue.value === "string") {
    const result = applyToConfigString(
      param.defaultValue.value,
      values,
      `${PARAM}.defaultValue`
    );
    if (result) {
      param.defaultValue.value = result.value;
      allChanges.push({ target: "defaultValue", changes: result.changes });
    }
  }

  for (const [condition, cv] of Object.entries(param.conditionalValues || {})) {
    if (typeof cv.value !== "string") continue;
    const result = applyToConfigString(
      cv.value,
      values,
      `${PARAM}.conditionalValues.${condition}`
    );
    if (result) {
      cv.value = result.value;
      allChanges.push({ target: `condition:${condition}`, changes: result.changes });
    }
  }

  if (!allChanges.length) return { published: false, changes: [] };
  if (dryRun) return { published: false, dryRun: true, changes: allChanges };

  await putTemplate(template, etag);
  return { published: true, changes: allChanges };
}

module.exports = { publish, isConfigured, fetchTemplate, MANAGED_KEYS, PARAM };
