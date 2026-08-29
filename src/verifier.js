/**
 * Hourly check that the values scraped from the bundle still work.
 *
 * Rescanning alone is not proof — an extractor can happily recover a build id
 * and mask that upstream no longer accepts. So each run also plays a real
 * signed query per lane and reports on the answer, which means a rotation shows
 * up in the logs within the hour instead of as user-reported breakage.
 *
 * Verified values are then published to Remote Config, because devices still
 * sign their own requests against the upstream host directly. That split is
 * deliberate: the captcha gate is per egress IP, so calls must come from many
 * user devices rather than this one server address, which means the devices
 * need the current values and this is what gives them to them.
 */
const { refresh, runQuery, state } = require("./upstream");
const rc = require("./remoteconfig");

const INTERVAL_MS = Number(process.env.VERIFY_INTERVAL_MS || 60 * 60 * 1000);
const START_DELAY_MS = Number(process.env.VERIFY_START_DELAY_MS || 15 * 1000);

/// Probes need real ids. Override per environment if these ever get delisted.
const PROBES = {
  episode: {
    showId: process.env.PROBE_SHOW_ID || "qSyzgmuetej3MG4dA",
    translationType: "sub",
    episodeString: process.env.PROBE_EPISODE || "1",
  },
  chapterPages: {
    mangaId: process.env.PROBE_MANGA_ID || "T3bWg4zbtjzbs5uKZ",
    translationType: "sub",
    chapterString: process.env.PROBE_CHAPTER || "0",
    limit: 10,
    offset: 0,
  },
};

let lastReport = null;
let timer = null;

function snapshot() {
  const m = state.material;
  return {
    buildId: m ? m.buildId : null,
    maskHex: m ? m.maskHex : null,
    bootPrefix: m ? m.params.bootPrefix : null,
    bootPayload: m ? m.params.parts.join(m.params.join) : null,
    bootJoin: m ? m.params.join : null,
    bootParts: m ? m.params.parts.join(",") : null,
    hashes: { ...state.hashes },
  };
}

function diff(before, after) {
  const changed = [];
  for (const field of ["buildId", "maskHex", "bootPrefix", "bootPayload"]) {
    if (before[field] && before[field] !== after[field]) {
      changed.push(`${field}: ${before[field]} -> ${after[field]}`);
    }
  }
  for (const [resolver, hash] of Object.entries(after.hashes)) {
    if (before.hashes[resolver] && before.hashes[resolver] !== hash) {
      changed.push(`${resolver} hash: ${before.hashes[resolver]} -> ${hash}`);
    }
  }
  return changed;
}

/// Whether a probe outcome proves the *values* are right, which is not the same
/// as the request succeeding.
///
/// Upstream checks the signature and resolves the persisted query before the
/// resolver runs, so a NEED_CAPTCHA or a rate-limit reply can only happen once
/// the build id, mask, boot parameters and query hash have all been accepted.
/// Treating those as failures would mean this server's own gated IP could stop
/// good values from ever reaching users.
function provesValuesValid(lane) {
  if (lane.ok) return true;
  return /NEED_CAPTCHA|Too many requests/i.test(lane.detail);
}

function describe(resolver, data) {
  if (resolver === "episode") {
    const n = data?.episode?.sourceUrls?.length;
    return n ? `${n} sources` : "no sources";
  }
  const n = data?.chapterPages?.edges?.[0]?.pictureUrls?.length;
  return n ? `${n} pages` : "no pages";
}

async function verify() {
  const before = snapshot();
  try {
    await refresh({ force: true });
  } catch (err) {
    console.error(`[verify] rescan failed: ${err.message}`);
  }
  const after = snapshot();

  const changed = diff(before, after);
  for (const line of changed) console.log(`[verify] rotated — ${line}`);

  const lanes = {};
  for (const resolver of Object.keys(PROBES)) {
    try {
      const data = await runQuery({ resolver, variables: PROBES[resolver] });
      const detail = describe(resolver, data);
      const ok = !detail.startsWith("no ");
      lanes[resolver] = { ok, detail };
      console.log(`[verify] ${resolver}: ${ok ? "ok" : "EMPTY"} — ${detail}`);
    } catch (err) {
      lanes[resolver] = { ok: false, detail: err.message };
      console.error(`[verify] ${resolver}: FAILED — ${err.message}`);
    }
  }

  const valuesValid =
    Boolean(after.buildId) &&
    Object.values(lanes).every(provesValuesValid);

  const publishResult = await maybePublish(after, valuesValid);

  lastReport = {
    at: new Date().toISOString(),
    ...after,
    maskHex: after.maskHex ? `${after.maskHex.slice(0, 12)}…` : null,
    changed,
    lanes,
    healthy: Object.values(lanes).every((l) => l.ok),
    valuesValid,
    publish: publishResult,
  };
  return lastReport;
}

/// Pushes the verified values to Remote Config so devices signing their own
/// requests stay current. Skips silently when unconfigured, and refuses to
/// publish values a probe could not vouch for.
async function maybePublish(snap, valuesValid) {
  if (!rc.isConfigured()) return { skipped: "no service account configured" };
  if (process.env.RC_PUBLISH === "false") return { skipped: "RC_PUBLISH=false" };
  if (!valuesValid) {
    console.warn("[publish] skipped — probes did not validate the values");
    return { skipped: "values not validated" };
  }

  const values = {
    anime_episode_info: snap.hashes.episode,
    manga_pages: snap.hashes.chapterPages,
    aa_build_id: snap.buildId,
    aa_mask: snap.maskHex,
    aa_boot_prefix: snap.bootPrefix,
    aa_boot_join: snap.bootJoin,
    aa_boot_parts: snap.bootParts,
  };
  for (const [k, v] of Object.entries(values)) {
    if (v === undefined || v === null || v === "") {
      console.warn(`[publish] skipped — ${k} missing from scan`);
      return { skipped: `${k} missing` };
    }
  }

  try {
    const result = await rc.publish(values);
    if (!result.published) {
      console.log("[publish] Remote Config already current");
      return { published: false, upToDate: true };
    }
    for (const target of result.changes) {
      for (const c of target.changes) {
        console.log(`[publish] ${target.target} ${c.key}: ${c.from} -> ${c.to}`);
      }
    }
    console.log("[publish] Remote Config updated");
    return { published: true, changes: result.changes };
  } catch (err) {
    console.error(`[publish] failed: ${err.message}`);
    return { published: false, error: err.message };
  }
}

function start() {
  if (timer) return;
  setTimeout(() => {
    verify().catch((err) => console.error(`[verify] ${err.message}`));
  }, START_DELAY_MS);
  timer = setInterval(() => {
    verify().catch((err) => console.error(`[verify] ${err.message}`));
  }, INTERVAL_MS);
  // A pending verify must never hold the process open during a redeploy.
  if (timer.unref) timer.unref();
  console.log(`[verify] scheduled every ${Math.round(INTERVAL_MS / 60000)} min`);
}

module.exports = { start, verify, report: () => lastReport };
