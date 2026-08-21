/**
 * Hourly check that the values scraped from the bundle still work.
 *
 * Rescanning alone is not proof — an extractor can happily recover a build id
 * and mask that upstream no longer accepts. So each run also plays a real
 * signed query per lane and reports on the answer, which means a rotation shows
 * up in the logs within the hour instead of as user-reported breakage.
 *
 * Verified values stay in this process. The app no longer computes signatures
 * or hashes, so there is nothing to publish back to it.
 */
const { refresh, runQuery, state } = require("./upstream");

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

  lastReport = {
    at: new Date().toISOString(),
    ...after,
    maskHex: after.maskHex ? `${after.maskHex.slice(0, 12)}…` : null,
    changed,
    lanes,
    healthy: Object.values(lanes).every((l) => l.ok),
  };
  return lastReport;
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
