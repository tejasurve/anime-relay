/**
 * Monitors for Build 173 activation on upstream.
 * Polls every 30 seconds and notifies when bootstrap succeeds.
 *
 * Usage: node monitor-build-173.js
 *
 * Once this reports "BUILD 173 ACTIVATED", the app will work immediately
 * (no code changes needed, no restart needed).
 */
const up = require("./src/upstream");

const CHECK_INTERVAL_MS = 30000;
let lastStatus = null;

async function check() {
  try {
    const { material } = await up.refresh();
    const boot = await up.getBootstrap("k9");

    const status = `✓ BUILD 173 ACTIVATED — bootstrap working`;
    if (status !== lastStatus) {
      console.log(
        `[${new Date().toISOString()}] ${status}`
      );
      lastStatus = status;
      console.log(`  epoch: ${boot.epoch}, partB length: ${boot.partB.length}`);
      return true;
    }
  } catch (err) {
    const msg = err.message || String(err);
    const isBootReject =
      msg.includes("invalid_boot_token") || msg.includes("bootstrap rejected");

    const status = isBootReject
      ? `✗ Still waiting for upstream activation (bootstrap rejected)`
      : `⚠ Unexpected error: ${msg.slice(0, 60)}`;

    if (status !== lastStatus) {
      console.log(
        `[${new Date().toISOString()}] ${status}`
      );
      lastStatus = status;
    }
  }
  return false;
}

(async () => {
  console.log("Monitoring Build 173 activation...");
  console.log("Check interval: 30 seconds\n");

  while (true) {
    const activated = await check();
    if (activated) {
      console.log(
        "\n🎉 Your app will now work! Restart the backend (if running) or requests will auto-heal.\n"
      );
      process.exit(0);
    }
    await new Promise((r) => setTimeout(r, CHECK_INTERVAL_MS));
  }
})().catch((err) => {
  console.error("Monitor failed:", err.message);
  process.exit(1);
});
