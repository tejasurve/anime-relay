/**
 * Scans, verifies, then writes the current signing material into Firebase
 * Remote Config.
 *
 *   node publish-rc.js --dry-run   # show the diff, change nothing
 *   node publish-rc.js             # publish
 *
 * The server does this hourly on its own; this is for running it by hand and
 * for checking credentials before relying on them.
 */
const { verify } = require("./src/verifier");
const rc = require("./src/remoteconfig");
const up = require("./src/upstream");
const { scan } = require("./src/bundle");

const dryRun = process.argv.includes("--dry-run");

(async () => {
  if (!rc.isConfigured()) {
    console.error(
      "No service account. Set FIREBASE_SERVICE_ACCOUNT to the JSON, or\n" +
        "FIREBASE_SERVICE_ACCOUNT_B64 to its base64, then retry."
    );
    process.exit(1);
  }

  if (!dryRun) {
    const report = await verify();
    console.log("");
    console.log(JSON.stringify(report.publish, null, 2));
    return;
  }

  // Dry run does its own scan and probe so it never mutates anything.
  const { material, hashes } = await scan();
  console.log(`scanned build ${material.buildId}`);

  const probes = {
    episode: { showId: "qSyzgmuetej3MG4dA", translationType: "sub", episodeString: "1" },
    chapterPages: {
      mangaId: "T3bWg4zbtjzbs5uKZ",
      translationType: "sub",
      chapterString: "0",
      limit: 10,
      offset: 0,
    },
  };
  for (const [resolver, variables] of Object.entries(probes)) {
    try {
      await up.runQuery({ resolver, variables });
      console.log(`  ${resolver.padEnd(14)} ok`);
    } catch (err) {
      const benign = /NEED_CAPTCHA|Too many requests/i.test(err.message);
      console.log(
        `  ${resolver.padEnd(14)} ${err.message}` +
          (benign ? "  (values still accepted upstream)" : "  <-- values look wrong")
      );
    }
  }

  const values = {
    anime_episode_info: hashes.episode,
    manga_pages: hashes.chapterPages,
    aa_build_id: material.buildId,
    aa_mask: material.maskHex,
    aa_boot_prefix: material.params.bootPrefix,
    aa_boot_join: material.params.join,
    aa_boot_parts: material.params.parts.join(","),
  };

  const result = await rc.publish(values, { dryRun: true });
  console.log("");
  if (!result.changes.length) {
    console.log(`Remote Config parameter "${rc.PARAM}" is already current.`);
    return;
  }
  console.log(`Would change in "${rc.PARAM}":`);
  for (const target of result.changes) {
    console.log(`  [${target.target}]`);
    for (const c of target.changes) {
      console.log(`    ${c.key}`);
      console.log(`      from ${c.from}`);
      console.log(`      to   ${c.to}`);
    }
  }
})().catch((err) => {
  console.error(`error: ${err.message}`);
  process.exit(1);
});
