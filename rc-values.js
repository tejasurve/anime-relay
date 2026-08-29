/**
 * Prints the `third_party_api_hashes` values that upstream currently expects,
 * after checking that they actually work.
 *
 * This exists for the case where the app is still signing requests itself and
 * has to be told these values through Remote Config. Every field below rotates
 * together — build id, mask, the three boot-token parameters and both query
 * hashes — and a partial update fails in a way that looks like a dead endpoint,
 * so the whole block is emitted at once and only after a live probe passes.
 *
 *   node rc-values.js
 *
 * Once traffic goes through this backend none of it is needed by the app.
 */
const { scan } = require("./src/bundle");
const up = require("./src/upstream");

const PROBES = {
  episode: {
    showId: "qSyzgmuetej3MG4dA",
    translationType: "sub",
    episodeString: "1",
  },
  chapterPages: {
    mangaId: "T3bWg4zbtjzbs5uKZ",
    translationType: "sub",
    chapterString: "0",
    limit: 10,
    offset: 0,
  },
};

(async () => {
  const { material, hashes, errors } = await scan();
  if (errors.length) console.error(`warning: ${errors.join("; ")}`);
  if (!hashes.episode || !hashes.chapterPages) {
    throw new Error("could not recover both query hashes");
  }

  // Proving the values work matters more than recovering them: the extractor
  // can succeed against a bundle upstream has already stopped accepting.
  const results = {};
  for (const [resolver, variables] of Object.entries(PROBES)) {
    try {
      const data = await up.runQuery({ resolver, variables });
      const count =
        resolver === "episode"
          ? data?.episode?.sourceUrls?.length
          : data?.chapterPages?.edges?.[0]?.pictureUrls?.length;
      results[resolver] = count ? `ok (${count})` : "returned nothing";
    } catch (err) {
      results[resolver] = `FAILED — ${err.message}`;
    }
  }

  const ok = Object.values(results).every((r) => r.startsWith("ok"));
  console.error("");
  for (const [resolver, r] of Object.entries(results)) {
    console.error(`  ${resolver.padEnd(14)} ${r}`);
  }
  console.error("");

  if (!ok) {
    console.error(
      "Not emitting values: at least one lane failed, so pasting these would\n" +
        "not fix the app. A NEED_CAPTCHA here is this machine's IP, not the values."
    );
    process.exitCode = 1;
    return;
  }

  const block = {
    anime_episode_info: hashes.episode,
    manga_pages: hashes.chapterPages,
    aa_build_id: material.buildId,
    aa_mask: material.maskHex,
    aa_boot_prefix: material.params.bootPrefix,
    aa_boot_join: material.params.join,
    aa_boot_parts: material.params.parts.join(","),
  };

  console.error("Merge into third_party_api_hashes (all seven, together):");
  console.log(
    JSON.stringify(block, null, 2)
      .replace(/^{\n/, "")
      .replace(/\n}$/, "")
  );
})().catch((err) => {
  console.error(`error: ${err.message}`);
  process.exit(1);
});
