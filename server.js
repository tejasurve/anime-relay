/**
 * Express port of the mkissa API passthrough relay (for Railway / Node hosts).
 *
 * CRITICAL: forward the client's `x-build-id` and `x-aa-boot` headers.
 * Build 81+ bootstrap rejects requests without a valid boot token.
 */
const express = require("express");

const app = express();
const PORT = process.env.PORT || 3000;
const UPSTREAM = "https://api.mkissa.net";

const DEFAULT_HEADERS = {
  accept: "*/*",
  "accept-language": "en-GB,en-US;q=0.9,en;q=0.8",
  origin: "https://mkissa.to",
  referer: "https://mkissa.to/",
  "user-agent":
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/148.0.0.0 Safari/537.36",
};

const PASSTHROUGH = [
  "x-build-id",
  "x-aa-boot",
  "origin",
  "referer",
  "user-agent",
  "accept",
  "accept-language",
  "content-type",
];

app.use(express.raw({ type: "*/*" }));

app.all("*", async (req, res) => {
  if (req.path === "/" || req.path === "/healthz") {
    return res.send("allanime relay: ok");
  }

  const target = `${UPSTREAM}${req.originalUrl}`;
  console.log(`Forwarding -> ${target}`);

  const headers = { ...DEFAULT_HEADERS };
  for (const name of PASSTHROUGH) {
    const v = req.headers[name];
    if (typeof v === "string" && v.length) headers[name] = v;
  }

  try {
    const upstream = await fetch(target, {
      method: req.method,
      headers,
      body: req.method === "GET" || req.method === "HEAD" ? undefined : req.body,
      redirect: "follow",
    });

    res.status(upstream.status);
    const ct = upstream.headers.get("content-type");
    if (ct) res.setHeader("content-type", ct);
    res.setHeader("Access-Control-Allow-Origin", "*");
    res.send(Buffer.from(await upstream.arrayBuffer()));
  } catch (err) {
    console.error("Relay Error:", err);
    res.status(502).json({
      error: "relay_fetch_failed",
      detail: String(err),
    });
  }
});

app.listen(PORT, () => {
  console.log(`Relay listening on port ${PORT}`);
});
