const express = require("express");

const app = express();

const PORT = process.env.PORT || 3000;

// Must match the backend the working browser uses (mkissa.to -> api.mkissa.net).
// api.allanime.day is a DIFFERENT backend on a different aaReq key schedule and
// its bootstrap is Cloudflare-locked, so signed requests forwarded there fail
// with AA_CRYPTO_STALE.
const UPSTREAM = "https://api.mkissa.net";

const FORWARD_HEADERS = {
  accept: "*/*",
  "accept-language": "en-GB,en-US;q=0.9,en;q=0.8",
  origin: "https://mkissa.to",
  referer: "https://mkissa.to/",
  "user-agent":
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/148.0.0.0 Safari/537.36",
};

app.use(express.raw({ type: "*/*" }));

app.all("*", async (req, res) => {
  // Health endpoint
  if (req.path === "/" || req.path === "/healthz") {
    return res.send("allanime relay: ok");
  }

  const target = `${UPSTREAM}${req.originalUrl}`;

  console.log(`Forwarding -> ${target}`);

  try {
    const upstream = await fetch(target, {
      method: req.method,
      headers: FORWARD_HEADERS,
      body:
        req.method === "GET" || req.method === "HEAD"
          ? undefined
          : req.body,
      redirect: "follow",
    });

    res.status(upstream.status);

    upstream.headers.forEach((value, key) => {
      res.setHeader(key, value);
    });

    res.setHeader("Access-Control-Allow-Origin", "*");

    const buffer = Buffer.from(await upstream.arrayBuffer());

    res.send(buffer);
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
