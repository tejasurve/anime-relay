const express = require("express");

const app = express();

const PORT = process.env.PORT || 3000;

const UPSTREAM = "https://api.allanime.day";

const FORWARD_HEADERS = {
  accept: "*/*",
  "accept-language": "en-GB,en-US;q=0.9,en;q=0.8",
  origin: "https://allmanga.to",
  referer: "https://allmanga.to/",
  "user-agent":
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36",
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
