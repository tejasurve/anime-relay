/**
 * AnimangaX API backend.
 *
 * The two protected resolvers — `episode` and `chapterPages` — are answered
 * here rather than forwarded. The app still speaks the GraphQL shape it always
 * has, but its persisted-query hash, `aaReq` signature and build id are all
 * ignored: this process derives its own from the live bundle, signs the call,
 * decrypts the response and hands back plain JSON. The app decrypts nothing.
 *
 * That inversion is the point. Every upstream rotation used to mean a Remote
 * Config edit or a store release, because the fragile values were baked into a
 * shipped binary. Now a rotation is a rescan, and clients too old to know about
 * any of it keep working unchanged.
 *
 * Everything else is a plain passthrough.
 */
const express = require("express");

const upstream = require("./src/upstream");
const verifier = require("./src/verifier");

const app = express();
const PORT = process.env.PORT || 3000;
const UPSTREAM = upstream.UPSTREAM;
const BOOTSTRAP_PATH = "/client-crypto/v1/bootstrap";

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

/// Identify the resolver from the variables rather than the client's hash or
/// `k`, both of which go stale in released apps. The variable names are part of
/// the app's own request shape, so they are the one thing we can trust.
function resolverFor(variables) {
  if (!variables || typeof variables !== "object") return null;
  if (variables.showId && variables.episodeString !== undefined) return "episode";
  if (variables.mangaId && variables.chapterString !== undefined) return "chapterPages";
  return null;
}

function parseJsonParam(raw) {
  if (typeof raw !== "string" || !raw) return null;
  try {
    return JSON.parse(raw);
  } catch {
    return null;
  }
}

function graphqlError(res, resolver, message, status = 200) {
  res.status(status);
  res.setHeader("content-type", "application/json");
  res.setHeader("access-control-allow-origin", "*");
  res.send(
    JSON.stringify({
      errors: [{ message, path: [resolver] }],
      data: { [resolver]: null },
    })
  );
}

async function handleProtected(req, res, resolver, variables) {
  const started = Date.now();
  try {
    const data = await upstream.query({ resolver, variables });
    res.setHeader("content-type", "application/json");
    res.setHeader("access-control-allow-origin", "*");
    res.setHeader("x-relay-mode", "server-signed");
    res.send(JSON.stringify({ data }));
    console.log(`[api] ${resolver} ok in ${Date.now() - started}ms`);
  } catch (err) {
    console.error(`[api] ${resolver} failed: ${err.message}`);
    graphqlError(res, resolver, err.message);
  }
}

/// Older clients still bootstrap before they sign. Their signature is discarded
/// upstream of here, but a failed bootstrap can stop them from sending the
/// request at all, so answer it from the same cache the signer uses.
async function handleBootstrap(req, res) {
  const url = new URL(UPSTREAM + req.originalUrl);
  const lane = url.searchParams.get("k") || "k7";
  try {
    const boot = await upstream.getBootstrap(lane);
    res.setHeader("content-type", "application/json");
    res.setHeader("access-control-allow-origin", "*");
    res.send(JSON.stringify(boot.raw));
  } catch (err) {
    console.error(`[boot] ${lane} failed: ${err.message}`);
    res.status(502).json({ error: "bootstrap_failed", detail: err.message });
  }
}

async function handlePassthrough(req, res) {
  const headers = {
    ...upstream.baseHeaders(),
  };
  for (const name of PASSTHROUGH) {
    const v = req.headers[name];
    if (typeof v === "string" && v.length) headers[name] = v;
  }
  try {
    const r = await fetch(`${UPSTREAM}${req.originalUrl}`, {
      method: req.method,
      headers,
      body: req.method === "GET" || req.method === "HEAD" ? undefined : req.body,
      redirect: "follow",
    });
    res.status(r.status);
    const ct = r.headers.get("content-type");
    if (ct) res.setHeader("content-type", ct);
    res.setHeader("access-control-allow-origin", "*");
    res.send(Buffer.from(await r.arrayBuffer()));
  } catch (err) {
    console.error(`[proxy] ${req.originalUrl}: ${err.message}`);
    res.status(502).json({ error: "relay_fetch_failed", detail: err.message });
  }
}

app.use(express.raw({ type: "*/*" }));

app.get("/healthz", async (_req, res) => {
  try {
    await upstream.refresh();
  } catch {
    /* report the stale state below rather than failing outright */
  }
  const m = upstream.state.material;
  res.json({
    ok: Boolean(m),
    buildId: m ? m.buildId : null,
    bootPrefix: m ? m.params.bootPrefix : null,
    bootPayload: m ? m.params.parts.join(m.params.join) : null,
    hashes: upstream.state.hashes,
    scannedAt: upstream.state.scannedAt
      ? new Date(upstream.state.scannedAt).toISOString()
      : null,
    scanError: upstream.state.lastError,
    captchaParked: Object.fromEntries(
      [...upstream.state.captcha]
        .filter(([, until]) => Date.now() < until)
        .map(([lane, until]) => [lane, new Date(until).toISOString()])
    ),
    lastVerify: verifier.report(),
  });
});

/// Manual trigger for the same check the hourly job runs.
app.post("/admin/verify", async (_req, res) => {
  try {
    res.json(await verifier.verify());
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// `app.use` rather than `app.all("*")`: Express 5 rejects the wildcard string.
app.use(async (req, res) => {
  if (req.path === "/") return res.send("animangax api: ok");

  if (req.path === BOOTSTRAP_PATH && req.method === "GET") {
    return handleBootstrap(req, res);
  }

  if (req.path === "/api" && req.method === "GET") {
    const variables = parseJsonParam(req.query.variables);
    const resolver = resolverFor(variables);
    if (resolver) return handleProtected(req, res, resolver, variables);
  }

  return handlePassthrough(req, res);
});

app.listen(PORT, () => {
  console.log(`animangax api listening on ${PORT} -> ${UPSTREAM}`);
  upstream.refresh().catch(() => {});
  verifier.start();
});
