# anime-relay

Keeps AnimangaX content working without app releases.

Upstream rotates its request-signing material (build id, XOR mask, boot-token
formula) and its persisted GraphQL query hashes every few days. The Flutter app
reads all of that from Firebase Remote Config, so before this service existed,
every rotation broke episodes and manga pages until someone manually recovered
the new values and pasted them in.

This service recovers them automatically, proves they work, and publishes them.

## How it works

1. **Scan** (`src/bundle.js`) walks the live site's JS bundles and recovers the
   build id, mask and boot-token parameters by replaying the relevant bundle
   code in a VM sandbox, plus the persisted query hashes by evaluating the
   GraphQL template literals. Structural signatures are used rather than string
   patterns, so obfuscation changes between builds don't break it.
2. **Probe** (`src/verifier.js`) signs one real query per lane, hourly, to prove
   the recovered values are actually accepted.
3. **Publish** (`src/remoteconfig.js`) writes the proven values into Remote
   Config, so every device picks them up on next launch.

It also serves `/api` directly (`src/upstream.js`), signing and decrypting on
behalf of clients, with self-healing on stale hashes and crypto.

### Why publish to the app instead of just proxying

The upstream captcha gate is applied **per egress IP**. This service runs on one
address, so routing all traffic through it gets that address gated — which is
exactly what the `NEED_CAPTCHA` responses in the logs are. Requests need to come
from many individual user devices, which means the devices need current signing
values, and publishing to Remote Config is how they get them. The proxy path is
a fallback, not the primary route.

### Why a captcha response still counts as success

Upstream validates the signature and resolves the persisted query *before* the
resolver runs. So a `NEED_CAPTCHA` reply can only happen once the build id, mask,
boot parameters and query hash have all been accepted. Treating it as a failure
would let this server's own gated IP permanently block good values from reaching
users, so the publish gate accepts it. Crypto errors (`AA_CRYPTO_*`,
`invalid_boot_token`, `unknown_build_id`) and `PersistedQueryNotFound` are the
outcomes that mean the values are genuinely wrong, and those do block a publish.

## Environment

| Variable | Required | Purpose |
| --- | --- | --- |
| `FIREBASE_SERVICE_ACCOUNT` | for publishing | Service account JSON, verbatim. Without it the service still proxies, but stops publishing. |
| `FIREBASE_SERVICE_ACCOUNT_B64` | alternative | Base64 of the same JSON, for hosts that mangle multi-line values. |
| `ADMIN_TOKEN` | no | Enables `POST /admin/verify`. Endpoint returns 404 while unset. |
| `RC_PUBLISH` | no | Set to `false` to scan and probe without writing. |
| `RC_PARAM_NAME` | no | Remote Config parameter holding the app config. Defaults to `my_android_configs`. |
| `VERIFY_INTERVAL_MS` | no | Verify cadence. Defaults to one hour. |
| `PROBE_SHOW_ID`, `PROBE_MANGA_ID` | no | Override the probe targets if they stop existing upstream. |

The service account needs the **Firebase Remote Config Admin** role. Never
commit the key; `.gitignore` blocks the usual filenames as a backstop.

## Deploying on Railway

Push to `main` and Railway redeploys. Set `FIREBASE_SERVICE_ACCOUNT` (and
optionally `ADMIN_TOKEN`) under Variables. `npm start` runs `server.js`, which
binds `PORT`.

Confirm a deploy with `/healthz` — it reports the current build id, mask, hashes,
scan errors, which lanes are captcha-parked, and the last verify report
including whether a publish happened.

## Running by hand

```bash
npm install
export FIREBASE_SERVICE_ACCOUNT="$(cat /path/to/key.json)"

npm run publish-rc:dry   # scan, probe, show the exact Remote Config diff
npm run publish-rc       # same, then publish
npm run values           # print verified values for manual pasting
npm start                # run the server
```

Start with the dry run when changing anything about publishing: it reads the
template and prints the diff without writing.

## Notes on the Remote Config write

The app keeps its **entire** configuration in one parameter as a JSON string, so
publishing is a read-modify-write inside that string rather than a field update.
Two consequences worth remembering:

- Only the seven signing keys are ever written (`MANAGED_KEYS` in
  `src/remoteconfig.js`). Every other setting is passed through untouched.
- The parameter's conditional values are updated as well as its default. A
  device matching a condition needs current signing material just as much as one
  on the default, and a stale iOS conditional override has already caused an
  outage that looked exactly like a bad hash.

Writes are guarded with the template ETag, so an edit made in the Firebase
console between read and write fails the request instead of being overwritten.
