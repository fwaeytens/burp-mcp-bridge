# Integration tests — real Burp, real bridge

These tests run a **real Burp Suite Community** with the freshly built MCP
extension loaded, and drive it the way an AI agent would: through the MCP
bridge, as an MCP client. They assert on the structured responses the agent
would get back.

They are a second layer on top of the unit tests (138 Java, 27 Node). The unit
tests run against hand-written fakes of the Montoya API; a fake can disagree
with real Burp and still pass. This suite catches exactly that class of bug (see
the proxy-history ID fix in commit `d5af19d`).

They are **opt-in** and need Docker. `npm test` / `mvn package` stay fast and
Docker-free.

## What runs

The suite spins up **two containers** with Docker Compose, and the **test
scripts run on the host** and drive them:

1. **`burp` container — Burp with the MCP extension, plus an X server.** Burp
   is a desktop (Swing) application, so the container runs a virtual X server
   (Xvfb) for it to draw on. The container accepts Burp's EULA, clicks through
   the startup dialog, and loads the extension, whose API server then listens
   for MCP calls. Burp's proxy (8080) and the extension API (8081) are published
   on `127.0.0.1` only, on ports Docker picks at startup.
2. **`target` container — a dummy web server to test against.** It returns
   fixed, predictable responses (a page that echoes a query parameter, JSON,
   cookies, redirects, chosen status codes, and a route that drops the
   connection without answering), so the tests never touch the internet.
3. **Test scripts on the host — standing in for the agent.** Each test file
   acts as an MCP client: it starts the bridge (`bridge/index.js`) over stdio
   exactly as an agent's MCP host would, calls Burp tools through it, and checks
   the results. To give Burp something to look at, the tests also send requests
   to the target *through Burp's proxy*, so they land in proxy history and the
   site map.

```
 host
 ┌──────────────────────────────────────────────────────────────────────────┐
 │  test scripts (MCP client, stand-in for the agent)                       │
 │    │ stdio                                         │ curl --proxy        │
 │    ▼                                               │                     │
 │  bridge/index.js                                   │                     │
 │    │ JSON-RPC over HTTP                            │                     │
 │ ┌──┼───────────────────────────────────────────────┼───────────────────┐ │
 │ │  ▼  burp container                               ▼                   │ │
 │ │  extension API :8081   ◄── Burp Community ──►  proxy :8080           │ │
 │ │                            (on Xvfb)              │                  │ │
 │ └───────────────────────────────────────────────────┼──────────────────┘ │
 │ ┌───────────────────────────────────────────────────▼──────────────────┐ │
 │ │  target container: dummy web server, http://target                   │ │
 │ └──────────────────────────────────────────────────────────────────────┘ │
 └──────────────────────────────────────────────────────────────────────────┘
```

## Prerequisites

- Docker (daemon running). On arm64 the base images are multi-arch.
- The built extension jar: `(cd extension && mvn -q package -DskipTests)`.
- The Burp Community jar, cached once (≈685 MB, not committed, not baked into
  any image):

  ```bash
  npm run fetch-burp          # downloads to ~/.cache/burp-mcp-bridge/
  # or set BURP_COMMUNITY_JAR=/abs/path/burpsuite_community_v*.jar
  ```

## Run

```bash
cd integration
npm run test:integration        # build + up + test + down
npm run test:integration:keep   # same, but leave the stack running for debugging
```

The orchestrator (`scripts/run-integration.js`) resolves both jars into `.env`,
brings the stack up (waiting on the healthchecks), discovers the published
ports, runs `node --test`, and tears the stack down. By default the suite covers
the bundled **Community** edition only.

**Testing a Burp you run yourself** (any edition, e.g. Professional): open a
**fresh project** (a new temporary project is fine) with the MCP extension
loaded, proxy listener running, and no upstream proxy rule catching
`127.0.0.1` — Burp must reach the mock server on loopback directly. Then:

```bash
npm run test:integration -- --burp-api 127.0.0.1:8081 --burp-proxy 127.0.0.1:8080 --edition professional
```

All three flags are required. Only the mock server container is started. A
preflight refuses to run unless the extension answers, the proxy history is
empty, and Burp can fetch the mock server. The tests write into that project
(proxy history, annotations, scope, site map, and on Professional a scan that is
started and cancelled), which is why it must be a fresh one.

## Design notes

- **Ephemeral ports, discovered from Docker.** Nothing is hardcoded to 8080/8081,
  so the suite never collides with a Burp you already have running. The
  orchestrator reads `docker compose port burp 8080|8081` and passes the result
  to the tests via `BURP_IT_*` variables (see `lib/endpoints.js`). The test
  helpers have **no defaults** — they fail loudly if the orchestrator did not
  set them.
- **The mock server is addressed as Burp reaches it.** The bundled Burp uses its
  compose name, `http://target`, which the host cannot resolve. A Burp you run
  yourself uses the server's loopback port. Requests go through Burp's proxy
  with `NO_PROXY` cleared (`curl --noproxy ''`), so they can never bypass it.
- **The extension's IP allowlist is disabled on the container** (`*`). The API
  port is already loopback-scoped by Docker, and published-port NAT makes the
  bridge arrive as the Docker gateway IP. Scoped to the throwaway test image.
- **Edition-based selection.** Tests that depend on the edition declare it
  (`onlyOn('community')` / `onlyOn('professional')` in `test/edition.test.js`)
  and are reported as *skipped* on the other edition. The edition is not
  guessed: it is `community` for the bundled Burp and `--edition` for yours.
  - On Community, Scanner, Collaborator, and HTTP jobs must refuse (the
    Professional-only features are absent).
  - On Professional, the scanner must start an active scan of the mock server;
    the test cancels it right away.

## Known bugs

- **`burp_scanner` refusal wording on Community.** `START_SCAN` refuses as it
  should, but says `Failed to start scan: null` rather than "Requires Burp Suite
  Professional": that message is only returned when `api.scanner()` is null,
  and Community returns a non-null scanner. The test checks the refusal, not the
  wording.

## Disabled tests

- **History gaps (the `d5af19d` real-id fix).** Ids and Burp's `#` only differ
  once an entry is deleted, and the Montoya API cannot delete proxy history, so
  the test deletes one through Burp's UI (`burp/delete-history-row.sh`, xdotool
  at calibrated screen coordinates). That proved flaky, so the test is skipped.
  Plan: replace the clicking with a test-only helper extension that drives the
  Swing components from inside Burp's JVM by label instead of by pixel. Until
  then the gap case is covered by unit tests with non-contiguous fake ids
  (`ProxyHistoryIterateTest` for `iterate`).

## Current behaviour pinned by tests (to be confirmed)

- **`statusCode` filter and unanswered requests.** The mock server's `/hangup`
  route drops the connection without responding, so the history always holds a
  request with no response. Filtering `burp_proxy_history` by `statusCode`
  returns such entries too: the filter only rejects a *different* code. The test
  asserts that as-is; flip it if the behaviour is changed.

## Files

| Path | Role |
|------|------|
| `docker-compose.yml`        | the mock server (always started) |
| `docker-compose.burp.yml`   | the bundled Burp Community (default mode only) |
| `test/edition.test.js`      | edition-dependent tests |
| `burp/Dockerfile`           | Temurin 21 + Xvfb + fluxbox + xdotool |
| `burp/entrypoint.sh`        | EULA, wizard, extension load, readiness |
| `burp/user-config.json`     | registers the extension |
| `burp/project-config.json`  | proxy listener on all interfaces |
| `mock-server/server.js`     | the mock web server (compose service `target`) |
| `lib/stack.js`              | compose up/down + port discovery + jar resolution |
| `lib/endpoints.js`          | the orchestrator→test contract: endpoints, mock server, edition |
| `lib/mcp-client.js`         | stdio MCP client (spawns the bridge) |
| `lib/traffic.js`            | proxied-traffic helper |
| `scripts/run-integration.js`| orchestrator |
| `scripts/fetch-burp-community.sh` | one-time jar download to the cache |
