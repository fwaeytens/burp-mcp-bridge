// The one place tests learn where the live stack is and what they run against.
// The orchestrator (scripts/run-integration.js) works these out — from Docker
// for the bundled Burp, from its command line for a Burp you point it at — and
// exports them to the test child process. They are an explicit
// orchestrator->test contract, not ambient defaults: if one is missing we throw,
// we never guess.

function required(name) {
  const v = process.env[name];
  if (!v) {
    throw new Error(
      `${name} is not set. Run the suite via "npm run test:integration" so the ` +
      `orchestrator can set up the stack and export where it is.`
    );
  }
  return v;
}

function hostPort(value) {
  const i = value.lastIndexOf(':');
  return { host: value.slice(0, i), port: Number(value.slice(i + 1)) };
}

/** { host, port } of the Burp extension API, from BURP_IT_API (host:port). */
export function apiEndpoint() {
  return hostPort(required('BURP_IT_API'));
}

/** Burp's proxy as the test runner reaches it (http://host:port), from BURP_IT_PROXY. */
export function proxyUrl() {
  return required('BURP_IT_PROXY');
}

/**
 * Burp's proxy listener as Burp itself reaches it, from BURP_IT_PROXY_IN_BURP
 * (host:port). Differs from proxyUrl() for the bundled Burp, whose listener is
 * 127.0.0.1:8080 inside its container but an ephemeral port on the host.
 */
export function proxyInBurp() {
  return hostPort(required('BURP_IT_PROXY_IN_BURP'));
}

/**
 * The mock server as Burp reaches it, from BURP_IT_TARGET (a base URL with no
 * trailing slash): http://target inside compose, http://127.0.0.1:<port> when
 * the tests drive a Burp outside it.
 */
export function target() {
  const base = required('BURP_IT_TARGET');
  const u = new URL(base);
  return { base, host: u.hostname, port: Number(u.port || 80) };
}

const EDITIONS = new Set(['community', 'professional']);

/** Edition of the Burp under test, from BURP_IT_EDITION. */
export function edition() {
  const e = required('BURP_IT_EDITION');
  if (!EDITIONS.has(e)) throw new Error(`BURP_IT_EDITION must be community or professional, got "${e}"`);
  return e;
}

/** node:test options that run a test only against the given edition. */
export function onlyOn(wanted) {
  return { skip: edition() === wanted ? false : `needs Burp ${wanted}` };
}

/** True when the tests drive the bundled Burp container, from BURP_IT_BUNDLED. */
export function bundledBurp() {
  const v = required('BURP_IT_BUNDLED');
  if (v !== 'true' && v !== 'false') throw new Error(`BURP_IT_BUNDLED must be true or false, got "${v}"`);
  return v === 'true';
}

/**
 * node:test options for tests that drive Burp's UI. Only the bundled Burp's
 * display is ours to automate, at a resolution the clicks are calibrated for.
 */
export function onlyBundled() {
  return { skip: bundledBurp() ? false : 'drives Burp\'s UI; only possible on the bundled Burp' };
}
