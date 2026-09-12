import { accessSync, constants as fsConstants, existsSync, readFileSync } from 'node:fs';
import { homedir, tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

import { bracketIpv6, toInt } from './bridge-utils.js';

const DEFAULT_BRIDGE_DIR = dirname(fileURLToPath(new URL('../index.js', import.meta.url)));

/** Read the bridge version from package.json so runtime metadata has one source. */
export function getBridgeVersion(packageUrl = new URL('../package.json', import.meta.url)) {
  try {
    const pkg = JSON.parse(readFileSync(packageUrl, 'utf8'));
    return pkg.version || '0.0.0-dev';
  } catch {
    return '0.0.0-dev';
  }
}

/** Nearest ancestor that exists, so a not-yet-created directory can still be probed. */
function nearestExistingDir(dir) {
  let current = dir;
  for (;;) {
    if (existsSync(current)) return current;
    const parent = dirname(current);
    if (parent === current) return current;
    current = parent;
  }
}

/** True when certs could be created at this path. */
export function isWritableDir(dir) {
  try {
    accessSync(nearestExistingDir(dir), fsConstants.W_OK);
    return true;
  } catch {
    return false;
  }
}

/**
 * Global installs (`npm i -g`, `npx`) place the package in a root-owned or cache
 * directory, so the package-local certs directory is not always writable. An
 * explicit MCP_CERT_PATH always wins; otherwise fall back to per-user state.
 */
export function resolveCertPath({ env, bridgeDir, probe = isWritableDir, platform = process.platform }) {
  if (env.MCP_CERT_PATH) return env.MCP_CERT_PATH;

  const packageLocal = join(bridgeDir, 'certs');
  if (probe(packageLocal)) return packageLocal;

  const home = env.HOME || env.USERPROFILE || homedir();
  const base = platform === 'win32'
    ? (env.LOCALAPPDATA || join(home, 'AppData', 'Local'))
    : (env.XDG_STATE_HOME || join(home, '.local', 'state'));
  const perUser = join(base, 'burp-mcp-bridge', 'certs');
  if (probe(perUser)) return perUser;

  return join(tmpdir(), 'burp-mcp-bridge', 'certs');
}

export function createBridgeConfig({
  env = process.env,
  bridgeDir = DEFAULT_BRIDGE_DIR,
  probe = isWritableDir,
  platform = process.platform
} = {}) {
  const burpPort = String(toInt(env.BURP_MCP_SERVER_PORT, 8081));
  const burpHost = env.BURP_MCP_SERVER_HOST ?? 'localhost';
  const burpUrl = new URL('http://localhost');
  burpUrl.hostname = bracketIpv6(burpHost);
  burpUrl.port = burpPort;

  const useHttps = env.MCP_USE_HTTPS !== 'false';
  const certPath = resolveCertPath({ env, bridgeDir, probe, platform });
  const bindLoopbackOnly = env.MCP_BIND_LOOPBACK_ONLY !== 'false';
  const requestedHost = env.MCP_HTTP_HOST ?? '127.0.0.1';
  const requestedMode = (env.MCP_TRANSPORT_MODE ?? 'both').toLowerCase();
  const validModes = new Set(['stdio', 'http', 'both']);

  return {
    debug: env.BURP_MCP_DEBUG === 'true',
    burpPort,
    burpHost,
    burpBaseUrl: burpUrl.toString(),
    requestTimeout: toInt(env.BURP_MCP_REQUEST_TIMEOUT, 30_000),
    maxSseSessions: toInt(env.MCP_MAX_SSE, 100),
    maxHttpSessions: toInt(env.MCP_MAX_HTTP_SESSIONS, 100),
    maxPostBytes: toInt(env.MCP_MAX_POST_BYTES, 1_048_576),
    sessionIdleMs: toInt(env.MCP_SESSION_IDLE_MS, 30 * 60 * 1000),
    httpPort: toInt(env.MCP_HTTP_PORT, 3000),
    useHttps,
    certPath,
    keyFile: env.MCP_KEY_FILE || join(certPath, 'key.pem'),
    certFile: env.MCP_CERT_FILE || join(certPath, 'cert.pem'),
    bindLoopbackOnly,
    httpHost: bindLoopbackOnly ? '127.0.0.1' : requestedHost,
    transportMode: validModes.has(requestedMode) ? requestedMode : 'both',
    httpSseTransportName: useHttps ? 'https-sse' : 'http-sse',
    streamableHttpTransportName: 'streamable-http',
    bridgeVersion: getBridgeVersion()
  };
}
