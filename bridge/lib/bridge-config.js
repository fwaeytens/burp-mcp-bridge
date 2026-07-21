import { readFileSync } from 'node:fs';
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

export function createBridgeConfig({ env = process.env, bridgeDir = DEFAULT_BRIDGE_DIR } = {}) {
  const burpPort = String(toInt(env.BURP_MCP_SERVER_PORT, 8081));
  const burpHost = env.BURP_MCP_SERVER_HOST ?? 'localhost';
  const burpUrl = new URL('http://localhost');
  burpUrl.hostname = bracketIpv6(burpHost);
  burpUrl.port = burpPort;

  const useHttps = env.MCP_USE_HTTPS !== 'false';
  const certPath = env.MCP_CERT_PATH || join(bridgeDir, 'certs');
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
