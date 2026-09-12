import test from 'node:test';
import assert from 'node:assert/strict';

import { tmpdir } from 'node:os';

import { createBridgeConfig } from '../lib/bridge-config.js';

test('createBridgeConfig normalizes IPv6 Burp targets and invalid numeric envs', () => {
  const config = createBridgeConfig({
    env: {
      BURP_MCP_SERVER_HOST: '::1',
      BURP_MCP_SERVER_PORT: '8089',
      BURP_MCP_REQUEST_TIMEOUT: 'not-a-number',
      MCP_USE_HTTPS: 'false',
      MCP_TRANSPORT_MODE: 'invalid'
    },
    bridgeDir: '/tmp/burp-mcp-bridge'
  });

  assert.equal(config.burpBaseUrl, 'http://[::1]:8089/');
  assert.equal(config.requestTimeout, 30_000);
  assert.equal(config.transportMode, 'both');
  assert.equal(config.httpSseTransportName, 'http-sse');
  assert.equal(config.keyFile, '/tmp/burp-mcp-bridge/certs/key.pem');
});

test('createBridgeConfig forces loopback binding by default', () => {
  const config = createBridgeConfig({
    env: { MCP_HTTP_HOST: '0.0.0.0' },
    bridgeDir: '/tmp/burp-mcp-bridge'
  });

  assert.equal(config.bindLoopbackOnly, true);
  assert.equal(config.httpHost, '127.0.0.1');
});

test('createBridgeConfig honours an explicit MCP_CERT_PATH over every fallback', () => {
  const config = createBridgeConfig({
    env: { MCP_CERT_PATH: '/explicit/certs' },
    bridgeDir: '/opt/pkg',
    probe: () => false,
    platform: 'linux'
  });

  assert.equal(config.certPath, '/explicit/certs');
  assert.equal(config.keyFile, '/explicit/certs/key.pem');
  assert.equal(config.certFile, '/explicit/certs/cert.pem');
});

test('createBridgeConfig keeps certs package-local when that directory is writable', () => {
  const config = createBridgeConfig({
    env: {},
    bridgeDir: '/home/dev/burp-mcp/bridge',
    probe: () => true,
    platform: 'linux'
  });

  assert.equal(config.certPath, '/home/dev/burp-mcp/bridge/certs');
});

test('createBridgeConfig falls back to per-user state for read-only global installs', () => {
  const probed = [];
  const config = createBridgeConfig({
    env: { HOME: '/home/dev' },
    bridgeDir: '/usr/lib/node_modules/burp-mcp-bridge',
    probe: (dir) => { probed.push(dir); return !dir.startsWith('/usr/lib'); },
    platform: 'linux'
  });

  assert.equal(config.certPath, '/home/dev/.local/state/burp-mcp-bridge/certs');
  assert.equal(probed[0], '/usr/lib/node_modules/burp-mcp-bridge/certs');
});

test('createBridgeConfig respects XDG_STATE_HOME and LOCALAPPDATA when falling back', () => {
  const linux = createBridgeConfig({
    env: { HOME: '/home/dev', XDG_STATE_HOME: '/home/dev/.state' },
    bridgeDir: '/usr/lib/node_modules/burp-mcp-bridge',
    probe: (dir) => !dir.startsWith('/usr/lib'),
    platform: 'linux'
  });
  assert.equal(linux.certPath, '/home/dev/.state/burp-mcp-bridge/certs');

  const windows = createBridgeConfig({
    env: { USERPROFILE: 'C:\\Users\\dev', LOCALAPPDATA: 'C:\\Users\\dev\\AppData\\Local' },
    bridgeDir: 'C:\\Program Files\\nodejs\\burp-mcp-bridge',
    probe: (dir) => !dir.startsWith('C:\\Program Files'),
    platform: 'win32'
  });
  assert.match(windows.certPath, /AppData[\\/]Local[\\/]burp-mcp-bridge[\\/]certs$/);
});

test('createBridgeConfig uses a temp directory when no writable location exists', () => {
  const config = createBridgeConfig({
    env: { HOME: '/home/dev' },
    bridgeDir: '/usr/lib/node_modules/burp-mcp-bridge',
    probe: () => false,
    platform: 'linux'
  });

  assert.match(config.certPath, /burp-mcp-bridge[\\/]certs$/);
  assert.ok(config.certPath.startsWith(tmpdir()));
});
