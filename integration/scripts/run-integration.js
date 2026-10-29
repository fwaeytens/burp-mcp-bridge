#!/usr/bin/env node
// Orchestrate one integration run: compose up (build + wait) -> work out where
// everything is -> run the node:test suite -> compose down. Exits with the test
// process's status so `npm run test:integration` is CI-usable.
//
// Two modes:
//   default    the bundled Burp Community in Docker, plus the mock server.
//   external   a Burp you run yourself (any edition), plus the mock server:
//                --burp-api host:port --burp-proxy host:port --edition <community|professional>
//              All three are required; nothing about your Burp is guessed.
import { spawnSync } from 'node:child_process';
import { parseArgs } from 'node:util';
import { INTEGRATION_DIR, ensureEnv, createStack, dockerAvailable } from '../lib/stack.js';

const EDITIONS = ['community', 'professional'];

function fail(message) {
  console.error(`[run] ${message}`);
  process.exit(2);
}

function parseHostPort(flag, value) {
  const m = /^(.+):(\d+)$/.exec(value);
  if (!m) fail(`${flag} must be host:port, got "${value}"`);
  return { host: m[1], port: Number(m[2]) };
}

function parseCli() {
  const { values } = parseArgs({
    options: {
      'keep-up': { type: 'boolean', default: false },
      'burp-api': { type: 'string' },
      'burp-proxy': { type: 'string' },
      edition: { type: 'string' }
    }
  });
  const external = ['burp-api', 'burp-proxy', 'edition'].filter((k) => values[k] !== undefined);
  if (external.length > 0 && external.length < 3) {
    fail('to test your own Burp, give all of --burp-api host:port, --burp-proxy host:port and ' +
         `--edition (${EDITIONS.join('|')}); got only ${external.map((k) => `--${k}`).join(', ')}`);
  }
  if (external.length === 0) return { keepUp: values['keep-up'], external: null };
  if (!EDITIONS.includes(values.edition)) fail(`--edition must be one of ${EDITIONS.join('|')}`);
  return {
    keepUp: values['keep-up'],
    external: {
      api: parseHostPort('--burp-api', values['burp-api']),
      proxy: parseHostPort('--burp-proxy', values['burp-proxy']),
      edition: values.edition
    }
  };
}

/**
 * Checks before testing a Burp the user runs: the extension answers, the project
 * is fresh, and Burp can reach the mock server. Each failure names its cause
 * instead of surfacing later as a confusing test failure.
 */
async function preflight(env) {
  Object.assign(process.env, env);
  const { McpClient } = await import('../lib/mcp-client.js');
  const { apiEndpoint, target } = await import('../lib/endpoints.js');
  const { proxyGetBody } = await import('../lib/traffic.js');

  const client = new McpClient({ ...apiEndpoint(), timeoutMs: 15000 });
  try {
    await client.start();
    const history = await client.callTool('burp_proxy_history', { action: 'list', limit: 1 });
    if (history.isError) {
      throw new Error(`the MCP extension at ${env.BURP_IT_API} did not answer: ${history.text}`);
    }
    if (history.structured.total !== 0) {
      throw new Error(`Burp's proxy history already has ${history.structured.total} entries; ` +
                      'the suite needs a fresh project (e.g. a new temporary project)');
    }
  } finally {
    await client.stop();
  }

  const probe = `preflight${Date.now()}`;
  let body = '';
  try {
    ({ body } = await proxyGetBody(`/reflect?q=${probe}`));
  } catch (err) {
    body = err.message;
  }
  if (!body.includes(`reflected:[${probe}]`)) {
    throw new Error(`Burp's proxy at ${env.BURP_IT_PROXY} could not fetch the mock server at ` +
                    `${target().base} (got: ${body.slice(0, 160) || 'no response'}). Burp must ` +
                    'reach 127.0.0.1 directly: check that no upstream proxy rule catches it.');
  }
}

async function main() {
  const cli = parseCli();
  if (!dockerAvailable()) fail('Docker is not available; the integration suite needs a running Docker daemon.');

  const bundledBurp = cli.external === null;
  if (bundledBurp) {
    const { community, ext } = ensureEnv();
    console.error(`[run] bundled Burp Community jar: ${community}`);
    console.error(`[run] extension jar:              ${ext}`);
  } else {
    const { api, proxy, edition } = cli.external;
    console.error(`[run] testing your Burp: API ${api.host}:${api.port}, proxy ${proxy.host}:${proxy.port}, edition ${edition}`);
    console.error('[run] the tests write into its project: proxy history, annotations (cleared), scope (restored), site map, and a scan if professional');
  }

  const stack = createStack({ bundledBurp });
  let testStatus = 1;
  try {
    console.error(`[run] bringing up ${bundledBurp ? 'Burp and the mock server' : 'the mock server'} (build + wait for healthy)…`);
    stack.up();

    let env;
    if (bundledBurp) {
      const api = stack.publishedPort('burp', 8081);
      const proxy = stack.publishedPort('burp', 8080);
      env = {
        BURP_IT_API: `${api.host}:${api.port}`,
        BURP_IT_PROXY: `http://${proxy.host}:${proxy.port}`,
        // The listener inside the burp container (burp/project-config.json).
        BURP_IT_PROXY_IN_BURP: '127.0.0.1:8080',
        // Burp reaches the mock server by its compose service name.
        BURP_IT_TARGET: 'http://target',
        BURP_IT_EDITION: 'community',
        BURP_IT_BUNDLED: 'true'
      };
    } else {
      const { api, proxy, edition } = cli.external;
      const mock = stack.publishedPort('target', 80);
      env = {
        BURP_IT_API: `${api.host}:${api.port}`,
        BURP_IT_PROXY: `http://${proxy.host}:${proxy.port}`,
        // Your Burp runs on this machine, so it sees its listener where we do.
        BURP_IT_PROXY_IN_BURP: `${proxy.host}:${proxy.port}`,
        BURP_IT_TARGET: `http://${mock.host}:${mock.port}`,
        BURP_IT_EDITION: edition,
        BURP_IT_BUNDLED: 'false'
      };
      await preflight(env);
    }
    console.error(`[run] ready. API ${env.BURP_IT_API}, proxy ${env.BURP_IT_PROXY}, ` +
                  `mock server as Burp sees it ${env.BURP_IT_TARGET}, edition ${env.BURP_IT_EDITION}`);

    const res = spawnSync(
      process.execPath,
      ['--test', '--test-concurrency=1', '--test-reporter=spec', 'test/*.test.js'],
      {
        cwd: INTEGRATION_DIR,
        stdio: 'inherit',
        // Explicit orchestrator->test contract; tests read these via lib/endpoints.js.
        env: { ...process.env, ...env }
      }
    );
    testStatus = res.status ?? 1;
  } catch (err) {
    console.error(`[run] setup failed: ${err.message}`);
    const logs = stack.logs().trim();
    if (logs) console.error(`[run] --- last container logs ---\n${logs}`);
    testStatus = 2;
  } finally {
    if (cli.keepUp) {
      const files = stack.files.map((f) => `-f ${f}`).join(' ');
      console.error('[run] --keep-up set; leaving the stack running. Tear down with:');
      console.error(`      (cd ${INTEGRATION_DIR} && docker compose ${files} down -v)`);
    } else {
      console.error('[run] tearing down compose stack');
      stack.down();
    }
  }
  process.exit(testStatus);
}

main();
