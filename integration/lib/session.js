// Shared per-file test plumbing: a connected MCP client and unique markers.
import { randomBytes } from 'node:crypto';
import { McpClient } from './mcp-client.js';
import { apiEndpoint } from './endpoints.js';

/** Start a bridge connected to the stack the orchestrator discovered. */
export async function connect() {
  const client = new McpClient(apiEndpoint());
  await client.start();
  return client;
}

/**
 * A marker unique to this run, so a test can find its own traffic in the
 * shared proxy history no matter what other test files captured before it.
 */
export function marker(prefix = 'it') {
  return `${prefix}${randomBytes(6).toString('hex')}`;
}

/** Call a tool and fail with the tool's own message if it reports an error. */
export async function callOk(client, name, args) {
  const r = await client.callTool(name, args);
  if (r.isError) throw new Error(`${name} ${JSON.stringify(args)} failed: ${r.text}`);
  return r.structured;
}

/** All proxy-history entries whose URL contains `needle`, oldest first. */
export async function historyMatching(client, needle) {
  const s = await callOk(client, 'burp_proxy_history', { action: 'list', limit: 10000 });
  return s.entries.filter((e) => e.url.includes(needle)).sort((a, b) => a.id - b.id);
}
