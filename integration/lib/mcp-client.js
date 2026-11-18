// Minimal MCP stdio client: spawns bridge/index.js exactly as Claude Code does
// and speaks newline-delimited JSON-RPC to it over stdio. Deliberately
// dependency-free (no MCP SDK) so the suite needs nothing installed beyond the
// bridge itself.
import { spawn } from 'node:child_process';
import { createInterface } from 'node:readline';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';

const __dirname = dirname(fileURLToPath(import.meta.url));
const BRIDGE_ENTRY = join(__dirname, '..', '..', 'bridge', 'index.js');

export class McpClient {
  // host and port are REQUIRED and have no defaults on purpose: the integration
  // Burp is published on an ephemeral port that only `docker compose port` knows,
  // and defaulting to anything (e.g. the sandbox's BURP_API_PORT=8081) would
  // silently point the bridge at the wrong Burp. Callers pass what the harness
  // discovered from Docker.
  constructor({ host, port, timeoutMs = 30000 } = {}) {
    if (!host || !port) {
      throw new Error('McpClient requires explicit { host, port } from discovered Docker endpoints');
    }
    this.burpHost = host;
    this.burpPort = Number(port);
    this.timeoutMs = timeoutMs;
    this.proc = null;
    this.nextId = 1;
    this.pending = new Map();
  }

  async start() {
    this.proc = spawn(process.execPath, [BRIDGE_ENTRY], {
      stdio: ['pipe', 'pipe', 'pipe'],
      env: {
        ...process.env,
        MCP_TRANSPORT_MODE: 'stdio',
        BURP_MCP_SERVER_HOST: this.burpHost,
        BURP_MCP_SERVER_PORT: String(this.burpPort)
      }
    });

    this.proc.on('exit', (code) => {
      const err = new Error(`bridge exited (code ${code})`);
      for (const { reject } of this.pending.values()) reject(err);
      this.pending.clear();
    });

    // Bridge logs go to stderr; stdout carries only JSON-RPC, one object a line.
    this.rl = createInterface({ input: this.proc.stdout });
    this.rl.on('line', (line) => this._onLine(line));

    await this._request('initialize', {
      protocolVersion: '2025-06-18',
      capabilities: {},
      clientInfo: { name: 'burp-mcp-integration', version: '1.0.0' }
    });
    this._notify('notifications/initialized');
  }

  _onLine(line) {
    const text = line.trim();
    if (!text) return;
    let msg;
    try {
      msg = JSON.parse(text);
    } catch {
      return; // ignore non-JSON noise
    }
    if (msg.id == null || !this.pending.has(msg.id)) return;
    const { resolve, reject, timer } = this.pending.get(msg.id);
    clearTimeout(timer);
    this.pending.delete(msg.id);
    if (msg.error) reject(new Error(msg.error.message || 'JSON-RPC error'));
    else resolve(msg.result);
  }

  _send(obj) {
    this.proc.stdin.write(JSON.stringify(obj) + '\n');
  }

  _notify(method, params) {
    this._send({ jsonrpc: '2.0', method, params });
  }

  _request(method, params) {
    const id = this.nextId++;
    return new Promise((resolve, reject) => {
      const timer = setTimeout(() => {
        this.pending.delete(id);
        reject(new Error(`timeout waiting for ${method} (${this.timeoutMs}ms)`));
      }, this.timeoutMs);
      this.pending.set(id, { resolve, reject, timer });
      this._send({ jsonrpc: '2.0', id, method, params });
    });
  }

  listTools() {
    return this._request('tools/list', {});
  }

  /**
   * Call a Burp tool. Returns { result, structured, text, isError } where
   * `structured` is the parsed structuredContent (what assertions use) and
   * `text` is the concatenated text content.
   */
  async callTool(name, args = {}) {
    const result = await this._request('tools/call', { name, arguments: args });
    const text = (result?.content || [])
      .filter((c) => c.type === 'text')
      .map((c) => c.text)
      .join('\n');
    return {
      result,
      structured: result?.structuredContent,
      text,
      isError: result?.isError === true
    };
  }

  async stop() {
    try {
      this.rl?.close();
    } catch { /* ignore */ }
    if (this.proc && !this.proc.killed) this.proc.kill('SIGTERM');
  }
}
