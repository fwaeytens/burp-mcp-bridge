// Bring the docker-compose integration stack up and down, and, for the bundled
// Burp, make sure the two host-provided jars (Burp Community + the built
// extension) exist and are wired into .env before compose runs.
import { spawnSync } from 'node:child_process';
import { existsSync, readdirSync, writeFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';
import { homedir } from 'node:os';

const __dirname = dirname(fileURLToPath(import.meta.url));
export const INTEGRATION_DIR = join(__dirname, '..');
const REPO_DIR = join(INTEGRATION_DIR, '..');
const ENV_FILE = join(INTEGRATION_DIR, '.env');
const CACHE_DIR = join(homedir(), '.cache', 'burp-mcp-bridge');

function findCommunityJar() {
  if (process.env.BURP_COMMUNITY_JAR && existsSync(process.env.BURP_COMMUNITY_JAR)) {
    return process.env.BURP_COMMUNITY_JAR;
  }
  if (existsSync(CACHE_DIR)) {
    const jar = readdirSync(CACHE_DIR)
      .filter((f) => /^burpsuite_community_v.*\.jar$/.test(f))
      .sort()
      .pop();
    if (jar) return join(CACHE_DIR, jar);
  }
  return null;
}

function findExtensionJar() {
  // An explicit jar (e.g. an older build, to show a test catches a regression)
  // wins over the one in extension/target.
  if (process.env.BURP_EXT_JAR) {
    if (!existsSync(process.env.BURP_EXT_JAR)) throw new Error(`BURP_EXT_JAR does not exist: ${process.env.BURP_EXT_JAR}`);
    return process.env.BURP_EXT_JAR;
  }
  const targetDir = join(REPO_DIR, 'extension', 'target');
  if (!existsSync(targetDir)) return null;
  const jar = readdirSync(targetDir)
    .filter((f) => /^burp-mcp-bridge-.*\.jar$/.test(f) && !f.startsWith('original-'))
    .sort()
    .pop();
  return jar ? join(targetDir, jar) : null;
}

/** Resolve both jars, writing their paths to integration/.env for compose. */
export function ensureEnv() {
  const community = findCommunityJar();
  if (!community) {
    throw new Error(
      'Burp Community jar not found. Run integration/scripts/fetch-burp-community.sh ' +
      'or set BURP_COMMUNITY_JAR to an absolute path.'
    );
  }
  const ext = findExtensionJar();
  if (!ext) {
    throw new Error(
      'Extension jar not found under extension/target/. Build it first: ' +
      '(cd extension && mvn -q package -DskipTests).'
    );
  }
  writeFileSync(ENV_FILE, `BURP_COMMUNITY_JAR=${community}\nBURP_EXT_JAR=${ext}\n`);
  return { community, ext };
}

/**
 * The compose stack: always the mock server (docker-compose.yml), plus the
 * bundled Burp Community (docker-compose.burp.yml) unless the tests drive a
 * Burp the user runs. The burp file is only passed when it is used, so testing
 * your own Burp needs neither jar nor .env.
 */
export function createStack({ bundledBurp }) {
  const files = ['docker-compose.yml', ...(bundledBurp ? ['docker-compose.burp.yml'] : [])];
  const fileArgs = files.flatMap((f) => ['-f', join(INTEGRATION_DIR, f)]);

  function compose(args, opts = {}) {
    return spawnSync('docker', ['compose', ...fileArgs, ...args], {
      cwd: INTEGRATION_DIR,
      stdio: opts.capture ? 'pipe' : 'inherit',
      encoding: 'utf8'
    });
  }

  /**
   * Ask Docker which ephemeral host port it published for a container port.
   * `docker compose port burp 8081` prints "127.0.0.1:49xxx". This is the single
   * source of truth for where the stack is reachable — nothing is hardcoded.
   */
  function publishedPort(service, containerPort) {
    const r = compose(['port', service, String(containerPort)], { capture: true });
    const line = (r.stdout || '').trim().split('\n').pop() || '';
    const m = line.match(/^(.+):(\d+)$/);
    if (!m) throw new Error(`could not discover published port for ${service}:${containerPort} (got "${line}")`);
    // Docker may report 0.0.0.0; the tests connect over loopback.
    const host = m[1] === '0.0.0.0' ? '127.0.0.1' : m[1];
    return { host, port: Number(m[2]) };
  }

  return {
    up() {
      // --wait blocks until healthchecks pass (burp's healthcheck = API on 8081).
      const r = compose(['up', '-d', '--build', '--wait']);
      if (r.status !== 0) throw new Error(`docker compose up failed (status ${r.status})`);
    },
    down() {
      compose(['down', '-v', '--remove-orphans']);
    },
    logs() {
      const r = compose(['logs', '--no-color', '--tail=60'], { capture: true });
      return r.stdout || '';
    },
    publishedPort,
    files
  };
}

/**
 * Run a command inside the bundled Burp container (e.g. to drive its UI).
 * Only meaningful when the tests run against the bundled Burp.
 */
export function execInBurp(args) {
  const stack = createStack({ bundledBurp: true });
  const fileArgs = stack.files.flatMap((f) => ['-f', join(INTEGRATION_DIR, f)]);
  const r = spawnSync('docker', ['compose', ...fileArgs, 'exec', '-T', 'burp', ...args], {
    cwd: INTEGRATION_DIR,
    encoding: 'utf8'
  });
  if (r.status !== 0) {
    throw new Error(`docker compose exec burp ${args.join(' ')} failed (${r.status}): ${r.stderr || r.stdout}`);
  }
  return r.stdout;
}

export function dockerAvailable() {
  const r = spawnSync('docker', ['version', '--format', '{{.Server.Version}}'], { encoding: 'utf8' });
  return r.status === 0;
}
