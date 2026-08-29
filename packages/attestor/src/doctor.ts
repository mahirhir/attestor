// `attestor doctor` — diagnose setup health, node version, permissions, PATH, MCP commands, Rekor, and pending anchors.
import { execSync } from 'node:child_process';
import { existsSync, readFileSync, readdirSync, accessSync, constants } from 'node:fs';
import { homedir, platform } from 'node:os';
import { delimiter, join } from 'node:path';
import { attestorHome, keysDir, listKeyIds } from './keys.ts';
import { findConfigs } from './setup.ts';

const BOLD = '\x1b[1m';
const DIM = '\x1b[2m';
const GREEN = '\x1b[32m';
const YELLOW = '\x1b[33m';
const RED = '\x1b[31m';
const RESET = '\x1b[0m';

function color(code: string, s: string): string {
  return process.stdout.isTTY ? `${code}${s}${RESET}` : s;
}

function say(s = ''): void {
  process.stdout.write(s + '\n');
}

export interface DoctorCheck {
  name: string;
  passed: boolean;
  message: string;
  fix?: string;
  warningOnly?: boolean;
}

export async function runDoctor(argv: string[] = []): Promise<number> {
  say(color(BOLD, 'attestor doctor'));
  say(color(DIM, `Platform: ${platform()} · Node: ${process.version} · Home: ${attestorHome()}`));
  say('');

  const checks: DoctorCheck[] = [];

  // 1. Node Version Check (Node 24+)
  const major = Number(process.versions.node.split('.')[0]);
  if (!Number.isFinite(major) || major < 24) {
    checks.push({
      name: 'Node runtime version',
      passed: false,
      message: `Node ${process.version} is installed, but Node 24+ is required for native TypeScript execution.`,
      fix: 'Install Node 24+: https://nodejs.org/en/download',
    });
  } else {
    checks.push({
      name: 'Node runtime version',
      passed: true,
      message: `Node ${process.version} (>= 24.0.0)`,
    });
  }

  // 2. attestor on PATH Check
  let attestorPath: string | undefined;
  const pathDirs = (process.env.PATH ?? '').split(delimiter);
  for (const dir of pathDirs) {
    const candidate = platform() === 'win32' ? join(dir, 'attestor.cmd') : join(dir, 'attestor');
    const candidateExe = platform() === 'win32' ? join(dir, 'attestor.exe') : join(dir, 'attestor');
    if (existsSync(candidate)) {
      attestorPath = candidate;
      break;
    } else if (existsSync(candidateExe)) {
      attestorPath = candidateExe;
      break;
    }
  }

  if (attestorPath) {
    checks.push({
      name: 'attestor CLI resolution on PATH',
      passed: true,
      message: `Resolved on PATH at ${attestorPath}`,
    });
  } else {
    checks.push({
      name: 'attestor CLI resolution on PATH',
      passed: false,
      message: '`attestor` command is not found in your system PATH.',
      fix: 'Run `npm install -g @attestor/cli` or add its bin directory to PATH.',
      warningOnly: true,
    });
  }

  // 3. ATTESTOR_HOME existence and writability
  const home = attestorHome();
  if (!existsSync(home)) {
    checks.push({
      name: 'ATTESTOR_HOME directory',
      passed: false,
      message: `Directory ${home} does not exist.`,
      fix: 'Run `attestor setup` to initialize the home directory and signing keys.',
    });
  } else {
    try {
      accessSync(home, constants.R_OK | constants.W_OK);
      checks.push({
        name: 'ATTESTOR_HOME directory',
        passed: true,
        message: `${home} exists and is writable`,
      });
    } catch {
      checks.push({
        name: 'ATTESTOR_HOME directory',
        passed: false,
        message: `${home} exists but is not writable.`,
        fix: `Fix directory permissions for ${home}.`,
      });
    }
  }

  // 4. Signing Key Presence & Permissions
  const keys = listKeyIds(home);
  if (keys.length === 0) {
    checks.push({
      name: 'Recorder signing keys',
      passed: false,
      message: `No recorder signing keys found in ${keysDir(home)}.`,
      fix: 'Run `attestor keys init` or `attestor setup` to generate a P-256 key pair.',
    });
  } else {
    const activeKey = keys[keys.length - 1];
    const keyFile = join(keysDir(home), `${activeKey}.pem`);
    let permOk = true;

    if (platform() === 'win32') {
      try {
        const icaclsOut = execSync(`icacls "${keyFile}"`, { encoding: 'utf8', stdio: ['ignore', 'pipe', 'ignore'] });
        permOk = !icaclsOut.includes('Everyone') && !icaclsOut.includes('BUILTIN\\Users:(F)');
      } catch {
        permOk = true; // Best effort on Windows
      }
    }

    checks.push({
      name: 'Recorder signing keys',
      passed: permOk,
      message: `Active key ${activeKey} present in ${keysDir(home)}`,
      fix: permOk ? undefined : `Restrict private key permissions with icacls or chmod 600 "${keyFile}"`,
    });
  }

  // 5. Discovered MCP Configs and Target Executable Existence
  const configs = findConfigs();
  let invalidCommands = 0;
  for (const config of configs) {
    for (const group of config.groups) {
      for (const [name, def] of Object.entries(group.servers)) {
        const cmd = def.command;
        if (typeof cmd === 'string' && cmd.length > 0) {
          // Check if command is a relative/absolute path or in PATH
          let found = existsSync(cmd);
          if (!found) {
            for (const d of pathDirs) {
              if (existsSync(join(d, cmd)) || (platform() === 'win32' && existsSync(join(d, `${cmd}.cmd`)))) {
                found = true;
                break;
              }
            }
          }
          if (!found && !cmd.includes('npx') && !cmd.includes('node') && !cmd.includes('uvx') && !cmd.includes('python')) {
            invalidCommands++;
            checks.push({
              name: `MCP Server target command: ${name}`,
              passed: false,
              message: `Command '${cmd}' defined in ${config.label} (${config.path}) does not resolve.`,
              fix: `Verify the executable path for '${name}' in ${config.path}.`,
            });
          }
        }
      }
    }
  }

  if (invalidCommands === 0) {
    checks.push({
      name: 'Discovered MCP configurations',
      passed: true,
      message: `${configs.length} config file(s) scanned; all commands resolve.`,
    });
  }

  // 6. Rekor Reachability
  const rekorUrl = process.env.ATTESTOR_REKOR_URL ?? 'https://rekor.sigstore.dev';
  try {
    const res = await fetch(`${rekorUrl}/api/v1/log`, { method: 'GET', signal: AbortSignal.timeout(3000) });
    if (res.ok) {
      checks.push({
        name: 'Rekor public transparency log',
        passed: true,
        message: `${rekorUrl} is reachable (HTTP ${res.status})`,
      });
    } else {
      checks.push({
        name: 'Rekor public transparency log',
        passed: false,
        message: `${rekorUrl} returned HTTP ${res.status}.`,
        fix: 'Check network connectivity or set ATTESTOR_OFFLINE=1 for local-only operation.',
        warningOnly: true,
      });
    }
  } catch (err) {
    checks.push({
      name: 'Rekor public transparency log',
      passed: false,
      message: `Failed to connect to ${rekorUrl}: ${(err as Error).message}`,
      fix: 'Check internet access, corporate proxies, or set ATTESTOR_OFFLINE=1.',
      warningOnly: true,
    });
  }

  // 7. Pending Anchors & Backlog Check
  const ledgersDir = join(home, 'ledgers');
  let pendingAnchorsCount = 0;
  if (existsSync(ledgersDir)) {
    try {
      const entries = readdirSync(ledgersDir, { withFileTypes: true });
      for (const entry of entries) {
        if (entry.isDirectory()) {
          const pendingFile = join(ledgersDir, entry.name, 'anchors', 'pending.jsonl');
          if (existsSync(pendingFile)) {
            const lines = readFileSync(pendingFile, 'utf8').trim().split('\n').filter(Boolean);
            pendingAnchorsCount += lines.length;
          }
        }
      }
    } catch {
      // Ignore
    }
  }

  if (pendingAnchorsCount > 0) {
    checks.push({
      name: 'Pending anchor backlog',
      passed: false,
      message: `${pendingAnchorsCount} pending anchor(s) waiting in queue.`,
      fix: 'Run `attestor wrap` while online to drain pending anchors to Rekor.',
      warningOnly: true,
    });
  } else {
    checks.push({
      name: 'Pending anchor backlog',
      passed: true,
      message: 'No unanchored pending checkpoints.',
    });
  }

  // ---- Output Results ----
  let hasFailure = false;
  for (const check of checks) {
    if (check.passed) {
      say(`  ${color(GREEN, '✔')} ${color(BOLD, check.name)}: ${check.message}`);
    } else if (check.warningOnly) {
      say(`  ${color(YELLOW, '!')} ${color(BOLD, check.name)}: ${check.message}`);
      if (check.fix) say(`    ${color(DIM, 'Fix:')} ${check.fix}`);
    } else {
      hasFailure = true;
      say(`  ${color(RED, '✘')} ${color(BOLD, check.name)}: ${check.message}`);
      if (check.fix) say(`    ${color(DIM, 'Fix:')} ${check.fix}`);
    }
  }

  say('');
  if (hasFailure) {
    say(color(RED, `Doctor discovered actionable failures. Please follow the fix instructions above.`));
    return 1;
  } else {
    say(color(GREEN, `All required checks passed. attestor environment is healthy.`));
    return 0;
  }
}
