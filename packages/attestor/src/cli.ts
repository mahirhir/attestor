#!/usr/bin/env node
// attestor CLI: keys, wrap, install, verify, export, redact, replay, demo, doctor.
import { parseArgs } from 'node:util';
import { existsSync, readFileSync, writeFileSync, copyFileSync } from 'node:fs';
import { homedir, platform } from 'node:os';
import { fileURLToPath } from 'node:url';
import { delimiter, join, resolve } from 'node:path';
import { attestorHome, generateKey, listKeyIds, loadKey } from './keys.ts';
import { Ledger, readEntries, uuidv7, type LedgerEntry } from './ledger.ts';
import { Checkpointer, lastCheckpointSize } from './checkpoint.ts';
import { anchorCheckpoint, retryPending } from './rekor.ts';
import { renderReport, verifyLedger } from './verify.ts';
import { runProxy } from './proxy.ts';
import { attestorInvocation, claudeDesktopConfigPaths, wrapConfig, type McpServerDef } from './mcpconfig.ts';

const USAGE = `attestor — tamper-evident flight recorder for AI agents

Usage:
  attestor doctor                                diagnose environment, keys, configs, Rekor
  attestor setup [--yes] [--config <f>]          guided install: key + wrap your MCP servers
  attestor keys init [--passphrase-file <f>]     generate a P-256 recorder key
  attestor keys list                             list recorder keys (active last)
  attestor keys rotate --ledger <dir>            rotate: new key signed into the chain by the old one
  attestor wrap [opts] -- <server command...>    record an MCP stdio server
  attestor install [--config <file>] [--dry-run] wrap every server in .mcp.json / Claude Desktop config
  attestor verify <dir> [--online] [--entry N] [--json]
                        [--rekor-pubkey <f>] [--rekor-url <u>]   authenticate anchors with a key you trust
                        [--expect-key <keyid|pem>]                require a known recorder identity
  attestor export <ledger-dir> [--out <dir>]     write a regulator-ready evidence pack
  attestor redact <ledger-dir> <seq>             strip a payload (chain & sigs stay valid)
  attestor replay <ledger-dir> [--session <id>]  print recorded tool calls
  attestor demo tamper [--live]                  30-second tamper-evidence demo (offline by default)

Options:
  --ledger <dir>        ledger directory (default $ATTESTOR_HOME/ledgers/default)
  --on-error <mode>     block | continue         (default block: fail closed)
  --durability <mode>   strict | group           (default strict: fsync per entry)
  --offline             queue anchors, never touch the network
  --online              verify against the public Rekor log too
Env: ATTESTOR_HOME, ATTESTOR_REKOR_URL, ATTESTOR_OFFLINE=1, ATTESTOR_LIVE=1

Exit codes (verify): 0 verified · 1 tamper · 2 usage/IO error · 3 Rekor unreachable
                     4 chain intact, but anchors not authenticated (use --online)`;

function fail(msg: string): never {
  process.stderr.write(`attestor: ${msg}\n`);
  process.exit(2);
}

function defaultLedgerDir(): string {
  return join(attestorHome(), 'ledgers', 'default');
}

function loadOrInitKeys(passphrase?: string) {
  if (listKeyIds().length === 0) {
    const pair = generateKey(attestorHome(), passphrase);
    process.stderr.write(`[attestor] generated recorder key ${pair.keyId} at ${attestorHome()}/keys\n`);
    return pair;
  }
  return loadKey(attestorHome(), undefined, passphrase);
}

function readPassphrase(file?: string): string | undefined {
  if (file === undefined) return undefined;
  return readFileSync(file, 'utf8').trim();
}

// ---------------- subcommands ----------------

async function cmdKeys(argv: string[]): Promise<void> {
  const sub = argv[0];
  const { values } = parseArgs({
    args: argv.slice(1),
    options: {
      ledger: { type: 'string' },
      'passphrase-file': { type: 'string' },
    },
  });
  const passphrase = readPassphrase(values['passphrase-file']);
  if (sub === 'init') {
    const pair = generateKey(attestorHome(), passphrase);
    process.stdout.write(`generated P-256 recorder key ${pair.keyId}\n  private: ${attestorHome()}/keys/${pair.keyId}.pem (0600${passphrase !== undefined ? ', scrypt-encrypted' : ''})\n  public:  ${attestorHome()}/keys/${pair.keyId}.pub\n`);
    return;
  }
  if (sub === 'list') {
    const ids = listKeyIds();
    if (ids.length === 0) {
      process.stdout.write('no keys — run: attestor keys init\n');
      return;
    }
    ids.forEach((id, i) => {
      process.stdout.write(`${id}${i === ids.length - 1 ? '  (active)' : ''}\n`);
    });
    return;
  }
  if (sub === 'rotate') {
    const dir = values.ledger ?? defaultLedgerDir();
    if (!existsSync(join(dir, 'ledger.jsonl'))) fail(`no ledger at ${dir} — rotation is recorded in the chain`);
    const oldKeys = loadKey(attestorHome(), undefined, passphrase);
    const ledger = Ledger.open(dir, oldKeys);
    const newKeys = generateKey(attestorHome(), passphrase);
    ledger.append({
      type: 'key_rotation',
      origin: 'system',
      payload: newKeys.publicPem,
    });
    ledger.close();
    process.stdout.write(`rotated ${oldKeys.keyId} → ${newKeys.keyId} (rotation entry signed by the old key)\n`);
    return;
  }
  fail(`unknown keys subcommand: ${sub ?? '(none)'}\n\n${USAGE}`);
}

async function cmdWrap(argv: string[]): Promise<void> {
  const sep = argv.indexOf('--');
  if (sep === -1 || sep === argv.length - 1) fail('usage: attestor wrap [opts] -- <server command...>');
  const { values } = parseArgs({
    args: argv.slice(0, sep),
    options: {
      ledger: { type: 'string' },
      'ledger-name': { type: 'string' },
      'on-error': { type: 'string', default: 'block' },
      durability: { type: 'string', default: 'strict' },
      offline: { type: 'boolean', default: false },
      'passphrase-file': { type: 'string' },
    },
  });
  const command = argv[sep + 1]!;
  const args = argv.slice(sep + 2);
  const onError = values['on-error'] as 'block' | 'continue';
  if (!['block', 'continue'].includes(onError)) fail(`--on-error must be block|continue`);
  const durability = values.durability as 'strict' | 'group';
  if (!['strict', 'group'].includes(durability)) fail(`--durability must be strict|group`);

  const keys = loadOrInitKeys(readPassphrase(values['passphrase-file']));
  const dir =
    values.ledger ??
    (values['ledger-name'] !== undefined
      ? join(attestorHome(), 'ledgers', values['ledger-name'])
      : defaultLedgerDir());
  const ledger = Ledger.open(dir, keys, { durability });
  if (ledger.tornRecovery.recovered) {
    process.stderr.write(`[attestor] recovered torn tail (${ledger.tornRecovery.tornBytes} bytes → ledger.torn)\n`);
  }
  const offline = values.offline || process.env.ATTESTOR_OFFLINE === '1';
  // Track every in-flight anchor so exit can await them: dropping one loses
  // the external-anchoring guarantee for that checkpoint with no pending-queue
  // trace (anchorCheckpoint only queues on a network error, not on process death).
  const inFlight = new Set<Promise<unknown>>();
  const track = (p: Promise<unknown>) => {
    inFlight.add(p);
    void p.finally(() => inFlight.delete(p));
  };
  const checkpointer = new Checkpointer(ledger, {
    initialCoveredSize: lastCheckpointSize(readEntries(join(dir, 'ledger.jsonl'))),
    onCheckpoint: (entry) => {
      track(
        anchorCheckpoint(ledger, entry, { offline }).catch((err) =>
          process.stderr.write(`[attestor] anchor failed: ${(err as Error).message}\n`),
        ),
      );
    },
  });
  if (!offline) {
    // drain anchors queued while Rekor was unreachable; without this they sit
    // in pending.jsonl forever and the ledger stays silently unanchored
    track(
      retryPending(ledger).catch((err) =>
        process.stderr.write(`[attestor] anchor retry failed: ${(err as Error).message}\n`),
      ),
    );
  }
  const code = await runProxy({ ledger, checkpointer, command, args, onError, handleSignals: true });
  // Drain in-flight anchors before closing the ledger (each Rekor request is
  // itself bounded by a 10s timeout, so this cannot hang indefinitely).
  while (inFlight.size > 0) {
    await Promise.allSettled([...inFlight]);
  }
  ledger.close();
  process.exit(code);
}

async function cmdInstall(argv: string[]): Promise<void> {
  const { values } = parseArgs({
    args: argv,
    options: {
      config: { type: 'string' },
      'dry-run': { type: 'boolean', default: false },
    },
  });
  let configPath = values.config;
  if (configPath === undefined) {
    const candidates = [resolve('.mcp.json'), ...claudeDesktopConfigPaths()];
    configPath = candidates.find((p) => existsSync(p));
    if (configPath === undefined) fail('no .mcp.json or Claude Desktop config found — pass --config <file>');
  }
  const config = JSON.parse(readFileSync(configPath, 'utf8')) as { mcpServers?: Record<string, McpServerDef> };
  const { changed, skipped } = wrapConfig(config);
  for (const s of skipped) process.stdout.write(`already wrapped: ${s}\n`);
  if (changed.length === 0) {
    process.stdout.write('nothing to change\n');
    return;
  }
  if (values['dry-run']) {
    process.stdout.write(JSON.stringify(config, null, 2) + '\n');
    return;
  }
  copyFileSync(configPath, configPath + '.bak');
  writeFileSync(configPath, JSON.stringify(config, null, 2) + '\n');
  process.stdout.write(`wrapped ${changed.join(', ')} in ${configPath} (backup: ${configPath}.bak)\n`);
}

async function cmdVerify(argv: string[]): Promise<void> {
  const { values, positionals } = parseArgs({
    args: argv,
    allowPositionals: true,
    options: {
      online: { type: 'boolean', default: false },
      entry: { type: 'string' },
      json: { type: 'boolean', default: false },
      'rekor-pubkey': { type: 'string' },
      'rekor-url': { type: 'string' },
      'expect-key': { type: 'string' },
    },
  });
  const target = positionals[0] ?? defaultLedgerDir();
  const trustedPem =
    values['rekor-pubkey'] !== undefined ? readFileSync(values['rekor-pubkey'], 'utf8') : undefined;
  const report = await verifyLedger(target, {
    online: values.online,
    ...(values.entry !== undefined && { entry: Number(values.entry) }),
    ...(trustedPem !== undefined && { rekorPubPem: trustedPem }),
    ...(values['rekor-url'] !== undefined && { rekorUrl: values['rekor-url'] }),
    ...(values['expect-key'] !== undefined && {
      expectKeyId: existsSync(values['expect-key'])
        ? readFileSync(values['expect-key'], 'utf8')
        : values['expect-key'],
    }),
  });
  if (values.json) {
    process.stdout.write(JSON.stringify(report, null, 2) + '\n');
  } else {
    process.stdout.write(renderReport(report) + '\n');
    if (report.auditPacket) {
      process.stdout.write('\naudit-packet.json:\n' + JSON.stringify(report.auditPacket, null, 2) + '\n');
    }
  }
  process.exit(report.exitCode);
}

async function cmdReplay(argv: string[]): Promise<void> {
  const { values, positionals } = parseArgs({
    args: argv,
    allowPositionals: true,
    options: { session: { type: 'string' }, json: { type: 'boolean', default: false } },
  });
  const dir = positionals[0] ?? defaultLedgerDir();
  const path = existsSync(join(dir, 'ledger.jsonl')) ? join(dir, 'ledger.jsonl') : join(dir, 'ledger', 'entries.jsonl');
  if (!existsSync(path)) fail(`no ledger at ${dir}`);
  const entries = readEntries(path).filter(
    (e) => values.session === undefined || e.session_id === values.session,
  );
  // Pair within a session: proxy call_ids ("c2s:1", "c2s:2", …) restart at 1
  // every session, so a bare call_id would pair a result with another
  // session's request. Walk in order and consume each request once.
  const requests = new Map<string, LedgerEntry>();
  const key = (e: LedgerEntry) => `${e.session_id} ${e.call_id}`;
  for (const e of entries) {
    if (e.type === 'call_request' && e.call_id !== undefined && !requests.has(key(e))) {
      requests.set(key(e), e);
    }
  }
  for (const e of entries) {
    if (e.type !== 'call_result' || e.call_id === undefined) continue;
    const req = requests.get(key(e));
    if (!req) continue;
    requests.delete(key(e));
    const durationMs = Date.parse(e.ts) - Date.parse(req.ts);
    const show = (entry: LedgerEntry) =>
      entry.payload === undefined ? `[REDACTED payload_hash=${entry.payload_hash.slice(0, 16)}…]` : entry.payload;
    const status = e.payload?.includes('"error"') || e.payload?.includes('"isError":true') ? 'error' : 'ok';
    if (values.json) {
      process.stdout.write(
        JSON.stringify({
          call_id: e.call_id,
          tool: req.tool,
          session_id: e.session_id,
          request_ts: req.ts,
          duration_ms: durationMs,
          status,
          request: req.payload !== undefined ? JSON.parse(req.payload) : null,
          result: e.payload !== undefined ? JSON.parse(e.payload) : null,
          redacted: req.payload === undefined || e.payload === undefined,
        }) + '\n',
      );
    } else {
      process.stdout.write(
        `[${req.ts}] ${req.tool?.name ?? '?'} (${e.call_id}) ${status} ${durationMs}ms\n  → ${show(req)}\n  ← ${show(e)}\n`,
      );
    }
  }
}

// placeholders replaced as components land
async function cmdExport(argv: string[]): Promise<void> {
  const { runExport } = await import('./export.ts');
  await runExport(argv);
}

async function cmdRedact(argv: string[]): Promise<void> {
  const { runRedact } = await import('./redact.ts');
  await runRedact(argv);
}

async function cmdSetup(argv: string[]): Promise<void> {
  const { runSetup } = await import('./setup.ts');
  await runSetup(argv);
}

async function cmdDemo(argv: string[]): Promise<void> {
  const { runDemo } = await import('./demo.ts');
  await runDemo(argv);
}

async function cmdDoctor(argv: string[]): Promise<void> {
  const { runDoctor } = await import('./doctor.ts');
  const code = await runDoctor(argv);
  process.exit(code);
}

// ---------------- dispatch ----------------

const [cmd, ...rest] = process.argv.slice(2);
try {
  switch (cmd) {
    case 'doctor':
      await cmdDoctor(rest);
      break;
    case 'keys':
      await cmdKeys(rest);
      break;
    case 'wrap':
      await cmdWrap(rest);
      break;
    case 'install':
      await cmdInstall(rest);
      break;
    case 'verify':
      await cmdVerify(rest);
      break;
    case 'export':
      await cmdExport(rest);
      break;
    case 'redact':
      await cmdRedact(rest);
      break;
    case 'replay':
      await cmdReplay(rest);
      break;
    case 'setup':
      await cmdSetup(rest);
      break;
    case 'demo':
      await cmdDemo(rest);
      break;
    case undefined:
    case 'help':
    case '--help':
    case '-h':
      process.stdout.write(USAGE + '\n');
      break;
    default:
      fail(`unknown command: ${cmd}\n\n${USAGE}`);
  }
} catch (err) {
  fail((err as Error).message);
}
