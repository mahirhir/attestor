// `attestor demo tamper` — the 30-second pitch, live:
//   1. record 12 tool calls (one moves money), checkpoint, anchor
//   2. verify → green
//   3. attacker byte-edits 100.00 → 100000.00 → verify screams, exit 1
//   4. kicker: attacker re-signs the ENTIRE ledger with their own key —
//      self-consistent chain — and the public-log anchor still catches it.
import { generateKeyPairSync, createHash } from 'node:crypto';
import { mkdtempSync, readFileSync, writeFileSync, mkdirSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { parseArgs } from 'node:util';
import canonicalize from 'canonicalize';
import { sign as cryptoSign } from 'node:crypto';
import { attestorHome, generateKey, keyIdOf, keysDir } from './keys.ts';
import {
  canonicalCoreBytes,
  coreOf,
  genesisPrev,
  hashCore,
  Ledger,
  payloadHash,
  readEntries,
  signCore,
  type LedgerEntry,
} from './ledger.ts';
import { writeCheckpoint } from './checkpoint.ts';
import { anchorCheckpoint, hashedRekordBody, type AnchorPayload } from './rekor.ts';
import { leafHash, merkleRoot } from './merkle.ts';
import { renderReport, verifyLedger } from './verify.ts';

const TOOLS: [string, string][] = [
  ['files.read', '{"path":"/data/q3-invoices.csv"}'],
  ['db.query', '{"sql":"SELECT balance FROM accounts WHERE id=9"}'],
  ['email.draft', '{"to":"cfo@example.com","subject":"Q3 transfers"}'],
  ['payments.transfer', '{"amount":"100.00","to":"acct-9","memo":"invoice 4411"}'],
  ['db.query', '{"sql":"SELECT * FROM invoices WHERE status=\'open\'"}'],
  ['files.write', '{"path":"/data/receipts/4411.txt"}'],
];

function say(s = ''): void {
  process.stdout.write(s + '\n');
}

function header(s: string): void {
  const useColor = process.stdout.isTTY ?? false;
  say('');
  say(useColor ? `\x1b[1m--- ${s} ---\x1b[0m` : `--- ${s} ---`);
}

export async function runDemo(argv: string[]): Promise<void> {
  const sub = argv[0];
  if (sub !== 'tamper') {
    process.stderr.write('attestor: usage: attestor demo tamper [--live]\n');
    process.exit(2);
  }
  const { values } = parseArgs({
    args: argv.slice(1),
    options: {
      live: { type: 'boolean', default: false },
      offline: { type: 'boolean', default: false },
    },
  });
  // Default OFFLINE on purpose: the demo must not write a junk entry into
  // Sigstore's shared public log every time somebody reads the README.
  // `--live` opts in to a real anchor.
  const offline = !values.live || values.offline || process.env.ATTESTOR_OFFLINE === '1';

  const dir = mkdtempSync(join(tmpdir(), 'attestor-demo-'));
  const home = join(dir, 'home');
  const ledgerDir = join(dir, 'ledger');
  process.env.ATTESTOR_HOME = home;

  header('recording: 12 tool calls through a hash-chained, signed ledger');
  const keys = generateKey(home);
  const ledger = Ledger.open(ledgerDir, keys);
  for (const [name, args] of TOOLS) {
    const callId = `call-${name}-${ledger.size}`;
    ledger.append({
      type: 'call_request',
      origin: 'proxy',
      call_id: callId,
      tool: { server: 'agent-tools', name },
      payload: `{"jsonrpc":"2.0","id":"${callId}","method":"tools/call","params":{"name":"${name}","arguments":${args}}}`,
    });
    ledger.append({
      type: 'call_result',
      origin: 'proxy',
      call_id: callId,
      tool: { server: 'agent-tools', name },
      payload: `{"jsonrpc":"2.0","id":"${callId}","result":{"content":[{"type":"text","text":"ok"}]}}`,
    });
    say(`  recorded  ${name.padEnd(18)} ${name === 'payments.transfer' ? '→ amount 100.00  ◀ watch this one' : ''}`);
  }
  const ckpt = writeCheckpoint(ledger);
  say(`  checkpoint: Merkle root over ${ledger.size - 1} entries, signed (seq ${ckpt.seq})`);

  let logIndex: number | undefined;
  if (offline) {
    simulateAnchor(ledger, ckpt);
    say('  anchor: SIMULATED — nothing was written to the public log.');
    say('          `attestor demo tamper --live` anchors in Sigstore Rekor for real.');
  } else {
    const anchorEntry = await anchorCheckpoint(ledger, ckpt, {});
    if (anchorEntry) {
      const p = JSON.parse(anchorEntry.payload!) as AnchorPayload;
      logIndex = p.logIndex;
      say(`  anchor: PUBLIC — Rekor logIndex ${p.logIndex}`);
      say(`          https://search.sigstore.dev/?logIndex=${p.logIndex}`);
    } else {
      say('  anchor: Rekor unreachable — queued (pending.jsonl). Continuing offline-style.');
    }
  }
  ledger.close();

  header('attestor verify');
  const green = await verifyLedger(ledgerDir);
  say(renderReport(green));
  if (green.exitCode !== 0) {
    process.stderr.write('demo setup failed verification — this is a bug\n');
    process.exit(2);
  }

  header('attacker edits the ledger (has file access, NOT your signing key)');
  const path = join(ledgerDir, 'ledger.jsonl');
  const lines = readFileSync(path, 'utf8').trimEnd().split('\n');
  // payloads are JSON strings inside the entry line, so quotes are escaped
  const needle = '\\"amount\\":\\"100.00\\"';
  const idx = lines.findIndex((l) => l.includes(needle));
  if (idx === -1) throw new Error('demo ledger missing the transfer entry');
  lines[idx] = lines[idx]!.replace(needle, '\\"amount\\":\\"100000.00\\"');
  writeFileSync(path, lines.join('\n') + '\n');
  say(`  entry ${idx}: payments.transfer`);
  say(`  - "amount":"100.00"`);
  say(`  + "amount":"100000.00"`);

  header('attestor verify — after the edit');
  const red = await verifyLedger(ledgerDir);
  say(renderReport(red));
  say('');
  say('audit-packet.json:');
  say(JSON.stringify(red.auditPacket, null, 2));
  if (red.exitCode !== 1) {
    process.stderr.write('tamper was NOT detected — this is a bug\n');
    process.exit(2);
  }

  header('kicker: the attacker steals a key and re-signs EVERYTHING');
  say('  To hide the edit properly, the attacker rewrites every entry from the');
  say('  tampered one on, fixes the hash chain, recomputes the Merkle root, and');
  say('  re-signs the whole ledger with a key they control. Chain ✔ roots ✔ sigs ✔ —');
  say('  a perfectly self-consistent forgery.');
  attackerFullRewrite(ledgerDir);
  say('');
  const kicker = await verifyLedger(ledgerDir, { online: !offline && logIndex !== undefined });
  say(renderReport(kicker));
  say('');
  if (kicker.exitCode === 1) {
    say(`  Caught anyway: the original checkpoint root is already ${offline ? 'anchored' : 'PUBLIC'} in the`);
    say('  Rekor transparency log' + (logIndex !== undefined ? ` (logIndex ${logIndex})` : '') + '. Rekor is append-only — the forged ledger');
    say('  can never match what the world already witnessed. That is the difference');
    say('  between "our logs say so" and evidence.');
  } else {
    process.stderr.write('kicker rewrite was NOT detected — this is a bug\n');
    process.exit(2);
  }
  say('');
  say(`demo ledger kept at ${ledgerDir} — poke at it: attestor verify ${ledgerDir}`);
}

/** Offline stand-in for a Rekor anchor, honestly labeled SIMULATED. */
function simulateAnchor(ledger: Ledger, ckpt: LedgerEntry): void {
  const fake = generateKeyPairSync('ec', { namedCurve: 'prime256v1' });
  const fakePem = fake.publicKey.export({ type: 'spki', format: 'pem' }).toString();
  const artifact = canonicalCoreBytes(coreOf(ckpt as unknown as Record<string, unknown>));
  const body = Buffer.from(JSON.stringify(hashedRekordBody(artifact, ledger.keys))).toString('base64');
  const integratedTime = Math.floor(Date.now() / 1000);
  const logIndex = 0;
  // A real log's ID is sha256(SPKI DER) of its own key, and key selection binds
  // an anchor to the key whose fingerprint equals this. A literal placeholder
  // here made the simulated anchor unauthenticatable except through a fallback
  // that ignored the log ID, so the demo was exercising a path that should not
  // exist rather than the path a real anchor takes.
  const logID = createHash('sha256')
    .update(fake.publicKey.export({ type: 'spki', format: 'der' }))
    .digest('hex');
  const uuid = createHash('sha256').update(body).digest('hex');
  const rootHash = leafHash(Buffer.from(body, 'base64')).toString('hex');
  const noteBody = `attestor-demo-simulated - 0\n1\n${Buffer.from(rootHash, 'hex').toString('base64')}\n`;
  const noteSig = cryptoSign('sha256', Buffer.from(noteBody, 'utf8'), fake.privateKey);
  const set = cryptoSign(
    'sha256',
    Buffer.from(canonicalize({ body, integratedTime, logID, logIndex })!, 'utf8'),
    fake.privateKey,
  ).toString('base64');
  const anchorsDir = join(ledger.dir, 'anchors');
  mkdirSync(anchorsDir, { recursive: true });
  writeFileSync(
    join(anchorsDir, `${ckpt.seq}.json`),
    JSON.stringify(
      {
        uuid,
        body,
        integratedTime,
        logID,
        logIndex,
        simulated: true,
        verification: {
          signedEntryTimestamp: set,
          inclusionProof: {
            checkpoint: `${noteBody}\n— attestor-demo-simulated ${Buffer.concat([Buffer.from([0, 0, 0, 0]), noteSig]).toString('base64')}\n`,
            hashes: [],
            logIndex: 0,
            rootHash,
            treeSize: 1,
          },
        },
      },
      null,
      2,
    ),
  );
  writeFileSync(join(anchorsDir, 'rekor-pub.pem'), fakePem);
  // Pin the simulated log key into the demo's throwaway home, so the offline
  // run shows the same green→red→caught arc a real anchor would. The anchor
  // itself is still labelled SIMULATED above — this stands in for "a log you
  // trust", it does not pretend anything reached the public log.
  const pinDir = keysDir(attestorHome());
  mkdirSync(pinDir, { recursive: true });
  writeFileSync(join(pinDir, 'rekor-pub.pem'), fakePem);
  ledger.append({
    type: 'anchor',
    origin: 'system',
    payload: JSON.stringify({
      checkpoint_seq: ckpt.seq,
      provider: 'rekor-v1',
      uuid,
      logIndex,
      integratedTime,
      url: 'simulated://offline',
    } satisfies AnchorPayload),
    session_id: ckpt.session_id,
  });
}

/** Rewrite + re-sign the whole ledger with an attacker-held key. */
function attackerFullRewrite(ledgerDir: string): void {
  const path = join(ledgerDir, 'ledger.jsonl');
  const entries = readEntries(path);
  const genesis = JSON.parse(entries[0]!.payload!) as { ledger_id: string };
  const atk = generateKeyPairSync('ec', { namedCurve: 'prime256v1' });
  const atkPem = atk.publicKey.export({ type: 'spki', format: 'pem' }).toString();
  const atkKeyId = keyIdOf(atk.publicKey);
  let prev = genesisPrev(genesis.ledger_id);
  const newHashes: string[] = [];
  const rewritten: string[] = [];
  for (const e of entries) {
    if (e.type === 'genesis') {
      e.payload = JSON.stringify({ ledger_id: genesis.ledger_id, public_key_pem: atkPem, attestor_version: 1 });
    }
    if (e.type === 'checkpoint' && e.payload !== undefined) {
      const p = JSON.parse(e.payload) as { ledger_id: string; tree_size: number; root: string };
      p.root = merkleRoot(newHashes.slice(0, p.tree_size).map((h) => Buffer.from(h, 'hex'))).toString('hex');
      e.payload = JSON.stringify(p);
    }
    e.key_id = atkKeyId;
    e.prev = prev;
    e.payload_hash = payloadHash(e.salt, e.payload);
    const core = coreOf(e as unknown as Record<string, unknown>);
    e.hash = hashCore(core);
    e.sig = signCore(core, atk.privateKey);
    prev = e.hash;
    newHashes.push(e.hash);
    rewritten.push(JSON.stringify(e));
  }
  writeFileSync(path, rewritten.join('\n') + '\n');
}
