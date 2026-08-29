// Redaction: delete the unsigned `payload` of one entry and rewrite that
// line. Chain, signatures, Merkle roots, and Rekor anchors all stay valid,
// because the signed core commits payload_hash = SHA256(salt ‖ payload) —
// never the payload itself. The random salt defeats brute-force on
// low-entropy redacted payloads. System entries (genesis, checkpoint,
// anchor, key_rotation) are never redactable: their payloads are
// load-bearing for verification.
import { existsSync, readFileSync, renameSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { parseArgs } from 'node:util';
import type { KeyPair } from './keys.ts';
import { attestorHome, loadKey } from './keys.ts';
import { Ledger, SYSTEM_TYPES, type LedgerEntry } from './ledger.ts';

export interface RedactOptions {
  reason?: string;
  keys?: KeyPair;
  recordInChain?: boolean;
}

export interface RedactionRecordPayload {
  target_seq: number;
  target_hash?: string;
  redacted_at: string;
  reason?: string;
}

export function redactEntry(ledgerDir: string, seq: number, opts: RedactOptions = {}): LedgerEntry {
  const path = join(ledgerDir, 'ledger.jsonl');
  if (!existsSync(path)) throw new Error(`no ledger at ${ledgerDir}`);
  const lockPath = join(ledgerDir, 'ledger.lock');
  if (existsSync(lockPath)) {
    const pid = Number(readFileSync(lockPath, 'utf8').trim());
    try {
      process.kill(pid, 0);
      throw new Error(`ledger is being written by pid ${pid} — stop the recorder first`);
    } catch (err) {
      if ((err as NodeJS.ErrnoException).code !== 'ESRCH') throw err;
    }
  }
  const raw = readFileSync(path, 'utf8');
  // A crash can leave an unterminated final line. `verify` ignores it and the
  // recorder folds it into ledger.torn on next open — but rewriting the file
  // here would newline-terminate it, converting benign crash damage into a
  // permanent "not valid JSON" tamper finding. Drop it, same rule as
  // Ledger.recoverTornTail.
  const hadTornTail = raw !== '' && !raw.endsWith('\n');
  const lines = raw.trimEnd().split('\n');
  if (hadTornTail) lines.pop();
  if (seq < 0 || seq >= lines.length) throw new Error(`seq ${seq} out of range [0, ${lines.length})`);
  const entry = JSON.parse(lines[seq]!) as LedgerEntry;
  if (entry.seq !== seq) throw new Error(`ledger line ${seq} has seq ${entry.seq} — verify the ledger first`);
  if (SYSTEM_TYPES.has(entry.type)) {
    throw new Error(`refusing to redact ${entry.type} entry — its payload is required for verification`);
  }
  if (entry.payload === undefined) throw new Error(`entry ${seq} is already redacted`);
  // Drop BOTH payload and salt: with the salt gone, the surviving signed
  // payload_hash = SHA256(salt‖bytes) can no longer be brute-forced.
  delete entry.payload;
  delete entry.salt;
  lines[seq] = JSON.stringify(entry);
  const tmpPath = path + '.redact-tmp';
  writeFileSync(tmpPath, lines.join('\n') + '\n');
  renameSync(tmpPath, path);

  // If keys are provided or found in home, append an in-chain redaction certificate
  if (opts.recordInChain !== false) {
    let keys = opts.keys;
    if (!keys) {
      try {
        keys = loadKey(attestorHome());
      } catch {
        /* no default key, skip auto in-chain record */
      }
    }
    if (keys) {
      const ledger = Ledger.open(ledgerDir, keys);
      const payload: RedactionRecordPayload = {
        target_seq: seq,
        target_hash: entry.entry_hash,
        redacted_at: new Date().toISOString(),
        reason: opts.reason ?? 'redacted by operator',
      };
      ledger.append({
        type: 'redaction',
        origin: 'system',
        payload: JSON.stringify(payload),
        session_id: entry.session_id,
      });
      ledger.close();
    }
  }

  return entry;
}

export async function runRedact(argv: string[]): Promise<void> {
  const { positionals, values } = parseArgs({
    args: argv,
    allowPositionals: true,
    options: {
      reason: { type: 'string', short: 'r' },
    },
  });
  const [dir, seqStr] = positionals;
  if (dir === undefined || seqStr === undefined || !/^\d+$/.test(seqStr)) {
    process.stderr.write('attestor: usage: attestor redact <ledger-dir> <seq> [--reason <reason>]\n');
    process.exit(2);
  }
  const entry = redactEntry(dir, Number(seqStr), { reason: values.reason });
  process.stdout.write(
    `redacted payload of entry ${entry.seq} (${entry.type})\n` +
      `  salted commitment retained: ${entry.payload_hash}\n` +
      `  chain, signatures, Merkle roots and anchors remain valid — run: attestor verify ${dir}\n`,
  );
}
