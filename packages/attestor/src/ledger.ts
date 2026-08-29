// Append-only hash-chained ledger: one JSON object per line.
// Signed core is canonicalized with RFC 8785 JCS, hashed SHA-256, signed
// ECDSA P-256. `payload` (exact wire bytes as a JSON string) is UNSIGNED but
// committed via payload_hash = SHA256(salt ‖ payload) — so `attestor redact`
// can strip payloads without breaking the chain, and the 16-byte salt defeats
// brute-force on low-entropy redacted payloads.
import canonicalize from 'canonicalize';
import {
  createHash,
  randomBytes,
  sign as cryptoSign,
  verify as cryptoVerify,
  type KeyObject,
} from 'node:crypto';
import {
  appendFileSync,
  closeSync,
  existsSync,
  fsyncSync,
  mkdirSync,
  openSync,
  readFileSync,
  unlinkSync,
  writeFileSync,
  writeSync,
} from 'node:fs';
import { join } from 'node:path';
import type { KeyPair } from './keys.ts';

export type EntryType =
  | 'genesis'
  | 'session_start'
  | 'session_end'
  | 'wire'
  | 'call_request'
  | 'call_result'
  | 'tool_execution'
  | 'checkpoint'
  | 'anchor'
  | 'gap'
  | 'key_rotation'
  | 'redaction';

export type Origin = 'proxy' | 'sdk' | 'manual' | 'system';

/**
 * Entry types whose payload is load-bearing for verification — never
 * redactable. `gap` is here because its payload documents unrecorded traffic:
 * redacting it would erase evidence of a hole in the record.
 */
export const SYSTEM_TYPES: ReadonlySet<EntryType> = new Set([
  'genesis',
  'checkpoint',
  'anchor',
  'key_rotation',
  'gap',
  'redaction',
]);

export interface SignedCore {
  v: number;
  seq: number;
  ts: string;
  type: EntryType;
  session_id: string;
  call_id?: string;
  direction?: 'c2s' | 's2c';
  origin: Origin;
  actor?: Record<string, string>;
  tool?: Record<string, string>;
  payload_hash: string;
  prev: string;
  key_id: string;
}

export interface LedgerEntry extends SignedCore {
  /**
   * 16-byte hex salt. UNSIGNED and dropped by redaction alongside `payload`,
   * so that after redaction only the signed `payload_hash = SHA256(salt‖bytes)`
   * remains — with the salt gone, a low-entropy payload cannot be brute-forced.
   */
  salt?: string;
  /** Exact wire/body bytes as a JSON string. Unsigned; strippable by redact. */
  payload?: string;
  /** hex SHA256(JCS(core)) — chain link. */
  hash: string;
  /** base64 DER ECDSA-P256-SHA256 over the same JCS core bytes. */
  sig: string;
}

const CORE_FIELDS = [
  'v',
  'seq',
  'ts',
  'type',
  'session_id',
  'call_id',
  'direction',
  'origin',
  'actor',
  'tool',
  'payload_hash',
  'prev',
  'key_id',
] as const;

/** Every legal top-level key on a ledger line (core + unsigned siblings). */
export const KNOWN_ENTRY_KEYS: ReadonlySet<string> = new Set([
  ...CORE_FIELDS,
  'salt',
  'payload',
  'hash',
  'sig',
]);

export function coreOf(entry: Record<string, unknown>): SignedCore {
  const core: Record<string, unknown> = {};
  for (const f of CORE_FIELDS) {
    if (entry[f] !== undefined) core[f] = entry[f];
  }
  return core as unknown as SignedCore;
}

export function canonicalCoreBytes(core: SignedCore): Buffer {
  const canon = canonicalize(coreOf(core as unknown as Record<string, unknown>));
  if (canon === undefined) throw new Error('JCS canonicalization failed');
  return Buffer.from(canon, 'utf8');
}

export function sha256Hex(data: Buffer | string): string {
  return createHash('sha256').update(data).digest('hex');
}

export function hashCore(core: SignedCore): string {
  return sha256Hex(canonicalCoreBytes(core));
}

export function signCore(core: SignedCore, privateKey: KeyObject): string {
  return cryptoSign('sha256', canonicalCoreBytes(core), privateKey).toString('base64');
}

export function verifyCoreSig(core: SignedCore, sigB64: string, publicKey: KeyObject): boolean {
  try {
    return cryptoVerify(
      'sha256',
      canonicalCoreBytes(core),
      publicKey,
      Buffer.from(sigB64, 'base64'),
    );
  } catch {
    return false;
  }
}

/**
 * The salt is exactly 16 bytes, always. Enforcing that at verification time is
 * load-bearing, not cosmetic: `payload_hash` is SHA256(salt‖payload) with no
 * length prefix, and the salt is unsigned (redaction has to be able to drop
 * it). Without a fixed length an attacker could slide the boundary — move the
 * payload bytes into the salt and blank the payload — and the commitment would
 * still match, silently erasing recorded content. A fixed-width salt pins the
 * split point and closes that.
 */
export const SALT_HEX = /^[0-9a-f]{32}$/;

export function payloadHash(saltHex: string | undefined, payload: string | undefined): string {
  const h = createHash('sha256');
  if (saltHex !== undefined) h.update(Buffer.from(saltHex, 'hex'));
  if (payload !== undefined) h.update(Buffer.from(payload, 'utf8'));
  return h.digest('hex');
}

export interface GapNote {
  unrecorded_lines?: number;
  unrecorded_events?: number;
  from_ts?: string;
  to_ts: string;
}

/**
 * Persist a gap note when the ledger is unwritable at shutdown: the next
 * successful open folds it into a signed `gap` entry, so a hole in the record
 * can never disappear just because the process died while the disk was full.
 */
export function writeGapPending(dir: string, note: GapNote): void {
  appendFileSync(join(dir, 'gap.pending'), JSON.stringify(note) + '\n');
}

export function readGapPending(dir: string): GapNote[] {
  const p = join(dir, 'gap.pending');
  if (!existsSync(p)) return [];
  const out: GapNote[] = [];
  for (const line of readFileSync(p, 'utf8').split('\n')) {
    if (line === '') continue;
    try {
      out.push(JSON.parse(line) as GapNote);
    } catch {
      /* skip malformed note */
    }
  }
  return out;
}

export function genesisPrev(ledgerId: string): string {
  return sha256Hex(`attestor-genesis:${ledgerId}`);
}

/** RFC 9562 UUIDv7: 48-bit unix ms + version/variant bits + random. */
export function uuidv7(): string {
  const b = randomBytes(16);
  const ms = BigInt(Date.now());
  b[0] = Number((ms >> 40n) & 0xffn);
  b[1] = Number((ms >> 32n) & 0xffn);
  b[2] = Number((ms >> 24n) & 0xffn);
  b[3] = Number((ms >> 16n) & 0xffn);
  b[4] = Number((ms >> 8n) & 0xffn);
  b[5] = Number(ms & 0xffn);
  b[6] = (b[6]! & 0x0f) | 0x70;
  b[8] = (b[8]! & 0x3f) | 0x80;
  const hex = b.toString('hex');
  return `${hex.slice(0, 8)}-${hex.slice(8, 12)}-${hex.slice(12, 16)}-${hex.slice(16, 20)}-${hex.slice(20)}`;
}

export function parseLine(line: string): LedgerEntry {
  return JSON.parse(line) as LedgerEntry;
}

/** Read and parse every entry in a ledger file. Throws on unparsable lines. */
export function readEntries(ledgerPath: string): LedgerEntry[] {
  if (!existsSync(ledgerPath)) return [];
  const raw = readFileSync(ledgerPath, 'utf8');
  const out: LedgerEntry[] = [];
  for (const line of raw.split('\n')) {
    if (line === '') continue;
    out.push(parseLine(line));
  }
  return out;
}

export interface AppendInput {
  type: EntryType;
  payload?: string;
  session_id?: string;
  call_id?: string;
  direction?: 'c2s' | 's2c';
  origin?: Origin;
  actor?: Record<string, string>;
  tool?: Record<string, string>;
}

export interface LedgerOptions {
  durability?: 'strict' | 'group';
  /** Group-commit flush interval (ms). */
  groupIntervalMs?: number;
  /** Group-commit flush threshold (entries). */
  groupMaxPending?: number;
}

interface TornRecovery {
  recovered: boolean;
  tornBytes: number;
}

// ponytail: whole-file read on open + all entry hashes in memory; fine to ~1M
// entries, stream + incremental index if ledgers outgrow that.
export class Ledger {
  readonly dir: string;
  readonly ledgerId: string;
  readonly path: string;
  readonly keys: KeyPair;
  readonly durability: 'strict' | 'group';
  readonly tornRecovery: TornRecovery = { recovered: false, tornBytes: 0 };
  /** hex hash of every entry, index == seq */
  readonly hashes: string[] = [];
  private fd: number;
  private lastHash: string;
  private nextSeq = 0;
  private pendingFsync = 0;
  private flushTimer: NodeJS.Timeout | undefined;
  private readonly groupIntervalMs: number;
  private readonly groupMaxPending: number;
  private closed = false;

  private constructor(dir: string, ledgerId: string, keys: KeyPair, opts: LedgerOptions) {
    this.dir = dir;
    this.ledgerId = ledgerId;
    this.path = join(dir, 'ledger.jsonl');
    this.keys = keys;
    this.durability = opts.durability ?? 'strict';
    this.groupIntervalMs = opts.groupIntervalMs ?? 25;
    this.groupMaxPending = opts.groupMaxPending ?? 256;
    this.lastHash = genesisPrev(ledgerId);
    this.acquireLock();
    this.recoverTornTail();
    for (const e of readEntries(this.path)) {
      if (e.seq !== this.nextSeq) {
        this.releaseLock();
        throw new Error(`ledger corrupt: expected seq ${this.nextSeq}, found ${e.seq}`);
      }
      this.hashes.push(e.hash);
      this.lastHash = e.hash;
      this.nextSeq++;
    }
    this.fd = openSync(this.path, 'a'); // O_APPEND
  }

  /** Create a new ledger (writes genesis) or open an existing one. */
  static open(dir: string, keys: KeyPair, opts: LedgerOptions = {}): Ledger {
    mkdirSync(dir, { recursive: true });
    const idPath = join(dir, 'ledger_id');
    let ledgerId: string;
    let isNew = false;
    if (existsSync(idPath)) {
      ledgerId = readFileSync(idPath, 'utf8').trim();
    } else {
      ledgerId = uuidv7();
      writeFileSync(idPath, ledgerId + '\n');
      isNew = true;
    }
    const ledger = new Ledger(dir, ledgerId, keys, opts);
    if (isNew || ledger.nextSeq === 0) {
      ledger.append({
        type: 'genesis',
        origin: 'system',
        payload: JSON.stringify({
          ledger_id: ledgerId,
          public_key_pem: keys.publicPem,
          attestor_version: 1,
        }),
      });
    }
    // A previous run died while the ledger was unwritable — record the hole
    // now that we can write again, before anything else lands in the chain.
    for (const note of readGapPending(dir)) {
      ledger.append({ type: 'gap', origin: 'system', payload: JSON.stringify(note) });
    }
    try {
      unlinkSync(join(dir, 'gap.pending'));
    } catch {
      /* nothing pending */
    }
    return ledger;
  }

  get size(): number {
    return this.nextSeq;
  }

  get head(): string {
    return this.lastHash;
  }

  append(input: AppendInput, sessionId?: string): LedgerEntry {
    if (this.closed) throw new Error('ledger closed');
    const salt = randomBytes(16).toString('hex');
    const core: SignedCore = {
      v: 1,
      seq: this.nextSeq,
      ts: new Date().toISOString(),
      type: input.type,
      session_id: input.session_id ?? sessionId ?? '00000000-0000-0000-0000-000000000000',
      ...(input.call_id !== undefined && { call_id: input.call_id }),
      ...(input.direction !== undefined && { direction: input.direction }),
      origin: input.origin ?? 'system',
      ...(input.actor !== undefined && { actor: input.actor }),
      ...(input.tool !== undefined && { tool: input.tool }),
      payload_hash: payloadHash(salt, input.payload),
      prev: this.lastHash,
      key_id: this.keys.keyId,
    };
    const hash = hashCore(core);
    const sig = signCore(core, this.keys.privateKey);
    // salt is UNSIGNED (payload_hash in the core binds it); redaction drops it.
    const entry: LedgerEntry = {
      ...core,
      salt,
      ...(input.payload !== undefined && { payload: input.payload }),
      hash,
      sig,
    };
    const line = Buffer.from(JSON.stringify(entry) + '\n', 'utf8');
    // writeSync can short-write a large buffer; loop so a big payload never
    // leaves a torn line in the middle of the ledger (a false tamper signal).
    for (let off = 0; off < line.length; ) {
      off += writeSync(this.fd, line, off, line.length - off);
    }
    if (this.durability === 'strict') {
      fsyncSync(this.fd);
    } else {
      this.pendingFsync++;
      if (this.pendingFsync >= this.groupMaxPending) {
        this.flush();
      } else if (!this.flushTimer) {
        this.flushTimer = setTimeout(() => this.flush(), this.groupIntervalMs);
        this.flushTimer.unref();
      }
    }
    this.hashes.push(hash);
    this.lastHash = hash;
    this.nextSeq++;
    return entry;
  }

  flush(): void {
    if (this.flushTimer) {
      clearTimeout(this.flushTimer);
      this.flushTimer = undefined;
    }
    if (this.pendingFsync > 0 && !this.closed) {
      fsyncSync(this.fd);
      this.pendingFsync = 0;
    }
  }

  close(): void {
    if (this.closed) return;
    this.flush();
    this.closed = true;
    closeSync(this.fd);
    this.releaseLock();
  }

  private get lockPath(): string {
    return join(this.dir, 'ledger.lock');
  }

  private acquireLock(): void {
    try {
      const fd = openSync(this.lockPath, 'wx'); // O_EXCL
      writeSync(fd, String(process.pid));
      closeSync(fd);
    } catch (err: unknown) {
      if ((err as NodeJS.ErrnoException).code !== 'EEXIST') throw err;
      const holder = Number(readFileSync(this.lockPath, 'utf8').trim());
      if (holder && this.pidAlive(holder)) {
        throw new Error(`ledger locked by pid ${holder} (${this.lockPath})`);
      }
      // stale lock — previous holder is gone
      unlinkSync(this.lockPath);
      this.acquireLock();
    }
  }

  private pidAlive(pid: number): boolean {
    try {
      process.kill(pid, 0);
      return true;
    } catch (err: unknown) {
      return (err as NodeJS.ErrnoException).code === 'EPERM';
    }
  }

  private releaseLock(): void {
    try {
      unlinkSync(this.lockPath);
    } catch {
      /* already gone */
    }
  }

  /**
   * A crash can leave a torn final line (a partial write is always a prefix,
   * so the damage is exactly one unterminated trailing line). Move those
   * bytes to `ledger.torn` and truncate; the chain resumes from the last good
   * entry. A newline-TERMINATED line that fails hash checks is deliberately
   * NOT recovered here — that is tamper evidence, and verify must see it.
   */
  private recoverTornTail(): void {
    if (!existsSync(this.path)) return;
    const raw = readFileSync(this.path, 'utf8');
    if (raw === '' || raw.endsWith('\n')) return;
    const idx = raw.lastIndexOf('\n');
    const torn = raw.slice(idx + 1);
    appendFileSync(join(this.dir, 'ledger.torn'), torn + '\n');
    writeFileSync(this.path, idx === -1 ? '' : raw.slice(0, idx + 1));
    this.tornRecovery.recovered = true;
    this.tornRecovery.tornBytes = Buffer.byteLength(torn);
  }
}
