// Rekor v1 anchoring over plain fetch: hashedrekord POST, offline pending
// queue with jittered backoff, SET + inclusion-proof verification.
// The anchored artifact is always a checkpoint entry's JCS core bytes.
import canonicalize from 'canonicalize';
import { createHash, createPublicKey, sign as cryptoSign, verify as cryptoVerify } from 'node:crypto';
import {
  existsSync,
  mkdirSync,
  readdirSync,
  readFileSync,
  renameSync,
  writeFileSync,
} from 'node:fs';
import { join } from 'node:path';
import type { KeyPair } from './keys.ts';
import { attestorHome, isRekorPinFile, keysDir } from './keys.ts';
import {
  canonicalCoreBytes,
  coreOf,
  readEntries,
  sha256Hex,
  type Ledger,
  type LedgerEntry,
} from './ledger.ts';
import { leafHash, rootFromInclusion } from './merkle.ts';

export const DEFAULT_REKOR_URL = 'https://rekor.sigstore.dev';

export class UntrustedRekorKeyError extends Error {}

/**
 * Pinned SHA-256 SPKI log IDs for official Sigstore Rekor instances
 * (matches logID: sha256(spki_der)).
 *
 * Rotation / migration: this is a set, not a single value. When Sigstore
 * rotates the log key (or shards the log), the new ID is ADDED here and both
 * remain valid until ledgers anchored under the old key have aged out — so a
 * pin taken before the rotation still authenticates, and a fresh pin taken
 * after it does too. Removing an ID is the (rare) revocation act and is a
 * breaking change by design.
 *
 * Custom logs: the allowlist gates ONLY the official public host. Any other
 * host (a private Rekor, a mock in tests, and also lookalike spellings of the
 * official domain) is a custom log: the auditor chose it and pinned its key
 * themselves, and this list makes no claim about it. What the gate prevents
 * is exactly one thing — a key that is NOT Sigstore's being accepted as if it
 * were the official log's.
 */
export const KNOWN_SIGSTORE_REKOR_LOG_IDS: readonly string[] = [
  'c0d23d6ad406973f9559f3ba2d1ca01f84147d8ffc5b8445c224f98b9591801d', // Sigstore active v1 log
];

/** Compute RFC 6962 / Sigstore log ID: sha256(SPKI DER). */
export function getSpkiFingerprint(pem: string): string {
  const key = createPublicKey(pem);
  const der = key.export({ type: 'spki', format: 'der' });
  return createHash('sha256').update(der).digest('hex');
}

/**
 * WHATWG-canonicalized hostname, with the DNS root label normalized away.
 *
 * `new URL()` lowercases and IDNA/punycodes the host but PRESERVES a terminal
 * root dot, and it percent-decodes `%2e` into that same dot. So
 * `rekor.sigstore.dev.`, `rekor.sigstore.dev%2e/` and `rekor.sigstore.dev.:443/`
 * all yield `rekor.sigstore.dev.` — DNS-equivalent to the bare name, but not
 * string-equal to it, which let them slip past exact host classification and be
 * treated as custom logs.
 *
 * Exactly one terminal dot is stripped. `rekor.sigstore.dev..` has an empty
 * label, is not a resolvable name, and deliberately stays distinct.
 */
function canonicalHost(baseUrl: string): string | undefined {
  let hostname: string;
  try {
    hostname = new URL(baseUrl).hostname;
  } catch {
    return undefined; // unparsable → cannot be the official host (fetch would fail anyway)
  }
  return hostname.endsWith('.') && !hostname.endsWith('..')
    ? hostname.slice(0, -1)
    : hostname;
}

/**
 * True when `baseUrl` targets the official public Sigstore Rekor instance.
 * The comparison is on the canonicalized hostname (lowercased, IDNA/punycoded,
 * root dot normalized) — never on the raw string. Raw matching was bypassable
 * in both directions: `HTTPS://REKOR.SIGSTORE.DEV` read as a custom log (gate
 * skipped for the real host), while substring matching promoted lookalike
 * hosts that merely contained the official name.
 */
export function isOfficialSigstoreHost(baseUrl: string): boolean {
  const host = canonicalHost(baseUrl);
  return host !== undefined && host === canonicalHost(DEFAULT_REKOR_URL);
}

/**
 * Verify a log public key against the pinned Sigstore trust root when (and
 * only when) `baseUrl` targets the official public Rekor host. Throws
 * `UntrustedRekorKeyError` — callers must let it surface, not swallow it.
 *
 * Unparsable key material for the official host is a trust failure, not an
 * incidental crypto error: `createPublicKey()` throws something generic, which
 * would otherwise escape this contract and surface as a crash rather than as a
 * trust finding.
 */
export function verifyRekorKeyTrust(baseUrl: string, pem: string): void {
  if (!isOfficialSigstoreHost(baseUrl)) return; // custom log: the auditor's own trust decision
  let fingerprint: string;
  try {
    fingerprint = getSpkiFingerprint(pem);
  } catch (err) {
    throw new UntrustedRekorKeyError(
      `Unusable Rekor public key for ${baseUrl}: key material did not parse as an SPKI public key (${(err as Error).message}).`,
    );
  }
  if (!KNOWN_SIGSTORE_REKOR_LOG_IDS.includes(fingerprint)) {
    throw new UntrustedRekorKeyError(
      `Untrusted Rekor public key for ${baseUrl}: SPKI digest ${fingerprint} does not match any pinned Sigstore trust root key.`,
    );
  }
}

/** Bound every Rekor request so exit-time anchor flushes can never hang. */
const FETCH_TIMEOUT_MS = 10_000;

export function rekorUrl(): string {
  return process.env.ATTESTOR_REKOR_URL ?? DEFAULT_REKOR_URL;
}

export interface RekorInclusionProof {
  checkpoint?: string;
  hashes: string[];
  logIndex: number;
  rootHash: string;
  treeSize: number;
}

export interface RekorEntry {
  body: string;
  integratedTime: number;
  logID: string;
  logIndex: number;
  verification?: {
    signedEntryTimestamp?: string;
    inclusionProof?: RekorInclusionProof;
  };
}

export interface HashedRekordSpec {
  apiVersion: '0.0.1';
  kind: 'hashedrekord';
  spec: {
    data: { hash: { algorithm: 'sha256'; value: string } };
    signature: {
      content: string;
      publicKey: { content: string };
    };
  };
}

export function hashedRekordBody(artifact: Buffer, keys: KeyPair): HashedRekordSpec {
  const sigDer = cryptoSign('sha256', artifact, keys.privateKey);
  return {
    apiVersion: '0.0.1',
    kind: 'hashedrekord',
    spec: {
      data: { hash: { algorithm: 'sha256', value: sha256Hex(artifact) } },
      signature: {
        content: sigDer.toString('base64'),
        publicKey: { content: Buffer.from(keys.publicPem).toString('base64') },
      },
    },
  };
}

export class RekorUnavailableError extends Error {}

/** POST an entry; handles 201 (created) and 409 (duplicate → fetch existing). */
export async function postEntry(
  baseUrl: string,
  body: HashedRekordSpec,
): Promise<{ uuid: string; entry: RekorEntry }> {
  let res: Response;
  try {
    res = await fetch(`${baseUrl}/api/v1/log/entries`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(body),
      signal: AbortSignal.timeout(FETCH_TIMEOUT_MS),
    });
  } catch (err) {
    throw new RekorUnavailableError(`rekor unreachable: ${(err as Error).message}`);
  }
  if (res.status === 201) {
    const json = (await res.json()) as Record<string, RekorEntry>;
    const uuid = Object.keys(json)[0]!;
    return { uuid, entry: json[uuid]! };
  }
  if (res.status === 409) {
    const location = res.headers.get('location');
    if (!location) throw new Error('rekor 409 without Location header');
    const uuid = location.split('/').pop()!;
    return { uuid, entry: await getEntry(baseUrl, uuid) };
  }
  const text = await res.text().catch(() => '');
  if (res.status === 429 || res.status >= 500) {
    throw new RekorUnavailableError(`rekor ${res.status}: ${text.slice(0, 200)}`);
  }
  throw new Error(`rekor POST failed ${res.status}: ${text.slice(0, 200)}`);
}

export async function getEntry(baseUrl: string, uuid: string): Promise<RekorEntry> {
  let res: Response;
  try {
    res = await fetch(`${baseUrl}/api/v1/log/entries/${uuid}`, { signal: AbortSignal.timeout(FETCH_TIMEOUT_MS) });
  } catch (err) {
    throw new RekorUnavailableError(`rekor unreachable: ${(err as Error).message}`);
  }
  if (!res.ok) {
    const cls = res.status === 429 || res.status >= 500 ? RekorUnavailableError : Error;
    throw new cls(`rekor GET ${uuid} failed: ${res.status}`);
  }
  const json = (await res.json()) as Record<string, RekorEntry>;
  const entry = json[uuid] ?? Object.values(json)[0];
  if (!entry) throw new Error(`rekor GET ${uuid}: empty response`);
  return entry;
}

/**
 * Discover every Rekor UUID logged under a recorder public key. Best-effort:
 * the public instance's index endpoint may be disabled, in which case this
 * throws RekorUnavailableError and the caller degrades gracefully.
 */
export async function searchByPublicKey(baseUrl: string, publicPem: string): Promise<string[]> {
  let res: Response;
  try {
    res = await fetch(`${baseUrl}/api/v1/index/retrieve`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ publicKey: { format: 'x509', content: Buffer.from(publicPem).toString('base64') } }),
      signal: AbortSignal.timeout(FETCH_TIMEOUT_MS),
    });
  } catch (err) {
    throw new RekorUnavailableError(`rekor index unreachable: ${(err as Error).message}`);
  }
  if (res.status === 404 || res.status === 501) return []; // endpoint disabled — degrade
  if (!res.ok) {
    if (res.status === 429 || res.status >= 500) throw new RekorUnavailableError(`rekor index ${res.status}`);
    return [];
  }
  const json = (await res.json().catch(() => [])) as unknown;
  return Array.isArray(json) ? (json as string[]) : [];
}

export async function getLogPublicKey(baseUrl: string): Promise<string> {
  let res: Response;
  try {
    res = await fetch(`${baseUrl}/api/v1/log/publicKey`, { signal: AbortSignal.timeout(FETCH_TIMEOUT_MS) });
  } catch (err) {
    throw new RekorUnavailableError(`rekor unreachable: ${(err as Error).message}`);
  }
  if (!res.ok) throw new RekorUnavailableError(`rekor publicKey failed: ${res.status}`);
  return res.text();
}

/**
 * Verify the Signed Entry Timestamp: ECDSA-P256-SHA256 by the Rekor log key
 * over JCS({body, integratedTime, logID, logIndex}).
 */
export function verifySET(entry: RekorEntry, rekorPubPem: string): boolean {
  const set = entry.verification?.signedEntryTimestamp;
  if (!set) return false;
  const canon = canonicalize({
    body: entry.body,
    integratedTime: entry.integratedTime,
    logID: entry.logID,
    logIndex: entry.logIndex,
  });
  if (canon === undefined) return false;
  try {
    return cryptoVerify(
      'sha256',
      Buffer.from(canon, 'utf8'),
      createPublicKey(rekorPubPem),
      Buffer.from(set, 'base64'),
    );
  } catch {
    return false;
  }
}

/**
 * Verify the entry's inclusion proof: RFC 6962 leaf over the decoded body
 * bytes, audit path up to the proof's rootHash.
 */
export function verifyRekorInclusion(entry: RekorEntry): boolean {
  const proof = entry.verification?.inclusionProof;
  if (!proof) return false;
  const bodyBytes = Buffer.from(entry.body, 'base64');
  const root = rootFromInclusion(
    proof.logIndex,
    proof.treeSize,
    leafHash(bodyBytes),
    proof.hashes.map((h) => Buffer.from(h, 'hex')),
  );
  return root !== undefined && root.toString('hex') === proof.rootHash;
}

/**
 * Verify the signed note in inclusionProof.checkpoint against the Rekor log
 * key, and that it commits the same root as the proof.
 * Note format: "<origin>\n<size>\n<b64 root>\n[extra lines]\n\n— <origin> <b64(4-byte hint ‖ sig)>\n"
 */
export function verifyCheckpointNote(proof: RekorInclusionProof, rekorPubPem: string): boolean {
  const note = proof.checkpoint;
  if (!note) return false;
  const sep = note.indexOf('\n\n');
  if (sep === -1) return false;
  const body = note.slice(0, sep + 1); // signed bytes: body incl. trailing \n
  const sigLines = note.slice(sep + 2).trim().split('\n');
  const bodyLines = body.trimEnd().split('\n');
  if (bodyLines.length < 3) return false;
  const noteRoot = Buffer.from(bodyLines[2]!, 'base64').toString('hex');
  if (noteRoot !== proof.rootHash) return false;
  if (Number(bodyLines[1]) !== proof.treeSize) return false;
  for (const line of sigLines) {
    const m = /^— \S+ (\S+)$/.exec(line);
    if (!m) continue;
    const sigBytes = Buffer.from(m[1]!, 'base64');
    const sig = sigBytes.subarray(4); // strip 4-byte key hint
    try {
      if (
        cryptoVerify('sha256', Buffer.from(body, 'utf8'), createPublicKey(rekorPubPem), sig)
      ) {
        return true;
      }
    } catch {
      /* try next sig line */
    }
  }
  return false;
}

export interface AnchorPayload {
  checkpoint_seq: number;
  provider: 'rekor-v1';
  uuid: string;
  logIndex: number;
  integratedTime: number;
  url: string;
}

interface PendingAnchor {
  checkpoint_seq: number;
  attempts: number;
  next_at: number; // epoch ms
}

export function anchorsDir(ledgerDir: string): string {
  return join(ledgerDir, 'anchors');
}

/** Jittered exponential backoff: 1 min → 1 h cap. */
export function backoffMs(attempts: number): number {
  const base = Math.min(60_000 * 2 ** attempts, 3_600_000);
  return Math.round(base * (0.5 + Math.random()));
}

/** POST the checkpoint artifact and record the anchor entry. Throws on failure. */
async function tryAnchor(
  ledger: Ledger,
  checkpointEntry: LedgerEntry,
  baseUrl: string,
  home?: string,
): Promise<LedgerEntry> {
  const dir = anchorsDir(ledger.dir);
  mkdirSync(dir, { recursive: true });
  const artifact = canonicalCoreBytes(coreOf(checkpointEntry as unknown as Record<string, unknown>));
  const { uuid, entry } = await postEntry(baseUrl, hashedRekordBody(artifact, ledger.keys));
  // Stage the Rekor record under a name the verifier ignores, append the
  // in-chain anchor entry, then publish it with a rename. A crash anywhere in
  // between leaves either nothing or a complete pair — never a stored anchor
  // with no entry, which is indistinguishable from an attacker deleting the
  // entry to hide a rewrite.
  const finalPath = join(dir, `${checkpointEntry.seq}.json`);
  const stagedPath = `${finalPath}.partial`;
  writeFileSync(stagedPath, JSON.stringify({ uuid, ...entry }, null, 2));
  const payload: AnchorPayload = {
    checkpoint_seq: checkpointEntry.seq,
    provider: 'rekor-v1',
    uuid,
    logIndex: entry.logIndex,
    integratedTime: entry.integratedTime,
    url: baseUrl,
  };
  const anchorEntry = ledger.append({
    type: 'anchor',
    origin: 'system',
    payload: JSON.stringify(payload),
    session_id: checkpointEntry.session_id,
  });
  renameSync(stagedPath, finalPath);
  // pinning the log key is a convenience, not part of the anchor record, so it
  // happens after the window is closed. Network failure while pinning is a
  // missed convenience and stays silent — but an UNTRUSTED key is a trust
  // failure and must surface loudly, not be swallowed with it. The anchor
  // entry itself is already recorded and stays valid; what failed is pinning.
  await pinRekorKey(baseUrl, ledger.dir, home, entry.logID).catch((err) => {
    if (err instanceof UntrustedRekorKeyError) throw err;
  });
  return anchorEntry;
}

/**
 * Anchor a checkpoint entry to Rekor. Never throws on network failure —
 * queues to anchors/pending.jsonl instead. Anchoring never blocks recording.
 */
export async function anchorCheckpoint(
  ledger: Ledger,
  checkpointEntry: LedgerEntry,
  opts: { baseUrl?: string; offline?: boolean; home?: string } = {},
): Promise<LedgerEntry | undefined> {
  const baseUrl = opts.baseUrl ?? rekorUrl();
  const offline = opts.offline ?? process.env.ATTESTOR_OFFLINE === '1';
  if (offline) {
    queuePending(ledger.dir, checkpointEntry.seq, 0);
    return undefined;
  }
  try {
    return await tryAnchor(ledger, checkpointEntry, baseUrl, opts.home);
  } catch (err) {
    if (err instanceof RekorUnavailableError) {
      queuePending(ledger.dir, checkpointEntry.seq, 0);
      return undefined;
    }
    throw err;
  }
}

/** Filename a log key is pinned under, keyed by its log ID (SPKI digest). */
export function rekorKeyPinName(logId: string): string {
  return `rekor-pub-${logId}.pem`;
}

/**
 * Read every pinned Rekor log key found in `dirs`, keyed by log ID.
 *
 * A pin set has to be a keyring rather than a single file for the documented
 * rotation policy to mean anything: a ledger can span a key rotation, so its
 * anchors legitimately carry different `logID`s and no single key verifies all
 * of them. Keys are indexed by their real SPKI digest, recomputed here — the
 * filename is a hint, never the trust decision. The legacy single-file pin
 * (`rekor-pub.pem`) is read in as just another keyring member so pins taken
 * before this existed keep working.
 *
 * Earlier directories win, so callers can pass host pins ahead of artifact
 * pins and keep the "the artifact cannot vouch for itself" ordering.
 */
export function readRekorKeyring(dirs: readonly string[]): Map<string, string> {
  const ring = new Map<string, string>();
  for (const dir of dirs) {
    if (!existsSync(dir)) continue;
    let names: string[];
    try {
      names = readdirSync(dir);
    } catch {
      continue;
    }
    for (const name of names) {
      if (!isRekorPinFile(name)) continue;
      let pem: string;
      try {
        pem = readFileSync(join(dir, name), 'utf8');
      } catch {
        continue;
      }
      let fingerprint: string;
      try {
        fingerprint = getSpkiFingerprint(pem);
      } catch {
        continue; // unparsable pin is not a usable key; the trust gate reports it
      }
      if (!ring.has(fingerprint)) ring.set(fingerprint, pem);
    }
  }
  return ring;
}

/**
 * Pin the Rekor log public key.
 *
 * `logId` is the log ID of the entry that was just anchored. When a pin for
 * that exact log already exists there is nothing to learn and no request is
 * made; when the log has rotated its key, the ID is new, so the new key is
 * fetched, trust-checked, and pinned ALONGSIDE the old one instead of being
 * skipped because some pin file happened to exist. That skip was why the
 * documented rotation policy could not work.
 */
export async function pinRekorKey(
  baseUrl: string,
  ledgerDir: string,
  home?: string,
  logId?: string,
): Promise<void> {
  const dir = anchorsDir(ledgerDir);
  const homeKeys = keysDir(home ?? attestorHome());
  if (logId !== undefined) {
    const name = rekorKeyPinName(logId);
    if (existsSync(join(dir, name)) && existsSync(join(homeKeys, name))) return;
  } else if (existsSync(join(dir, 'rekor-pub.pem'))) {
    return; // no log ID to distinguish by — preserve the original pin-once behaviour
  }
  const pem = await getLogPublicKey(baseUrl);
  verifyRekorKeyTrust(baseUrl, pem);
  // Index the pin by the key's own digest, not by the log ID the entry claimed,
  // so a lying logID cannot cause a key to be filed under someone else's name.
  const name = rekorKeyPinName(getSpkiFingerprint(pem));
  mkdirSync(dir, { recursive: true });
  writeFileSync(join(dir, name), pem);
  mkdirSync(homeKeys, { recursive: true });
  writeFileSync(join(homeKeys, name), pem);
  // Keep the legacy single-file pin pointing at the first key ever seen, so
  // older verifiers reading only this path behave exactly as before.
  const legacyLocal = join(dir, 'rekor-pub.pem');
  if (!existsSync(legacyLocal)) writeFileSync(legacyLocal, pem);
  const legacyHome = join(homeKeys, 'rekor-pub.pem');
  if (!existsSync(legacyHome)) writeFileSync(legacyHome, pem);
}

function pendingPath(ledgerDir: string): string {
  return join(anchorsDir(ledgerDir), 'pending.jsonl');
}

export function readPending(ledgerDir: string): PendingAnchor[] {
  const p = pendingPath(ledgerDir);
  if (!existsSync(p)) return [];
  const bySeq = new Map<number, PendingAnchor>();
  for (const line of readFileSync(p, 'utf8').split('\n')) {
    if (!line) continue;
    const rec = JSON.parse(line) as PendingAnchor;
    bySeq.set(rec.checkpoint_seq, rec);
  }
  return [...bySeq.values()];
}

function writePendingAll(ledgerDir: string, records: PendingAnchor[]): void {
  mkdirSync(anchorsDir(ledgerDir), { recursive: true });
  writeFileSync(
    pendingPath(ledgerDir),
    records.map((r) => JSON.stringify(r) + '\n').join(''),
  );
}

function queuePending(ledgerDir: string, checkpointSeq: number, attempts: number): void {
  const all = readPending(ledgerDir).filter((r) => r.checkpoint_seq !== checkpointSeq);
  all.push({
    checkpoint_seq: checkpointSeq,
    attempts: attempts + 1,
    next_at: Date.now() + backoffMs(attempts),
  });
  writePendingAll(ledgerDir, all);
}

/** Retry queued anchors whose backoff has elapsed. Returns count anchored. */
export async function retryPending(
  ledger: Ledger,
  opts: { baseUrl?: string; home?: string; now?: number } = {},
): Promise<number> {
  if (process.env.ATTESTOR_OFFLINE === '1') return 0;
  const now = opts.now ?? Date.now();
  const pending = readPending(ledger.dir);
  if (pending.length === 0) return 0;
  const baseUrl = opts.baseUrl ?? rekorUrl();
  const entries = readEntries(join(ledger.dir, 'ledger.jsonl'));
  let anchored = 0;
  const survivors: PendingAnchor[] = [];
  for (const rec of pending) {
    if (rec.next_at > now) {
      survivors.push(rec);
      continue;
    }
    const ckpt = entries.find((e) => e.seq === rec.checkpoint_seq && e.type === 'checkpoint');
    if (!ckpt) continue; // no such checkpoint — drop the queue record
    try {
      await tryAnchor(ledger, ckpt, baseUrl, opts.home);
      anchored++;
    } catch (err) {
      if (!(err instanceof RekorUnavailableError)) throw err;
      survivors.push({
        checkpoint_seq: rec.checkpoint_seq,
        attempts: rec.attempts + 1,
        next_at: now + backoffMs(rec.attempts + 1),
      });
    }
  }
  writePendingAll(ledger.dir, survivors);
  return anchored;
}
