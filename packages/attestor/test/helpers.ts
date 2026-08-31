// Shared test helpers: build ledgers and simulate Rekor anchors offline with
// a fake log keypair, so the full ANCHOR verification path runs in tests.
import canonicalize from 'canonicalize';
import { createHash, generateKeyPairSync, sign as cryptoSign, type KeyObject } from 'node:crypto';
import { mkdirSync, mkdtempSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { attestorHome, generateKey, keysDir, type KeyPair } from '../src/keys.ts';
import { canonicalCoreBytes, coreOf, Ledger, type LedgerEntry } from '../src/ledger.ts';
import { hashedRekordBody, type AnchorPayload } from '../src/rekor.ts';
import { leafHash } from '../src/merkle.ts';
import { writeCheckpoint } from '../src/checkpoint.ts';

export function tmp(prefix = 'attestor-test-'): string {
  return mkdtempSync(join(tmpdir(), prefix));
}

export interface FakeRekor {
  publicPem: string;
  privateKey: KeyObject;
  logId: string;
  nextIndex: number;
}

export function fakeRekor(): FakeRekor {
  const { privateKey, publicKey } = generateKeyPairSync('ec', { namedCurve: 'prime256v1' });
  const publicPem = publicKey.export({ type: 'spki', format: 'pem' }).toString();
  return {
    publicPem,
    privateKey,
    logId: createHash('sha256').update(publicKey.export({ type: 'spki', format: 'der' })).digest('hex'),
    nextIndex: 1000,
  };
}

/** Build a Rekor entry (SET, single-leaf inclusion proof, signed note) the way the real log would. */
export function rekorEntryFor(
  rekor: FakeRekor,
  bodyObj: unknown,
  integratedTimeOverride?: number,
): {
  uuid: string;
  body: string;
  integratedTime: number;
  logID: string;
  logIndex: number;
  verification: {
    signedEntryTimestamp: string;
    inclusionProof: { checkpoint: string; hashes: string[]; logIndex: number; rootHash: string; treeSize: number };
  };
} {
  const body = Buffer.from(JSON.stringify(bodyObj)).toString('base64');
  const logIndex = rekor.nextIndex++;
  const integratedTime = integratedTimeOverride ?? Math.floor(Date.now() / 1000);
  const uuid = createHash('sha256').update(body).digest('hex');
  const rootHash = leafHash(Buffer.from(body, 'base64')).toString('hex');
  const noteBody = `rekor.fake - 42\n1\n${Buffer.from(rootHash, 'hex').toString('base64')}\n`;
  const noteSig = cryptoSign('sha256', Buffer.from(noteBody, 'utf8'), rekor.privateKey);
  const note = `${noteBody}\n— rekor.fake ${Buffer.concat([Buffer.from([1, 2, 3, 4]), noteSig]).toString('base64')}\n`;
  const setCanon = canonicalize({ body, integratedTime, logID: rekor.logId, logIndex })!;
  const set = cryptoSign('sha256', Buffer.from(setCanon, 'utf8'), rekor.privateKey).toString('base64');
  return {
    uuid,
    body,
    integratedTime,
    logID: rekor.logId,
    logIndex,
    verification: {
      signedEntryTimestamp: set,
      inclusionProof: { checkpoint: note, hashes: [], logIndex: 0, rootHash, treeSize: 1 },
    },
  };
}

/**
 * Simulate what a real `anchorCheckpoint` produces: anchors/<seq>.json with a
 * Rekor-signed SET + single-leaf inclusion proof + signed note, an `anchor`
 * ledger entry, and the pinned log key at anchors/rekor-pub.pem.
 */
export function fakeAnchor(
  ledger: Ledger,
  ckpt: LedgerEntry,
  rekor: FakeRekor,
  opts: { integratedTime?: number; url?: string } = {},
): LedgerEntry {
  const artifact = canonicalCoreBytes(coreOf(ckpt as unknown as Record<string, unknown>));
  const bodyObj = hashedRekordBody(artifact, ledger.keys);
  // The SET is re-signed over whatever integratedTime we use, so an overridden
  // time still yields a fully authenticated anchor — tests can isolate the
  // time policy from every signature check.
  const stored = rekorEntryFor(rekor, bodyObj, opts.integratedTime);
  const { uuid, logIndex, integratedTime } = stored;
  const anchorsDir = join(ledger.dir, 'anchors');
  mkdirSync(anchorsDir, { recursive: true });
  writeFileSync(join(anchorsDir, `${ckpt.seq}.json`), JSON.stringify(stored, null, 2));
  writeFileSync(join(anchorsDir, 'rekor-pub.pem'), rekor.publicPem);
  // Also pin it as the HOST key, standing in for an auditor who trusts this log
  // independently. Without a pin the anchor is unauthenticated (exit 4) — and
  // ATTESTOR_HOME must be set per test, or this would read the developer's real
  // ~/.attestor and make results depend on machine state.
  const pinDir = keysDir(attestorHome());
  mkdirSync(pinDir, { recursive: true });
  writeFileSync(join(pinDir, 'rekor-pub.pem'), rekor.publicPem);
  const payload: AnchorPayload = {
    checkpoint_seq: ckpt.seq,
    provider: 'rekor-v1',
    uuid,
    logIndex,
    integratedTime,
    url: opts.url ?? 'https://rekor.fake',
  };
  return ledger.append({
    type: 'anchor',
    origin: 'system',
    payload: JSON.stringify(payload),
    session_id: ckpt.session_id,
  });
}

/** A ledger with `calls` synthetic tool-call pairs, a checkpoint, and a fake anchor. */
export function buildAnchoredLedger(opts: { calls?: number } = {}): {
  dir: string;
  ledgerDir: string;
  keys: KeyPair;
  rekor: FakeRekor;
  ledgerId: string;
} {
  const dir = tmp();
  const ledgerDir = join(dir, 'ledger');
  // hermetic: never touch the developer's real ~/.attestor
  process.env.ATTESTOR_HOME = join(dir, 'home');
  const keys = generateKey(join(dir, 'home'));
  const ledger = Ledger.open(ledgerDir, keys);
  const rekor = fakeRekor();
  const calls = opts.calls ?? 6;
  for (let i = 0; i < calls; i++) {
    ledger.append({
      type: 'call_request',
      origin: 'proxy',
      call_id: `call-${i}`,
      tool: { server: 'toy', name: i === 3 ? 'payments.transfer' : 'echo' },
      payload: JSON.stringify(
        i === 3 ? { amount: '100.00', to: 'acct-9' } : { text: `hello ${i}` },
      ),
    });
    ledger.append({
      type: 'call_result',
      origin: 'proxy',
      call_id: `call-${i}`,
      payload: JSON.stringify({ status: 'ok', duration_ms: 12 + i }),
    });
  }
  const ckpt = writeCheckpoint(ledger);
  fakeAnchor(ledger, ckpt, rekor);
  const ledgerId = ledger.ledgerId;
  ledger.close();
  return { dir, ledgerDir, keys, rekor, ledgerId };
}
