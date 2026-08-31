// Verify CLI core: CHAIN → MERKLE → SIG → ANCHOR (offline) → ANCHOR-ONLINE.
// Exit codes: 0 verified · 1 tamper · 2 usage/IO error · 3 --online requested
// but Rekor unreachable · 4 chain intact but anchors unauthenticated (only a
// key shipped with the artifact was available, which proves nothing). Never trusts stored `hash` fields — every check runs
// over recomputed hashes from the signed cores.
import { createPublicKey, type KeyObject } from 'node:crypto';
import { existsSync, readFileSync, readdirSync } from 'node:fs';
import { join } from 'node:path';
import { attestorHome, keyIdOf, keysDir } from './keys.ts';
import {
  coreOf,
  genesisPrev,
  hashCore,
  KNOWN_ENTRY_KEYS,
  payloadHash,
  SALT_HEX,
  SYSTEM_TYPES,
  verifyCoreSig,
  type LedgerEntry,
} from './ledger.ts';
import { computeRootHex, type CheckpointPayload } from './checkpoint.ts';
import { inclusionProof, leafHash, verifyInclusion } from './merkle.ts';
import {
  getEntry,
  getLogPublicKey,
  isOfficialSigstoreHost,
  rekorUrl,
  RekorUnavailableError,
  searchByPublicKey,
  UntrustedRekorKeyError,
  verifyCheckpointNote,
  verifyRekorInclusion,
  verifyRekorKeyTrust,
  verifySET,
  type AnchorPayload,
  type RekorEntry,
} from './rekor.ts';

/**
 * Maximum clock skew tolerance between a local entry `ts` and the covering
 * anchor's Rekor `integratedTime` (5 minutes — generous for NTP drift).
 *
 * Policy (deliberately narrow):
 * - The check is one-directional: a covered entry claiming a `ts` LATER than
 *   `integratedTime + skew` is impossible if both clocks are honest (the log
 *   integrated a commitment to an entry that "hadn't happened yet"), so it is
 *   reported as ANCHOR tamper (exit 1). Entries far EARLIER than
 *   `integratedTime` are normal — anchoring always happens after recording.
 * - Within the tolerance nothing is reported, not even a warning: sub-skew
 *   differences are indistinguishable from ordinary clock drift and a warning
 *   would train users to ignore ANCHOR output.
 * - The check runs ONLY for anchors whose SET was independently authenticated
 *   (trusted log key). On an unauthenticated anchor `integratedTime` is
 *   attacker-controlled metadata; acting on it would let a forged anchor
 *   manufacture a tamper verdict, so those anchors stay in the exit-4 lane.
 */
export const MAX_ANCHOR_CLOCK_SKEW_SEC = 300;

export interface TamperFinding {
  seq: number;
  check: 'CHAIN' | 'MERKLE' | 'SIG' | 'ANCHOR' | 'ANCHOR-ONLINE';
  reason: string;
  expected?: string;
  got?: string;
}

export interface CheckLine {
  name: string;
  ok: boolean;
  /** ok, but with a caveat the auditor must see (e.g. anchors not authenticated). */
  warn?: boolean;
  skipped?: boolean;
  lines: string[];
}

export interface VerifyReport {
  result: 'VERIFIED' | 'ANCHORS UNAUTHENTICATED' | 'TAMPER DETECTED' | 'ERROR' | 'REKOR UNREACHABLE';
  exitCode: 0 | 1 | 2 | 3 | 4;
  checks: CheckLine[];
  findings: TamperFinding[];
  blastRadius?: { from: number; to: number };
  anchorLag?: { count: number; fromSeq: number; toSeq: number };
  entryFocus?: {
    seq: number;
    ok: boolean;
    checkpointSeq?: number;
    treeSize?: number;
    proofLength?: number;
    anchored?: boolean;
    logIndex?: number;
    note: string;
  };
  entryCount: number;
  ledgerId?: string;
  auditPacket?: Record<string, unknown>;
}

export interface VerifyOptions {
  online?: boolean;
  entry?: number;
  /** Auditor-trusted Rekor base URL for --online (never the ledger-embedded URL). */
  rekorUrl?: string;
  /** Auditor-supplied trusted Rekor log public key (PEM), highest precedence. */
  rekorPubPem?: string;
  /**
   * The recorder key the auditor expects this ledger to be signed by — a key
   * id, or a PEM. Without it, a ledger is only internally consistent: an
   * attacker can rewrite history under a fresh key of their own, anchor it in
   * the (open) public log, and every check passes, because nothing binds the
   * artifact to an identity the auditor knows independently.
   */
  expectKeyId?: string;
}

interface ResolvedLedger {
  entries: LedgerEntry[];
  /** Positions where a newline-terminated line failed to parse (tamper). */
  unparsableAt: number[];
  /** Bytes of a benign crash-torn unterminated trailing line. */
  tornTailBytes: number;
  anchorFile: (checkpointSeq: number) => string | undefined;
  storedAnchorSeqs: number[];
  /** Rekor log key the auditor independently trusts (host-pinned). */
  trustedRekorPem: string | undefined;
  /** Rekor log key shipped INSIDE the artifact — NOT trusted to authenticate itself. */
  artifactRekorPem: string | undefined;
  /** True if a Rekor log key was pinned alongside this ledger (only written after a successful anchor). */
  hadPinnedLogKey: boolean;
  /** Anchors an exported pack's manifest claims to contain. */
  manifestAnchors: { checkpoint_seq: number; log_index?: number; uuid?: string }[];
}

/** Accepts a live ledger dir, an exported evidence pack, or a ledger.jsonl path. */
function resolveTarget(target: string): ResolvedLedger {
  let ledgerPath: string | undefined;
  let base = target;
  if (target.endsWith('.jsonl')) {
    ledgerPath = target;
    base = join(target, '..');
  } else {
    for (const candidate of ['ledger.jsonl', join('ledger', 'entries.jsonl')]) {
      if (existsSync(join(target, candidate))) {
        ledgerPath = join(target, candidate);
        break;
      }
    }
  }
  if (!ledgerPath || !existsSync(ledgerPath)) {
    throw new Error(`no ledger found at ${target} (expected ledger.jsonl or ledger/entries.jsonl)`);
  }
  const entries: LedgerEntry[] = [];
  const unparsableAt: number[] = [];
  let tornTailBytes = 0;
  const raw = readFileSync(ledgerPath, 'utf8');
  const segments = raw.split('\n');
  const endsWithNewline = raw.endsWith('\n');
  for (let i = 0; i < segments.length; i++) {
    const line = segments[i]!;
    if (line === '') continue;
    try {
      entries.push(JSON.parse(line) as LedgerEntry);
    } catch {
      if (i === segments.length - 1 && !endsWithNewline) {
        // crash-torn unterminated tail — benign; verify the intact prefix
        tornTailBytes = Buffer.byteLength(line);
      } else {
        // a newline-terminated unparsable line is tamper, not an IO error
        unparsableAt.push(entries.length);
      }
    }
  }
  // `<pack>/ledger/entries.jsonl` puts `base` at `<pack>/ledger`, so the pack's
  // own `anchors/` sits one level up — check there too, or an intact pack
  // verified by file path reports its anchors as missing.
  const anchorDirs = [
    join(base, 'anchors'),
    join(base, 'anchors', 'rekor'),
    join(base, '..', 'anchors'),
    join(base, '..', 'anchors', 'rekor'),
  ];
  const anchorFile = (seq: number): string | undefined => {
    for (const d of anchorDirs) {
      const p = join(d, `${seq}.json`);
      if (existsSync(p)) return p;
    }
    return undefined;
  };
  const storedAnchorSeqs: number[] = [];
  for (const d of anchorDirs) {
    if (!existsSync(d)) continue;
    for (const f of readdirSync(d)) {
      const m = /^(\d+)\.json$/.exec(f);
      if (m) storedAnchorSeqs.push(Number(m[1]));
    }
  }
  // The auditor's own pinned Rekor key is trusted. The copy shipped inside the
  // artifact (pack/ledger) is NOT — an attacker who forges anchors can ship a
  // matching key. Keeping them separate is the whole point.
  const hostPin = join(keysDir(attestorHome()), 'rekor-pub.pem');
  const trustedRekorPem = existsSync(hostPin) ? readFileSync(hostPin, 'utf8') : undefined;
  let artifactRekorPem: string | undefined;
  let hadPinnedLogKey = false;
  for (const p of [
    join(base, 'anchors', 'rekor-pub.pem'),
    join(base, 'keys', 'rekor-pub.pem'),
    join(base, '..', 'anchors', 'rekor-pub.pem'),
    join(base, '..', 'keys', 'rekor-pub.pem'),
  ]) {
    if (existsSync(p)) {
      artifactRekorPem = readFileSync(p, 'utf8');
      hadPinnedLogKey = true;
      break;
    }
  }
  // The manifest is part of the exhibit; verification should use it rather than
  // let it sit there as decoration an auditor might read and believe.
  let manifestAnchors: ResolvedLedger['manifestAnchors'] = [];
  const manifestPath = existsSync(join(base, 'manifest.json'))
    ? join(base, 'manifest.json')
    : join(base, '..', 'manifest.json');
  if (existsSync(manifestPath)) {
    try {
      const m = JSON.parse(readFileSync(manifestPath, 'utf8')) as {
        anchors?: { checkpoint_seq: number; log_index?: number; uuid?: string }[];
      };
      manifestAnchors = m.anchors ?? [];
    } catch {
      /* unparsable manifest is not itself evidence of tamper */
    }
  }
  return {
    entries,
    unparsableAt,
    tornTailBytes,
    anchorFile,
    storedAnchorSeqs: [...new Set(storedAnchorSeqs)].sort((a, b) => a - b),
    trustedRekorPem,
    artifactRekorPem,
    hadPinnedLogKey,
    manifestAnchors,
  };
}

export async function verifyLedger(target: string, opts: VerifyOptions = {}): Promise<VerifyReport> {
  let resolved: ResolvedLedger;
  try {
    resolved = resolveTarget(target);
  } catch (err) {
    return {
      result: 'ERROR',
      exitCode: 2,
      checks: [],
      findings: [],
      entryCount: 0,
      auditPacket: { error: (err as Error).message },
    };
  }
  const { entries, anchorFile, storedAnchorSeqs, unparsableAt, tornTailBytes } = resolved;
  const findings: TamperFinding[] = [];
  const checks: CheckLine[] = [];
  const n = entries.length;
  for (const at of unparsableAt) {
    findings.push({
      seq: Math.min(at, Math.max(n - 1, 0)),
      check: 'CHAIN',
      reason: `a newline-terminated ledger line near position ${at} is not valid JSON (corrupted or tampered)`,
    });
  }

  if (n === 0) {
    return {
      result: 'ERROR',
      exitCode: 2,
      checks: [],
      findings: [],
      entryCount: 0,
      auditPacket: { error: 'empty ledger' },
    };
  }

  // ---- CHAIN ----------------------------------------------------------
  const genesis = entries[0]!;
  let ledgerId: string | undefined;
  let genesisPubPem: string | undefined;
  if (genesis.type !== 'genesis' || genesis.payload === undefined) {
    findings.push({ seq: 0, check: 'CHAIN', reason: 'first entry is not a genesis entry with payload' });
  } else {
    try {
      const gp = JSON.parse(genesis.payload) as { ledger_id: string; public_key_pem: string };
      ledgerId = gp.ledger_id;
      genesisPubPem = gp.public_key_pem;
    } catch {
      findings.push({ seq: 0, check: 'CHAIN', reason: 'genesis payload unparsable' });
    }
  }

  const recomputed: string[] = [];
  let redactedCount = 0;
  let prev = ledgerId !== undefined ? genesisPrev(ledgerId) : undefined;
  for (let i = 0; i < n; i++) {
    const e = entries[i]!;
    const core = coreOf(e as unknown as Record<string, unknown>);
    const h = hashCore(core);
    recomputed.push(h);
    if (e.seq !== i) {
      findings.push({
        seq: i,
        check: 'CHAIN',
        reason: `seq gap or reorder: expected seq ${i}, found ${e.seq} (deleted or swapped lines)`,
        expected: String(i),
        got: String(e.seq),
      });
      continue;
    }
    if (prev !== undefined && e.prev !== prev) {
      findings.push({
        seq: i,
        check: 'CHAIN',
        reason: `prev-hash link broken at entry ${i}`,
        expected: prev,
        got: e.prev,
      });
    }
    if (e.hash !== h) {
      findings.push({
        seq: i,
        check: 'CHAIN',
        reason: `entry ${i} core does not match its recorded hash (core field mutated)`,
        expected: h,
        got: e.hash,
      });
    }
    // no unsigned top-level key may ride along unhashed
    for (const k of Object.keys(e)) {
      if (!KNOWN_ENTRY_KEYS.has(k)) {
        findings.push({
          seq: i,
          check: 'CHAIN',
          reason: `entry ${i} carries unknown unsigned field "${k}" (not covered by the signature)`,
        });
      }
    }
    if (e.payload !== undefined) {
      // A malformed salt makes the salt‖payload split ambiguous, which would
      // let an attacker move payload bytes into the salt and blank the payload
      // while the signed commitment still matched.
      if (e.salt === undefined || !SALT_HEX.test(e.salt)) {
        findings.push({
          seq: i,
          check: 'CHAIN',
          reason: `entry ${i} has a malformed salt (expected 32 lowercase hex characters) — payload boundary is not pinned`,
          expected: '32 hex chars',
          got: e.salt === undefined ? '(absent)' : `${e.salt.length} chars`,
        });
      } else if (payloadHash(e.salt, e.payload) !== e.payload_hash) {
        findings.push({
          seq: i,
          check: 'CHAIN',
          reason: `entry ${i} payload does not match its signed commitment (payload mutated)`,
          expected: e.payload_hash,
          got: payloadHash(e.salt, e.payload),
        });
      }
    } else if (e.payload === '' && SYSTEM_TYPES.has(e.type)) {
      findings.push({
        seq: i,
        check: 'CHAIN',
        reason: `entry ${i} is a ${e.type} entry whose payload was blanked (system payloads are load-bearing)`,
      });
    } else if (SYSTEM_TYPES.has(e.type)) {
      // genesis/checkpoint/anchor/key_rotation/gap payloads are load-bearing —
      // a missing one is tamper, not a legitimate redaction.
      findings.push({
        seq: i,
        check: 'CHAIN',
        reason: `entry ${i} is a ${e.type} entry with its payload stripped (system payloads are not redactable)`,
      });
    } else if (e.type !== 'session_end') {
      redactedCount++;
    }
    prev = h;
  }
  const chainOk = findings.filter((f) => f.check === 'CHAIN').length === 0;
  checks.push({
    name: 'CHAIN',
    ok: chainOk,
    lines: chainOk
      ? [
          `${n.toLocaleString('en-US')} entries, hash chain intact` +
            (redactedCount > 0 ? ` (${redactedCount} redacted payload${redactedCount === 1 ? '' : 's'})` : '') +
            (tornTailBytes > 0 ? ` — ${tornTailBytes}-byte crash-torn partial tail ignored` : ''),
        ]
      : findingLines(findings, 'CHAIN'),
  });

  // ---- MERKLE ---------------------------------------------------------
  const checkpoints = entries.filter((e) => e.type === 'checkpoint');
  let merkleFailures = 0;
  const checkpointPayloads = new Map<number, CheckpointPayload>();
  for (const c of checkpoints) {
    if (c.payload === undefined) {
      findings.push({ seq: c.seq, check: 'MERKLE', reason: `checkpoint ${c.seq} payload missing (checkpoints are never redactable)` });
      merkleFailures++;
      continue;
    }
    let payload: CheckpointPayload;
    try {
      payload = JSON.parse(c.payload) as CheckpointPayload;
    } catch {
      findings.push({ seq: c.seq, check: 'MERKLE', reason: `checkpoint ${c.seq} payload unparsable` });
      merkleFailures++;
      continue;
    }
    checkpointPayloads.set(c.seq, payload);
    if (payload.tree_size > n) {
      findings.push({
        seq: c.seq,
        check: 'MERKLE',
        reason: `checkpoint ${c.seq} covers ${payload.tree_size} entries but ledger has only ${n} (post-anchor truncation)`,
        expected: `>= ${payload.tree_size} entries`,
        got: `${n} entries`,
      });
      merkleFailures++;
      continue;
    }
    const root = computeRootHex(recomputed, payload.tree_size);
    if (root !== payload.root) {
      findings.push({
        seq: c.seq,
        check: 'MERKLE',
        reason: `checkpoint ${c.seq} root mismatch over entries [0, ${payload.tree_size})`,
        expected: payload.root,
        got: root,
      });
      merkleFailures++;
    }
  }
  checks.push({
    name: 'MERKLE',
    ok: merkleFailures === 0,
    lines:
      merkleFailures === 0
        ? [`${checkpoints.length} checkpoint${checkpoints.length === 1 ? '' : 's'}, all roots reproduce`]
        : findingLines(findings, 'MERKLE'),
  });

  // ---- SIG (walks the key-rotation chain from genesis) ------------------
  let sigFailures = 0;
  let activePub: KeyObject | undefined;
  let activePem = genesisPubPem;
  const pemAtSeq: string[] = [];
  const validKeyIds = new Set<string>(); // every recorder key in the rotation chain
  try {
    activePub = genesisPubPem !== undefined ? createPublicKey(genesisPubPem) : undefined;
    if (activePub) validKeyIds.add(keyIdOf(activePub));
  } catch {
    findings.push({ seq: 0, check: 'SIG', reason: 'genesis public key unparsable' });
    sigFailures++;
  }
  for (let i = 0; i < n && activePub !== undefined; i++) {
    const e = entries[i]!;
    pemAtSeq.push(activePem!);
    const core = coreOf(e as unknown as Record<string, unknown>);
    const expectedKeyId = keyIdOf(activePub);
    if (e.key_id !== expectedKeyId) {
      findings.push({
        seq: i,
        check: 'SIG',
        reason: `entry ${i} signed with unexpected key (re-signed with a foreign key?)`,
        expected: expectedKeyId,
        got: e.key_id,
      });
      sigFailures++;
    } else if (!verifyCoreSig(core, e.sig, activePub)) {
      findings.push({ seq: i, check: 'SIG', reason: `entry ${i} signature invalid` });
      sigFailures++;
    }
    if (e.type === 'key_rotation' && e.payload !== undefined) {
      try {
        activePub = createPublicKey(e.payload);
        activePem = e.payload;
        validKeyIds.add(keyIdOf(activePub));
      } catch {
        findings.push({ seq: i, check: 'SIG', reason: `key_rotation ${i} carries unparsable public key` });
        sigFailures++;
      }
    }
  }
  // Bind the ledger to a recorder identity the auditor knows out of band.
  if (opts.expectKeyId !== undefined && genesisPubPem !== undefined) {
    let expected = opts.expectKeyId.trim();
    if (expected.includes('BEGIN PUBLIC KEY')) {
      try {
        expected = keyIdOf(createPublicKey(expected));
      } catch {
        findings.push({ seq: 0, check: 'SIG', reason: '--expect-key is not a readable public key' });
        sigFailures++;
      }
    }
    let actual: string | undefined;
    try {
      actual = keyIdOf(createPublicKey(genesisPubPem));
    } catch {
      /* already reported */
    }
    if (actual !== undefined && actual !== expected) {
      findings.push({
        seq: 0,
        check: 'SIG',
        reason: `this ledger was recorded by a different key than expected — it is internally consistent, but it is not the recorder you asked for`,
        expected,
        got: actual,
      });
      sigFailures++;
    }
  }
  checks.push({
    name: 'SIG',
    ok: sigFailures === 0 && activePub !== undefined,
    lines:
      sigFailures === 0 && activePub !== undefined
        ? [
            `${n}/${n} entry signatures valid (key ${entries[n - 1]!.key_id})` +
              (opts.expectKeyId !== undefined ? ', matching the expected recorder key' : ''),
          ]
        : findingLines(findings, 'SIG'),
  });

  // ---- ANCHOR (offline) -------------------------------------------------
  // SET/inclusion/note authenticity requires a TRUSTED Rekor log key (auditor-
  // supplied or host-pinned). The key shipped inside the artifact cannot
  // authenticate the artifact, so it is never used for that.
  const trustedRekorPem = opts.rekorPubPem ?? resolved.trustedRekorPem;
  const anchorEntries = entries.filter((e) => e.type === 'anchor');
  const anchors: { payload: AnchorPayload; stored: RekorEntry & { uuid?: string } }[] = [];
  let anchorFailures = 0;
  let setChecked = 0;
  let unauthenticated = 0; // anchors whose digest matched but SET was not trust-verified
  for (const a of anchorEntries) {
    if (a.payload === undefined) {
      findings.push({ seq: a.seq, check: 'ANCHOR', reason: `anchor ${a.seq} payload missing` });
      anchorFailures++;
      continue;
    }
    let payload: AnchorPayload;
    try {
      payload = JSON.parse(a.payload) as AnchorPayload;
    } catch {
      findings.push({ seq: a.seq, check: 'ANCHOR', reason: `anchor ${a.seq} payload unparsable` });
      anchorFailures++;
      continue;
    }
    const file = anchorFile(payload.checkpoint_seq);
    if (file === undefined) {
      findings.push({
        seq: a.seq,
        check: 'ANCHOR',
        reason: `anchor ${a.seq}: stored Rekor entry anchors/${payload.checkpoint_seq}.json missing`,
      });
      anchorFailures++;
      continue;
    }
    const stored = JSON.parse(readFileSync(file, 'utf8')) as RekorEntry & { uuid?: string };
    anchors.push({ payload, stored });
    const ckptEntry = entries[payload.checkpoint_seq];
    if (!ckptEntry || ckptEntry.type !== 'checkpoint') {
      findings.push({
        seq: a.seq,
        check: 'ANCHOR',
        reason: `anchor ${a.seq} references seq ${payload.checkpoint_seq}, which is not a checkpoint`,
      });
      anchorFailures++;
      continue;
    }
    // The anchored artifact is the checkpoint's JCS core bytes — recompute.
    const artifactHash = recomputed[payload.checkpoint_seq]!;
    let decoded: { kind?: string; spec?: { data?: { hash?: { value?: string } }; signature?: { publicKey?: { content?: string } } } };
    try {
      decoded = JSON.parse(Buffer.from(stored.body, 'base64').toString('utf8'));
    } catch {
      findings.push({ seq: a.seq, check: 'ANCHOR', reason: `anchor ${a.seq}: stored Rekor body undecodable` });
      anchorFailures++;
      continue;
    }
    const anchoredHash = decoded.spec?.data?.hash?.value;
    if (anchoredHash !== artifactHash) {
      findings.push({
        seq: a.seq,
        check: 'ANCHOR',
        reason: `checkpoint ${payload.checkpoint_seq} does not match what was anchored in Rekor (logIndex ${payload.logIndex})`,
        expected: anchoredHash,
        got: artifactHash,
      });
      anchorFailures++;
      continue;
    }
    // The Rekor artifact must have been signed by one of the ledger's own
    // recorder keys (any key in the rotation chain — an anchor may be written
    // by a rotated key when a queued checkpoint drains after rotation).
    const anchoredPubPem = decoded.spec?.signature?.publicKey?.content
      ? Buffer.from(decoded.spec.signature.publicKey.content, 'base64').toString('utf8')
      : undefined;
    if (anchoredPubPem !== undefined && validKeyIds.size > 0) {
      try {
        if (!validKeyIds.has(keyIdOf(createPublicKey(anchoredPubPem)))) {
          findings.push({
            seq: a.seq,
            check: 'ANCHOR',
            reason: `anchor ${a.seq} was signed by a key that is not in this ledger's recorder-key rotation chain`,
          });
          anchorFailures++;
          continue;
        }
      } catch {
        /* unparsable pem already reported elsewhere */
      }
    }
    // Two distinct questions, deliberately separated:
    //   AUTHENTIC — signed by the real Rekor log? Needs a key the auditor
    //     trusts independently (flag, or host pin). Only this proves anything.
    //   CONSISTENT — does the anchor at least verify under the key shipped
    //     alongside it? A mismatch is tamper regardless of trust; a match with
    //     no trusted key proves nothing and is reported as unauthenticated.
    const checkKey = trustedRekorPem ?? resolved.artifactRekorPem;
    // Allowlist at the point of use: when this anchor CLAIMS to come from the
    // official public Sigstore log, whatever key is about to authenticate it —
    // an existing host/home pin (possibly a legacy TOFU pin taken before this
    // gate existed) or the artifact-shipped key — must itself be the official
    // log key. A rogue pin authenticating an "official log" anchor is forged
    // evidence, not an unauthenticated anchor. Custom-log anchors are not
    // gated: the auditor chose and pinned that log themselves.
    if (checkKey !== undefined && payload.url !== undefined && isOfficialSigstoreHost(payload.url)) {
      try {
        verifyRekorKeyTrust(payload.url, checkKey);
      } catch (err) {
        if (!(err instanceof UntrustedRekorKeyError)) throw err;
        findings.push({
          seq: a.seq,
          check: 'ANCHOR',
          reason: `anchor ${a.seq} claims the official Sigstore log but the key available to authenticate it is not Sigstore's: ${err.message}`,
        });
        anchorFailures++;
        continue;
      }
    }
    if (checkKey !== undefined) {
      const trusted = trustedRekorPem !== undefined;
      const under = trusted ? 'the trusted log key' : 'the log key shipped with this artifact';
      if (!verifySET(stored, checkKey)) {
        findings.push({
          seq: a.seq,
          check: 'ANCHOR',
          reason: `anchor ${a.seq}: Rekor SET signature invalid under ${under} (stored anchor forged?)`,
        });
        anchorFailures++;
        continue;
      }
      const proof = stored.verification?.inclusionProof;
      if (!proof) {
        findings.push({ seq: a.seq, check: 'ANCHOR', reason: `anchor ${a.seq}: no inclusion proof present (stripped?)` });
        anchorFailures++;
        continue;
      }
      if (!verifyRekorInclusion(stored)) {
        findings.push({ seq: a.seq, check: 'ANCHOR', reason: `anchor ${a.seq}: stored inclusion proof invalid` });
        anchorFailures++;
        continue;
      }
      if (!verifyCheckpointNote(proof, checkKey)) {
        findings.push({ seq: a.seq, check: 'ANCHOR', reason: `anchor ${a.seq}: Rekor checkpoint note signature invalid under ${under}` });
        anchorFailures++;
        continue;
      }
      if (trusted) {
        setChecked++;
        // integratedTime cross-check — see MAX_ANCHOR_CLOCK_SKEW_SEC for the
        // policy. Runs only here, after the SET, inclusion proof and note all
        // verified under an independently trusted log key: an unauthenticated
        // integratedTime is attacker-controlled and must never mint a tamper
        // verdict (unauthenticated anchors keep their exit-4 semantics).
        if (typeof stored.integratedTime === 'number' && stored.integratedTime > 0) {
          // The covered prefix is defined by the REFERENCED CHECKPOINT's
          // tree_size (AnchorPayload itself carries no tree_size). Resolve it
          // and refuse to guess: an unresolvable size would otherwise make
          // slice() silently scan the whole ledger, post-checkpoint entries
          // included.
          const treeSize = checkpointPayloads.get(payload.checkpoint_seq)?.tree_size;
          if (typeof treeSize !== 'number' || !Number.isInteger(treeSize) || treeSize < 0 || treeSize > n) {
            findings.push({
              seq: a.seq,
              check: 'ANCHOR',
              reason: `anchor ${a.seq}: checkpoint ${payload.checkpoint_seq} has no valid integer tree_size, so the prefix covered by integratedTime cannot be determined`,
            });
            anchorFailures++;
          } else {
            const anchorTimeSec = stored.integratedTime;
            for (const e of entries.slice(0, treeSize)) {
              const entryTimeSec = Math.floor(new Date(e.ts).getTime() / 1000);
              if (entryTimeSec > anchorTimeSec + MAX_ANCHOR_CLOCK_SKEW_SEC) {
                findings.push({
                  seq: e.seq,
                  check: 'ANCHOR',
                  reason: `entry ${e.seq} timestamp (${e.ts}) is later than covering Rekor anchor ${a.seq} integratedTime (${new Date(anchorTimeSec * 1000).toISOString()}) by more than ${MAX_ANCHOR_CLOCK_SKEW_SEC}s tolerance`,
                });
                anchorFailures++;
                break;
              }
            }
          }
        }
      } else unauthenticated++;
    } else {
      // digest matched our recomputed checkpoint, but nothing authenticates it
      unauthenticated++;
    }
  }
  // Stored-anchor sweep — driven by the FILES on disk, never by what the
  // ledger chooses to declare. Deleting the `anchor` entry (or truncating past
  // it) must not downgrade a rewritten ledger to "no anchors recorded": every
  // anchor file is an independent commitment that the checkpoint at that seq
  // hashed to a specific value.
  const declaredCheckpointSeqs = new Set(anchors.map((a) => a.payload.checkpoint_seq));
  for (const seq of storedAnchorSeqs) {
    if (declaredCheckpointSeqs.has(seq)) continue; // already fully checked above
    const file = anchorFile(seq);
    if (file === undefined) continue;
    let storedDigest: string | undefined;
    let stored: RekorEntry | undefined;
    try {
      stored = JSON.parse(readFileSync(file, 'utf8')) as RekorEntry;
      storedDigest = (JSON.parse(Buffer.from(stored.body, 'base64').toString('utf8')) as {
        spec?: { data?: { hash?: { value?: string } } };
      }).spec?.data?.hash?.value;
    } catch {
      /* undecodable — reported below */
    }
    const ckpt = entries[seq];
    if (ckpt === undefined || ckpt.type !== 'checkpoint') {
      findings.push({
        seq: Math.min(seq, n - 1),
        check: 'ANCHOR',
        reason: `a Rekor anchor is stored for checkpoint seq ${seq}, but the ledger ${seq >= n ? `ends at seq ${n - 1}` : 'has no checkpoint there'} — history was truncated past an anchor`,
      });
      anchorFailures++;
      continue;
    }
    if (storedDigest === undefined) {
      findings.push({ seq, check: 'ANCHOR', reason: `stored Rekor anchor for checkpoint ${seq} is undecodable` });
      anchorFailures++;
      continue;
    }
    if (storedDigest !== recomputed[seq]) {
      findings.push({
        seq,
        check: 'ANCHOR',
        reason: `checkpoint ${seq} does not match the anchor stored for it (the ledger's own \`anchor\` entry is missing — deleted to hide a rewrite?)`,
        expected: storedDigest,
        got: recomputed[seq],
      });
      anchorFailures++;
      continue;
    }
    // digest matches but the chain no longer records the anchoring event
    findings.push({
      seq,
      check: 'ANCHOR',
      reason: `checkpoint ${seq} has a stored Rekor anchor but no \`anchor\` entry in the chain (entry deleted)`,
    });
    anchorFailures++;
  }
  // A ledger that was never anchored and one whose anchors were deleted look
  // identical in the chain — so check the artifacts anchoring leaves behind.
  // Deleting anchors must not be cheaper than forging them.
  if (anchorEntries.length === 0) {
    if (resolved.hadPinnedLogKey) {
      findings.push({
        seq: n - 1,
        check: 'ANCHOR',
        reason:
          'a Rekor log key is pinned alongside this ledger — which only happens after a successful anchor — but the ledger contains no anchor entries (anchors deleted?)',
      });
      anchorFailures++;
    }
    for (const m of resolved.manifestAnchors) {
      findings.push({
        seq: Math.min(m.checkpoint_seq, Math.max(n - 1, 0)),
        check: 'ANCHOR',
        reason: `the pack manifest declares an anchor for checkpoint ${m.checkpoint_seq}${m.log_index !== undefined ? ` (logIndex ${m.log_index})` : ''}, but the ledger contains no anchor entries`,
      });
      anchorFailures++;
    }
  } else {
    // manifest and ledger must agree on which checkpoints are anchored
    const present = new Set(anchors.map((a) => a.payload.checkpoint_seq));
    for (const m of resolved.manifestAnchors) {
      if (!present.has(m.checkpoint_seq)) {
        findings.push({
          seq: Math.min(m.checkpoint_seq, Math.max(n - 1, 0)),
          check: 'ANCHOR',
          reason: `the pack manifest declares an anchor for checkpoint ${m.checkpoint_seq} that is missing from the ledger`,
        });
        anchorFailures++;
      }
    }
  }
  const anchorOk = anchorFailures === 0;
  const anchorWarn = anchorOk && unauthenticated > 0;
  const anchorSummary =
    anchorEntries.length === 0
      ? ['no anchors recorded — ledger is chain-protected only, not externally anchored']
      : [
          `${anchorEntries.length - anchorFailures}/${anchorEntries.length} anchor${anchorEntries.length === 1 ? '' : 's'} recorded` +
            (anchors.length > 0 ? ` (latest logIndex ${anchors[anchors.length - 1]!.payload.logIndex})` : '') +
            (setChecked > 0 ? `, SET+inclusion authenticated for ${setChecked} against the trusted Rekor key` : ''),
          ...(unauthenticated > 0
            ? [
                `${unauthenticated} anchor${unauthenticated === 1 ? '' : 's'} matched the local checkpoint digest but are NOT authenticated — no trusted Rekor key available. Run with --online (or pin the log key) to confirm against the public log.`,
              ]
            : []),
        ];
  checks.push({
    name: 'ANCHOR',
    ok: anchorOk,
    warn: anchorWarn,
    lines: anchorOk ? anchorSummary : findingLines(findings, 'ANCHOR'),
  });

  // anchor lag: entries not covered by any verified anchor's checkpoint
  const anchoredSizes = anchors
    .filter((a) => checkpointPayloads.has(a.payload.checkpoint_seq))
    .map((a) => checkpointPayloads.get(a.payload.checkpoint_seq)!.tree_size);
  const maxAnchored = anchoredSizes.length > 0 ? Math.max(...anchoredSizes) : 0;
  const anchorLag =
    n > maxAnchored && anchorEntries.length > 0
      ? { count: n - maxAnchored, fromSeq: maxAnchored, toSeq: n - 1 }
      : undefined;

  // ---- ANCHOR-ONLINE ----------------------------------------------------
  let rekorUnreachable = false;
  // set when --online authenticated every anchor against the LIVE log key,
  // which supersedes the offline "unauthenticated" state
  let onlineAuthenticatedAll = false;
  if (opts.online) {
    let onlineFailures = 0;
    let checked = 0;
    let discovered = 0;
    // false when the log's key index could not be swept, so "no hidden anchors"
    // was never actually established
    let discoveryWorked = true;
    // Trust anchor for --online: the auditor's URL (flag/env/default) — NEVER
    // the URL embedded in the ledger, which an attacker controls.
    const trustedUrl = opts.rekorUrl ?? rekorUrl();
    let liveLogKey: string | undefined;
    try {
      liveLogKey = await getLogPublicKey(trustedUrl);
      // Allowlist at the online point of use: a key fetched live from the
      // official host must be the official log key. A substituted key here
      // (MITM, poisoned resolver) would otherwise authenticate whatever the
      // attacker anchored. Throws UntrustedRekorKeyError → handled below as a
      // finding, never swallowed.
      verifyRekorKeyTrust(trustedUrl, liveLogKey);
      for (const { payload, stored } of anchors) {
        let fresh: RekorEntry;
        try {
          fresh = await getEntry(trustedUrl, payload.uuid);
        } catch (err) {
          if (err instanceof RekorUnavailableError) throw err; // network — handled below
          // "the anchor this ledger claims is not in the public log" is the
          // strongest tamper signal there is; it must not surface as an IO error
          // that throws away every finding collected so far.
          findings.push({
            seq: payload.checkpoint_seq,
            check: 'ANCHOR-ONLINE',
            reason: `the anchor this ledger claims (uuid ${payload.uuid.slice(0, 16)}…, logIndex ${payload.logIndex}) is not in the public log: ${(err as Error).message}`,
          });
          onlineFailures++;
          continue;
        }
        checked++;
        // authenticate the fresh entry against the LIVE log key, then compare
        // its committed digest to our recomputed checkpoint.
        if (!verifySET(fresh, liveLogKey)) {
          findings.push({ seq: payload.checkpoint_seq, check: 'ANCHOR-ONLINE', reason: `logIndex ${payload.logIndex}: fresh Rekor SET invalid under the live log key` });
          onlineFailures++;
          continue;
        }
        if (fresh.verification?.inclusionProof && !verifyRekorInclusion(fresh)) {
          findings.push({ seq: payload.checkpoint_seq, check: 'ANCHOR-ONLINE', reason: `fresh inclusion proof invalid for logIndex ${payload.logIndex}` });
          onlineFailures++;
          continue;
        }
        const freshBodyHash = (JSON.parse(Buffer.from(fresh.body, 'base64').toString('utf8')) as {
          spec?: { data?: { hash?: { value?: string } } };
        }).spec?.data?.hash?.value;
        if (freshBodyHash !== recomputed[payload.checkpoint_seq]) {
          findings.push({
            seq: payload.checkpoint_seq,
            check: 'ANCHOR-ONLINE',
            reason: `local checkpoint ${payload.checkpoint_seq} does not match the public log (full-rewrite or forged anchor detected)`,
            expected: freshBodyHash,
            got: recomputed[payload.checkpoint_seq],
          });
          onlineFailures++;
        }
      }
      // Discover-by-pubkey: anchors that exist in the PUBLIC log under our
      // recorder key(s) but that our local ledger does not account for →
      // evidence that history was longer (deleted anchors / rollback).
      const heldUuids = new Set(anchors.map((a) => a.payload.uuid));
      const localRoots = new Set([...checkpointPayloads.values()].map((p) => p.root));
      for (const pem of new Set(pemAtSeq)) {
        let uuids: string[] = [];
        try {
          const found = await searchByPublicKey(trustedUrl, pem);
          if (found.length === 0) discoveryWorked = false; // may mean "none" or "index disabled"
          uuids = found;
        } catch (err) {
          if (err instanceof RekorUnavailableError) {
            discoveryWorked = false;
            continue;
          }
          throw err;
        }
        for (const uuid of uuids) {
          if (heldUuids.has(uuid)) continue;
          const extra = await getEntry(trustedUrl, uuid).catch(() => undefined);
          if (!extra || !verifySET(extra, liveLogKey)) continue;
          discovered++;
          const digest = (JSON.parse(Buffer.from(extra.body, 'base64').toString('utf8')) as {
            spec?: { data?: { hash?: { value?: string } } };
          }).spec?.data?.hash?.value;
          // If the public log holds an anchor whose committed checkpoint root
          // our ledger cannot reproduce, history was altered or truncated.
          if (digest !== undefined && !recomputed.includes(digest) && !localRoots.has(digest)) {
            findings.push({
              seq: n - 1,
              check: 'ANCHOR-ONLINE',
              reason: `public Rekor log holds an anchor (logIndex ${extra.logIndex}) under this recorder key that the local ledger does not account for — history was truncated or rewritten`,
            });
            onlineFailures++;
          }
        }
      }
    } catch (err) {
      if (err instanceof RekorUnavailableError) rekorUnreachable = true;
      else if (err instanceof UntrustedRekorKeyError) {
        // The live key failed the trust-root allowlist: nothing it signed can
        // be believed, so the whole online phase fails rather than proceeding
        // to "authenticate" anchors under an untrusted key.
        findings.push({ seq: n - 1, check: 'ANCHOR-ONLINE', reason: err.message });
        onlineFailures++;
        liveLogKey = undefined;
      } else throw err;
    }
    onlineAuthenticatedAll =
      !rekorUnreachable && onlineFailures === 0 && checked === anchors.length && liveLogKey !== undefined;
    checks.push({
      name: 'ANCHOR-ONLINE',
      ok: !rekorUnreachable && onlineFailures === 0,
      skipped: rekorUnreachable,
      lines: rekorUnreachable
        ? ['Rekor unreachable — cannot compare against the public log']
        : onlineFailures === 0
          ? [
              `${checked}/${anchors.length} anchor${anchors.length === 1 ? '' : 's'} authenticated against the live log` +
                (discovered > 0 ? `; ${discovered} extra log entr${discovered === 1 ? 'y' : 'ies'} discovered and reconciled` : ''),
              // Whether the log could be swept for anchors this ledger does NOT
              // mention is the difference between "no hidden history" and "did
              // not look" — the report must not render both the same way.
              ...(discoveryWorked
                ? []
                : [
                    'note: the log could not be searched by recorder key (index unavailable), so anchors this ledger does not mention were NOT ruled out',
                  ]),
            ]
          : findingLines(findings, 'ANCHOR-ONLINE'),
    });
  }

  // ---- entry focus (--entry SEQ): inclusion path to nearest checkpoint ----
  let entryFocus: VerifyReport['entryFocus'];
  if (opts.entry !== undefined) {
    const seq = opts.entry;
    if (!Number.isInteger(seq)) {
      entryFocus = { seq, ok: false, note: `--entry must be an integer, got "${String(seq)}"` };
    } else if (seq < 0 || seq >= n) {
      entryFocus = { seq, ok: false, note: `entry ${seq} out of range [0, ${n})` };
    } else {
      // nearest checkpoint whose tree covers this entry, preferring an anchored one
      const anchoredCkptSeqs = new Set(anchors.map((a) => a.payload.checkpoint_seq));
      const covering = checkpoints
        .map((c) => ({ c, p: checkpointPayloads.get(c.seq) }))
        .filter((x) => x.p !== undefined && x.p.tree_size > seq && x.p.tree_size <= n)
        .sort((a, b) => a.p!.tree_size - b.p!.tree_size);
      const anchoredPick = covering.find((x) => anchoredCkptSeqs.has(x.c.seq));
      const pick = anchoredPick ?? covering[0];
      if (!pick) {
        entryFocus = {
          seq,
          ok: findings.every((f) => f.seq !== seq),
          note: `entry ${seq} hash+signature checked; no checkpoint covers it yet (ANCHOR LAG region)`,
        };
      } else {
        const size = pick.p!.tree_size;
        const leaves = recomputed.slice(0, size).map((h) => Buffer.from(h, 'hex'));
        const proof = inclusionProof(seq, leaves);
        const ok = verifyInclusion(seq, size, leafHash(leaves[seq]!), proof, Buffer.from(pick.p!.root, 'hex'));
        const anchor = anchors.find((a) => a.payload.checkpoint_seq === pick.c.seq);
        entryFocus = {
          seq,
          ok: ok && findings.every((f) => f.seq !== seq),
          checkpointSeq: pick.c.seq,
          treeSize: size,
          proofLength: proof.length,
          anchored: anchor !== undefined,
          ...(anchor !== undefined && { logIndex: anchor.payload.logIndex }),
          note: ok
            ? `entry ${seq} included in checkpoint ${pick.c.seq} (tree_size ${size}, ${proof.length}-hash proof)` +
              (anchor ? `, anchored at Rekor logIndex ${anchor.payload.logIndex}` : ', not yet anchored')
            : `entry ${seq} FAILS inclusion in checkpoint ${pick.c.seq}`,
        };
      }
    }
  }

  // ---- verdict ----------------------------------------------------------
  const tamper = findings.length > 0;
  const firstSeq = tamper ? Math.min(...findings.map((f) => f.seq)) : undefined;
  // Anchors that only verify against a key shipped with the artifact prove
  // nothing — an attacker who forges anchors ships a matching key. That must
  // not exit 0: the exit code is the machine-readable verdict, and a CI job or
  // `&&` chain would read 0 as "checked and genuine". Exit 4 says "the chain is
  // intact, but the external claim is unconfirmed", which is the honest verdict
  // and fails safe for anything that only tests for success.
  const unauthenticatedAnchors =
    !tamper && !rekorUnreachable && unauthenticated > 0 && !onlineAuthenticatedAll;
  const report: VerifyReport = {
    result: tamper
      ? 'TAMPER DETECTED'
      : rekorUnreachable
        ? 'REKOR UNREACHABLE'
        : unauthenticatedAnchors
          ? 'ANCHORS UNAUTHENTICATED'
          : 'VERIFIED',
    exitCode: tamper ? 1 : rekorUnreachable ? 3 : unauthenticatedAnchors ? 4 : 0,
    checks,
    findings,
    entryCount: n,
    ...(ledgerId !== undefined && { ledgerId }),
    ...(tamper && {
      blastRadius: { from: firstSeq!, to: n - 1 },
    }),
    ...(anchorLag !== undefined && { anchorLag }),
    ...(entryFocus !== undefined && { entryFocus }),
  };
  if (tamper) {
    report.auditPacket = {
      attestor_audit_packet: 1,
      generated_at: new Date().toISOString(),
      ledger_id: ledgerId,
      result: 'TAMPER DETECTED',
      findings: findings.map((f) => ({
        seq: f.seq,
        check: f.check,
        reason: f.reason,
        ...(f.expected !== undefined && { expected: f.expected }),
        ...(f.got !== undefined && { got: f.got }),
      })),
      blast_radius: { from_seq: firstSeq, to_seq: n - 1 },
      anchors: anchors.map((a) => ({
        checkpoint_seq: a.payload.checkpoint_seq,
        log_index: a.payload.logIndex,
        rekor_url: a.payload.url,
        search_url: `https://search.sigstore.dev/?logIndex=${a.payload.logIndex}`,
      })),
    };
  }
  return report;
}

function findingLines(findings: TamperFinding[], check: string): string[] {
  return findings
    .filter((f) => f.check === check)
    .slice(0, 5)
    .flatMap((f) => {
      const lines = [f.reason];
      if (f.expected !== undefined && f.got !== undefined) {
        lines.push(`expected ${truncate(f.expected)}, got ${truncate(f.got)}`);
      }
      return lines;
    });
}

function truncate(s: string): string {
  return s.length > 20 ? `${s.slice(0, 8)}…${s.slice(-8)}` : s;
}

const GREEN = '\x1b[32m';
const RED = '\x1b[31m';
const YELLOW = '\x1b[33m';
const DIM = '\x1b[2m';
const BOLD = '\x1b[1m';
const RESET = '\x1b[0m';

export function renderReport(report: VerifyReport, useColor = process.stdout.isTTY ?? false): string {
  const c = (code: string, s: string) => (useColor ? `${code}${s}${RESET}` : s);
  const out: string[] = [];
  for (const check of report.checks) {
    const mark = check.skipped
      ? c(DIM, '∅')
      : !check.ok
        ? c(RED, '✖')
        : check.warn
          ? c(YELLOW, '⚠')
          : c(GREEN, '✔');
    const first = check.lines[0] ?? '';
    out.push(`${mark} ${check.name.padEnd(8)} ${check.ok || check.skipped ? first : c(RED, first)}`);
    for (const extra of check.lines.slice(1)) {
      out.push(`           ${c(check.warn ? YELLOW : DIM, extra)}`);
    }
  }
  if (report.blastRadius) {
    out.push(`           ${c(RED, `blast radius: entries ${report.blastRadius.from}–${report.blastRadius.to} untrustworthy`)}`);
  }
  if (report.anchorLag) {
    out.push(
      `${c(DIM, 'ℹ')} ANCHOR LAG  ${report.anchorLag.count} entr${report.anchorLag.count === 1 ? 'y' : 'ies'} (seq ${report.anchorLag.fromSeq}–${report.anchorLag.toSeq}) after last anchor — chain-protected, not yet anchored`,
    );
  }
  if (report.entryFocus) {
    const f = report.entryFocus;
    out.push(`${f.ok ? c(GREEN, '✔') : c(RED, '✖')} ENTRY ${String(f.seq).padEnd(4)} ${f.ok ? f.note : c(RED, f.note)}`);
  }
  out.push(
    `RESULT: ${
      report.exitCode === 0
        ? c(GREEN + BOLD, report.result)
        : report.exitCode === 4
          ? c(YELLOW + BOLD, report.result)
          : c(RED + BOLD, report.result)
    }  (exit ${report.exitCode})`,
  );
  if (report.exitCode === 4) {
    out.push(
      c(DIM, '        The hash chain and signatures are intact. What is NOT confirmed is that'),
    );
    out.push(c(DIM, '        the anchors are really in the public log — re-run with --online.'));
  }
  return out.join('\n');
}
