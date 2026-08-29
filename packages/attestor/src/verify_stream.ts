import { createReadStream } from 'node:fs'
import { createInterface } from 'node:readline'
import { createPublicKey } from 'node:crypto'
import {
  coreOf,
  genesisPrev,
  hashCore,
  payloadHash,
  verifyCoreSig,
  type LedgerEntry,
} from './ledger.ts'
import { computeRootHex } from './checkpoint.ts'

export interface StreamVerifyResult {
  ok: boolean
  entryCount: number
  checkpointCount: number
  error?: string
  findings: Array<{ seq: number; check: string; reason: string }>
}

/**
 * Streaming verification of an attestor ledger file.
 * Verifies hash-chain continuity, payload integrity, signatures, and Merkle checkpoint roots in sequential stream mode.
 */
export async function verifyLedgerStream(
  filePath: string,
  options: { expectKeyId?: string } = {},
): Promise<StreamVerifyResult> {
  const fileStream = createReadStream(filePath, { encoding: 'utf8' })
  const rl = createInterface({ input: fileStream, crlfDelay: Infinity })

  let prevHash: string | undefined = undefined
  let expectedSeq = 0
  let entryCount = 0
  let checkpointCount = 0
  const findings: Array<{ seq: number; check: string; reason: string }> = []
  const entryHashes: string[] = []

  let pubKeyObj: ReturnType<typeof createPublicKey> | null = null

  for await (const line of rl) {
    const trimmed = line.trim()
    if (!trimmed) continue

    let entry: LedgerEntry
    try {
      entry = JSON.parse(trimmed) as LedgerEntry
    } catch {
      findings.push({
        seq: expectedSeq,
        check: 'FORMAT',
        reason: 'unparsable JSON line in ledger stream',
      })
      return { ok: false, entryCount, checkpointCount, error: 'JSON parse error', findings }
    }

    if (entry.seq !== expectedSeq) {
      findings.push({
        seq: entry.seq,
        check: 'CHAIN',
        reason: `sequence gap: expected ${expectedSeq}, got ${entry.seq}`,
      })
    }

    if (prevHash !== undefined && entry.prev !== prevHash) {
      findings.push({
        seq: entry.seq,
        check: 'CHAIN',
        reason: `broken chain link at seq ${entry.seq}`,
      })
    }

    if (entry.payload !== undefined && entry.payload_hash !== undefined) {
      const computedPayloadHash = payloadHash(entry.salt, entry.payload)
      if (computedPayloadHash !== entry.payload_hash) {
        findings.push({
          seq: entry.seq,
          check: 'PAYLOAD',
          reason: `payload hash mismatch at seq ${entry.seq}: claimed ${entry.payload_hash}, computed ${computedPayloadHash}`,
        })
      }
    }

    const core = coreOf(entry)
    const computedHash = hashCore(core)
    if (entry.hash !== computedHash) {
      findings.push({
        seq: entry.seq,
        check: 'CHAIN',
        reason: `hash mismatch: claimed ${entry.hash}, computed ${computedHash}`,
      })
    }

    if (!pubKeyObj && entry.pub) {
      try {
        pubKeyObj = createPublicKey(entry.pub)
      } catch (err) {
        findings.push({
          seq: entry.seq,
          check: 'SIG',
          reason: `invalid public key format: ${(err as Error).message}`,
        })
      }
    }

    if (pubKeyObj && entry.sig) {
      const sigOk = verifyCoreSig(core, entry.sig, pubKeyObj)
      if (!sigOk) {
        findings.push({
          seq: entry.seq,
          check: 'SIG',
          reason: `signature verification failed at seq ${entry.seq}`,
        })
      }
    }

    entryHashes.push(entry.hash)

    if (entry.type === 'checkpoint' && entry.payload) {
      checkpointCount++
      try {
        const payload = JSON.parse(entry.payload) as { tree_size: number; root: string }
        const computedRoot = computeRootHex(entryHashes, payload.tree_size)
        if (computedRoot !== payload.root) {
          findings.push({
            seq: entry.seq,
            check: 'MERKLE',
            reason: `checkpoint root mismatch at seq ${entry.seq}: claimed ${payload.root}, computed ${computedRoot}`,
          })
        }
      } catch {
        findings.push({
          seq: entry.seq,
          check: 'MERKLE',
          reason: `corrupt checkpoint payload at seq ${entry.seq}`,
        })
      }
    }

    prevHash = entry.hash
    expectedSeq++
    entryCount++
  }

  const ok = findings.length === 0
  return {
    ok,
    entryCount,
    checkpointCount,
    findings,
  }
}
