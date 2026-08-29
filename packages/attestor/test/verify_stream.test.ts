import { describe, it } from 'node:test'
import assert from 'node:assert/strict'
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs'
import { join } from 'node:path'
import { tmpdir } from 'node:os'
import { verifyLedgerStream } from '../src/verify_stream.ts'
import { generateKey } from '../src/keys.ts'
import { Ledger, uuidv7 } from '../src/ledger.ts'
import { writeCheckpoint } from '../src/checkpoint.ts'

describe('verifyLedgerStream', () => {
  it('successfully verifies a valid ledger stream', async () => {
    const dir = mkdtempSync(join(tmpdir(), 'attestor-stream-test-'))
    const keys = generateKey(join(dir, 'home'))
    const ledger = Ledger.open(dir, keys)

    const session = uuidv7()
    for (let i = 0; i < 5; i++) {
      ledger.append({
        type: 'call_request',
        origin: 'proxy',
        call_id: `call-${i}`,
        payload: JSON.stringify({ index: i }),
        session_id: session,
      })
    }
    writeCheckpoint(ledger, session)
    ledger.close()

    const res = await verifyLedgerStream(ledger.path)
    assert.equal(res.ok, true)
    assert.equal(res.entryCount >= 6, true)
    assert.equal(res.checkpointCount >= 1, true)
    assert.equal(res.findings.length, 0)

    rmSync(dir, { recursive: true, force: true })
  })

  it('detects hash tamper and chain breakage in stream', async () => {
    const dir = mkdtempSync(join(tmpdir(), 'attestor-stream-test-'))
    const keys = generateKey(join(dir, 'home'))
    const ledger = Ledger.open(dir, keys)

    ledger.append({
      type: 'call_request',
      origin: 'proxy',
      call_id: 'call-1',
      payload: JSON.stringify({ x: 1 }),
      session_id: uuidv7(),
    })
    ledger.close()

    const lines = readFileSync(ledger.path, 'utf8').trim().split('\n')
    const entry2 = JSON.parse(lines[1])
    entry2.payload = 'tampered'
    lines[1] = JSON.stringify(entry2)
    writeFileSync(ledger.path, lines.join('\n') + '\n')

    const res = await verifyLedgerStream(ledger.path)
    assert.equal(res.ok, false)
    assert.equal(res.findings.length > 0, true)

    rmSync(dir, { recursive: true, force: true })
  })
})
