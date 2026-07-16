import { afterEach, beforeEach, describe, expect, it } from 'vitest'
import * as fs from 'node:fs'
import * as http from 'node:http'
import * as os from 'node:os'
import * as path from 'node:path'
import { DstackKmsError, loadRootSeedFromDstackKms } from '../dstack-kms.js'

let dir: string
let sock: string
let server: http.Server | undefined

function startAgent(handler: http.RequestListener): Promise<void> {
  server = http.createServer(handler)
  return new Promise((resolve) => server!.listen(sock, resolve))
}

beforeEach(() => {
  dir = fs.mkdtempSync(path.join(os.tmpdir(), 'dstack-kms-test-'))
  sock = path.join(dir, 'dstack.sock')
})

afterEach(async () => {
  if (server) {
    await new Promise((resolve) => server!.close(resolve))
    server = undefined
  }
  fs.rmSync(dir, { recursive: true, force: true })
})

describe('loadRootSeedFromDstackKms', () => {
  it('derives a deterministic 32-byte seed from the agent key', async () => {
    await startAgent((_req, res) => {
      res.end(JSON.stringify({ key: 'ab'.repeat(48), signature_chain: [] }))
    })
    const a = await loadRootSeedFromDstackKms({ sockPath: sock })
    const b = await loadRootSeedFromDstackKms({ sockPath: sock })
    expect(a.length).toBe(32)
    expect(a.equals(b)).toBe(true)
    // HKDF output, not the raw key
    expect(a.toString('hex')).not.toBe('ab'.repeat(32))
  })

  it('different KMS key material yields different seeds', async () => {
    let call = 0
    await startAgent((_req, res) => {
      call += 1
      res.end(
        JSON.stringify({
          key: (call === 1 ? 'aa' : 'bb').repeat(32),
          signature_chain: [],
        }),
      )
    })
    const a = await loadRootSeedFromDstackKms({ sockPath: sock })
    const b = await loadRootSeedFromDstackKms({ sockPath: sock })
    expect(a.equals(b)).toBe(false)
  })

  it('passes key path and purpose to the guest agent', async () => {
    let seenPath: string | undefined
    let seenBody: Record<string, unknown> | undefined
    await startAgent((req, res) => {
      const chunks: Buffer[] = []
      req.on('data', (chunk: Buffer) => chunks.push(chunk))
      req.on('end', () => {
        seenPath = req.url
        seenBody = JSON.parse(Buffer.concat(chunks).toString('utf8'))
        res.end(JSON.stringify({ key: 'cd'.repeat(32), signature_chain: [] }))
      })
    })
    await loadRootSeedFromDstackKms({
      sockPath: sock,
      keyPath: 'custom/seed-path',
      purpose: 'root-seed',
    })
    expect(seenPath).toBe('/GetKey')
    expect(seenBody).toMatchObject({
      path: 'custom/seed-path',
      purpose: 'root-seed',
      algorithm: 'secp256k1',
    })
  })

  it('rejects responses without a key', async () => {
    await startAgent((_req, res) => {
      res.end(JSON.stringify({ signature_chain: [] }))
    })
    await expect(loadRootSeedFromDstackKms({ sockPath: sock })).rejects.toThrow(
      /GetKey failed/,
    )
  })

  it('rejects unparsable responses', async () => {
    await startAgent((_req, res) => {
      res.end('not json')
    })
    await expect(loadRootSeedFromDstackKms({ sockPath: sock })).rejects.toThrow(
      DstackKmsError,
    )
  })

  it('rejects invalid key material', async () => {
    await startAgent((_req, res) => {
      res.end(JSON.stringify({ key: 'zz'.repeat(32), signature_chain: [] }))
    })
    await expect(loadRootSeedFromDstackKms({ sockPath: sock })).rejects.toThrow(
      /missing key/,
    )
  })

  it('rejects short key material', async () => {
    await startAgent((_req, res) => {
      res.end(JSON.stringify({ key: 'ab'.repeat(8), signature_chain: [] }))
    })
    await expect(loadRootSeedFromDstackKms({ sockPath: sock })).rejects.toThrow(
      /need at least 32/,
    )
  })

  it('fails hard when the guest-agent socket does not exist', async () => {
    await expect(
      loadRootSeedFromDstackKms({
        sockPath: path.join(dir, 'missing.sock'),
      }),
    ).rejects.toThrow(DstackKmsError)
  })
})
