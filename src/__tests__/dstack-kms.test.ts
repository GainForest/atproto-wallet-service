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
      res.end(JSON.stringify({ key: (call === 1 ? 'aa' : 'bb').repeat(32) }))
    })
    const a = await loadRootSeedFromDstackKms({ sockPath: sock })
    const b = await loadRootSeedFromDstackKms({ sockPath: sock })
    expect(a.equals(b)).toBe(false)
  })

  it('passes key path and purpose to the guest agent', async () => {
    let seen: URL | undefined
    await startAgent((req, res) => {
      seen = new URL(req.url as string, 'http://localhost')
      res.end(JSON.stringify({ key: 'cd'.repeat(32) }))
    })
    await loadRootSeedFromDstackKms({
      sockPath: sock,
      keyPath: 'custom/seed-path',
      purpose: 'root-seed',
    })
    expect(seen?.pathname).toBe('/GetKey')
    expect(seen?.searchParams.get('path')).toBe('custom/seed-path')
    expect(seen?.searchParams.get('purpose')).toBe('root-seed')
  })

  it('rejects responses without a key', async () => {
    await startAgent((_req, res) => {
      res.end(JSON.stringify({ signature_chain: [] }))
    })
    await expect(loadRootSeedFromDstackKms({ sockPath: sock })).rejects.toThrow(
      /missing key/,
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

  it('rejects non-hex key material', async () => {
    await startAgent((_req, res) => {
      res.end(JSON.stringify({ key: 'zz'.repeat(32) }))
    })
    await expect(loadRootSeedFromDstackKms({ sockPath: sock })).rejects.toThrow(
      /not valid hex/,
    )
  })

  it('rejects short key material', async () => {
    await startAgent((_req, res) => {
      res.end(JSON.stringify({ key: 'ab'.repeat(8) }))
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
