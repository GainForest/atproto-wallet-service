import { afterEach, beforeEach, describe, expect, it } from 'vitest'
import * as fs from 'node:fs'
import * as os from 'node:os'
import * as path from 'node:path'
import { SignerStore } from '../store.js'

let dir: string
let store: SignerStore

beforeEach(() => {
  dir = fs.mkdtempSync(path.join(os.tmpdir(), 'epds-signer-test-'))
  store = new SignerStore(path.join(dir, 'signer.sqlite'))
})

afterEach(() => {
  store.close()
  fs.rmSync(dir, { recursive: true, force: true })
})

describe('SignerStore.enroll', () => {
  it('is trust-on-first-use', () => {
    expect(store.enroll('did:plc:a', '02aa')).toBe('created')
    expect(store.getEnrollment('did:plc:a')?.requestPubkeyHex).toBe('02aa')
  })

  it('is idempotent for the same key', () => {
    store.enroll('did:plc:a', '02aa')
    expect(store.enroll('did:plc:a', '02aa')).toBe('unchanged')
  })

  it('refuses to overwrite with a different key', () => {
    store.enroll('did:plc:a', '02aa')
    expect(store.enroll('did:plc:a', '03bb')).toBe('conflict')
    expect(store.getEnrollment('did:plc:a')?.requestPubkeyHex).toBe('02aa')
  })

  it('keeps DIDs independent', () => {
    store.enroll('did:plc:a', '02aa')
    expect(store.enroll('did:plc:b', '03bb')).toBe('created')
  })
})

describe('SignerStore.rotateEnrollment', () => {
  it('replaces the enrolled key', () => {
    store.enroll('did:plc:a', '02aa')
    store.rotateEnrollment('did:plc:a', '03bb')
    expect(store.getEnrollment('did:plc:a')?.requestPubkeyHex).toBe('03bb')
  })

  it('creates the row when none exists', () => {
    store.rotateEnrollment('did:plc:a', '03bb')
    expect(store.getEnrollment('did:plc:a')?.requestPubkeyHex).toBe('03bb')
  })
})

describe('SignerStore wallet records', () => {
  const row = {
    did: 'did:plc:a',
    serverShareCipherHex: 'aabb',
    evmPubkeyHex: '02cc',
    evmAddress: '0xAbC',
    solPubkeyHex: 'dd',
    solAddress: 'SoL',
  }

  it('creates and reads a wallet', () => {
    expect(store.getWallet('did:plc:a')).toBeNull()
    expect(store.createWallet(row)).toBe(true)
    const got = store.getWallet('did:plc:a')
    expect(got).toMatchObject({ ...row, version: 1 })
    expect(got?.createdAt).toBeGreaterThan(0)
  })

  it('refuses to create twice', () => {
    expect(store.createWallet(row)).toBe(true)
    expect(store.createWallet(row)).toBe(false)
    expect(store.createWallet({ ...row, serverShareCipherHex: 'ffff' })).toBe(
      false,
    )
    expect(store.getWallet('did:plc:a')?.serverShareCipherHex).toBe('aabb')
  })

  it('replaceServerShare bumps the version', () => {
    store.createWallet(row)
    expect(store.replaceServerShare('did:plc:a', 'ccdd')).toBe(2)
    expect(store.replaceServerShare('did:plc:a', 'eeff')).toBe(3)
    const got = store.getWallet('did:plc:a')
    expect(got?.serverShareCipherHex).toBe('eeff')
    expect(got?.version).toBe(3)
  })

  it('replaceServerShare throws for a missing wallet', () => {
    expect(() => store.replaceServerShare('did:plc:none', 'ff')).toThrow(
      /no wallet/,
    )
  })
})

describe('SignerStore pregenerated wallets (defer-split)', () => {
  const pregen = {
    did: 'did:plc:a',
    entropyCipherHex: 'eecc',
    evmPubkeyHex: '02cc',
    evmAddress: '0xAbC',
    solPubkeyHex: 'dd',
    solAddress: 'SoL',
  }
  const walletRow = {
    did: 'did:plc:a',
    serverShareCipherHex: 'aabb',
    evmPubkeyHex: '02cc',
    evmAddress: '0xAbC',
    solPubkeyHex: 'dd',
    solAddress: 'SoL',
  }

  it('creates and reads a pregen record', () => {
    expect(store.getPregen('did:plc:a')).toBeNull()
    expect(store.createPregen(pregen)).toBe(true)
    const got = store.getPregen('did:plc:a')
    expect(got).toMatchObject(pregen)
    expect(got?.createdAt).toBeGreaterThan(0)
  })

  it('refuses to pregenerate twice', () => {
    expect(store.createPregen(pregen)).toBe(true)
    expect(store.createPregen({ ...pregen, entropyCipherHex: 'ffff' })).toBe(
      false,
    )
    expect(store.getPregen('did:plc:a')?.entropyCipherHex).toBe('eecc')
  })

  it('claimPregen inserts the wallet and deletes the pregen row atomically', () => {
    store.createPregen(pregen)
    expect(store.claimPregen('did:plc:a', walletRow)).toBe(true)
    expect(store.getWallet('did:plc:a')).toMatchObject({
      ...walletRow,
      version: 1,
    })
    // The whole-entropy blob is gone — the custody window is closed.
    expect(store.getPregen('did:plc:a')).toBeNull()
  })

  it('claimPregen refuses when a wallet already exists, keeping the pregen row', () => {
    store.createPregen(pregen)
    store.createWallet(walletRow)
    expect(store.claimPregen('did:plc:a', walletRow)).toBe(false)
    expect(store.getPregen('did:plc:a')).not.toBeNull()
  })

  it('keeps pregen records independent of wallet records per DID', () => {
    store.createPregen(pregen)
    expect(store.createWallet({ ...walletRow, did: 'did:plc:b' })).toBe(true)
    expect(store.getPregen('did:plc:b')).toBeNull()
    expect(store.getPregen('did:plc:a')).not.toBeNull()
  })
})

describe('SignerStore.consumeNonce', () => {
  it('accepts strictly increasing nonces', () => {
    expect(store.consumeNonce('did:plc:a', 1)).toBe(true)
    expect(store.consumeNonce('did:plc:a', 2)).toBe(true)
    expect(store.consumeNonce('did:plc:a', 10)).toBe(true)
  })

  it('rejects replays and reordering', () => {
    expect(store.consumeNonce('did:plc:a', 5)).toBe(true)
    expect(store.consumeNonce('did:plc:a', 5)).toBe(false)
    expect(store.consumeNonce('did:plc:a', 4)).toBe(false)
  })

  it('tracks nonces per DID', () => {
    expect(store.consumeNonce('did:plc:a', 5)).toBe(true)
    expect(store.consumeNonce('did:plc:b', 5)).toBe(true)
  })
})

describe('SignerStore durability & single-writer (spot hardening)', () => {
  it('runs WAL with synchronous=FULL and an exclusive lock by default', () => {
    const info = store.durabilityInfo()
    expect(info.journalMode).toBe('wal')
    expect(info.synchronous).toBe(2) // FULL — nonce commits survive preemption
    expect(info.lockingMode).toBe('exclusive')
  })

  it('a second instance on the same file fails fast at startup', () => {
    // `store` (beforeEach) already holds the exclusive lock on the
    // durable-disk database — a failover replacement attaching the same
    // disk while we are alive must refuse to start.
    expect(
      () =>
        new SignerStore(path.join(dir, 'signer.sqlite'), {
          busyTimeoutMs: 100,
        }),
    ).toThrow(/database is locked/)
  })

  it('allows shared connections when exclusive mode is disabled', () => {
    const p = path.join(dir, 'shared.sqlite')
    const a = new SignerStore(p, { exclusive: false })
    const b = new SignerStore(p, { exclusive: false, busyTimeoutMs: 100 })
    try {
      a.enroll('did:plc:shared', '02aa')
      expect(b.getEnrollment('did:plc:shared')?.requestPubkeyHex).toBe('02aa')
      expect(a.durabilityInfo().lockingMode).toBe('normal')
    } finally {
      a.close()
      b.close()
    }
  })

  it('close() leaves a fully checkpointed database behind', () => {
    const p = path.join(dir, 'ckpt.sqlite')
    const s = new SignerStore(p)
    s.enroll('did:plc:ckpt', '02aa')
    s.consumeNonce('did:plc:ckpt', 1)
    s.close()
    // After a controlled shutdown the WAL must be flushed into the main
    // file so the durable disk can be detached and re-attached cleanly.
    const wal = `${p}-wal`
    if (fs.existsSync(wal)) expect(fs.statSync(wal).size).toBe(0)
    const reopened = new SignerStore(p)
    try {
      expect(reopened.getEnrollment('did:plc:ckpt')?.requestPubkeyHex).toBe(
        '02aa',
      )
      // The consumed nonce survived — no replay window re-opened.
      expect(reopened.consumeNonce('did:plc:ckpt', 1)).toBe(false)
    } finally {
      reopened.close()
    }
  })
})
