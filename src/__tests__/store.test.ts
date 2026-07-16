import { afterEach, beforeEach, describe, expect, it } from 'vitest'
import Database from 'better-sqlite3'
import * as fs from 'node:fs'
import * as os from 'node:os'
import * as path from 'node:path'
import { SqliteWalletStateRepository } from '../store.js'
import { emptyState, sealState, unsealState } from '../state.js'

const seed = Buffer.alloc(32, 41)
const did = 'did:plc:storetest'
let dir: string
let dbPath: string
let store: SqliteWalletStateRepository

beforeEach(() => {
  dir = fs.mkdtempSync(path.join(os.tmpdir(), 'wallet-state-test-'))
  dbPath = path.join(dir, 'wallet.sqlite')
  store = new SqliteWalletStateRepository(dbPath, { rootSeed: seed })
})

afterEach(() => {
  store.close()
  fs.rmSync(dir, { recursive: true, force: true })
})

function sealed(version: number) {
  const state = emptyState(did, 1)
  state.stateVersion = version
  return sealState(seed, state)
}

describe('SqliteWalletStateRepository CAS', () => {
  it('creates and loads opaque sealed state', async () => {
    expect(await store.load(did)).toBeNull()
    expect(await store.create(did, sealed(1))).toBe('created')
    expect(await store.create(did, sealed(2))).toBe('exists')
    const snapshot = await store.load(did)
    expect(snapshot?.revision).toBe('1')
    expect(unsealState(seed, did, snapshot!.sealed).stateVersion).toBe(1)
  })

  it('updates only the expected revision', async () => {
    await store.create(did, sealed(1))
    expect(await store.compareAndSwap(did, '1', sealed(2))).toBe('updated')
    expect(await store.compareAndSwap(did, '1', sealed(3))).toBe('conflict')
    const snapshot = await store.load(did)
    expect(snapshot?.revision).toBe('2')
    expect(unsealState(seed, did, snapshot!.sealed).stateVersion).toBe(2)
  })

  it('distinguishes missing records and invalid revisions', async () => {
    expect(await store.compareAndSwap(did, '1', sealed(1))).toBe('missing')
    await store.create(did, sealed(1))
    expect(await store.compareAndSwap(did, 'garbage', sealed(2))).toBe(
      'conflict',
    )
  })

  it('allows one winner for competing CAS writes', async () => {
    await store.create(did, sealed(1))
    const [a, b] = await Promise.all([
      store.compareAndSwap(did, '1', sealed(2)),
      store.compareAndSwap(did, '1', sealed(3)),
    ])
    expect([a, b].sort()).toEqual(['conflict', 'updated'])
  })
})

describe('SQLite durability and fencing', () => {
  it('runs WAL with synchronous=FULL and an exclusive lock', () => {
    expect(store.durabilityInfo()).toEqual({
      journalMode: 'wal',
      synchronous: 2,
      lockingMode: 'exclusive',
    })
  })

  it('a second exclusive instance fails fast', () => {
    expect(
      () =>
        new SqliteWalletStateRepository(dbPath, {
          rootSeed: seed,
          busyTimeoutMs: 100,
        }),
    ).toThrow(/database is locked/)
  })

  it('shared adapters still enforce CAS', async () => {
    const sharedPath = path.join(dir, 'shared.sqlite')
    const a = new SqliteWalletStateRepository(sharedPath, {
      rootSeed: seed,
      exclusive: false,
    })
    const b = new SqliteWalletStateRepository(sharedPath, {
      rootSeed: seed,
      exclusive: false,
    })
    try {
      await a.create(did, sealed(1))
      const snap = await b.load(did)
      expect(snap?.revision).toBe('1')
      expect(await a.compareAndSwap(did, '1', sealed(2))).toBe('updated')
      expect(await b.compareAndSwap(did, '1', sealed(3))).toBe('conflict')
    } finally {
      a.close()
      b.close()
    }
  })

  it('controlled close checkpoints committed state', async () => {
    await store.create(did, sealed(1))
    store.close()
    const wal = `${dbPath}-wal`
    if (fs.existsSync(wal)) expect(fs.statSync(wal).size).toBe(0)
    store = new SqliteWalletStateRepository(dbPath, { rootSeed: seed })
    expect((await store.load(did))?.revision).toBe('1')
  })
})

describe('legacy aggregate migration', () => {
  it('atomically moves enrollment, nonce, wallet, and pregen rows into sealed V2 state', async () => {
    store.close()
    const db = new Database(dbPath)
    db.exec(`
      CREATE TABLE wallet_enrollment (
        did TEXT PRIMARY KEY, request_pubkey_hex TEXT NOT NULL,
        created_at INTEGER NOT NULL
      );
      CREATE TABLE wallet_nonce (
        did TEXT PRIMARY KEY, last_nonce INTEGER NOT NULL
      );
      CREATE TABLE wallet (
        did TEXT PRIMARY KEY, server_share_cipher_hex TEXT NOT NULL,
        evm_pubkey_hex TEXT NOT NULL, evm_address TEXT NOT NULL,
        sol_pubkey_hex TEXT NOT NULL, sol_address TEXT NOT NULL,
        version INTEGER NOT NULL, created_at INTEGER NOT NULL
      );
      CREATE TABLE wallet_pregen (
        did TEXT PRIMARY KEY, entropy_cipher_hex TEXT NOT NULL,
        evm_pubkey_hex TEXT NOT NULL, evm_address TEXT NOT NULL,
        sol_pubkey_hex TEXT NOT NULL, sol_address TEXT NOT NULL,
        created_at INTEGER NOT NULL
      );
    `)
    db.prepare('INSERT INTO wallet_enrollment VALUES (?, ?, ?)').run(
      did,
      '02aa',
      100,
    )
    db.prepare('INSERT INTO wallet_nonce VALUES (?, ?)').run(did, 17)
    db.prepare('INSERT INTO wallet VALUES (?, ?, ?, ?, ?, ?, ?, ?)').run(
      did,
      'aabb',
      '02cc',
      '0xabc',
      'dd',
      'sol',
      3,
      101,
    )
    const pregenDid = 'did:plc:legacypregen'
    db.prepare('INSERT INTO wallet_pregen VALUES (?, ?, ?, ?, ?, ?, ?)').run(
      pregenDid,
      'eeff',
      '02ff',
      '0xdef',
      'aa',
      'sol2',
      102,
    )
    db.close()

    store = new SqliteWalletStateRepository(dbPath, {
      rootSeed: seed,
      keyEpoch: 2,
    })
    const walletState = unsealState(seed, did, (await store.load(did))!.sealed)
    expect(walletState).toMatchObject({
      schema: 2,
      keyEpoch: 2,
      stateVersion: 1,
      lastNonce: 17,
      enrollment: { requestPubkeyHex: '02aa', createdAt: 100 },
      wallet: {
        shareSetVersion: 3,
        serverShareCipherHex: 'aabb',
      },
    })
    const pregenState = unsealState(
      seed,
      pregenDid,
      (await store.load(pregenDid))!.sealed,
    )
    expect(pregenState.pregen?.entropyCipherHex).toBe('eeff')

    store.close()
    const check = new Database(dbPath, { readonly: true })
    try {
      expect(
        (
          check.prepare('SELECT count(*) AS n FROM wallet').get() as {
            n: number
          }
        ).n,
      ).toBe(0)
      expect(
        (
          check.prepare('SELECT count(*) AS n FROM wallet_pregen').get() as {
            n: number
          }
        ).n,
      ).toBe(0)
    } finally {
      check.close()
    }
    store = new SqliteWalletStateRepository(dbPath, { rootSeed: seed })
  })
})
