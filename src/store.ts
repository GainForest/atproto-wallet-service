/**
 * SQLite development adapter for the async sealed-state repository.
 *
 * Production stateless deployments will replace this adapter with a
 * strongly-consistent external CAS store. Keeping SQLite behind the
 * same load/create/compareAndSwap contract lets the complete optimistic
 * state machine run locally and in tests today.
 *
 * Legacy databases are migrated atomically per DID into one fully
 * sealed V2 aggregate. Legacy server-share and pregen ciphertexts move
 * verbatim — device/recovery shares are never present and no wallet
 * secret is decrypted during migration.
 */
import Database from 'better-sqlite3'
import type {
  CasResult,
  CreateResult,
  StateSnapshot,
  WalletStateRepository,
} from './repository.js'
import {
  DEFAULT_KEY_EPOCH,
  emptyState,
  sealState,
  type SealedState,
  type WalletStateV2,
} from './state.js'

export interface SqliteRepositoryOptions {
  rootSeed: Uint8Array
  keyEpoch?: number
  exclusive?: boolean
  busyTimeoutMs?: number
}

interface LegacyEnrollment {
  did: string
  requestPubkeyHex: string
  createdAt: number
}
interface LegacyNonce {
  did: string
  lastNonce: number
}
interface LegacyWallet {
  did: string
  serverShareCipherHex: string
  evmPubkeyHex: string
  evmAddress: string
  solPubkeyHex: string
  solAddress: string
  version: number
  createdAt: number
}
interface LegacyPregen {
  did: string
  entropyCipherHex: string
  evmPubkeyHex: string
  evmAddress: string
  solPubkeyHex: string
  solAddress: string
  createdAt: number
}

export class SqliteWalletStateRepository implements WalletStateRepository {
  private readonly db: Database.Database

  constructor(dbPath: string, opts: SqliteRepositoryOptions) {
    this.db = new Database(dbPath)
    this.db.pragma(`busy_timeout = ${Math.max(0, opts.busyTimeoutMs ?? 5000)}`)
    this.db.pragma('journal_mode = WAL')
    this.db.pragma('synchronous = FULL')
    if (opts.exclusive !== false) {
      this.db.pragma('locking_mode = EXCLUSIVE')
    }
    this.db.exec(`
      CREATE TABLE IF NOT EXISTS wallet_state_v2 (
        did TEXT PRIMARY KEY,
        revision INTEGER NOT NULL,
        schema INTEGER NOT NULL,
        key_epoch INTEGER NOT NULL,
        cipher_b64 TEXT NOT NULL,
        updated_at INTEGER NOT NULL
      );
    `)
    if (opts.exclusive !== false) {
      const v = this.db.pragma('user_version', { simple: true }) as number
      this.db.pragma(`user_version = ${v}`)
    }
    this.migrateLegacy(opts.rootSeed, opts.keyEpoch ?? DEFAULT_KEY_EPOCH)
  }

  durabilityInfo(): {
    journalMode: string
    synchronous: number
    lockingMode: string
  } {
    return {
      journalMode: this.db.pragma('journal_mode', { simple: true }) as string,
      synchronous: this.db.pragma('synchronous', { simple: true }) as number,
      lockingMode: this.db.pragma('locking_mode', { simple: true }) as string,
    }
  }

  private tableExists(name: string): boolean {
    return Boolean(
      this.db
        .prepare(
          "SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = ?",
        )
        .get(name),
    )
  }

  /**
   * Convert all four operation-shaped legacy tables into one V2 row
   * per DID. Each DID is inserted and its old rows deleted in the same
   * SQLite transaction. If a V2 row already exists it is authoritative
   * and legacy rows for that DID are left untouched for manual review.
   */
  private migrateLegacy(rootSeed: Uint8Array, keyEpoch: number): void {
    const tables = [
      'wallet_enrollment',
      'wallet_nonce',
      'wallet',
      'wallet_pregen',
    ].filter((name) => this.tableExists(name))
    if (tables.length === 0) return

    const dids = new Set<string>()
    for (const table of tables) {
      const rows = this.db.prepare(`SELECT did FROM ${table}`).all() as Array<{
        did: string
      }>
      for (const row of rows) dids.add(row.did)
    }
    if (dids.size === 0) return

    const migrateOne = this.db.transaction((did: string): void => {
      if (
        this.db.prepare('SELECT 1 FROM wallet_state_v2 WHERE did = ?').get(did)
      ) {
        return
      }
      const enrollment = this.tableExists('wallet_enrollment')
        ? (this.db
            .prepare(
              `SELECT did, request_pubkey_hex AS requestPubkeyHex,
                      created_at AS createdAt
                 FROM wallet_enrollment WHERE did = ?`,
            )
            .get(did) as LegacyEnrollment | undefined)
        : undefined
      const nonce = this.tableExists('wallet_nonce')
        ? (this.db
            .prepare(
              'SELECT did, last_nonce AS lastNonce FROM wallet_nonce WHERE did = ?',
            )
            .get(did) as LegacyNonce | undefined)
        : undefined
      const wallet = this.tableExists('wallet')
        ? (this.db
            .prepare(
              `SELECT did,
                      server_share_cipher_hex AS serverShareCipherHex,
                      evm_pubkey_hex AS evmPubkeyHex,
                      evm_address AS evmAddress,
                      sol_pubkey_hex AS solPubkeyHex,
                      sol_address AS solAddress,
                      version, created_at AS createdAt
                 FROM wallet WHERE did = ?`,
            )
            .get(did) as LegacyWallet | undefined)
        : undefined
      const pregen = this.tableExists('wallet_pregen')
        ? (this.db
            .prepare(
              `SELECT did, entropy_cipher_hex AS entropyCipherHex,
                      evm_pubkey_hex AS evmPubkeyHex,
                      evm_address AS evmAddress,
                      sol_pubkey_hex AS solPubkeyHex,
                      sol_address AS solAddress,
                      created_at AS createdAt
                 FROM wallet_pregen WHERE did = ?`,
            )
            .get(did) as LegacyPregen | undefined)
        : undefined

      if (wallet && pregen) {
        throw new Error(`legacy state for ${did} contains wallet and pregen`)
      }
      const state: WalletStateV2 = {
        ...emptyState(did, keyEpoch),
        // Version 1 denotes the migration transition. Historical
        // operation count is unknowable from the old schema.
        stateVersion: 1,
        enrollment: enrollment
          ? {
              requestPubkeyHex: enrollment.requestPubkeyHex,
              createdAt: enrollment.createdAt,
            }
          : null,
        lastNonce: nonce?.lastNonce ?? 0,
        wallet: wallet
          ? {
              shareSetVersion: wallet.version,
              serverShareCipherHex: wallet.serverShareCipherHex,
              evmPubkeyHex: wallet.evmPubkeyHex,
              evmAddress: wallet.evmAddress,
              solPubkeyHex: wallet.solPubkeyHex,
              solAddress: wallet.solAddress,
              createdAt: wallet.createdAt,
            }
          : null,
        pregen: pregen
          ? {
              entropyCipherHex: pregen.entropyCipherHex,
              evmPubkeyHex: pregen.evmPubkeyHex,
              evmAddress: pregen.evmAddress,
              solPubkeyHex: pregen.solPubkeyHex,
              solAddress: pregen.solAddress,
              createdAt: pregen.createdAt,
            }
          : null,
      }
      const sealed = sealState(rootSeed, state)
      this.insertRow(did, sealed)
      for (const table of tables) {
        this.db.prepare(`DELETE FROM ${table} WHERE did = ?`).run(did)
      }
    })

    for (const did of dids) migrateOne(did)
  }

  private insertRow(did: string, sealed: SealedState): void {
    this.db
      .prepare(
        `INSERT INTO wallet_state_v2
           (did, revision, schema, key_epoch, cipher_b64, updated_at)
         VALUES (?, 1, ?, ?, ?, ?)`,
      )
      .run(did, sealed.schema, sealed.keyEpoch, sealed.cipherB64, Date.now())
  }

  async load(did: string): Promise<StateSnapshot | null> {
    const row = this.db
      .prepare(
        `SELECT revision, schema, key_epoch AS keyEpoch,
                cipher_b64 AS cipherB64
           FROM wallet_state_v2 WHERE did = ?`,
      )
      .get(did) as
      | {
          revision: number
          schema: number
          keyEpoch: number
          cipherB64: string
        }
      | undefined
    return row
      ? {
          revision: String(row.revision),
          sealed: {
            schema: row.schema,
            keyEpoch: row.keyEpoch,
            cipherB64: row.cipherB64,
          },
        }
      : null
  }

  async create(did: string, sealed: SealedState): Promise<CreateResult> {
    try {
      this.insertRow(did, sealed)
      return 'created'
    } catch (err) {
      if (
        err instanceof Error &&
        err.message.includes('UNIQUE constraint failed')
      ) {
        return 'exists'
      }
      throw err
    }
  }

  async compareAndSwap(
    did: string,
    expectedRevision: string,
    sealed: SealedState,
  ): Promise<CasResult> {
    if (!/^\d+$/.test(expectedRevision)) return 'conflict'
    const result = this.db
      .prepare(
        `UPDATE wallet_state_v2
            SET revision = revision + 1, schema = ?, key_epoch = ?,
                cipher_b64 = ?, updated_at = ?
          WHERE did = ? AND revision = ?`,
      )
      .run(
        sealed.schema,
        sealed.keyEpoch,
        sealed.cipherB64,
        Date.now(),
        did,
        Number(expectedRevision),
      )
    if (result.changes === 1) return 'updated'
    return this.db
      .prepare('SELECT 1 FROM wallet_state_v2 WHERE did = ?')
      .get(did)
      ? 'conflict'
      : 'missing'
  }

  close(): void {
    try {
      this.db.pragma('wal_checkpoint(TRUNCATE)')
    } catch {
      // Best effort; close still matters.
    }
    this.db.close()
  }
}

/** Transitional export name for downstream imports. */
export { SqliteWalletStateRepository as SignerStore }
