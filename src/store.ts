/**
 * Signer persistence — wallet records, enrollments, anti-replay nonces.
 *
 * Repo-key derivation is pure, so no repo-key state exists. Per DID
 * the signer keeps: (a) which user request-key is enrolled, (b) the
 * last accepted wallet nonce (monotonic counter), and (c) the wallet
 * record — the SERVER SHARE of the 2-of-3 split, encrypted under the
 * measurement-bound KEK (opaque to whoever holds this file), plus
 * cached public material (addresses/pubkeys) so lookups never touch
 * secrets. Device and recovery shares are NEVER stored here — the
 * whole point of the split is that this store alone reconstructs
 * nothing.
 *
 * The one deliberate exception is `wallet_pregen`: a wallet
 * provisioned for a DID before its first login (defer-split
 * pregeneration) stores its WHOLE entropy, KEK-encrypted. Until the
 * user claims it, that wallet is enclave-custodial and receive-only —
 * no wallet row exists, so sign/export/recover are impossible.
 * Claiming moves it into `wallet` (2-of-3 split) and deletes the
 * pregen row in one transaction. Pregen rows are keyed by DID alone —
 * the DID does not need to be an account on this PDS yet (it may
 * live on another PDS and migrate in later).
 *
 * Threat-model note (see docs/design/tee-signer.md): the host controls
 * this disk, so it can roll the file back. Rolling back the nonce table
 * re-opens a replay window for envelopes the user *already signed* —
 * it never lets the host forge a new one. A production deployment
 * should anchor freshness outside the host (monotonic counter service
 * or on-chain nonce checks); enrollment rows additionally carry the
 * request-key so a rollback can only restore an older key the user
 * once controlled, not substitute the host's own.
 */
import Database from 'better-sqlite3'

export interface SignerStoreOptions {
  /**
   * Hold the SQLite EXCLUSIVE lock for the lifetime of this store
   * (default true). On a durable data disk that is re-attached to a
   * replacement instance during failover, this guarantees only ONE
   * process can ever write the nonce/wallet tables — a second instance
   * attaching the same disk fails fast at startup instead of silently
   * splitting the monotonic nonce state.
   */
  exclusive?: boolean
  /** How long to wait on SQLITE_BUSY before failing (ms, default 5000). */
  busyTimeoutMs?: number
}

export interface EnrollmentRow {
  did: string
  requestPubkeyHex: string
  createdAt: number
}

export interface PregenRow {
  did: string
  /** AES-256-GCM ciphertext of the WHOLE wallet entropy, hex (iv‖tag‖ct). */
  entropyCipherHex: string
  evmPubkeyHex: string
  evmAddress: string
  solPubkeyHex: string
  solAddress: string
  createdAt: number
}

export interface WalletRow {
  did: string
  /** AES-256-GCM ciphertext of the SSS server share, hex (iv‖tag‖ct). */
  serverShareCipherHex: string
  evmPubkeyHex: string
  evmAddress: string
  solPubkeyHex: string
  solAddress: string
  /** Incremented on every re-shard (recovery). */
  version: number
  createdAt: number
}

export class SignerStore {
  private readonly db: Database.Database

  constructor(dbPath: string, opts: SignerStoreOptions = {}) {
    this.db = new Database(dbPath)
    this.db.pragma(`busy_timeout = ${Math.max(0, opts.busyTimeoutMs ?? 5000)}`)
    this.db.pragma('journal_mode = WAL')
    // WAL's default synchronous=NORMAL may lose the most recently
    // committed transactions on sudden power-off — exactly what spot
    // preemption looks like. Losing a nonce commit silently re-opens a
    // replay window for an envelope the user already signed, so this
    // store pays the fsync cost: every commit is durable before the
    // HTTP response that depends on it can be sent.
    this.db.pragma('synchronous = FULL')
    if (opts.exclusive !== false) {
      // Single-writer guard for controlled failover (see options doc).
      // Must be set AFTER entering WAL mode — SQLite cannot change
      // journal modes while the locking mode is EXCLUSIVE.
      this.db.pragma('locking_mode = EXCLUSIVE')
    }
    this.db.exec(`
      CREATE TABLE IF NOT EXISTS wallet_enrollment (
        did TEXT PRIMARY KEY,
        request_pubkey_hex TEXT NOT NULL,
        created_at INTEGER NOT NULL
      );
      CREATE TABLE IF NOT EXISTS wallet_nonce (
        did TEXT PRIMARY KEY,
        last_nonce INTEGER NOT NULL
      );
      CREATE TABLE IF NOT EXISTS wallet (
        did TEXT PRIMARY KEY,
        server_share_cipher_hex TEXT NOT NULL,
        evm_pubkey_hex TEXT NOT NULL,
        evm_address TEXT NOT NULL,
        sol_pubkey_hex TEXT NOT NULL,
        sol_address TEXT NOT NULL,
        version INTEGER NOT NULL DEFAULT 1,
        created_at INTEGER NOT NULL
      );
      CREATE TABLE IF NOT EXISTS wallet_pregen (
        did TEXT PRIMARY KEY,
        entropy_cipher_hex TEXT NOT NULL,
        evm_pubkey_hex TEXT NOT NULL,
        evm_address TEXT NOT NULL,
        sol_pubkey_hex TEXT NOT NULL,
        sol_address TEXT NOT NULL,
        created_at INTEGER NOT NULL
      );
    `)
    if (opts.exclusive !== false) {
      // Force a write transaction NOW so the exclusive lock is actually
      // acquired at startup (fail fast when another instance holds the
      // disk) instead of lazily on the first wallet write.
      const v = this.db.pragma('user_version', { simple: true }) as number
      this.db.pragma(`user_version = ${v}`)
    }
  }

  /** Per-connection durability settings — exposed for tests and ops. */
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

  getEnrollment(did: string): EnrollmentRow | null {
    const row = this.db
      .prepare(
        'SELECT did, request_pubkey_hex AS requestPubkeyHex, created_at AS createdAt FROM wallet_enrollment WHERE did = ?',
      )
      .get(did) as EnrollmentRow | undefined
    return row ?? null
  }

  /**
   * Trust-on-first-use enrollment. Returns:
   *  - 'created'   — no key was enrolled; this one now is.
   *  - 'unchanged' — the same key was already enrolled (idempotent).
   *  - 'conflict'  — a different key is enrolled; caller must reject.
   *    Key rotation requires an envelope signed by the current key and
   *    is intentionally not implemented via plain re-enrollment.
   */
  enroll(
    did: string,
    requestPubkeyHex: string,
  ): 'created' | 'unchanged' | 'conflict' {
    const existing = this.getEnrollment(did)
    if (existing) {
      return existing.requestPubkeyHex === requestPubkeyHex
        ? 'unchanged'
        : 'conflict'
    }
    this.db
      .prepare(
        'INSERT INTO wallet_enrollment (did, request_pubkey_hex, created_at) VALUES (?, ?, ?)',
      )
      .run(did, requestPubkeyHex, Date.now())
    return 'created'
  }

  /**
   * Rotate the enrolled request key. Only reachable from the recovery
   * path, where possession of the recovery share (verified in-enclave
   * against the wallet's stored public keys) authorizes the rotation.
   */
  rotateEnrollment(did: string, requestPubkeyHex: string): void {
    this.db
      .prepare(
        `INSERT INTO wallet_enrollment (did, request_pubkey_hex, created_at)
         VALUES (?, ?, ?)
         ON CONFLICT(did) DO UPDATE SET request_pubkey_hex = excluded.request_pubkey_hex`,
      )
      .run(did, requestPubkeyHex, Date.now())
  }

  getWallet(did: string): WalletRow | null {
    const row = this.db
      .prepare(
        `SELECT did,
                server_share_cipher_hex AS serverShareCipherHex,
                evm_pubkey_hex AS evmPubkeyHex,
                evm_address AS evmAddress,
                sol_pubkey_hex AS solPubkeyHex,
                sol_address AS solAddress,
                version,
                created_at AS createdAt
         FROM wallet WHERE did = ?`,
      )
      .get(did) as WalletRow | undefined
    return row ?? null
  }

  /** Shared insert used by createWallet and claimPregen. */
  private insertWallet(row: Omit<WalletRow, 'version' | 'createdAt'>): boolean {
    try {
      this.db
        .prepare(
          `INSERT INTO wallet (did, server_share_cipher_hex, evm_pubkey_hex,
                               evm_address, sol_pubkey_hex, sol_address,
                               version, created_at)
           VALUES (?, ?, ?, ?, ?, ?, 1, ?)`,
        )
        .run(
          row.did,
          row.serverShareCipherHex,
          row.evmPubkeyHex,
          row.evmAddress,
          row.solPubkeyHex,
          row.solAddress,
          Date.now(),
        )
      return true
    } catch (err) {
      if (
        err instanceof Error &&
        err.message.includes('UNIQUE constraint failed')
      ) {
        return false
      }
      /* v8 ignore next 1 -- non-constraint sqlite failures */
      throw err
    }
  }

  /**
   * Insert a new wallet record. Returns false when a wallet already
   * exists for the DID (creation is once-only; the entropy behind an
   * existing wallet must never be silently replaced).
   */
  createWallet(row: Omit<WalletRow, 'version' | 'createdAt'>): boolean {
    return this.insertWallet(row)
  }

  getPregen(did: string): PregenRow | null {
    const row = this.db
      .prepare(
        `SELECT did,
                entropy_cipher_hex AS entropyCipherHex,
                evm_pubkey_hex AS evmPubkeyHex,
                evm_address AS evmAddress,
                sol_pubkey_hex AS solPubkeyHex,
                sol_address AS solAddress,
                created_at AS createdAt
         FROM wallet_pregen WHERE did = ?`,
      )
      .get(did) as PregenRow | undefined
    return row ?? null
  }

  /**
   * Insert a pregenerated (defer-split, unclaimed) wallet record.
   * Returns false when one already exists for the DID — pregeneration
   * is once-only for the same reason wallet creation is.
   */
  createPregen(row: Omit<PregenRow, 'createdAt'>): boolean {
    try {
      this.db
        .prepare(
          `INSERT INTO wallet_pregen (did, entropy_cipher_hex, evm_pubkey_hex,
                                      evm_address, sol_pubkey_hex, sol_address,
                                      created_at)
           VALUES (?, ?, ?, ?, ?, ?, ?)`,
        )
        .run(
          row.did,
          row.entropyCipherHex,
          row.evmPubkeyHex,
          row.evmAddress,
          row.solPubkeyHex,
          row.solAddress,
          Date.now(),
        )
      return true
    } catch (err) {
      if (
        err instanceof Error &&
        err.message.includes('UNIQUE constraint failed')
      ) {
        return false
      }
      /* v8 ignore next 1 -- non-constraint sqlite failures */
      throw err
    }
  }

  /**
   * Claim a pregenerated wallet: atomically insert the real wallet
   * record (2-of-3 split, server share only) and DELETE the
   * whole-entropy pregen row — after this the enclave holds one share
   * like any other wallet. Returns false when a wallet already exists
   * (the pregen row is left untouched in that case).
   */
  claimPregen(
    did: string,
    row: Omit<WalletRow, 'version' | 'createdAt'>,
  ): boolean {
    const tx = this.db.transaction((): boolean => {
      if (!this.insertWallet(row)) return false
      this.db.prepare('DELETE FROM wallet_pregen WHERE did = ?').run(did)
      return true
    })
    return tx()
  }

  /**
   * Replace the encrypted server share after a re-shard (recovery with
   * fresh SSS coefficients). Returns the new version number.
   */
  replaceServerShare(did: string, serverShareCipherHex: string): number {
    const tx = this.db.transaction((): number => {
      const row = this.db
        .prepare('SELECT version FROM wallet WHERE did = ?')
        .get(did) as { version: number } | undefined
      if (!row) throw new Error(`no wallet for ${did}`)
      const version = row.version + 1
      this.db
        .prepare(
          'UPDATE wallet SET server_share_cipher_hex = ?, version = ? WHERE did = ?',
        )
        .run(serverShareCipherHex, version, did)
      return version
    })
    return tx()
  }

  /**
   * Atomically accept `nonce` for `did` iff it is strictly greater than
   * the last accepted nonce. Returns false on replay/reorder.
   */
  consumeNonce(did: string, nonce: number): boolean {
    const tx = this.db.transaction((): boolean => {
      const row = this.db
        .prepare(
          'SELECT last_nonce AS lastNonce FROM wallet_nonce WHERE did = ?',
        )
        .get(did) as { lastNonce: number } | undefined
      if (row && nonce <= row.lastNonce) return false
      this.db
        .prepare(
          'INSERT INTO wallet_nonce (did, last_nonce) VALUES (?, ?) ON CONFLICT(did) DO UPDATE SET last_nonce = excluded.last_nonce',
        )
        .run(did, nonce)
      return true
    })
    return tx()
  }

  close(): void {
    // Flush the WAL into the main database file before closing so a
    // controlled shutdown (drain → close → detach disk → failover)
    // leaves a fully checkpointed file behind. Best-effort: close
    // proceeds regardless.
    try {
      this.db.pragma('wal_checkpoint(TRUNCATE)')
      /* v8 ignore next 3 -- checkpoint failures are not reproducible */
    } catch {
      // ignore — close() below is what matters
    }
    this.db.close()
  }
}
