/**
 * Sealed per-DID wallet state — the V2 state aggregate.
 *
 * Everything the service knows about one DID (enrollment, anti-replay
 * nonce, the encrypted server share, unclaimed pregenerated entropy,
 * and idempotency receipts) lives in ONE versioned state object. The
 * whole record — not individual fields — is sealed with AES-256-GCM
 * under a key derived from the enclave root seed, so storage only
 * ever sees ciphertext plus the routing header (schema / key epoch).
 * Any single wallet operation is then one atomic state transition:
 * build the next state, seal it, and compare-and-swap it against the
 * revision that was read.
 *
 * Secret fields stay KEK-encrypted INSIDE the sealed plaintext (the
 * same iv‖tag‖ct hex format wallet.ts has always produced). This is
 * deliberate, not redundant:
 *   - raw share bytes never round-trip through unwipeable JS strings
 *     during JSON encode/decode — they only ever exist as zeroizable
 *     Uint8Arrays on the existing decrypt paths;
 *   - legacy SQLite rows migrate verbatim (the ciphertext moves as
 *     is, no decrypt-reencrypt window during migration);
 *   - what full-record sealing NEWLY protects is the integrity of
 *     everything that used to be host-mutable plaintext: the enrolled
 *     request key, the anti-replay nonce, share-set version, and
 *     idempotency receipts.
 *
 * AAD binds a fixed domain, the schema version, the key epoch, and
 * the DID, so a sealed record can never be replayed for a different
 * DID, schema, or epoch — the GCM tag check fails. The same fields
 * are REPEATED inside the plaintext and re-checked after decryption,
 * so a hostile store that rewrites the outer header is also caught.
 *
 * Rollback caveat (docs/stateless-tee-design.md §4): sealing
 * authenticates content, not freshness. A host that restores a valid
 * OLD ciphertext (and matching storage revision) can re-open replay
 * windows for envelopes the user already signed. Detecting that
 * requires the Phase 4 independent monotonic witness over
 * (didHash, stateVersion, ciphertextHash); `encodeState` is canonical
 * (sorted keys) precisely so that hash is well-defined.
 *
 * This module is enclave-pure: deterministic, no I/O.
 */
import * as crypto from 'node:crypto'
import { hkdf } from '@noble/hashes/hkdf'
import { sha256 } from '@noble/hashes/sha2'

export const STATE_SCHEMA = 2
export const DEFAULT_KEY_EPOCH = 1
/** Receipts kept per DID — enough for lost-response retries, small
 * enough that sealed records stay compact. Oldest evicted first. */
export const MAX_RECEIPTS = 8

const STATE_HKDF_SALT = sha256(
  new TextEncoder().encode('atproto-wallet-state:v2'),
)
const AAD_DOMAIN = 'atproto-wallet-state'

export type ReceiptOp =
  'create' | 'claim' | 'sign' | 'export' | 'recover' | 'recover-export'

/**
 * Committed result of a mutating operation, persisted in the SAME
 * state transition that performed it. A retry carrying the same
 * requestId gets `response` back verbatim instead of a conflict —
 * this is what makes lost create/recovery responses non-stranding.
 * Responses only ever contain public wallet info and user-encrypted
 * JWEs, never server-decryptable secrets.
 */
export interface OperationReceipt {
  requestId: string
  op: ReceiptOp
  /** SHA-256 of the authenticated request. Prevents a requestId from
   * being reused with different operation parameters. */
  requestHash: string
  at: number
  response: Record<string, unknown>
}

export interface EnrollmentState {
  /** Compressed P-256 request public key, lowercase hex. */
  requestPubkeyHex: string
  createdAt: number
}

export interface WalletState {
  /** Incremented on every re-shard (recovery). */
  shareSetVersion: number
  /** AES-256-GCM ciphertext of the SSS server share under the share
   * KEK (wallet.ts encryptServerShare, AAD = did), hex iv‖tag‖ct. */
  serverShareCipherHex: string
  evmPubkeyHex: string
  evmAddress: string
  solPubkeyHex: string
  solAddress: string
  createdAt: number
}

export interface PregenState {
  /** AES-256-GCM ciphertext of the WHOLE wallet entropy under the
   * share KEK (wallet.ts encryptPregenEntropy), hex iv‖tag‖ct —
   * defer-split custody window. */
  entropyCipherHex: string
  evmPubkeyHex: string
  evmAddress: string
  solPubkeyHex: string
  solAddress: string
  createdAt: number
}

export interface WalletStateV2 {
  schema: typeof STATE_SCHEMA
  did: string
  /** Monotonic logical version — incremented by every committed
   * transition. What the Phase 4 witness will attest. */
  stateVersion: number
  keyEpoch: number
  enrollment: EnrollmentState | null
  /** Last accepted envelope nonce (0 = none yet). */
  lastNonce: number
  wallet: WalletState | null
  pregen: PregenState | null
  receipts: OperationReceipt[]
}

/** Sealed record as stored externally. Header fields exist for key
 * selection/routing only — they are repeated inside the ciphertext
 * and re-verified after decryption. */
export interface SealedState {
  schema: number
  keyEpoch: number
  /** base64: iv(12) ‖ gcm-tag(16) ‖ ciphertext */
  cipherB64: string
}

export class StateSealError extends Error {}

/** Fresh empty state for a DID that has never been seen. */
export function emptyState(did: string, keyEpoch: number): WalletStateV2 {
  return {
    schema: STATE_SCHEMA,
    did,
    stateVersion: 0,
    keyEpoch,
    enrollment: null,
    lastNonce: 0,
    wallet: null,
    pregen: null,
    receipts: [],
  }
}

/** Derived status — 'active' once claimed/split, 'pregenerated' while
 * receive-only custody, 'enrolled' with only a request key. */
export function stateStatus(
  state: WalletStateV2,
): 'active' | 'pregenerated' | 'enrolled' | 'empty' {
  if (state.wallet) return 'active'
  if (state.pregen) return 'pregenerated'
  if (state.enrollment) return 'enrolled'
  return 'empty'
}

// ── Canonical encoding ───────────────────────────────────────────────

function sortDeep(value: unknown): unknown {
  if (Array.isArray(value)) return value.map(sortDeep)
  if (value !== null && typeof value === 'object') {
    const out: Record<string, unknown> = {}
    for (const key of Object.keys(value as Record<string, unknown>).sort()) {
      out[key] = sortDeep((value as Record<string, unknown>)[key])
    }
    return out
  }
  return value
}

/**
 * Canonical (sorted-key) JSON bytes of a state object. Deterministic:
 * the same logical state always encodes to the same bytes, so
 * SHA-256(encodeState(s)) is a stable state hash for the future
 * monotonic witness.
 */
export function encodeState(state: WalletStateV2): Uint8Array {
  return new TextEncoder().encode(JSON.stringify(sortDeep(state)))
}

const HEX_RE = /^[0-9a-f]*$/

const RECEIPT_OPS: readonly ReceiptOp[] = [
  'create',
  'claim',
  'sign',
  'export',
  'recover',
  'recover-export',
]

function isReceipt(v: unknown): v is OperationReceipt {
  if (typeof v !== 'object' || v === null) return false
  const r = v as Record<string, unknown>
  return (
    typeof r.requestId === 'string' &&
    RECEIPT_OPS.includes(r.op as ReceiptOp) &&
    typeof r.requestHash === 'string' &&
    /^[0-9a-f]{64}$/.test(r.requestHash) &&
    Number.isSafeInteger(r.at) &&
    typeof r.response === 'object' &&
    r.response !== null
  )
}

/** Parse + shape-check decrypted state bytes. Throws on any anomaly —
 * a sealed record that decrypts but does not parse is corruption. */
export function decodeState(bytes: Uint8Array): WalletStateV2 {
  let parsed: unknown
  try {
    parsed = JSON.parse(new TextDecoder().decode(bytes))
  } catch {
    throw new StateSealError('sealed state is not valid JSON')
  }
  if (typeof parsed !== 'object' || parsed === null) {
    throw new StateSealError('sealed state is not an object')
  }
  const s = parsed as Record<string, unknown>
  if (s.schema !== STATE_SCHEMA) {
    throw new StateSealError(`unsupported state schema ${String(s.schema)}`)
  }
  if (typeof s.did !== 'string' || s.did.length === 0) {
    throw new StateSealError('sealed state missing did')
  }
  if (!Number.isSafeInteger(s.stateVersion) || (s.stateVersion as number) < 0) {
    throw new StateSealError('sealed state has invalid stateVersion')
  }
  if (!Number.isSafeInteger(s.keyEpoch) || (s.keyEpoch as number) < 1) {
    throw new StateSealError('sealed state has invalid keyEpoch')
  }
  if (!Number.isSafeInteger(s.lastNonce) || (s.lastNonce as number) < 0) {
    throw new StateSealError('sealed state has invalid lastNonce')
  }
  const enrollment = s.enrollment as EnrollmentState | null
  if (enrollment !== null) {
    if (
      typeof enrollment !== 'object' ||
      typeof enrollment.requestPubkeyHex !== 'string'
    ) {
      throw new StateSealError('sealed state has invalid enrollment')
    }
  }
  const wallet = s.wallet as WalletState | null
  if (wallet !== null) {
    if (
      typeof wallet !== 'object' ||
      typeof wallet.serverShareCipherHex !== 'string' ||
      !HEX_RE.test(wallet.serverShareCipherHex) ||
      !Number.isSafeInteger(wallet.shareSetVersion) ||
      wallet.shareSetVersion < 1
    ) {
      throw new StateSealError('sealed state has invalid wallet record')
    }
  }
  const pregen = s.pregen as PregenState | null
  if (pregen !== null) {
    if (
      typeof pregen !== 'object' ||
      typeof pregen.entropyCipherHex !== 'string' ||
      !HEX_RE.test(pregen.entropyCipherHex)
    ) {
      throw new StateSealError('sealed state has invalid pregen record')
    }
  }
  if (
    !Array.isArray(s.receipts) ||
    s.receipts.length > MAX_RECEIPTS ||
    !s.receipts.every(isReceipt)
  ) {
    throw new StateSealError('sealed state has invalid receipts')
  }
  if (wallet !== null && pregen !== null) {
    throw new StateSealError('sealed state cannot contain wallet and pregen')
  }
  return s as unknown as WalletStateV2
}

// ── Sealing (AES-256-GCM under an epoch-scoped root-derived key) ────

/**
 * State sealing key for one key epoch. Independent HKDF path from the
 * legacy share KEK and the inbound JWE key — compromise/rotation of
 * one does not touch the others. Bumping the epoch (new deployments,
 * Phase 5 cutover) yields an unrelated key; old-epoch records remain
 * readable because the record header names the epoch they were sealed
 * under, and are lazily re-sealed on their next write.
 */
export function deriveStateSealingKey(
  rootSeed: Uint8Array,
  keyEpoch: number,
): Uint8Array {
  if (!Number.isSafeInteger(keyEpoch) || keyEpoch < 1) {
    throw new StateSealError(`invalid key epoch ${String(keyEpoch)}`)
  }
  const info = new TextEncoder().encode(
    `wallet-service/state-sealing/v2\0epoch:${keyEpoch}`,
  )
  return hkdf(sha256, rootSeed, STATE_HKDF_SALT, info, 32)
}

function buildAad(schema: number, keyEpoch: number, did: string): Buffer {
  return Buffer.from(
    `${AAD_DOMAIN}\0v${schema}\0epoch:${keyEpoch}\0did:${did}`,
    'utf8',
  )
}

/** Seal a complete state record. The DID/schema/epoch inside `state`
 * are what get bound into the AAD — there is no way to seal a record
 * whose header disagrees with its content. */
export function sealState(
  rootSeed: Uint8Array,
  state: WalletStateV2,
): SealedState {
  const key = deriveStateSealingKey(rootSeed, state.keyEpoch)
  try {
    const iv = crypto.randomBytes(12)
    const cipher = crypto.createCipheriv('aes-256-gcm', key, iv)
    cipher.setAAD(buildAad(state.schema, state.keyEpoch, state.did))
    const plaintext = encodeState(state)
    const ct = Buffer.concat([cipher.update(plaintext), cipher.final()])
    plaintext.fill(0)
    return {
      schema: state.schema,
      keyEpoch: state.keyEpoch,
      cipherB64: Buffer.concat([iv, cipher.getAuthTag(), ct]).toString(
        'base64',
      ),
    }
  } finally {
    key.fill(0)
  }
}

/**
 * Unseal a record fetched from (untrusted) storage for `did`. Throws
 * StateSealError on tamper, DID/epoch/schema swap, or corruption. The
 * inner fields are re-checked against the outer header AND the
 * expected DID, so neither half can be substituted independently.
 */
export function unsealState(
  rootSeed: Uint8Array,
  did: string,
  sealed: SealedState,
): WalletStateV2 {
  if (sealed.schema !== STATE_SCHEMA) {
    throw new StateSealError(
      `unsupported sealed schema ${String(sealed.schema)}`,
    )
  }
  const key = deriveStateSealingKey(rootSeed, sealed.keyEpoch)
  let plain: Buffer
  try {
    const raw = Buffer.from(sealed.cipherB64, 'base64')
    if (raw.length < 12 + 16 + 1) {
      throw new StateSealError('sealed state ciphertext too short')
    }
    const decipher = crypto.createDecipheriv(
      'aes-256-gcm',
      key,
      raw.subarray(0, 12),
    )
    decipher.setAAD(buildAad(sealed.schema, sealed.keyEpoch, did))
    decipher.setAuthTag(raw.subarray(12, 28))
    try {
      plain = Buffer.concat([
        decipher.update(raw.subarray(28)),
        decipher.final(),
      ])
    } catch {
      throw new StateSealError(
        'sealed state failed authentication (tampered, swapped, or wrong key)',
      )
    }
  } finally {
    key.fill(0)
  }
  try {
    const state = decodeState(plain)
    if (state.did !== did) {
      throw new StateSealError('sealed state DID does not match record')
    }
    if (state.keyEpoch !== sealed.keyEpoch) {
      throw new StateSealError('sealed state key epoch does not match header')
    }
    return state
  } finally {
    plain.fill(0)
  }
}

// ── Receipts ─────────────────────────────────────────────────────────

export function findReceipt(
  state: WalletStateV2,
  requestId: string,
): OperationReceipt | null {
  return state.receipts.find((r) => r.requestId === requestId) ?? null
}

/** Append a receipt, evicting the oldest beyond MAX_RECEIPTS. */
export function appendReceipt(
  receipts: OperationReceipt[],
  receipt: OperationReceipt,
): OperationReceipt[] {
  return [...receipts, receipt].slice(-MAX_RECEIPTS)
}
