/**
 * Standalone wallet-service HTTP surface.
 *
 * All durable information for one DID is one sealed WalletStateV2
 * aggregate. Every mutation is optimistic and atomic:
 *
 *   load → unseal → authorize → build complete response →
 *   seal(stateVersion + 1) → compare-and-swap
 *
 * Response JWEs and idempotency receipts are built before the CAS and
 * committed with the server-share / enrollment / nonce transition.
 * A lost create or recovery response can therefore be retried with the
 * same requestId and returns the exact committed ciphertexts.
 */
import * as crypto from 'node:crypto'
import express, {
  type Application,
  type NextFunction,
  type Request,
  type Response,
} from 'express'
import cors from 'cors'
import { rateLimit } from 'express-rate-limit'
import { timingSafeEqual, createLogger } from './lib/shared.js'
import type { VerifyServiceJwt } from './auth/service-auth.js'
import { getAttestation, type AttestationResult } from './attestation.js'
import {
  attestationManifestReportData,
  challengeBoundReportData,
  createAttestationManifest,
  isValidAttestationChallenge,
} from './attestation-manifest.js'
import { deriveIdentityPublicKey } from './derive.js'
import { buildDidWebDocument } from './did-web.js'
import {
  DEFAULT_FRESHNESS_SEC,
  isValidRequestId,
  verifyEnvelope,
  type WalletEnvelopePayload,
  type WalletOp,
} from './envelope.js'
import { bytesToHex, hexToBytes } from './keys.js'
import { isPlausibleDid } from './purposes.js'
import {
  buildExportPayload,
  combineWalletShares,
  decryptJweToEnclave,
  decryptPregenEntropy,
  decryptServerShare,
  deriveChainKeys,
  deriveShareKek,
  encryptPregenEntropy,
  encryptServerShare,
  encryptToRequestKey,
  generateWalletEntropy,
  getWalletEncryptionPublicJwk,
  isCompactJwe,
  isValidP256PublicKeyHex,
  signEvmDigestWithKey,
  signSolMessageWithKey,
  splitWalletEntropy,
  wipe,
  type WalletChainKeys,
} from './wallet.js'
import type { WalletStateRepository } from './repository.js'
import {
  DEFAULT_KEY_EPOCH,
  appendReceipt,
  emptyState,
  findReceipt,
  sealState,
  unsealState,
  type OperationReceipt,
  type ReceiptOp,
  type WalletState,
  type WalletStateV2,
  type PregenState,
} from './state.js'

const logger = createLogger('wallet-service')
const MAX_CAS_ATTEMPTS = 4

export interface SignerServiceOptions {
  rootSeed: Uint8Array
  store: WalletStateRepository
  internalSecret: string
  verifyServiceJwt: VerifyServiceJwt
  freshnessSec?: number
  stateKeyEpoch?: number
  dstackSockPath?: string
  /** Unix socket of the root-owned configfs-TSM quote helper. */
  tsmQuoteSockPath?: string
  /** configfs-TSM report directory (direct mode, needs privileges). */
  tsmReportDir?: string
  /** Production fail-closed attestation mode. */
  requireTeeAttestation?: boolean
  /** Number of explicitly trusted reverse-proxy hops (0 means direct). */
  trustProxyHops?: number
  isDraining?: () => boolean
  serviceDid?: string
}

export const LXM = {
  enroll: 'app.gainforest.wallet.enroll',
  create: 'app.gainforest.wallet.create',
  getWallet: 'app.gainforest.wallet.getWallet',
} as const

export function isCompressedP256Hex(value: unknown): value is string {
  return typeof value === 'string' && /^0[23][0-9a-fA-F]{64}$/.test(value)
}

class HttpError extends Error {
  constructor(
    readonly status: number,
    readonly body: Record<string, unknown>,
  ) {
    super(String(body.error ?? `HTTP ${status}`))
  }
}

interface TransitionResult {
  response: Record<string, unknown>
  /** false means read/idempotent result; no CAS required. */
  commit?: boolean
}

type Mutator = (state: WalletStateV2) => Promise<TransitionResult>

function abort(status: number, error: string): never {
  throw new HttpError(status, { error })
}

function stableJson(value: unknown): string {
  if (Array.isArray(value)) return `[${value.map(stableJson).join(',')}]`
  if (value !== null && typeof value === 'object') {
    return `{${Object.keys(value as Record<string, unknown>)
      .sort()
      .map(
        (key) =>
          `${JSON.stringify(key)}:${stableJson((value as Record<string, unknown>)[key])}`,
      )
      .join(',')}}`
  }
  return JSON.stringify(value)
}

function requestHash(value: unknown): string {
  return crypto.createHash('sha256').update(stableJson(value)).digest('hex')
}

function envelopeHash(payloadB64: string): string {
  return crypto
    .createHash('sha256')
    .update(Buffer.from(payloadB64, 'base64url'))
    .digest('hex')
}

function walletPublicInfo(
  did: string,
  row: WalletState,
  stateVersion: number,
): Record<string, unknown> {
  return {
    did,
    evm: { address: row.evmAddress, publicKeyHex: row.evmPubkeyHex },
    sol: { address: row.solAddress, publicKeyHex: row.solPubkeyHex },
    version: row.shareSetVersion,
    stateVersion,
    createdAt: row.createdAt,
  }
}

function pregenPublicInfo(
  did: string,
  row: PregenState,
  stateVersion: number,
): Record<string, unknown> {
  return {
    did,
    evm: { address: row.evmAddress, publicKeyHex: row.evmPubkeyHex },
    sol: { address: row.solAddress, publicKeyHex: row.solPubkeyHex },
    stateVersion,
    createdAt: row.createdAt,
  }
}

function validateExpectedStateVersion(
  value: unknown,
  state: WalletStateV2,
): void {
  if (value === undefined) return
  if (!Number.isSafeInteger(value) || (value as number) < 0) {
    abort(400, 'invalid expectedStateVersion')
  }
  if (value !== state.stateVersion) {
    abort(409, 'state version conflict')
  }
}

function committedReceipt(
  state: WalletStateV2,
  requestId: string,
  allowedOps: readonly ReceiptOp[],
  hash: string,
): Record<string, unknown> | null {
  const receipt = findReceipt(state, requestId)
  if (!receipt) return null
  if (!allowedOps.includes(receipt.op) || receipt.requestHash !== hash) {
    abort(409, 'requestId was already used for a different operation')
  }
  return receipt.response
}

function addReceipt(
  state: WalletStateV2,
  requestId: string,
  op: ReceiptOp,
  hash: string,
  response: Record<string, unknown>,
): void {
  const receipt: OperationReceipt = {
    requestId,
    op,
    requestHash: hash,
    at: Date.now(),
    response,
  }
  state.receipts = appendReceipt(state.receipts, receipt)
}

function requireRequestId(value: unknown): string {
  if (!isValidRequestId(value)) {
    abort(400, 'requestId is required (8-128 base64url characters)')
  }
  return value
}

function peekEnvelopeDid(body: unknown): string {
  const record = body as Record<string, unknown> | null
  if (
    !record ||
    typeof record.payload !== 'string' ||
    typeof record.sig !== 'string'
  ) {
    abort(400, 'missing payload or sig')
  }
  try {
    const did = JSON.parse(
      Buffer.from(record.payload, 'base64url').toString('utf8'),
    )?.did
    if (!isPlausibleDid(did)) abort(400, 'malformed payload')
    return did
  } catch (err) {
    if (err instanceof HttpError) throw err
    abort(400, 'malformed payload')
  }
}

export function createSignerApp(opts: SignerServiceOptions): Application {
  const { rootSeed, store, internalSecret } = opts
  const freshnessSec = opts.freshnessSec ?? DEFAULT_FRESHNESS_SEC
  const stateKeyEpoch = opts.stateKeyEpoch ?? DEFAULT_KEY_EPOCH
  const identityPubkeyHex = bytesToHex(deriveIdentityPublicKey(rootSeed))
  const shareKek = deriveShareKek(rootSeed)
  const walletEncryptionPublicJwk = getWalletEncryptionPublicJwk(rootSeed)
  const attestationManifest = createAttestationManifest({
    serviceDid: opts.serviceDid ?? '',
    identityPublicKeyHex: identityPubkeyHex,
    walletEncryptionPublicJwk,
  })
  const manifestReportDataHex =
    attestationManifestReportData(attestationManifest)

  const app = express()
  if ((opts.trustProxyHops ?? 0) > 0) {
    app.set('trust proxy', opts.trustProxyHops)
  }
  app.use(cors())
  app.use(express.json({ limit: '128kb' }))
  const writeLimiter = rateLimit({
    windowMs: 60_000,
    limit: 60,
    standardHeaders: true,
    legacyHeaders: false,
  })

  const requireSecret = (req: Request, res: Response, next: NextFunction) => {
    const header = req.headers['x-internal-secret']
    if (
      !internalSecret ||
      typeof header !== 'string' ||
      !timingSafeEqual(header, internalSecret)
    ) {
      res.status(401).json({ error: 'Unauthorized' })
      return
    }
    next()
  }

  const requireServiceAuth =
    (lxm: string) =>
    async (req: Request, res: Response, next: NextFunction): Promise<void> => {
      const header = req.headers.authorization
      if (typeof header !== 'string' || !header.startsWith('Bearer ')) {
        res.status(401).json({ error: 'missing service-auth token' })
        return
      }
      try {
        const { did } = await opts.verifyServiceJwt(header.slice(7), lxm)
        res.locals.authDid = did
        next()
      } catch (err) {
        logger.debug({ err, lxm }, 'service-auth verification failed')
        res.status(401).json({ error: 'invalid service-auth token' })
      }
    }

  async function loadState(did: string): Promise<WalletStateV2 | null> {
    const snapshot = await store.load(did)
    return snapshot ? unsealState(rootSeed, did, snapshot.sealed) : null
  }

  /** Run one optimistic state transition. Mutators may execute more
   * than once after a CAS conflict and therefore must not expose any
   * result before this helper reports a committed response. */
  async function transition(
    did: string,
    mutate: Mutator,
  ): Promise<Record<string, unknown>> {
    for (let attempt = 0; attempt < MAX_CAS_ATTEMPTS; attempt++) {
      const snapshot = await store.load(did)
      const state = snapshot
        ? unsealState(rootSeed, did, snapshot.sealed)
        : emptyState(did, stateKeyEpoch)
      const result = await mutate(state)
      if (result.commit === false) return result.response

      state.schema = 2
      state.did = did
      state.stateVersion += 1
      state.keyEpoch = stateKeyEpoch
      const sealed = sealState(rootSeed, state)
      const committed = snapshot
        ? await store.compareAndSwap(did, snapshot.revision, sealed)
        : await store.create(did, sealed)
      if (committed === 'updated' || committed === 'created') {
        return result.response
      }
      // Another replica won. Reload and fully re-authorize against the
      // winner; nonce/version/idempotency checks may now differ.
    }
    abort(409, 'concurrent state update; retry request')
  }

  async function handle(
    res: Response,
    action: () => Promise<Record<string, unknown>>,
    logMessage: string,
  ): Promise<void> {
    try {
      res.json(await action())
    } catch (err) {
      if (err instanceof HttpError) {
        res.status(err.status).json(err.body)
        return
      }
      logger.error({ err }, logMessage)
      res.status(500).json({ error: logMessage })
    }
  }

  app.get('/health', (_req, res) => {
    if (opts.isDraining?.()) {
      res
        .status(503)
        .json({ status: 'draining', service: 'atproto-wallet-service' })
      return
    }
    res.json({ status: 'ok', service: 'atproto-wallet-service' })
  })

  if (opts.serviceDid?.startsWith('did:web:')) {
    const didDoc = buildDidWebDocument(opts.serviceDid, identityPubkeyHex)
    app.get('/.well-known/did.json', (_req, res) => res.json(didDoc))
  }

  app.get('/v1/attestation', async (req, res) => {
    try {
      const challenge = req.query.challenge
      if (challenge !== undefined && !isValidAttestationChallenge(challenge)) {
        res.status(400).json({ error: 'invalid attestation challenge' })
        return
      }
      if (opts.requireTeeAttestation && challenge === undefined) {
        res.status(400).json({ error: 'attestation challenge is required' })
        return
      }
      const reportDataHex =
        challenge === undefined
          ? manifestReportDataHex
          : challengeBoundReportData(attestationManifest, challenge)
      const attestation: AttestationResult = await getAttestation({
        reportDataHex,
        dstackSockPath: opts.dstackSockPath,
        tsmQuoteSockPath: opts.tsmQuoteSockPath,
        tsmReportDir: opts.tsmReportDir,
        requireTee: opts.requireTeeAttestation,
      })
      res.json({
        ...attestation,
        challenge,
        manifest: attestationManifest,
        identityPublicKeyHex: identityPubkeyHex,
        walletEncryptionPublicJwk,
      })
    } catch (err) {
      logger.error({ err }, 'attestation failed')
      res.status(503).json({ error: 'attestation unavailable' })
    }
  })

  app.get('/v1/wallet/public/:did', async (req, res) => {
    await handle(
      res,
      async () => {
        const did = req.params.did
        if (!isPlausibleDid(did)) abort(400, 'invalid did')
        const state = await loadState(did)
        if (state?.wallet) {
          return {
            status: 'active',
            wallet: walletPublicInfo(did, state.wallet, state.stateVersion),
          }
        }
        if (state?.pregen) {
          return {
            status: 'pregenerated',
            wallet: pregenPublicInfo(did, state.pregen, state.stateVersion),
          }
        }
        abort(404, 'no wallet for this DID')
      },
      'wallet lookup failed',
    )
  })

  app.post(
    '/v1/wallet/enroll',
    writeLimiter,
    requireServiceAuth(LXM.enroll),
    async (req, res) => {
      const did = res.locals.authDid as string
      await handle(
        res,
        () =>
          transition(did, async (state) => {
            const { requestPublicKeyHex } = req.body ?? {}
            if (
              !isCompressedP256Hex(requestPublicKeyHex) ||
              !isValidP256PublicKeyHex(requestPublicKeyHex)
            ) {
              abort(400, 'invalid requestPublicKeyHex')
            }
            const normalized = requestPublicKeyHex.toLowerCase()
            if (state.enrollment) {
              if (state.enrollment.requestPubkeyHex !== normalized) {
                abort(
                  409,
                  'a different request key is already enrolled for this DID; key rotation requires wallet recovery',
                )
              }
              return { response: { status: 'unchanged' }, commit: false }
            }
            state.enrollment = {
              requestPubkeyHex: normalized,
              createdAt: Date.now(),
            }
            logger.info({ did }, 'wallet enrollment')
            return { response: { status: 'created' } }
          }),
        'wallet enrollment failed',
      )
    },
  )

  app.get('/v1/wallet/enrollment/:did', requireSecret, async (req, res) => {
    await handle(
      res,
      async () => {
        const did = req.params.did
        if (!isPlausibleDid(did)) abort(400, 'invalid did')
        return { enrolled: Boolean((await loadState(did))?.enrollment) }
      },
      'enrollment lookup failed',
    )
  })

  app.get(
    '/v1/wallet/info/:did',
    requireServiceAuth(LXM.getWallet),
    async (req, res) => {
      await handle(
        res,
        async () => {
          const did = req.params.did
          if (!isPlausibleDid(did)) abort(400, 'invalid did')
          if (did !== res.locals.authDid) {
            abort(403, 'token DID does not match requested DID')
          }
          const state = await loadState(did)
          return {
            enrolled: Boolean(state?.enrollment),
            stateVersion: state?.stateVersion ?? 0,
            wallet: state?.wallet
              ? walletPublicInfo(did, state.wallet, state.stateVersion)
              : null,
            pregen: state?.pregen
              ? pregenPublicInfo(did, state.pregen, state.stateVersion)
              : null,
            walletEncryptionPublicJwk,
          }
        },
        'wallet info failed',
      )
    },
  )

  app.post('/v1/wallet/pregenerate', requireSecret, async (req, res) => {
    const { did } = req.body ?? {}
    await handle(
      res,
      async () => {
        if (!isPlausibleDid(did)) abort(400, 'invalid did')
        return transition(did, async (state) => {
          if (state.wallet) abort(409, 'wallet already exists for this DID')
          if (state.pregen) {
            return {
              response: {
                status: 'exists',
                wallet: pregenPublicInfo(did, state.pregen, state.stateVersion),
              },
              commit: false,
            }
          }
          const entropy = generateWalletEntropy()
          let keys: WalletChainKeys | undefined
          try {
            keys = deriveChainKeys(entropy)
            const createdAt = Date.now()
            state.pregen = {
              entropyCipherHex: encryptPregenEntropy(shareKek, did, entropy),
              evmPubkeyHex: bytesToHex(keys.evmPublicKey),
              evmAddress: keys.evmAddress,
              solPubkeyHex: bytesToHex(keys.solPublicKey),
              solAddress: keys.solAddress,
              createdAt,
            }
            const response = {
              status: 'pregenerated',
              wallet: pregenPublicInfo(
                did,
                state.pregen,
                state.stateVersion + 1,
              ),
            }
            logger.info({ did }, 'wallet pregenerated (receive-only)')
            return { response }
          } finally {
            wipe(entropy, keys?.evmPrivateKey, keys?.solPrivateKey)
          }
        })
      },
      'wallet pregeneration failed',
    )
  })

  app.post(
    '/v1/wallet/create',
    writeLimiter,
    requireServiceAuth(LXM.create),
    async (req, res) => {
      const did = res.locals.authDid as string
      await handle(
        res,
        async () => {
          const requestId = requireRequestId(req.body?.requestId)
          const hash = requestHash({ did, requestId })
          return transition(did, async (state) => {
            const prior = committedReceipt(
              state,
              requestId,
              ['create', 'claim'],
              hash,
            )
            if (prior) return { response: prior, commit: false }
            validateExpectedStateVersion(req.body?.expectedStateVersion, state)
            if (!state.enrollment) {
              abort(403, 'enroll a request key before creating a wallet')
            }
            if (state.wallet) abort(409, 'wallet already exists for this DID')

            const pregen = state.pregen
            let entropy: Uint8Array | undefined
            let keys: WalletChainKeys | undefined
            let shares: [Uint8Array, Uint8Array, Uint8Array] | undefined
            try {
              entropy = pregen
                ? decryptPregenEntropy(shareKek, did, pregen.entropyCipherHex)
                : generateWalletEntropy()
              keys = deriveChainKeys(entropy)
              if (
                pregen &&
                (bytesToHex(keys.evmPublicKey) !== pregen.evmPubkeyHex ||
                  bytesToHex(keys.solPublicKey) !== pregen.solPubkeyHex)
              ) {
                abort(500, 'pregenerated wallet integrity check failed')
              }
              shares = await splitWalletEntropy(entropy)
              const createdAt = pregen?.createdAt ?? Date.now()
              const wallet: WalletState = {
                shareSetVersion: 1,
                serverShareCipherHex: encryptServerShare(
                  shareKek,
                  did,
                  shares[0],
                ),
                evmPubkeyHex: bytesToHex(keys.evmPublicKey),
                evmAddress: keys.evmAddress,
                solPubkeyHex: bytesToHex(keys.solPublicKey),
                solAddress: keys.solAddress,
                createdAt,
              }
              // Construct BOTH user delivery JWEs before the atomic CAS.
              const [deviceShareJwe, recoveryShareJwe] = await Promise.all([
                encryptToRequestKey(
                  state.enrollment.requestPubkeyHex,
                  shares[1],
                ),
                encryptToRequestKey(
                  state.enrollment.requestPubkeyHex,
                  shares[2],
                ),
              ])
              state.wallet = wallet
              state.pregen = null
              const op: ReceiptOp = pregen ? 'claim' : 'create'
              const response = {
                status: pregen ? 'claimed' : 'created',
                wallet: walletPublicInfo(did, wallet, state.stateVersion + 1),
                deviceShareJwe,
                recoveryShareJwe,
              }
              addReceipt(state, requestId, op, hash, response)
              logger.info(
                { did, claimedPregen: Boolean(pregen) },
                'wallet created',
              )
              return { response }
            } finally {
              wipe(
                entropy,
                keys?.evmPrivateKey,
                keys?.solPrivateKey,
                ...(shares ?? []),
              )
            }
          })
        },
        'wallet creation failed',
      )
    },
  )

  function verifyEnvelopeForState(
    body: Record<string, unknown>,
    state: WalletStateV2,
    expectedOp: WalletOp,
  ): { payload: WalletEnvelopePayload; hash: string; requestId: string } {
    if (!state.enrollment) abort(403, 'no wallet enrollment for this DID')
    const payloadB64 = body.payload
    const sigB64 = body.sig
    if (typeof payloadB64 !== 'string' || typeof sigB64 !== 'string') {
      abort(400, 'missing payload or sig')
    }
    const verified = verifyEnvelope({
      payloadB64,
      sigB64,
      requestPubkeyHex: state.enrollment.requestPubkeyHex,
      expectedOp,
      freshnessSec,
    })
    if (!verified.ok) abort(403, verified.error)
    const requestId = requireRequestId(verified.payload.requestId)
    return {
      payload: verified.payload,
      hash: envelopeHash(payloadB64),
      requestId,
    }
  }

  function validateEnvelopeVersions(
    payload: WalletEnvelopePayload,
    state: WalletStateV2,
  ): void {
    if (
      payload.stateVersion !== undefined &&
      payload.stateVersion !== state.stateVersion
    ) {
      abort(409, 'state version conflict')
    }
    if (
      payload.shareSetVersion !== undefined &&
      payload.shareSetVersion !== state.wallet?.shareSetVersion
    ) {
      abort(409, 'share set version conflict')
    }
  }

  async function reconstruct(
    state: WalletStateV2,
    payload: WalletEnvelopePayload,
  ): Promise<{
    entropy: Uint8Array
    keys: WalletChainKeys
    wallet: WalletState
  }> {
    if (!state.wallet) abort(403, 'no wallet exists for this DID')
    let deviceShare: Uint8Array | undefined
    let serverShare: Uint8Array | undefined
    let entropy: Uint8Array | undefined
    try {
      deviceShare = await decryptJweToEnclave(rootSeed, payload.deviceShareJwe)
      serverShare = decryptServerShare(
        shareKek,
        payload.did,
        state.wallet.serverShareCipherHex,
      )
      entropy = await combineWalletShares(serverShare, deviceShare)
      const keys = deriveChainKeys(entropy)
      if (bytesToHex(keys.evmPublicKey) !== state.wallet.evmPubkeyHex) {
        wipe(entropy, keys.evmPrivateKey, keys.solPrivateKey)
        abort(403, 'device share does not match wallet')
      }
      return { entropy, keys, wallet: state.wallet }
    } catch (err) {
      wipe(entropy)
      if (err instanceof HttpError) throw err
      logger.warn({ err, did: payload.did }, 'wallet reconstruction failed')
      abort(403, 'share reconstruction failed')
    } finally {
      wipe(deviceShare, serverShare)
    }
  }

  app.post('/v1/wallet/sign', writeLimiter, async (req, res) => {
    await handle(
      res,
      async () => {
        const did = peekEnvelopeDid(req.body)
        return transition(did, async (state) => {
          const verified = verifyEnvelopeForState(req.body, state, 'sign')
          const { payload: p, hash, requestId } = verified
          const prior = committedReceipt(state, requestId, ['sign'], hash)
          if (prior) return { response: prior, commit: false }
          validateEnvelopeVersions(p, state)
          if (!state.wallet) abort(403, 'no wallet exists for this DID')
          if (p.nonce <= state.lastNonce) {
            abort(409, 'nonce replayed or out of order')
          }
          const rec = await reconstruct(state, p)
          try {
            let response: Record<string, unknown>
            if (p.purpose === 'wallet/evm') {
              const { signature, recovery } = signEvmDigestWithKey(
                rec.keys.evmPrivateKey,
                hexToBytes(p.digestHex as string),
              )
              response = { signatureHex: bytesToHex(signature), recovery }
            } else {
              const signature = signSolMessageWithKey(
                rec.keys.solPrivateKey,
                Uint8Array.from(
                  Buffer.from(p.messageBase64 as string, 'base64url'),
                ),
              )
              response = { signatureHex: bytesToHex(signature) }
            }
            state.lastNonce = p.nonce
            addReceipt(state, requestId, 'sign', hash, response)
            logger.info({ did, purpose: p.purpose }, 'wallet signature issued')
            return { response }
          } finally {
            wipe(rec.entropy, rec.keys.evmPrivateKey, rec.keys.solPrivateKey)
          }
        })
      },
      'wallet signing failed',
    )
  })

  app.post('/v1/wallet/export', writeLimiter, async (req, res) => {
    await handle(
      res,
      async () => {
        const did = peekEnvelopeDid(req.body)
        return transition(did, async (state) => {
          const verified = verifyEnvelopeForState(req.body, state, 'export')
          const { payload: p, hash, requestId } = verified
          const prior = committedReceipt(state, requestId, ['export'], hash)
          if (prior) return { response: prior, commit: false }
          validateEnvelopeVersions(p, state)
          if (!state.wallet) abort(403, 'no wallet exists for this DID')
          if (p.nonce <= state.lastNonce) {
            abort(409, 'nonce replayed or out of order')
          }
          const rec = await reconstruct(state, p)
          let exportBytes: Uint8Array | undefined
          try {
            exportBytes = buildExportPayload(rec.entropy, rec.keys)
            const exportJwe = await encryptToRequestKey(
              state.enrollment!.requestPubkeyHex,
              exportBytes,
            )
            const response = { exportJwe }
            state.lastNonce = p.nonce
            addReceipt(state, requestId, 'export', hash, response)
            logger.info({ did }, 'wallet exported to user')
            return { response }
          } finally {
            wipe(
              rec.entropy,
              rec.keys.evmPrivateKey,
              rec.keys.solPrivateKey,
              exportBytes,
            )
          }
        })
      },
      'wallet export failed',
    )
  })

  app.post('/v1/wallet/recover', writeLimiter, async (req, res) => {
    const { did, recoveryShareJwe, requestPublicKeyHex } = req.body ?? {}
    await handle(
      res,
      async () => {
        if (!isPlausibleDid(did) || !isCompactJwe(recoveryShareJwe)) {
          abort(400, 'invalid did or recoveryShareJwe')
        }
        if (
          requestPublicKeyHex !== undefined &&
          (!isCompressedP256Hex(requestPublicKeyHex) ||
            !isValidP256PublicKeyHex(requestPublicKeyHex))
        ) {
          abort(400, 'invalid requestPublicKeyHex')
        }
        const requestId = requireRequestId(req.body?.requestId)
        const normalizedKey =
          typeof requestPublicKeyHex === 'string'
            ? requestPublicKeyHex.toLowerCase()
            : undefined
        const hash = requestHash({
          did,
          recoveryShareJwe,
          requestPublicKeyHex: normalizedKey,
          requestId,
        })
        return transition(did, async (state) => {
          const prior = committedReceipt(state, requestId, ['recover'], hash)
          if (prior) return { response: prior, commit: false }
          validateExpectedStateVersion(req.body?.expectedStateVersion, state)
          if (!state.wallet || !state.enrollment) {
            abort(403, 'no wallet exists for this DID')
          }
          let recoveryShare: Uint8Array | undefined
          let serverShare: Uint8Array | undefined
          let entropy: Uint8Array | undefined
          let keys: WalletChainKeys | undefined
          let shares: [Uint8Array, Uint8Array, Uint8Array] | undefined
          try {
            recoveryShare = await decryptJweToEnclave(
              rootSeed,
              recoveryShareJwe,
            )
            serverShare = decryptServerShare(
              shareKek,
              did,
              state.wallet.serverShareCipherHex,
            )
            entropy = await combineWalletShares(serverShare, recoveryShare)
            keys = deriveChainKeys(entropy)
            if (bytesToHex(keys.evmPublicKey) !== state.wallet.evmPubkeyHex) {
              abort(403, 'recovery share does not match wallet')
            }
            shares = await splitWalletEntropy(entropy)
            const targetKey = normalizedKey ?? state.enrollment.requestPubkeyHex
            // Build delivery ciphertext before changing either server
            // share or enrollment; all three commit together below.
            const [deviceShareJwe, newRecoveryShareJwe] = await Promise.all([
              encryptToRequestKey(targetKey, shares[1]),
              encryptToRequestKey(targetKey, shares[2]),
            ])
            state.wallet.serverShareCipherHex = encryptServerShare(
              shareKek,
              did,
              shares[0],
            )
            state.wallet.shareSetVersion += 1
            if (targetKey !== state.enrollment.requestPubkeyHex) {
              state.enrollment = {
                requestPubkeyHex: targetKey,
                createdAt: Date.now(),
              }
            }
            const response = {
              status: 'recovered',
              version: state.wallet.shareSetVersion,
              stateVersion: state.stateVersion + 1,
              deviceShareJwe,
              recoveryShareJwe: newRecoveryShareJwe,
            }
            addReceipt(state, requestId, 'recover', hash, response)
            logger.info(
              { did, version: state.wallet.shareSetVersion },
              'wallet recovered',
            )
            return { response }
          } catch (err) {
            if (err instanceof HttpError) throw err
            logger.warn({ err, did }, 'wallet recovery reconstruction failed')
            abort(403, 'share reconstruction failed')
          } finally {
            wipe(
              recoveryShare,
              serverShare,
              entropy,
              keys?.evmPrivateKey,
              keys?.solPrivateKey,
              ...(shares ?? []),
            )
          }
        })
      },
      'wallet recovery failed',
    )
  })

  app.post('/v1/wallet/recover-export', writeLimiter, async (req, res) => {
    const { did, entropyJwe, requestPublicKeyHex } = req.body ?? {}
    await handle(
      res,
      async () => {
        if (!isPlausibleDid(did) || !isCompactJwe(entropyJwe)) {
          abort(400, 'invalid did or entropyJwe')
        }
        if (
          !isCompressedP256Hex(requestPublicKeyHex) ||
          !isValidP256PublicKeyHex(requestPublicKeyHex)
        ) {
          abort(400, 'invalid requestPublicKeyHex')
        }
        const requestId = requireRequestId(req.body?.requestId)
        const normalizedKey = requestPublicKeyHex.toLowerCase()
        const hash = requestHash({
          did,
          entropyJwe,
          requestPublicKeyHex: normalizedKey,
          requestId,
        })
        return transition(did, async (state) => {
          const prior = committedReceipt(
            state,
            requestId,
            ['recover-export'],
            hash,
          )
          if (prior) return { response: prior, commit: false }
          validateExpectedStateVersion(req.body?.expectedStateVersion, state)
          if (!state.wallet || !state.enrollment) {
            abort(403, 'no wallet exists for this DID')
          }
          let entropy: Uint8Array | undefined
          let keys: WalletChainKeys | undefined
          let shares: [Uint8Array, Uint8Array, Uint8Array] | undefined
          try {
            entropy = await decryptJweToEnclave(rootSeed, entropyJwe)
            keys = deriveChainKeys(entropy)
            if (bytesToHex(keys.evmPublicKey) !== state.wallet.evmPubkeyHex) {
              abort(403, 'wallet export does not match wallet')
            }
            shares = await splitWalletEntropy(entropy)
            const [deviceShareJwe, recoveryShareJwe] = await Promise.all([
              encryptToRequestKey(normalizedKey, shares[1]),
              encryptToRequestKey(normalizedKey, shares[2]),
            ])
            state.wallet.serverShareCipherHex = encryptServerShare(
              shareKek,
              did,
              shares[0],
            )
            state.wallet.shareSetVersion += 1
            if (normalizedKey !== state.enrollment.requestPubkeyHex) {
              state.enrollment = {
                requestPubkeyHex: normalizedKey,
                createdAt: Date.now(),
              }
            }
            const response = {
              status: 'recovered-from-export',
              version: state.wallet.shareSetVersion,
              stateVersion: state.stateVersion + 1,
              deviceShareJwe,
              recoveryShareJwe,
            }
            addReceipt(state, requestId, 'recover-export', hash, response)
            logger.info(
              { did, version: state.wallet.shareSetVersion },
              'wallet recovered from export',
            )
            return { response }
          } catch (err) {
            if (err instanceof HttpError) throw err
            logger.warn({ err, did }, 'wallet export recovery failed')
            abort(403, 'wallet export is invalid')
          } finally {
            wipe(
              entropy,
              keys?.evmPrivateKey,
              keys?.solPrivateKey,
              ...(shares ?? []),
            )
          }
        })
      },
      'wallet export recovery failed',
    )
  })

  return app
}
