/**
 * Standalone wallet-service HTTP surface.
 *
 * Unlike its tPDS ancestor (where the PDS relayed every call and gated
 * transport with an internal secret), this service is exposed directly
 * to clients and serves users on ANY PDS. Three trust tiers:
 *
 *   USER TIER (ATProto service-auth JWT — auth/service-auth.ts):
 *     POST /v1/wallet/enroll  — TOFU-registers the user's request key.
 *       Authenticated by a `com.atproto.server.getServiceAuth` token
 *       (aud = this service's DID, lxm = app.gainforest.wallet.enroll)
 *       verified against the signing key in the user's DID document.
 *     POST /v1/wallet/create  — generates per-wallet entropy in-enclave
 *       (or claims a pregenerated wallet's entropy — same addresses),
 *       splits it 2-of-3, keeps only the KEK-encrypted server share,
 *       and returns the device + recovery shares encrypted to the
 *       enrolled request key.
 *     GET  /v1/wallet/info/:did — full wallet info for the owner.
 *
 *   ENVELOPE TIER (no token — the user-signed envelope IS the auth):
 *     POST /v1/wallet/sign    — reconstructs the key transiently from
 *       server share + the envelope's device share, signs, wipes. ONLY
 *       for envelopes signed by the enrolled user request key.
 *     POST /v1/wallet/export  — same reconstruction, returns the seed
 *       material encrypted to the request key (credible exit).
 *     POST /v1/wallet/recover — server share + user's recovery share;
 *       re-shards with fresh coefficients, optionally rotates the
 *       enrolled request key. Authorization is possession of a share
 *       that actually reconstructs this wallet — not the caller.
 *     POST /v1/wallet/recover-export — restores a legacy full-wallet export;
 *       encrypted entropy is verified against the registered wallet before
 *       fresh device/recovery shares are issued.
 *
 *   ADMIN TIER (x-internal-secret — operator tooling only):
 *     POST /v1/wallet/pregenerate — defer-split provisioning for a DID
 *       with no enrollment yet: the whole entropy is persisted
 *       KEK-encrypted so assets can be sent to the addresses before
 *       first login. Receive-only and enclave-custodial until claimed.
 *     GET  /v1/wallet/enrollment/:did — enrollment existence check.
 *
 *   OPEN (read-only):
 *     GET  /v1/wallet/public/:did — addresses only (receive/lookup).
 *     GET  /v1/attestation, GET /health.
 *
 * The repo-signing path deliberately does NOT exist here — repo keys
 * are the PDS's business (see tPDS). This service holds wallet share
 * material only.
 */
import * as crypto from 'node:crypto'
import express, {
  type Application,
  type Request,
  type Response,
  type NextFunction,
} from 'express'
import cors from 'cors'
import { rateLimit } from 'express-rate-limit'
import { timingSafeEqual, createLogger } from './lib/shared.js'
import type { VerifyServiceJwt } from './auth/service-auth.js'
import { getAttestation, type AttestationResult } from './attestation.js'
import { deriveIdentityPublicKey } from './derive.js'
import { buildDidWebDocument } from './did-web.js'
import {
  DEFAULT_FRESHNESS_SEC,
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
import type { PregenRow, SignerStore, WalletRow } from './store.js'

const logger = createLogger('wallet-service')

export interface SignerServiceOptions {
  rootSeed: Uint8Array
  store: SignerStore
  /** Gates the ADMIN tier only (pregenerate, enrollment check). */
  internalSecret: string
  /** Verifies user service-auth JWTs — injectable for tests. */
  verifyServiceJwt: VerifyServiceJwt
  freshnessSec?: number
  dstackSockPath?: string
  /**
   * When provided and returning true, /health flips to 503 — the
   * load-balancer drain signal during controlled shutdown/failover
   * (spot preemption, deploys). Existing in-flight requests still
   * complete; new traffic is steered away.
   */
  isDraining?: () => boolean
  /**
   * The service's own DID (aud of every accepted service-auth JWT).
   * When it is a bare-domain did:web, /.well-known/did.json is served,
   * binding the DID to the identity key and HTTPS endpoint.
   */
  serviceDid?: string
}

/** lxm values — the lexicon method each service-auth token must target. */
export const LXM = {
  enroll: 'app.gainforest.wallet.enroll',
  create: 'app.gainforest.wallet.create',
  getWallet: 'app.gainforest.wallet.getWallet',
} as const

/** Compressed P-256 public key: 33 bytes, 0x02/0x03 prefix. */
export function isCompressedP256Hex(value: unknown): value is string {
  return typeof value === 'string' && /^0[23][0-9a-fA-F]{64}$/.test(value)
}

/** Public wallet info — safe to return to anyone who may know the DID. */
function walletPublicInfo(row: WalletRow): Record<string, unknown> {
  return {
    did: row.did,
    evm: { address: row.evmAddress, publicKeyHex: row.evmPubkeyHex },
    sol: { address: row.solAddress, publicKeyHex: row.solPubkeyHex },
    version: row.version,
    createdAt: row.createdAt,
  }
}

/** Public info for an unclaimed pregenerated wallet (receive-only). */
function pregenPublicInfo(row: PregenRow): Record<string, unknown> {
  return {
    did: row.did,
    evm: { address: row.evmAddress, publicKeyHex: row.evmPubkeyHex },
    sol: { address: row.solAddress, publicKeyHex: row.solPubkeyHex },
    createdAt: row.createdAt,
  }
}

export function createSignerApp(opts: SignerServiceOptions): Application {
  const { rootSeed, store, internalSecret } = opts
  const freshnessSec = opts.freshnessSec ?? DEFAULT_FRESHNESS_SEC

  const identityPubkeyHex = bytesToHex(deriveIdentityPublicKey(rootSeed))
  const reportDataHex = crypto
    .createHash('sha256')
    .update(Buffer.from(identityPubkeyHex, 'hex'))
    .digest('hex')
  const shareKek = deriveShareKek(rootSeed)
  const walletEncryptionPublicJwk = getWalletEncryptionPublicJwk(rootSeed)

  const app = express()
  app.use(cors())
  app.use(express.json({ limit: '128kb' }))

  // Basic abuse damping on the write paths. Envelope verification is the
  // real gate — this only bounds brute-force and reconstruction load.
  const writeLimiter = rateLimit({
    windowMs: 60_000,
    limit: 60,
    standardHeaders: true,
    legacyHeaders: false,
  })

  /** ADMIN tier: operator tooling (pregenerate, enrollment check). */
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

  /**
   * USER tier: ATProto service-auth JWT bound to a specific lexicon
   * method. On success the verified user DID is placed on
   * `res.locals.authDid`; handlers must use that (never a body DID).
   */
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

  app.get('/health', (_req, res) => {
    if (opts.isDraining?.()) {
      res
        .status(503)
        .json({ status: 'draining', service: 'atproto-wallet-service' })
      return
    }
    res.json({ status: 'ok', service: 'atproto-wallet-service' })
  })

  // did:web resolution — bind SERVICE_DID to this deployment's identity
  // key and endpoint. Built once at startup; fails loud on a malformed
  // did:web rather than serving a document that misrepresents the DID.
  if (opts.serviceDid?.startsWith('did:web:')) {
    const didDoc = buildDidWebDocument(opts.serviceDid, identityPubkeyHex)
    app.get('/.well-known/did.json', (_req, res) => {
      res.json(didDoc)
    })
  }

  app.get('/v1/attestation', async (_req, res) => {
    let attestation: AttestationResult
    try {
      attestation = await getAttestation({
        reportDataHex,
        dstackSockPath: opts.dstackSockPath,
      })
    } catch (err) {
      /* v8 ignore next 3 -- getAttestation traps its own errors */
      logger.error({ err }, 'attestation failed')
      res.status(500).json({ error: 'attestation failed' })
      return
    }
    res.json({
      ...attestation,
      identityPublicKeyHex: identityPubkeyHex,
      walletEncryptionPublicJwk,
    })
  })

  /**
   * OPEN receive/lookup surface: addresses only, no enrollment state,
   * no encryption keys. Lets anyone prepare a transfer to a DID (and
   * lets indexers verify binding records) without authentication.
   */
  app.get('/v1/wallet/public/:did', (req, res) => {
    const did = req.params.did
    if (!isPlausibleDid(did)) {
      res.status(400).json({ error: 'invalid did' })
      return
    }
    const wallet = store.getWallet(did)
    if (wallet) {
      res.json({ status: 'active', wallet: walletPublicInfo(wallet) })
      return
    }
    const pregen = store.getPregen(did)
    if (pregen) {
      res.json({ status: 'pregenerated', wallet: pregenPublicInfo(pregen) })
      return
    }
    res.status(404).json({ error: 'no wallet for this DID' })
  })

  // ── USER TIER (service-auth JWT) ──────────────────────────────────
  app.post(
    '/v1/wallet/enroll',
    writeLimiter,
    requireServiceAuth(LXM.enroll),
    (req, res) => {
      const did = res.locals.authDid as string
      const { requestPublicKeyHex } = req.body ?? {}
      if (
        !isCompressedP256Hex(requestPublicKeyHex) ||
        !isValidP256PublicKeyHex(requestPublicKeyHex)
      ) {
        res.status(400).json({ error: 'invalid requestPublicKeyHex' })
        return
      }
      const outcome = store.enroll(did, requestPublicKeyHex.toLowerCase())
      if (outcome === 'conflict') {
        res.status(409).json({
          error:
            'a different request key is already enrolled for this DID; key rotation requires wallet recovery',
        })
        return
      }
      logger.info({ did, outcome }, 'wallet enrollment')
      res.json({ status: outcome })
    },
  )

  app.get('/v1/wallet/enrollment/:did', requireSecret, (req, res) => {
    const did = req.params.did
    if (!isPlausibleDid(did)) {
      res.status(400).json({ error: 'invalid did' })
      return
    }
    res.json({ enrolled: store.getEnrollment(did) !== null })
  })

  app.get(
    '/v1/wallet/info/:did',
    requireServiceAuth(LXM.getWallet),
    (req, res) => {
      const did = req.params.did
      if (!isPlausibleDid(did)) {
        res.status(400).json({ error: 'invalid did' })
        return
      }
      if (did !== res.locals.authDid) {
        res
          .status(403)
          .json({ error: 'token DID does not match requested DID' })
        return
      }
      const wallet = store.getWallet(did)
      const pregen = wallet ? null : store.getPregen(did)
      res.json({
        enrolled: store.getEnrollment(did) !== null,
        wallet: wallet ? walletPublicInfo(wallet) : null,
        pregen: pregen ? pregenPublicInfo(pregen) : null,
        walletEncryptionPublicJwk,
      })
    },
  )

  /**
   * Pregenerate (defer-split): provision a receive-only wallet for a
   * DID that has no enrollment yet, so assets can be sent to the
   * addresses before the user's first login. The DID only has to be
   * plausible — it may belong to an account that still lives on
   * another PDS and migrates here later; claiming (not pregeneration)
   * is what requires a local, authenticated account.
   *
   * This is the ONE place whole (unsplit) entropy is persisted —
   * KEK-encrypted, distinct AAD domain. Until claimed, custody of the
   * wallet rests entirely with the enclave. Two rules bound that
   * window:
   *   - unclaimed wallets can never sign/export/recover — those paths
   *     all require the wallet row that only claiming creates;
   *   - the first /v1/wallet/create after enrollment splits the
   *     entropy 2-of-3 and DELETES the pregen blob atomically.
   * Idempotent: repeat calls return the existing record's addresses.
   */
  app.post('/v1/wallet/pregenerate', requireSecret, (req, res) => {
    const { did } = req.body ?? {}
    if (!isPlausibleDid(did)) {
      res.status(400).json({ error: 'invalid did' })
      return
    }
    if (store.getWallet(did)) {
      res.status(409).json({ error: 'wallet already exists for this DID' })
      return
    }
    const existing = store.getPregen(did)
    if (existing) {
      res.json({ status: 'exists', wallet: pregenPublicInfo(existing) })
      return
    }
    const entropy = generateWalletEntropy()
    let keys: WalletChainKeys | undefined
    try {
      keys = deriveChainKeys(entropy)
      const created = store.createPregen({
        did,
        entropyCipherHex: encryptPregenEntropy(shareKek, did, entropy),
        evmPubkeyHex: bytesToHex(keys.evmPublicKey),
        evmAddress: keys.evmAddress,
        solPubkeyHex: bytesToHex(keys.solPublicKey),
        solAddress: keys.solAddress,
      })
      const row = store.getPregen(did)
      /* v8 ignore next 4 -- lost-race guard, not reachable single-threaded */
      if (!row) {
        res.status(500).json({ error: 'wallet pregeneration failed' })
        return
      }
      logger.info(
        { did, created },
        'wallet pregenerated (unclaimed, receive-only)',
      )
      res.json({
        status: created ? 'pregenerated' : 'exists',
        wallet: pregenPublicInfo(row),
      })
      /* v8 ignore next 4 -- CSPRNG/sqlite failures are not reproducible */
    } catch (err) {
      logger.error({ err, did }, 'wallet pregeneration failed')
      res.status(500).json({ error: 'wallet pregeneration failed' })
    } finally {
      wipe(entropy, keys?.evmPrivateKey, keys?.solPrivateKey)
    }
  })

  /**
   * Create the wallet: per-wallet entropy, 2-of-3 split. The server
   * share is the ONLY thing persisted (encrypted under the KEK); the
   * device and recovery shares are returned encrypted to the enrolled
   * request key and are gone from the enclave when the response is
   * sent. The client MUST re-protect the recovery share under a
   * user-controlled recovery factor — it is not re-issuable without a
   * recovery (fresh coefficients) round.
   *
   * If a pregenerated record exists for the DID, this call CLAIMS it:
   * the pregenerated entropy — not fresh CSPRNG output — becomes the
   * wallet (so assets already sent to the advertised addresses are
   * now under the user's 2-of-3 split), and the whole-entropy blob is
   * deleted in the same transaction. Response status 'claimed'
   * instead of 'created'.
   */
  app.post(
    '/v1/wallet/create',
    writeLimiter,
    requireServiceAuth(LXM.create),
    async (req, res) => {
      const did = res.locals.authDid as string
      const enrollment = store.getEnrollment(did)
      if (!enrollment) {
        res.status(403).json({
          error: 'enroll a request key before creating a wallet',
        })
        return
      }
      if (store.getWallet(did)) {
        res.status(409).json({ error: 'wallet already exists for this DID' })
        return
      }

      const pregen = store.getPregen(did)
      let entropy: Uint8Array | undefined
      let keys: WalletChainKeys | undefined
      let shares: [Uint8Array, Uint8Array, Uint8Array] | undefined
      try {
        entropy = pregen
          ? decryptPregenEntropy(shareKek, did, pregen.entropyCipherHex)
          : generateWalletEntropy()
        keys = deriveChainKeys(entropy)
        // A pregen blob that decrypts (KEK + AAD verified) but does not
        // reproduce the advertised addresses is corrupt — refuse rather
        // than bind the user to unknown material.
        /* v8 ignore next 5 -- requires a corrupted-but-authentic blob */
        if (pregen && bytesToHex(keys.evmPublicKey) !== pregen.evmPubkeyHex) {
          res
            .status(500)
            .json({ error: 'pregenerated wallet integrity check failed' })
          return
        }
        shares = await splitWalletEntropy(entropy)
        const walletRow = {
          did,
          serverShareCipherHex: encryptServerShare(shareKek, did, shares[0]),
          evmPubkeyHex: bytesToHex(keys.evmPublicKey),
          evmAddress: keys.evmAddress,
          solPubkeyHex: bytesToHex(keys.solPublicKey),
          solAddress: keys.solAddress,
        }
        const created = pregen
          ? store.claimPregen(did, walletRow)
          : store.createWallet(walletRow)
        if (!created) {
          res.status(409).json({ error: 'wallet already exists for this DID' })
          return
        }
        const [deviceShareJwe, recoveryShareJwe] = await Promise.all([
          encryptToRequestKey(enrollment.requestPubkeyHex, shares[1]),
          encryptToRequestKey(enrollment.requestPubkeyHex, shares[2]),
        ])
        logger.info(
          { did, claimedPregen: pregen !== null },
          'wallet created (2-of-3 shares issued)',
        )
        res.json({
          status: pregen ? 'claimed' : 'created',
          wallet: walletPublicInfo(store.getWallet(did) as WalletRow),
          deviceShareJwe,
          recoveryShareJwe,
        })
      } catch (err) {
        logger.error({ err, did }, 'wallet creation failed')
        res.status(500).json({ error: 'wallet creation failed' })
      } finally {
        wipe(
          entropy,
          keys?.evmPrivateKey,
          keys?.solPrivateKey,
          ...(shares ?? []),
        )
      }
    },
  )

  /**
   * Verify an envelope, consume its nonce, and reconstruct the wallet
   * entropy from server share + envelope device share. Returns null
   * after writing the HTTP error response on any failure. The caller
   * MUST wipe the returned material.
   */
  async function reconstructForEnvelope(
    req: Request,
    res: Response,
    expectedOp: WalletOp,
  ): Promise<{
    payload: WalletEnvelopePayload
    entropy: Uint8Array
    keys: WalletChainKeys
    wallet: WalletRow
  } | null> {
    const { payload, sig } = req.body ?? {}
    if (typeof payload !== 'string' || typeof sig !== 'string') {
      res.status(400).json({ error: 'missing payload or sig' })
      return null
    }

    // Peek at the DID inside the payload to find the enrolled key, but
    // trust NOTHING until verifyEnvelope has checked the signature.
    let claimedDid: unknown
    try {
      claimedDid = JSON.parse(
        Buffer.from(payload, 'base64url').toString('utf8'),
      )?.did
    } catch {
      res.status(400).json({ error: 'malformed payload' })
      return null
    }
    if (!isPlausibleDid(claimedDid)) {
      res.status(400).json({ error: 'malformed payload' })
      return null
    }
    const enrollment = store.getEnrollment(claimedDid)
    if (!enrollment) {
      res.status(403).json({ error: 'no wallet enrollment for this DID' })
      return null
    }

    const result = verifyEnvelope({
      payloadB64: payload,
      sigB64: sig,
      requestPubkeyHex: enrollment.requestPubkeyHex,
      expectedOp,
      freshnessSec,
    })
    if (!result.ok) {
      logger.warn(
        { did: claimedDid, reason: result.error },
        'wallet envelope rejected',
      )
      res.status(403).json({ error: result.error })
      return null
    }
    const p = result.payload

    const wallet = store.getWallet(p.did)
    if (!wallet) {
      res.status(403).json({ error: 'no wallet exists for this DID' })
      return null
    }

    if (!store.consumeNonce(p.did, p.nonce)) {
      res.status(409).json({ error: 'nonce replayed or out of order' })
      return null
    }

    let deviceShare: Uint8Array | undefined
    let serverShare: Uint8Array | undefined
    let entropy: Uint8Array | undefined
    try {
      deviceShare = await decryptJweToEnclave(rootSeed, p.deviceShareJwe)
      serverShare = decryptServerShare(
        shareKek,
        p.did,
        wallet.serverShareCipherHex,
      )
      entropy = await combineWalletShares(serverShare, deviceShare)
      const keys = deriveChainKeys(entropy)
      // Integrity check: a share that does not reproduce the wallet's
      // registered public keys is not this wallet's share.
      if (bytesToHex(keys.evmPublicKey) !== wallet.evmPubkeyHex) {
        wipe(entropy, keys.evmPrivateKey, keys.solPrivateKey)
        res.status(403).json({ error: 'device share does not match wallet' })
        return null
      }
      return { payload: p, entropy, keys, wallet }
    } catch (err) {
      wipe(entropy)
      logger.warn({ err, did: p.did }, 'wallet share reconstruction failed')
      res.status(403).json({ error: 'share reconstruction failed' })
      return null
    } finally {
      wipe(deviceShare, serverShare)
    }
  }

  app.post('/v1/wallet/sign', writeLimiter, async (req, res) => {
    const rec = await reconstructForEnvelope(req, res, 'sign')
    if (!rec) return
    const { payload: p, entropy, keys } = rec
    try {
      if (p.purpose === 'wallet/evm') {
        const { signature, recovery } = signEvmDigestWithKey(
          keys.evmPrivateKey,
          // Payload shape already validated by verifyEnvelope
          hexToBytes(p.digestHex as string),
        )
        logger.info(
          { did: p.did, purpose: p.purpose },
          'wallet signature issued',
        )
        res.json({ signatureHex: bytesToHex(signature), recovery })
        return
      }
      const signature = signSolMessageWithKey(
        keys.solPrivateKey,
        Uint8Array.from(Buffer.from(p.messageBase64 as string, 'base64url')),
      )
      logger.info({ did: p.did, purpose: p.purpose }, 'wallet signature issued')
      res.json({ signatureHex: bytesToHex(signature) })
      /* v8 ignore next 4 -- payload shapes are pre-validated */
    } catch (err) {
      logger.error({ err, did: p.did }, 'wallet signing failed')
      res.status(500).json({ error: 'wallet signing failed' })
    } finally {
      wipe(entropy, keys.evmPrivateKey, keys.solPrivateKey)
    }
  })

  /**
   * Credible exit: hand the user their key material, encrypted to
   * their enrolled request key. The PDS relays ciphertext; the
   * operator alone can never satisfy this route (it needs the user's
   * device share inside a user-signed envelope).
   */
  app.post('/v1/wallet/export', writeLimiter, async (req, res) => {
    const rec = await reconstructForEnvelope(req, res, 'export')
    if (!rec) return
    const { payload: p, entropy, keys } = rec
    let exportBytes: Uint8Array | undefined
    try {
      const enrollment = store.getEnrollment(p.did)
      /* v8 ignore next 4 -- enrollment checked in reconstructForEnvelope */
      if (!enrollment) {
        res.status(403).json({ error: 'no wallet enrollment for this DID' })
        return
      }
      exportBytes = buildExportPayload(entropy, keys)
      const exportJwe = await encryptToRequestKey(
        enrollment.requestPubkeyHex,
        exportBytes,
      )
      logger.info({ did: p.did }, 'wallet exported to user')
      res.json({ exportJwe })
      /* v8 ignore next 4 -- enrolled keys are validated on-curve */
    } catch (err) {
      logger.error({ err, did: p.did }, 'wallet export failed')
      res.status(500).json({ error: 'wallet export failed' })
    } finally {
      wipe(entropy, keys.evmPrivateKey, keys.solPrivateKey, exportBytes)
    }
  })

  /**
   * Device-loss recovery. The user proves control by presenting the
   * RECOVERY share (their recovery factor protects it; the operator
   * never could read it). The wallet entropy is reconstructed from
   * server + recovery shares, verified against the stored public keys,
   * and re-split with FRESH coefficients — old shares (including one
   * on a stolen device) become useless. Optionally rotates the
   * enrolled request key to the user's new device key.
   */
  app.post('/v1/wallet/recover', writeLimiter, async (req, res) => {
    const { did, recoveryShareJwe, requestPublicKeyHex } = req.body ?? {}
    if (!isPlausibleDid(did) || !isCompactJwe(recoveryShareJwe)) {
      res.status(400).json({ error: 'invalid did or recoveryShareJwe' })
      return
    }
    if (
      requestPublicKeyHex !== undefined &&
      (!isCompressedP256Hex(requestPublicKeyHex) ||
        !isValidP256PublicKeyHex(requestPublicKeyHex))
    ) {
      res.status(400).json({ error: 'invalid requestPublicKeyHex' })
      return
    }
    const wallet = store.getWallet(did)
    const enrollment = store.getEnrollment(did)
    if (!wallet || !enrollment) {
      res.status(403).json({ error: 'no wallet exists for this DID' })
      return
    }

    let recoveryShare: Uint8Array | undefined
    let serverShare: Uint8Array | undefined
    let entropy: Uint8Array | undefined
    let keys: WalletChainKeys | undefined
    let newShares: [Uint8Array, Uint8Array, Uint8Array] | undefined
    try {
      try {
        recoveryShare = await decryptJweToEnclave(rootSeed, recoveryShareJwe)
        serverShare = decryptServerShare(
          shareKek,
          did,
          wallet.serverShareCipherHex,
        )
        entropy = await combineWalletShares(serverShare, recoveryShare)
        keys = deriveChainKeys(entropy)
      } catch (err) {
        logger.warn({ err, did }, 'wallet recovery reconstruction failed')
        res.status(403).json({ error: 'share reconstruction failed' })
        return
      }
      if (bytesToHex(keys.evmPublicKey) !== wallet.evmPubkeyHex) {
        res.status(403).json({ error: 'recovery share does not match wallet' })
        return
      }

      // Fresh coefficients: every share changes, forward secrecy holds.
      newShares = await splitWalletEntropy(entropy)
      const version = store.replaceServerShare(
        did,
        encryptServerShare(shareKek, did, newShares[0]),
      )
      const targetKeyHex =
        typeof requestPublicKeyHex === 'string'
          ? requestPublicKeyHex.toLowerCase()
          : enrollment.requestPubkeyHex
      if (targetKeyHex !== enrollment.requestPubkeyHex) {
        store.rotateEnrollment(did, targetKeyHex)
        logger.info({ did }, 'request key rotated during recovery')
      }
      const [deviceShareJwe, newRecoveryShareJwe] = await Promise.all([
        encryptToRequestKey(targetKeyHex, newShares[1]),
        encryptToRequestKey(targetKeyHex, newShares[2]),
      ])
      logger.info({ did, version }, 'wallet recovered (re-sharded)')
      res.json({
        status: 'recovered',
        version,
        deviceShareJwe,
        recoveryShareJwe: newRecoveryShareJwe,
      })
      /* v8 ignore next 4 -- request keys are validated on-curve above */
    } catch (err) {
      logger.error({ err, did }, 'wallet recovery failed')
      res.status(500).json({ error: 'wallet recovery failed' })
    } finally {
      wipe(
        recoveryShare,
        serverShare,
        entropy,
        keys?.evmPrivateKey,
        keys?.solPrivateKey,
        ...(newShares ?? []),
      )
    }
  })

  /**
   * Legacy/full-export recovery. The browser sends only wallet entropy,
   * JWE-encrypted to the enclave. Possession of entropy is the authorization;
   * its derived public key must exactly match the registered wallet before the
   * server share or enrollment is changed.
   */
  app.post('/v1/wallet/recover-export', writeLimiter, async (req, res) => {
    const { did, entropyJwe, requestPublicKeyHex } = req.body ?? {}
    if (!isPlausibleDid(did) || !isCompactJwe(entropyJwe)) {
      res.status(400).json({ error: 'invalid did or entropyJwe' })
      return
    }
    if (
      !isCompressedP256Hex(requestPublicKeyHex) ||
      !isValidP256PublicKeyHex(requestPublicKeyHex)
    ) {
      res.status(400).json({ error: 'invalid requestPublicKeyHex' })
      return
    }
    const wallet = store.getWallet(did)
    const enrollment = store.getEnrollment(did)
    if (!wallet || !enrollment) {
      res.status(403).json({ error: 'no wallet exists for this DID' })
      return
    }

    let entropy: Uint8Array | undefined
    let keys: WalletChainKeys | undefined
    let newShares: [Uint8Array, Uint8Array, Uint8Array] | undefined
    try {
      try {
        entropy = await decryptJweToEnclave(rootSeed, entropyJwe)
        keys = deriveChainKeys(entropy)
      } catch (err) {
        logger.warn({ err, did }, 'wallet export recovery decryption failed')
        res.status(403).json({ error: 'wallet export is invalid' })
        return
      }
      if (bytesToHex(keys.evmPublicKey) !== wallet.evmPubkeyHex) {
        res.status(403).json({ error: 'wallet export does not match wallet' })
        return
      }

      newShares = await splitWalletEntropy(entropy)
      const targetKeyHex = requestPublicKeyHex.toLowerCase()
      const [deviceShareJwe, recoveryShareJwe] = await Promise.all([
        encryptToRequestKey(targetKeyHex, newShares[1]),
        encryptToRequestKey(targetKeyHex, newShares[2]),
      ])
      const version = store.replaceServerShare(
        did,
        encryptServerShare(shareKek, did, newShares[0]),
      )
      if (targetKeyHex !== enrollment.requestPubkeyHex) {
        store.rotateEnrollment(did, targetKeyHex)
        logger.info({ did }, 'request key rotated during export recovery')
      }
      logger.info({ did, version }, 'wallet recovered from export (re-sharded)')
      res.json({
        status: 'recovered-from-export',
        version,
        deviceShareJwe,
        recoveryShareJwe,
      })
    } catch (err) {
      logger.error({ err, did }, 'wallet export recovery failed')
      res.status(500).json({ error: 'wallet export recovery failed' })
    } finally {
      wipe(
        entropy,
        keys?.evmPrivateKey,
        keys?.solPrivateKey,
        ...(newShares ?? []),
      )
    }
  })

  return app
}
