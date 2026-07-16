/**
 * atproto-wallet-service entry point.
 *
 * IMPORTANT deployment note: this service holds the root seed (KEK) and
 * every wallet's server share. It must run on confidential-compute
 * hardware (dstack on TDX/SEV-SNP, a cloud confidential VM, or Phala)
 * in any real deployment. Plain-process mode exists for development only.
 *
 * Unlike the tPDS signer, this service is client-facing: users on any
 * PDS authenticate with ATProto service-auth JWTs (aud = SERVICE_DID),
 * and wallet operations are authorized by user-signed envelopes.
 *
 * Spot / failover hardening: the service is designed to run on
 * preemptible TDX instances with an external dstack KMS and a durable
 * data disk. The pieces that make that safe:
 *   - WALLET_SERVICE_ROOT_SEED_SOURCE=dstack-kms fetches the root seed
 *     from the external KMS via the guest agent at every boot — nothing
 *     secret lives on the (disposable) boot disk (src/dstack-kms.ts);
 *   - the sqlite store runs synchronous=FULL + EXCLUSIVE locking so
 *     preemption cannot roll back a committed nonce and a failover
 *     replacement cannot double-attach the data disk (src/store.ts);
 *   - WALLET_SERVICE_PREEMPTION_WATCH=gcp watches the metadata server
 *     for the ~30s preemption notice (src/preemption.ts);
 *   - shutdown is idempotent and bounded: /health flips to 503
 *     (drain), in-flight requests get a grace period, the WAL is
 *     checkpointed, and the in-memory root seed is wiped.
 */
import * as dotenv from 'dotenv'
dotenv.config()

import * as path from 'node:path'
import * as fs from 'node:fs'
import { createLogger } from './lib/shared.js'
import { createServiceJwtVerifier } from './auth/service-auth.js'
import { loadRootSeed } from './root-seed.js'
import { loadRootSeedFromDstackKms } from './dstack-kms.js'
import { getAttestation } from './attestation.js'
import { assertProductionConfig, isProduction } from './production.js'
import { watchGcpPreemption, type PreemptionWatcher } from './preemption.js'
import { createSignerApp } from './service.js'
import { SqliteWalletStateRepository } from './store.js'

const logger = createLogger('wallet-service')

/**
 * Resolve the root seed. Explicit source selection — a wallet service
 * must never guess where its key material comes from:
 *   - 'dstack-kms': external dstack KMS via the local guest agent
 *     (spot-safe: deterministic across instance re-creation, nothing
 *     persisted on the host).
 *   - unset: legacy env-hex / seed-file behavior (dev, pet instances).
 */
async function resolveRootSeed(dataDir: string): Promise<Buffer> {
  const source = (process.env.WALLET_SERVICE_ROOT_SEED_SOURCE || '').trim()
  if (source === 'dstack-kms') {
    logger.info('loading root seed from external dstack KMS')
    return loadRootSeedFromDstackKms({
      sockPath: process.env.WALLET_SERVICE_DSTACK_SOCK,
      keyPath: process.env.WALLET_SERVICE_KMS_KEY_PATH,
    })
  }
  if (source !== '') {
    throw new Error(
      `Unknown WALLET_SERVICE_ROOT_SEED_SOURCE "${source}" — expected "dstack-kms" or unset`,
    )
  }
  return loadRootSeed({
    SIGNER_ROOT_SEED_HEX: process.env.WALLET_SERVICE_ROOT_SEED_HEX,
    SIGNER_ROOT_SEED_FILE:
      process.env.WALLET_SERVICE_ROOT_SEED_FILE ||
      path.join(dataDir, 'root-seed'),
    SIGNER_ALLOW_DEV_SEED: process.env.WALLET_SERVICE_ALLOW_DEV_SEED,
  })
}

async function main(): Promise<void> {
  // Fail before touching any wallet state: production must never use a
  // file/env/dev seed, even if one happens to be configured.
  assertProductionConfig(process.env)
  const production = isProduction(process.env)
  const port = parseInt(process.env.WALLET_SERVICE_PORT || '3020', 10)
  const dataDir = process.env.WALLET_SERVICE_DATA_DIR || './data/wallet-service'
  const internalSecret = process.env.WALLET_SERVICE_ADMIN_SECRET || ''
  const serviceDid = process.env.SERVICE_DID || ''
  const shutdownGraceMs = parseInt(
    process.env.WALLET_SERVICE_SHUTDOWN_GRACE_MS || '10000',
    10,
  )
  const trustProxyHops = parseInt(
    process.env.WALLET_SERVICE_TRUST_PROXY_HOPS || '0',
    10,
  )

  if (
    !Number.isSafeInteger(trustProxyHops) ||
    trustProxyHops < 0 ||
    trustProxyHops > 8
  ) {
    throw new Error(
      'WALLET_SERVICE_TRUST_PROXY_HOPS must be an integer from 0 to 8',
    )
  }
  if (!internalSecret) {
    throw new Error('WALLET_SERVICE_ADMIN_SECRET must be set')
  }
  if (!serviceDid.startsWith('did:')) {
    throw new Error(
      'SERVICE_DID must be set to this service\u2019s DID (e.g. did:web:wallet.example.com) \u2014 it is the aud of every service-auth token',
    )
  }

  const rootSeed = await resolveRootSeed(dataDir)
  const stateKeyEpoch = parseInt(
    process.env.WALLET_SERVICE_STATE_KEY_EPOCH || '1',
    10,
  )
  if (!Number.isSafeInteger(stateKeyEpoch) || stateKeyEpoch < 1) {
    throw new Error('WALLET_SERVICE_STATE_KEY_EPOCH must be a positive integer')
  }

  // A quote endpoint that silently downgrades to dev mode is unsafe in
  // production. Probe the guest agent before opening the HTTP listener;
  // the real endpoint later binds its quote to the identity key.
  if (production) {
    await getAttestation({
      reportDataHex: '00'.repeat(32),
      dstackSockPath: process.env.WALLET_SERVICE_DSTACK_SOCK,
      requireTee: true,
    })
  }

  fs.mkdirSync(dataDir, { recursive: true })
  const store = new SqliteWalletStateRepository(
    path.join(dataDir, 'wallet-service.sqlite'),
    { rootSeed, keyEpoch: stateKeyEpoch },
  )

  let draining = false
  const app = createSignerApp({
    rootSeed,
    store,
    internalSecret,
    verifyServiceJwt: createServiceJwtVerifier({
      serviceDid,
      plcUrl: process.env.PLC_URL,
    }),
    freshnessSec: process.env.WALLET_SERVICE_FRESHNESS_SEC
      ? parseInt(process.env.WALLET_SERVICE_FRESHNESS_SEC, 10)
      : undefined,
    stateKeyEpoch,
    dstackSockPath: process.env.WALLET_SERVICE_DSTACK_SOCK,
    requireTeeAttestation: production,
    trustProxyHops,
    isDraining: () => draining,
    serviceDid,
  })

  const server = app.listen(port, () => {
    logger.info({ port, serviceDid }, 'atproto-wallet-service running')
  })

  let preemptionWatcher: PreemptionWatcher | undefined

  /**
   * Controlled shutdown, sized to fit inside GCP's ~30s spot
   * preemption window. Idempotent — SIGTERM, SIGINT, and the
   * preemption watcher may all fire for the same event.
   *
   * Order matters:
   *   1. flip /health to 503 so the LB drains us (failover starts);
   *   2. stop accepting connections, close idle keep-alives;
   *   3. give in-flight requests a bounded grace period;
   *   4. checkpoint + close the store (durable disk left clean);
   *   5. wipe the in-memory root seed and exit.
   */
  let shuttingDown = false
  const shutdown = (reason: string): void => {
    if (shuttingDown) return
    shuttingDown = true
    draining = true
    preemptionWatcher?.stop()
    logger.info(
      { reason, graceMs: shutdownGraceMs },
      'atproto-wallet-service shutting down',
    )

    const finish = (code: number): void => {
      try {
        store.close()
      } catch (err) {
        logger.error({ err }, 'store close failed during shutdown')
        code = 1
      }
      rootSeed.fill(0)
      process.exit(code)
    }

    const deadline = setTimeout(() => {
      logger.warn('shutdown grace period expired — forcing connection close')
      server.closeAllConnections()
      finish(1)
    }, shutdownGraceMs)
    deadline.unref()

    server.close(() => {
      clearTimeout(deadline)
      finish(0)
    })
    server.closeIdleConnections()
  }
  process.on('SIGTERM', () => shutdown('SIGTERM'))
  process.on('SIGINT', () => shutdown('SIGINT'))

  if (process.env.WALLET_SERVICE_PREEMPTION_WATCH === 'gcp') {
    preemptionWatcher = watchGcpPreemption({
      onPreempted: () => shutdown('gcp-spot-preemption'),
    })
    logger.info('GCP spot preemption watcher active')
  }
}

main().catch((err) => {
  logger.fatal({ err }, 'Failed to start atproto-wallet-service')
  process.exit(1)
})
