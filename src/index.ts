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
 */
import * as dotenv from 'dotenv'
dotenv.config()

import * as path from 'node:path'
import * as fs from 'node:fs'
import { createLogger } from './lib/shared.js'
import { createServiceJwtVerifier } from './auth/service-auth.js'
import { loadRootSeed } from './root-seed.js'
import { createSignerApp } from './service.js'
import { SignerStore } from './store.js'

const logger = createLogger('wallet-service')

function main(): void {
  const port = parseInt(process.env.WALLET_SERVICE_PORT || '3020', 10)
  const dataDir = process.env.WALLET_SERVICE_DATA_DIR || './data/wallet-service'
  const internalSecret = process.env.WALLET_SERVICE_ADMIN_SECRET || ''
  const serviceDid = process.env.SERVICE_DID || ''

  if (!internalSecret) {
    throw new Error('WALLET_SERVICE_ADMIN_SECRET must be set')
  }
  if (!serviceDid.startsWith('did:')) {
    throw new Error(
      'SERVICE_DID must be set to this service\u2019s DID (e.g. did:web:wallet.example.com) \u2014 it is the aud of every service-auth token',
    )
  }

  const rootSeed = loadRootSeed({
    SIGNER_ROOT_SEED_HEX: process.env.WALLET_SERVICE_ROOT_SEED_HEX,
    SIGNER_ROOT_SEED_FILE:
      process.env.WALLET_SERVICE_ROOT_SEED_FILE ||
      path.join(dataDir, 'root-seed'),
    SIGNER_ALLOW_DEV_SEED: process.env.WALLET_SERVICE_ALLOW_DEV_SEED,
  })

  fs.mkdirSync(dataDir, { recursive: true })
  const store = new SignerStore(path.join(dataDir, 'wallet-service.sqlite'))

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
    dstackSockPath: process.env.WALLET_SERVICE_DSTACK_SOCK,
  })

  const server = app.listen(port, () => {
    logger.info({ port, serviceDid }, 'atproto-wallet-service running')
  })

  const shutdown = () => {
    logger.info('atproto-wallet-service shutting down')
    server.close(() => {
      store.close()
      process.exit(0)
    })
  }
  process.on('SIGTERM', shutdown)
  process.on('SIGINT', shutdown)
}

try {
  main()
} catch (err) {
  logger.fatal({ err }, 'Failed to start atproto-wallet-service')
  process.exit(1)
}
