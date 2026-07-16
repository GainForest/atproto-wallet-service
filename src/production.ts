/** Production-only fail-closed configuration checks. */

export interface ProductionEnv {
  NODE_ENV?: string
  WALLET_SERVICE_ROOT_SEED_SOURCE?: string
}

export function isProduction(env: ProductionEnv): boolean {
  return env.NODE_ENV === 'production'
}

/**
 * A production wallet workload must obtain key material from an
 * attestation-gated KMS. Environment and local-file seeds let the VM
 * administrator copy wallet keys and are development-only.
 */
export function assertProductionConfig(env: ProductionEnv): void {
  if (!isProduction(env)) return
  if ((env.WALLET_SERVICE_ROOT_SEED_SOURCE ?? '').trim() !== 'dstack-kms') {
    throw new Error(
      'Production requires WALLET_SERVICE_ROOT_SEED_SOURCE=dstack-kms; ' +
        'file/env/dev root seeds are forbidden',
    )
  }
}
