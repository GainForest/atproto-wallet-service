import { describe, expect, it } from 'vitest'
import { assertProductionConfig, isProduction } from '../production.js'

describe('production fail-closed guards', () => {
  it('allows local seed sources only outside production', () => {
    expect(() => assertProductionConfig({ NODE_ENV: 'test' })).not.toThrow()
    expect(isProduction({ NODE_ENV: 'development' })).toBe(false)
  })

  it('rejects file/env/dev seed sources in production', () => {
    expect(() => assertProductionConfig({ NODE_ENV: 'production' })).toThrow(
      /dstack-kms/,
    )
    expect(() =>
      assertProductionConfig({
        NODE_ENV: 'production',
        WALLET_SERVICE_ROOT_SEED_SOURCE: '',
      }),
    ).toThrow(/forbidden/)
  })

  it('requires the explicit dstack-kms source', () => {
    expect(() =>
      assertProductionConfig({
        NODE_ENV: 'production',
        WALLET_SERVICE_ROOT_SEED_SOURCE: 'dstack-kms',
      }),
    ).not.toThrow()
  })
})
