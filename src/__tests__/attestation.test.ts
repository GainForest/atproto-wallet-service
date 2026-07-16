import { describe, expect, it } from 'vitest'
import { getAttestation } from '../attestation.js'

describe('attestation downgrade policy', () => {
  const reportDataHex = 'ab'.repeat(32)

  it('allows explicit dev mode outside production', async () => {
    await expect(
      getAttestation({
        reportDataHex,
        dstackSockPath: '/definitely/no/dstack.sock',
      }),
    ).resolves.toMatchObject({ mode: 'dev', quote: null })
  })

  it('fails closed when TEE attestation is required', async () => {
    await expect(
      getAttestation({
        reportDataHex,
        dstackSockPath: '/definitely/no/dstack.sock',
        requireTee: true,
      }),
    ).rejects.toThrow(/no TEE guest agent/)
  })
})
