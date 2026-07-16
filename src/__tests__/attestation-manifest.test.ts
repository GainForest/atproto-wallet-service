import { describe, expect, it } from 'vitest'
import {
  ATTESTATION_PROTOCOL,
  attestationManifestReportData,
  challengeBoundReportData,
  createAttestationManifest,
  isValidAttestationChallenge,
} from '../attestation-manifest.js'

const jwk = {
  kty: 'EC',
  crv: 'P-256',
  x: 'x-coordinate',
  y: 'y-coordinate',
}

describe('attestation manifest', () => {
  it('binds the service identity, protocol, and wallet encryption key', () => {
    const manifest = createAttestationManifest({
      serviceDid: 'did:web:wallet.example.com',
      identityPublicKeyHex: '02' + 'ab'.repeat(32),
      walletEncryptionPublicJwk: jwk,
    })

    expect(manifest).toEqual({
      version: 1,
      protocol: ATTESTATION_PROTOCOL,
      serviceDid: 'did:web:wallet.example.com',
      identityPublicKeyHex: '02' + 'ab'.repeat(32),
      walletEncryptionPublicJwk: jwk,
    })
    expect(attestationManifestReportData(manifest)).toMatch(/^[0-9a-f]{64}$/)
  })

  it('changes report data when any security binding changes', () => {
    const base = createAttestationManifest({
      serviceDid: 'did:web:wallet.example.com',
      identityPublicKeyHex: '02' + 'ab'.repeat(32),
      walletEncryptionPublicJwk: jwk,
    })
    const changed = createAttestationManifest({
      serviceDid: 'did:web:evil.example.com',
      identityPublicKeyHex: base.identityPublicKeyHex,
      walletEncryptionPublicJwk: jwk,
    })

    expect(attestationManifestReportData(changed)).not.toBe(
      attestationManifestReportData(base),
    )
  })

  it('binds a fresh verifier challenge into the second report-data half', () => {
    const manifest = createAttestationManifest({
      serviceDid: 'did:web:wallet.example.com',
      identityPublicKeyHex: '02' + 'ab'.repeat(32),
      walletEncryptionPublicJwk: jwk,
    })
    const challenge = Buffer.alloc(32, 7).toString('base64url')
    const reportData = challengeBoundReportData(manifest, challenge)

    expect(isValidAttestationChallenge(challenge)).toBe(true)
    expect(reportData).toHaveLength(128)
    expect(reportData.slice(0, 64)).toBe(
      attestationManifestReportData(manifest),
    )
    expect(challengeBoundReportData(manifest, challenge)).toBe(reportData)
    expect(
      challengeBoundReportData(
        manifest,
        Buffer.alloc(32, 8).toString('base64url'),
      ),
    ).not.toBe(reportData)
  })

  it('rejects malformed or undersized challenges', () => {
    expect(isValidAttestationChallenge('not+base64')).toBe(false)
    expect(isValidAttestationChallenge('short')).toBe(false)
  })

  it('rejects an incomplete encryption key', () => {
    expect(() =>
      createAttestationManifest({
        serviceDid: 'did:web:wallet.example.com',
        identityPublicKeyHex: '02' + 'ab'.repeat(32),
        walletEncryptionPublicJwk: { kty: 'EC' },
      }),
    ).toThrow(/incomplete/)
  })
})
