import * as crypto from 'node:crypto'

export const ATTESTATION_PROTOCOL = 'atproto-wallet-service/v1' as const

export interface WalletEncryptionJwk {
  kty: string
  crv: string
  x: string
  y: string
}

/** Public values cryptographically bound into the TDX quote report data. */
export interface AttestationManifestV1 {
  version: 1
  protocol: typeof ATTESTATION_PROTOCOL
  serviceDid: string
  identityPublicKeyHex: string
  walletEncryptionPublicJwk: WalletEncryptionJwk
}

/**
 * Build the manifest in a fixed property order. The browser hashes the exact
 * same canonical JSON before accepting the quote or encryption key.
 */
export function createAttestationManifest(input: {
  serviceDid: string
  identityPublicKeyHex: string
  walletEncryptionPublicJwk: Partial<WalletEncryptionJwk>
}): AttestationManifestV1 {
  const jwk = input.walletEncryptionPublicJwk
  if (!jwk.kty || !jwk.crv || !jwk.x || !jwk.y) {
    throw new Error('wallet encryption JWK is incomplete')
  }
  return {
    version: 1,
    protocol: ATTESTATION_PROTOCOL,
    serviceDid: input.serviceDid,
    identityPublicKeyHex: input.identityPublicKeyHex,
    walletEncryptionPublicJwk: {
      kty: jwk.kty,
      crv: jwk.crv,
      x: jwk.x,
      y: jwk.y,
    },
  }
}

export function attestationManifestReportData(
  manifest: AttestationManifestV1,
): string {
  return crypto
    .createHash('sha256')
    .update(JSON.stringify(manifest), 'utf8')
    .digest('hex')
}

export function isValidAttestationChallenge(value: unknown): value is string {
  if (typeof value !== 'string' || !/^[A-Za-z0-9_-]+$/.test(value)) return false
  const bytes = Buffer.from(value, 'base64url')
  return (
    bytes.length >= 16 &&
    bytes.length <= 64 &&
    bytes.toString('base64url') === value
  )
}

/**
 * TDX report data is 64 bytes: manifest hash || challenge hash. The challenge
 * prevents a previously captured quote from being replayed to a verifier.
 */
export function challengeBoundReportData(
  manifest: AttestationManifestV1,
  challenge: string,
): string {
  if (!isValidAttestationChallenge(challenge)) {
    throw new Error('attestation challenge must be 16-64 base64url bytes')
  }
  const challengeHash = crypto
    .createHash('sha256')
    .update('atproto-wallet-service/attestation-challenge/v1\0', 'utf8')
    .update(Buffer.from(challenge, 'base64url'))
    .digest('hex')
  return attestationManifestReportData(manifest) + challengeHash
}
