/**
 * did:web document for the service DID.
 *
 * Every service-auth JWT this service accepts carries
 * `aud = SERVICE_DID`, and the MVP/clients pin that DID in their
 * config. A did:web that does not resolve is a standards gap: nothing
 * ties the DID string to this deployment. Serving
 * `/.well-known/did.json` closes that — the document binds the DID to
 *
 *   - the service's **identity public key** (secp256k1, the same key
 *     whose SHA-256 is bound into the TEE attestation quote's
 *     report_data), published as a Multikey verification method; and
 *   - the HTTPS **service endpoint** clients should talk to.
 *
 * A verifier can therefore go DID → did.json → identityPublicKey →
 * attestation quote and check it is talking to the measured enclave,
 * not just "some host that answers on this domain".
 *
 * Only bare-domain did:web values are supported (`did:web:host` or
 * `did:web:host%3Aport`). Path-based did:web would relocate the
 * document away from /.well-known/did.json per spec, which this
 * service does not serve.
 */
import { formatMultikey, SECP256K1_JWT_ALG } from '@atproto/crypto'

/** DID document — the subset of DID-core this service publishes. */
export interface DidWebDocument {
  '@context': string[]
  id: string
  verificationMethod: {
    id: string
    type: 'Multikey'
    controller: string
    publicKeyMultibase: string
  }[]
  service: {
    id: string
    type: string
    serviceEndpoint: string
  }[]
}

/**
 * Resolve a bare-domain did:web to its HTTPS origin.
 * Throws on anything path-based or malformed — the caller must not
 * serve a document for a DID it cannot faithfully represent.
 */
export function didWebToHttpsUrl(did: string): string {
  const prefix = 'did:web:'
  if (!did.startsWith(prefix)) {
    throw new Error(`not a did:web: ${did}`)
  }
  const raw = did.slice(prefix.length)
  // ':' separates path segments in did:web; '%3A' is an encoded port.
  if (raw === '' || raw.includes(':') || raw.includes('/')) {
    throw new Error(`only bare-domain did:web is supported: ${did}`)
  }
  const host = decodeURIComponent(raw)
  if (!/^[a-zA-Z0-9.-]+(:[0-9]+)?$/.test(host)) {
    throw new Error(`invalid did:web host: ${did}`)
  }
  return `https://${host}`
}

/**
 * Build the DID document served at /.well-known/did.json.
 *
 * @param serviceDid bare-domain did:web this service runs as
 * @param identityPubkeyHex compressed secp256k1 identity public key
 */
export function buildDidWebDocument(
  serviceDid: string,
  identityPubkeyHex: string,
): DidWebDocument {
  const endpoint = didWebToHttpsUrl(serviceDid)
  const identityKey = Buffer.from(identityPubkeyHex, 'hex')
  return {
    '@context': [
      'https://www.w3.org/ns/did/v1',
      'https://w3id.org/security/multikey/v1',
    ],
    id: serviceDid,
    verificationMethod: [
      {
        id: `${serviceDid}#wallet_identity`,
        type: 'Multikey',
        controller: serviceDid,
        publicKeyMultibase: formatMultikey(SECP256K1_JWT_ALG, identityKey),
      },
    ],
    service: [
      {
        id: '#atproto_wallet',
        type: 'AtprotoWalletService',
        serviceEndpoint: endpoint,
      },
    ],
  }
}
