import { describe, expect, it } from 'vitest'
import { parseMultikey } from '@atproto/crypto'
import { secp256k1 } from '@noble/curves/secp256k1'
import { buildDidWebDocument, didWebToHttpsUrl } from '../did-web.js'
import { deriveIdentityPublicKey } from '../derive.js'
import { bytesToHex } from '../keys.js'

const seed = Buffer.alloc(32, 7)
const identityHex = bytesToHex(deriveIdentityPublicKey(seed))

describe('didWebToHttpsUrl', () => {
  it('resolves a bare domain', () => {
    expect(didWebToHttpsUrl('did:web:wallet.example.com')).toBe(
      'https://wallet.example.com',
    )
  })

  it('resolves an encoded port', () => {
    expect(didWebToHttpsUrl('did:web:localhost%3A3020')).toBe(
      'https://localhost:3020',
    )
  })

  it('rejects non-did:web DIDs', () => {
    expect(() => didWebToHttpsUrl('did:plc:abc123')).toThrow(/not a did:web/)
  })

  it('rejects path-based did:web', () => {
    expect(() => didWebToHttpsUrl('did:web:example.com:u:alice')).toThrow(
      /bare-domain/,
    )
    expect(() => didWebToHttpsUrl('did:web:example.com/path')).toThrow(
      /bare-domain/,
    )
  })

  it('rejects empty and garbage hosts', () => {
    expect(() => didWebToHttpsUrl('did:web:')).toThrow(/bare-domain/)
    expect(() => didWebToHttpsUrl('did:web:exa mple.com')).toThrow(
      /invalid did:web host/,
    )
  })
})

describe('buildDidWebDocument', () => {
  const did = 'did:web:wallet.example.com'
  const doc = buildDidWebDocument(did, identityHex)

  it('binds the DID to the identity key as a Multikey', () => {
    expect(doc.id).toBe(did)
    expect(doc.verificationMethod).toHaveLength(1)
    const vm = doc.verificationMethod[0]
    expect(vm.id).toBe(`${did}#wallet_identity`)
    expect(vm.controller).toBe(did)
    const parsed = parseMultikey(vm.publicKeyMultibase)
    expect(parsed.jwtAlg).toBe('ES256K')
    // parseMultikey returns the uncompressed point — recompress to compare
    // against the service's compressed identity key.
    const compressed = secp256k1.Point.fromHex(
      bytesToHex(parsed.keyBytes),
    ).toHex(true)
    expect(compressed).toBe(identityHex)
  })

  it('publishes the HTTPS service endpoint', () => {
    expect(doc.service).toEqual([
      {
        id: '#atproto_wallet',
        type: 'AtprotoWalletService',
        serviceEndpoint: 'https://wallet.example.com',
      },
    ])
  })

  it('includes the DID-core and multikey contexts', () => {
    expect(doc['@context']).toContain('https://www.w3.org/ns/did/v1')
    expect(doc['@context']).toContain('https://w3id.org/security/multikey/v1')
  })
})
