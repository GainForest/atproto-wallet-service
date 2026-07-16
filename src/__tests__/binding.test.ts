import { describe, expect, it } from 'vitest'
import { secp256k1 } from '@noble/curves/secp256k1'
import {
  BINDING_VERSION,
  bindingEvmDigest,
  buildBindingMessage,
} from '../binding.js'
import { deriveChainKeys, generateWalletEntropy } from '../wallet.js'
import { bytesToHex } from '../keys.js'

describe('wallet binding message', () => {
  const did = 'did:plc:bindingtest'

  it('is canonical: fixed field order, lowercased EVM address', () => {
    const msg = buildBindingMessage({
      did,
      evmAddress: '0xAbCd000000000000000000000000000000001234',
      solAddress: 'So11111111111111111111111111111111111111112',
    })
    expect(msg).toBe(
      [
        `atproto-wallet-binding:v${BINDING_VERSION}`,
        did,
        '0xabcd000000000000000000000000000000001234',
        'So11111111111111111111111111111111111111112',
      ].join('\n'),
    )
  })

  it('produces an EIP-191 digest a standard EVM signature verifies against', () => {
    const entropy = generateWalletEntropy()
    const keys = deriveChainKeys(entropy)
    const msg = buildBindingMessage({
      did,
      evmAddress: keys.evmAddress,
      solAddress: keys.solAddress,
    })
    const digest = bindingEvmDigest(msg)
    expect(digest).toHaveLength(32)

    // Sign with the wallet key the way /v1/wallet/sign does, verify
    // against the wallet's registered public key — the two-directional
    // binding check an indexer would run.
    const sig = secp256k1.sign(digest, keys.evmPrivateKey, { prehash: false })
    expect(
      secp256k1.verify(
        sig,
        digest,
        Buffer.from(bytesToHex(keys.evmPublicKey), 'hex'),
        {
          prehash: false,
        },
      ),
    ).toBe(true)
  })

  it('binds the DID: a different DID yields a different digest', () => {
    const base = {
      evmAddress: '0x' + '11'.repeat(20),
      solAddress: 'A'.repeat(40),
    }
    const a = bindingEvmDigest(buildBindingMessage({ did, ...base }))
    const b = bindingEvmDigest(
      buildBindingMessage({ did: 'did:plc:othervictim', ...base }),
    )
    expect(Buffer.from(a).toString('hex')).not.toBe(
      Buffer.from(b).toString('hex'),
    )
  })
})
