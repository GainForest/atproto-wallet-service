import { describe, expect, it } from 'vitest'
import {
  MAX_RECEIPTS,
  appendReceipt,
  decodeState,
  emptyState,
  encodeState,
  sealState,
  stateStatus,
  unsealState,
  type OperationReceipt,
} from '../state.js'

const seed = Buffer.alloc(32, 23)
const did = 'did:plc:statetest'

function receipt(n: number): OperationReceipt {
  return {
    requestId: `request-${n}`,
    op: 'sign',
    requestHash: n.toString(16).padStart(64, '0'),
    at: n,
    response: { n },
  }
}

describe('WalletStateV2 codec and sealing', () => {
  it('canonically encodes and decodes state', () => {
    const state = emptyState(did, 1)
    state.enrollment = { requestPubkeyHex: '02aa', createdAt: 1 }
    state.lastNonce = 9
    const encoded = encodeState(state)
    expect(encodeState(decodeState(encoded))).toEqual(encoded)
    expect(stateStatus(state)).toBe('enrolled')
  })

  it('round-trips a complete sealed aggregate', () => {
    const state = emptyState(did, 3)
    state.stateVersion = 7
    state.wallet = {
      shareSetVersion: 2,
      serverShareCipherHex: 'aabb',
      evmPubkeyHex: '02cc',
      evmAddress: '0xabc',
      solPubkeyHex: 'dd',
      solAddress: 'sol',
      createdAt: 5,
    }
    const sealed = sealState(seed, state)
    expect(sealed.schema).toBe(2)
    expect(sealed.keyEpoch).toBe(3)
    expect(unsealState(seed, did, sealed)).toEqual(state)
    expect(stateStatus(state)).toBe('active')
  })

  it('rejects ciphertext tampering', () => {
    const sealed = sealState(seed, emptyState(did, 1))
    const raw = Buffer.from(sealed.cipherB64, 'base64')
    raw[raw.length - 1] ^= 1
    expect(() =>
      unsealState(seed, did, {
        ...sealed,
        cipherB64: raw.toString('base64'),
      }),
    ).toThrow(/authentication/)
  })

  it('rejects DID swaps, header swaps, and wrong roots', () => {
    const sealed = sealState(seed, emptyState(did, 1))
    expect(() => unsealState(seed, 'did:plc:other', sealed)).toThrow(
      /authentication/,
    )
    expect(() => unsealState(seed, did, { ...sealed, keyEpoch: 2 })).toThrow(
      /authentication/,
    )
    expect(() => unsealState(Buffer.alloc(32, 24), did, sealed)).toThrow(
      /authentication/,
    )
  })

  it('bounds idempotency receipts by evicting oldest first', () => {
    let receipts: OperationReceipt[] = []
    for (let i = 0; i < MAX_RECEIPTS + 3; i++) {
      receipts = appendReceipt(receipts, receipt(i))
    }
    expect(receipts).toHaveLength(MAX_RECEIPTS)
    expect(receipts[0].requestId).toBe('request-3')
  })
})
