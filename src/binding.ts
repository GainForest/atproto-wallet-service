/**
 * Attested wallet-binding record support (`app.gainforest.wallet.binding`).
 *
 * The binding record is how a wallet is verifiably tied to a DID *on the
 * protocol*, without touching the DID document:
 *
 *   1. The user's client asks this service to sign a canonical binding
 *      message with the WALLET key (via the normal user-envelope sign
 *      flow — the service cannot mint this signature alone).
 *   2. The client writes an `app.gainforest.wallet.binding` record into
 *      the user's own repo, containing the addresses + that signature.
 *   3. The record is committed by the user's PDS and signed by the repo
 *      key like any other record.
 *
 * Verification is therefore bidirectional:
 *   - the repo commit proves the DID (owner) published the record, and
 *   - the embedded wallet signature proves the wallet key holder agreed
 *     to be bound to exactly this DID.
 *
 * A malicious operator can neither fabricate a binding for an address
 * they don't control (no wallet signature) nor replay one for another
 * DID (the DID is inside the signed message).
 */
import { keccak_256 } from '@noble/hashes/sha3.js'

export const BINDING_NSID = 'app.gainforest.wallet.binding'
export const BINDING_VERSION = 1

/**
 * Canonical message the WALLET key signs. Field order is fixed; all
 * values are lowercase where case-insensitive. Any change bumps
 * BINDING_VERSION.
 */
export function buildBindingMessage(opts: {
  did: string
  evmAddress: string
  solAddress: string
}): string {
  return [
    `atproto-wallet-binding:v${BINDING_VERSION}`,
    opts.did,
    opts.evmAddress.toLowerCase(),
    opts.solAddress,
  ].join('\n')
}

/**
 * EVM digest of the binding message, using EIP-191 personal-message
 * framing so the same signature is verifiable by standard Ethereum
 * tooling (`personal_sign` / `verifyMessage`).
 */
export function bindingEvmDigest(message: string): Uint8Array {
  const body = Buffer.from(message, 'utf8')
  const prefix = Buffer.from(
    `\u0019Ethereum Signed Message:\n${body.length}`,
    'utf8',
  )
  return keccak_256(Buffer.concat([prefix, body]))
}
