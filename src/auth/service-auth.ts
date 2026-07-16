/**
 * ATProto inter-service ("service auth") JWT verification.
 *
 * This is how a user on ANY PDS authenticates to this wallet service:
 * their client asks their own PDS for a short-lived token via
 * `com.atproto.server.getServiceAuth` with:
 *
 *   aud = this service's DID (SERVICE_DID, e.g. did:web:wallet.example.com)
 *   lxm = the specific method being called (e.g. app.gainforest.wallet.enroll)
 *
 * The PDS signs the token with the user's atproto signing key, and we
 * verify it against the key advertised in the user's DID document. No
 * OAuth session, no account on our side — the DID document is the trust
 * root, which also means the binding is externally verifiable by anyone.
 *
 * We deliberately use upstream primitives (@atproto/xrpc-server verifyJwt +
 * @atproto/identity IdResolver) rather than hand-rolling JWT or DID-doc
 * handling.
 *
 * Honest limitation (same TOFU shape as tPDS): the token is minted by the
 * user's PDS, so a malicious PDS operator can mint one for a user who has
 * never enrolled and register their own request key first. TOFU means an
 * already-enrolled wallet can never be taken over this way. Closing the
 * bootstrap gap requires an operator-independent factor at enrollment
 * (WebAuthn/passkey attestation) — tracked as future work.
 */
import { IdResolver } from '@atproto/identity'
import { verifyJwt } from '@atproto/xrpc-server'

/**
 * Verify a service-auth JWT for the given lexicon method (lxm) and return
 * the authenticated user DID. Throws on any verification failure.
 */
export type VerifyServiceJwt = (
  jwtStr: string,
  lxm: string,
) => Promise<{ did: string }>

export function createServiceJwtVerifier(opts: {
  /** This service's own DID — the expected `aud` of every token. */
  serviceDid: string
  /** PLC directory URL (default https://plc.directory). */
  plcUrl?: string
}): VerifyServiceJwt {
  const idResolver = new IdResolver({ plcUrl: opts.plcUrl })

  return async (jwtStr: string, lxm: string) => {
    const payload = await verifyJwt(
      jwtStr,
      opts.serviceDid,
      lxm,
      async (iss: string, forceRefresh: boolean) => {
        // iss may carry a service fragment (did:...#atproto_labeler etc.);
        // the signing key is always resolved from the bare DID.
        const did = iss.split('#')[0]
        return idResolver.did.resolveAtprotoKey(did, forceRefresh)
      },
    )
    return { did: payload.iss.split('#')[0] }
  }
}
