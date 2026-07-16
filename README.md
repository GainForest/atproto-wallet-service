# atproto-wallet-service

> [!WARNING]
> **Work in progress.** This code is experimental. It is not deployed and
> not audited, and the APIs and record schemas will change. Do not put real
> funds behind it.

A standalone, TEE-hosted embedded-wallet service for AT Protocol users on
any PDS, including Bluesky-hosted accounts. Every user gets a self-custodial
wallet (Ethereum-compatible + Solana) keyed to their DID. There is no seed
phrase to manage: keys are held as 2-of-3 Shamir shares (device,
server-in-TEE, recovery), and only requests signed on the user's own device
can spend. The operator can never sign, trap, or drain funds on their own,
and users can always export their keys and leave.

## How it works on the protocol

Three mechanisms, all standard ATProto or W3C DID machinery:

1. **Enrollment uses service auth.** A user on any PDS calls
   `com.atproto.server.getServiceAuth` (aud = this service's `SERVICE_DID`,
   lxm = the wallet method) and presents the short-lived JWT. We verify it
   against the signing key advertised in their DID document
   (`@atproto/xrpc-server` `verifyJwt` + `@atproto/identity`). No OAuth, no
   extra account, no PDS integration needed.
2. **Signing uses user-signed envelopes.** Sign, export, and recover all
   require an envelope signed by the user's enrolled P-256 request key,
   carrying their device share encrypted to the enclave. A token alone is
   never enough: compromising the transport or the operator yields no
   signatures.
3. **Verification uses an attested binding record.** The client writes an
   `app.gainforest.wallet.binding` record into their own repo containing the
   addresses plus a signature by the wallet key over a canonical
   `did + addresses` message ([lexicon](lexicons/app/gainforest/wallet/binding.json),
   [src/binding.ts](src/binding.ts)). The repo commit proves the DID owns
   the record, and the wallet signature proves the wallet agreed to the DID.
   The link works in both directions, is indexable and revocable, and
   survives repo-key rotation.

## API surface

| Tier     | Auth                 | Endpoints                                                                      |
| -------- | -------------------- | ------------------------------------------------------------------------------ |
| user     | service-auth JWT     | `POST /v1/wallet/enroll`, `POST /v1/wallet/create`, `GET /v1/wallet/info/:did` |
| envelope | user-signed envelope | `POST /v1/wallet/sign`, `POST /v1/wallet/export`, `POST /v1/wallet/recover`    |
| admin    | `x-internal-secret`  | `POST /v1/wallet/pregenerate`, `GET /v1/wallet/enrollment/:did`                |
| open     | none                 | `GET /v1/wallet/public/:did`, `GET /v1/attestation`, `GET /health`             |

Pregenerated wallets are receive-only and enclave-custodial until the DID's
first `create` after enrollment claims them (defer-split, atomic claim).

## Dev

```bash
pnpm install
cp .env.example .env   # set WALLET_SERVICE_ADMIN_SECRET + SERVICE_DID
pnpm dev               # plain process, NOT a real enclave
pnpm test
pnpm typecheck
```

Production must run inside a confidential VM
([dstack](https://github.com/Dstack-TEE/dstack) on TDX/SEV-SNP) with the
root seed provisioned by the dstack KMS. `GET /v1/attestation` exposes the
quote.

## Known gaps / next steps

- [ ] Enrollment TOFU gap: a malicious PDS operator can mint a service-auth
      token for a never-enrolled user and register their own request key
      first. Fix: WebAuthn/passkey attestation as an operator-independent
      enrollment factor.
- [ ] `POST /v1/wallet/bind`: an envelope-authorized endpoint returning the
      wallet signature for the binding record (message format already in
      `src/binding.ts`; for now clients would use the generic sign flow).
- [ ] Nonce/freshness anchoring outside the host (rollback-replay window).
- [ ] XRPC-shaped aliases (`/xrpc/app.gainforest.wallet.*`).
- [ ] did:web document + `/.well-known/did.json` serving for `SERVICE_DID`.
- [ ] Rate limiting is in-memory and per-instance only.

## License

MIT
