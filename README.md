# atproto-wallet-service

> [!WARNING]
> **Work-in-progress.** Experimental extraction — not deployed, not
> audited, APIs and record schemas will change. Do not put real funds
> behind it.

A **standalone, TEE-hosted embedded-wallet service for AT Protocol users on
any PDS** — including Bluesky-hosted accounts. Every user gets a
self-custodial wallet (Ethereum-compatible + Solana) keyed to their DID: no
seed phrase surfaced, keys held as **2-of-3 Shamir shares** (device /
server-in-TEE / recovery), and only requests signed on the user's own device
can spend. The operator alone can never sign, trap, or drain funds; users can
always export their keys and leave.

This is the "thinner service" successor to the wallet half of
[GainForest/tPDS](https://github.com/GainForest/tPDS): the enclave code
(`signer`) is carried over intact, while the PDS relay is replaced by a
direct client-facing surface. Repo signing stays in tPDS — this service holds
wallet material only.

## How it works on the protocol

Three mechanisms, all standard ATProto or W3C DID machinery:

1. **Enrollment auth = service auth.** A user on any PDS calls
   `com.atproto.server.getServiceAuth` (aud = this service's `SERVICE_DID`,
   lxm = the wallet method) and presents the short-lived JWT. We verify it
   against the signing key advertised in their DID document
   (`@atproto/xrpc-server` `verifyJwt` + `@atproto/identity`). No OAuth, no
   account, no PDS integration.
2. **Signing auth = user-signed envelopes.** Sign/export/recover require an
   envelope signed by the user's enrolled P-256 request key, carrying their
   device share encrypted to the enclave. Tokens are never sufficient —
   compromising the transport or the operator yields no signatures.
3. **Verification = attested binding record.** The client writes an
   `app.gainforest.wallet.binding` record into their own repo containing the
   addresses plus a signature _by the wallet key_ over a canonical
   `did + addresses` message ([lexicon](lexicons/app/gainforest/wallet/binding.json),
   [src/binding.ts](src/binding.ts)). Repo commit proves the DID owns the
   record; wallet signature proves the wallet agreed to the DID —
   bidirectional, indexable, revocable, and immune to repo-key rotation.

## API surface

| Tier     | Auth                 | Endpoints                                                                      |
| -------- | -------------------- | ------------------------------------------------------------------------------ |
| user     | service-auth JWT     | `POST /v1/wallet/enroll`, `POST /v1/wallet/create`, `GET /v1/wallet/info/:did` |
| envelope | user-signed envelope | `POST /v1/wallet/sign`, `POST /v1/wallet/export`, `POST /v1/wallet/recover`    |
| admin    | `x-internal-secret`  | `POST /v1/wallet/pregenerate`, `GET /v1/wallet/enrollment/:did`                |
| open     | none                 | `GET /v1/wallet/public/:did`, `GET /v1/attestation`, `GET /health`             |

Pregenerated wallets are receive-only and enclave-custodial until claimed by
the DID's first `create` after enrollment (defer-split, atomic claim).

## Dev

```bash
pnpm install
cp .env.example .env   # set WALLET_SERVICE_ADMIN_SECRET + SERVICE_DID
pnpm dev               # plain process — NOT a real enclave
pnpm test
pnpm typecheck
```

Production must run inside a confidential VM
([dstack](https://github.com/Dstack-TEE/dstack) on TDX/SEV-SNP) with the root
seed provisioned by the dstack KMS. `GET /v1/attestation` exposes the quote.

## Known gaps / next steps

- [ ] Enrollment TOFU gap: a malicious _PDS_ operator can mint a service-auth
      token for a never-enrolled user and register their own request key
      first. Fix: WebAuthn/passkey attestation as an operator-independent
      enrollment factor.
- [ ] `POST /v1/wallet/bind` — envelope-authorized endpoint returning the
      wallet signature for the binding record (message format already in
      `src/binding.ts`; currently clients would use the generic sign flow).
- [ ] Nonce/freshness anchoring outside the host (rollback-replay window).
- [ ] XRPC-shaped aliases (`/xrpc/app.gainforest.wallet.*`) for client
      symmetry with tPDS.
- [ ] did:web document + `/.well-known/did.json` serving for `SERVICE_DID`.
- [ ] Rate limiting is in-memory and per-instance only.

## Provenance

Enclave core (`derive`, `envelope`, `keys`, `purposes`, `root-seed`, `store`,
`wallet`, `attestation`) extracted unchanged from
[GainForest/tPDS](https://github.com/GainForest/tPDS)
`packages/signer` (MIT). The service surface (`service.ts`) is adapted:
repo-signing routes removed, PDS internal-secret trust replaced by
service-auth + envelope tiers.

## License

MIT
