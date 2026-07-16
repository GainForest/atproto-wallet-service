# atproto-wallet-service

> [!WARNING]
> **Work in progress.** This code is experimental, deployed only as an
> unattested demo, and not audited. The current deployment uses a file-based
> root seed that a VM administrator can access; it is not operator-proof.
> APIs and record schemas will change. Do not put real funds behind it.

A standalone, TEE-hosted embedded-wallet service for AT Protocol users on
any PDS, including Bluesky-hosted accounts. Every user gets a self-custodial
wallet (Ethereum-compatible + Solana) keyed to their DID. There is no seed
phrase to manage: keys are held as 2-of-3 Shamir shares (device,
server-in-TEE, recovery), and only requests signed on the user's own device
can spend. The target attested architecture prevents the operator from
signing alone and lets users export their keys and leave. The current demo
does **not** yet establish that guarantee; see
[Stateless TEE architecture review](docs/stateless-tee-design.md).

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

| Tier     | Auth                 | Endpoints                                                                                                     |
| -------- | -------------------- | ------------------------------------------------------------------------------------------------------------- |
| user     | service-auth JWT     | `POST /v1/wallet/enroll`, `POST /v1/wallet/create`, `GET /v1/wallet/info/:did`                                |
| envelope | user-signed envelope | `POST /v1/wallet/sign`, `POST /v1/wallet/export`, `POST /v1/wallet/recover`, `POST /v1/wallet/recover-export` |
| admin    | `x-internal-secret`  | `POST /v1/wallet/pregenerate`, `GET /v1/wallet/enrollment/:did`                                               |
| open     | none                 | `GET /v1/wallet/public/:did`, `GET /v1/attestation`, `GET /health`, `GET /.well-known/did.json`               |

Pregenerated wallets are receive-only and enclave-custodial until the DID's
first `create` after enrollment claims them (defer-split, atomic claim).

Every create, sign, export, and recovery request carries a random `requestId`
(8–128 base64url characters). Its exact response is stored as an encrypted
operation receipt in the same state transition. Retrying the same authenticated
request returns that receipt; reusing the ID with different parameters is
rejected. Envelope payloads may additionally carry `stateVersion` and
`shareSetVersion` to reject operations prepared against stale state.

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

On TDX CVMs without dstack (e.g. GCP confidential VMs on a stock guest
image) the service falls back to Linux configfs-TSM quotes
(`src/tsm-quote.ts`), either through the root-owned helper
(`dist/tsm-quote-helper.js` on `/run/tdx-quote.sock`) or directly when
privileged. The resulting `mode: "tdx-tsm"` proves genuine TDX hardware
and the measured boot chain over the same challenge-bound report data,
but — unlike a measured dstack workload — it does **not** prove the
operator is locked out of the VM.

## Spot instances / controlled failover

The current stateful implementation is hardened to run on preemptible TDX
instances (e.g. GCP spot) with an **external dstack KMS** and a **durable data disk**
(pd-balanced) that is re-attached to the replacement instance:

- **Root seed off the host** — `WALLET_SERVICE_ROOT_SEED_SOURCE=dstack-kms`
  fetches the seed from the external KMS through the guest-agent socket at
  every boot (`src/dstack-kms.ts`). The KMS binds the key to the measured
  app image, so a re-created instance derives the _same_ seed; nothing
  secret lives on the disposable boot disk.
- **Atomic sealed state** — enrollment, nonce, wallet/share-set version,
  pregen state, and idempotency receipts are one per-DID AES-GCM-sealed V2
  aggregate. The async repository uses revision CAS, so nonce consumption,
  re-sharding, request-key rotation, and delivery receipts commit together.
  SQLite runs WAL with `synchronous=FULL`; `close()` checkpoints the WAL.
- **Single writer enforced** — the store holds SQLite's EXCLUSIVE lock for
  its lifetime; a second instance attaching the same data disk fails fast
  at startup instead of splitting the monotonic nonce state.
- **Preemption notice** — `WALLET_SERVICE_PREEMPTION_WATCH=gcp` polls the
  metadata server for the ~30s spot notice (`src/preemption.ts`) in
  addition to the SIGTERM handler.
- **Bounded, idempotent shutdown** — `/health` flips to 503 (load-balancer
  drain), in-flight requests get `WALLET_SERVICE_SHUTDOWN_GRACE_MS`
  (default 10s) to finish, connections are then force-closed, the store is
  checkpointed and closed, and the in-memory root seed is wiped.

## Known gaps / next steps

- [ ] Replace the SQLite repository adapter with strongly-consistent external
      CAS storage, then deploy the measured stateless design in
      [docs/stateless-tee-design.md](docs/stateless-tee-design.md). The per-DID
      sealed aggregate, async repository seam, atomic CAS transitions,
      idempotent receipts, production seed guard, and attestation fail-closed
      guard are implemented. Still needed: external storage, measured workload
      governance, client verification, and an independent monotonic witness.
- [ ] Enrollment TOFU gap: a malicious PDS operator can mint a service-auth
      token for a never-enrolled user and register their own request key
      first. Fix: WebAuthn/passkey attestation as an operator-independent
      enrollment factor.
- [ ] `POST /v1/wallet/bind`: an envelope-authorized endpoint returning the
      wallet signature for the binding record (message format already in
      `src/binding.ts`; for now clients would use the generic sign flow).
- [ ] Nonce/freshness anchoring outside the host (rollback-replay window).
      `synchronous=FULL` closes the crash-loss case; a malicious host
      restoring an old disk snapshot still needs an external anchor.
- [ ] XRPC-shaped aliases (`/xrpc/app.gainforest.wallet.*`).
- [ ] Rate limiting is in-memory and per-instance only.

## License

MIT
