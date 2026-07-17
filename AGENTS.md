# AGENTS.md

Guidance for AI coding agents working in this repo.

## What this is

A standalone, TEE-hosted embedded-wallet service for AT Protocol users on
**any** PDS. Users get self-custodial wallets (Ethereum-compatible + Solana)
keyed to their DID, held as **2-of-3 Shamir shares** (device /
server-in-TEE / recovery). Read [README.md](README.md) first for the
protocol design and API surface.

Provenance: the enclave core was extracted from `GainForest/tPDS`
`packages/signer` (now private). Repo signing stayed in tPDS — this service
holds wallet material only.

## Commands

```bash
pnpm install
pnpm dev          # tsx watch src/index.ts — plain process, NOT a real enclave
pnpm test         # vitest run (src/__tests__/)
pnpm typecheck    # tsc --noEmit
pnpm build        # tsc --build → dist/
pnpm format       # prettier --write .
```

Needs Node >= 20 and a `.env` (copy `.env.example`; set
`WALLET_SERVICE_ADMIN_SECRET` + `SERVICE_DID`).

## GCP infrastructure status and rebuild procedure

**There is no live TDX infrastructure.** On 2026-07-17 the cost-bearing GCP
validation deployment in project `hypercerts-pds-472914` was intentionally and
completely deleted. This included:

- instances `wallet-cvm-staging`, `wallet-kms`, `wallet-kms-replica`, and
  `epds-tee-spot`;
- MIG `epds-tee-mig`, template `epds-tee-spot-tmpl`, all attached/durable
  disks, and reserved addresses `wallet-staging-ip`, `wallet-kms-ip`,
  `wallet-kms-replica-ip`, and `epds-tee-ip`;
- dstack boot/shared/data images, TDX firewall rules, buckets
  `hypercerts-dstack-images` and `hypercerts-pds-472914-dstack`, and Artifact
  Registry repository `us-central1-docker.pkg.dev/hypercerts-pds-472914/wallet`.

Do not treat old sslip.io endpoints, image digests, compose hashes, device IDs,
or attestation output in reports/history as live. The Vercel MVP still has the
old fail-closed pins and intentionally returns HTTP 503 until a new deployment
is configured. Because the KMS durable disks were deleted, the old KMS root
identity and the test wallets it protected are irrecoverable.

To recreate the measured deployment:

1. Read [deploy/dstack/README.md](deploy/dstack/README.md) and
   [deploy/dstack/kms/README.md](deploy/dstack/kms/README.md) in full. Start
   from service commit `86fe7a3` or newer and dstack OS `0.6.0` only after
   reviewing current TDX advisories and upstream releases.
2. Create a new private Artifact Registry repository and rebuild/publish the
   digest-pinned wallet, KMS, auth-policy, and verifier images. The historical
   registry and images no longer exist.
3. Create fresh GCS image buckets, reserved IPs, narrowly scoped firewall
   rules, and measured dstack project directories. Use `c3-standard-4` Intel
   TDX in a supported zone. Preserve data disks only after production data
   exists; never rely on a disposable boot disk for state.
4. Deploy and bootstrap the first self-hosted KMS with `key_provider=tpm`, then
   onboard a second KMS before issuing wallets. This creates a **new** root
   identity. Protect both KMS instances/disks from deletion and verify that
   both report the same root identity and `is_dev: false`.
5. Deploy the wallet with `key_provider=kms`, `WALLET_SERVICE_ROOT_SEED_SOURCE=dstack-kms`,
   the patched durable-disk behavior in `deploy/dstack/patch-dstack-cloud.py`,
   and digest-pinned compose images. Use a fresh service hostname/DID.
6. Deploy the verifier and authorization policy. The last validation used an
   operator-managed static measurement allowlist, not decentralized governance;
   document that trust boundary explicitly.
7. Independently verify the full versioned evidence bundle: TDX quote, vTPM,
   event-log replay, current TCB/advisories, exact OS hash, app ID, compose
   hash, KMS provider, challenge binding, service DID, identity key, and wallet
   encryption JWK.
8. Update the `atproto-wallet-mvp` Vercel production variables with the new
   URL/DID/verifier and exact measurements. Run tests/build, browser enrollment,
   wallet create/sign/export/recovery, negative probes, and a real VM
   recreation with an active zero-value wallet before calling it available.
9. Record the final resource inventory and current list-price estimate in this
   README. The deleted four-VM topology cost approximately $550–575/month.

Never reuse the deleted deployment's service DID or claim that its wallet state
can be restored. Allocate new addresses/hostnames and re-render measurements.

## Layout

| Path                           | Role                                                           |
| ------------------------------ | -------------------------------------------------------------- |
| `src/index.ts`                 | Entrypoint — env loading, server bootstrap                     |
| `src/service.ts`               | Express service surface: all `/v1/wallet/*` routes, auth tiers |
| `src/auth/service-auth.ts`     | ATProto service-auth JWT verification (enrollment tier)        |
| `src/envelope.ts`              | User-signed envelope verification (sign/export/recover tier)   |
| `src/wallet.ts`                | Wallet lifecycle: create, claim, Shamir split/combine, signing |
| `src/derive.ts`                | Key derivation (BIP-32/BIP-39, ed25519-hd-key for Solana)      |
| `src/keys.ts`                  | Key types + P-256 request keys                                 |
| `src/root-seed.ts`             | Enclave root seed (env/file sources, dev fallback locally)     |
| `src/dstack-kms.ts`            | Root seed from external dstack KMS via guest agent (spot-safe) |
| `src/preemption.ts`            | GCP spot preemption watcher → controlled shutdown              |
| `src/store.ts`                 | better-sqlite3 persistence                                     |
| `src/binding.ts`               | Canonical wallet↔DID binding message + signature               |
| `src/did-web.ts`               | did:web document for SERVICE_DID (/.well-known/did.json)       |
| `src/attestation.ts`           | TEE attestation quote endpoint support                         |
| `src/tsm-quote.ts`             | configfs-TSM TDX quotes (GCP CVMs without dstack)              |
| `src/tsm-quote-helper.ts`      | Root-owned quote helper on a local unix socket                 |
| `src/purposes.ts`              | Domain-separated derivation purposes                           |
| `lexicons/`                    | `app.gainforest.wallet.binding` lexicon                        |
| `src/__tests__/`               | Vitest suites — one file per module                            |
| `docs/stateless-tee-design.md` | Reviewed target architecture and migration plan                |
| `docs/splits-smartvault-vs-tdx.md` | BumiCerts SmartVault/TDX decision and risk comparison       |

## Security invariants — do not break these

This is security-critical wallet code. When editing, preserve:

1. **The operator can never sign alone.** Sign/export/recover MUST require a
   user-signed envelope carrying the device share; a service-auth token or
   admin secret alone must never reach a signing path.
2. **Shares never persist together.** The server share lives in the store;
   device and recovery shares leave the enclave at create time and are never
   written server-side. Don't log, cache, or persist plaintext shares or
   the combined seed.
3. **Enclave core stays enclave-pure.** `derive`, `envelope`, `keys`,
   `purposes`, `root-seed`, `store`, `wallet`, `attestation` must not grow
   network calls or non-deterministic dependencies.
4. **Auth tiers are strict** (see README table): user (service-auth JWT),
   envelope (user-signed), admin (`x-internal-secret`), open. Never loosen a
   route's tier.
5. **Pregenerated wallets are receive-only** until claimed atomically by the
   DID's first `create` after enrollment (defer-split). Keep the claim
   atomic.
6. **Binding messages are canonical.** Changing the `did + addresses`
   message format in `src/binding.ts` breaks existing on-repo records —
   treat it as frozen unless versioned.

## Conventions

- TypeScript, strict; ESM-style imports within `src/`.
- Prettier for formatting (`.prettierrc`) — run `pnpm format` before
  committing.
- Crypto via `@noble/*`, `@scure/*`, `@atproto/crypto` only — do not add ad
  hoc crypto or roll your own primitives.
- Every behavioral change needs a matching test in `src/__tests__/`;
  security-relevant changes need negative tests (wrong key, replayed
  envelope, wrong tier, etc.).
- Keep `lexicons/` JSON and any record shapes in sync with code that reads
  or writes them.

## Known gaps

See "Known gaps / next steps" in the README and
`docs/stateless-tee-design.md` before changing persistence, KMS,
attestation, or wallet state transitions. Several TODOs (WebAuthn enrollment
factor, `/v1/wallet/bind`, XRPC aliases) are already scoped there.
