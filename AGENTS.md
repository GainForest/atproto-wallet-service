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

## Layout

| Path                   | Role                                                            |
| ---------------------- | --------------------------------------------------------------- |
| `src/index.ts`         | Entrypoint — env loading, server bootstrap                      |
| `src/service.ts`       | Express service surface: all `/v1/wallet/*` routes, auth tiers  |
| `src/auth/service-auth.ts` | ATProto service-auth JWT verification (enrollment tier)     |
| `src/envelope.ts`      | User-signed envelope verification (sign/export/recover tier)    |
| `src/wallet.ts`        | Wallet lifecycle: create, claim, Shamir split/combine, signing  |
| `src/derive.ts`        | Key derivation (BIP-32/BIP-39, ed25519-hd-key for Solana)       |
| `src/keys.ts`          | Key types + P-256 request keys                                  |
| `src/root-seed.ts`     | Enclave root seed (dstack KMS in prod, dev fallback locally)    |
| `src/store.ts`         | better-sqlite3 persistence                                      |
| `src/binding.ts`       | Canonical wallet↔DID binding message + signature                |
| `src/attestation.ts`   | TEE attestation quote endpoint support                          |
| `src/purposes.ts`      | Domain-separated derivation purposes                            |
| `lexicons/`            | `app.gainforest.wallet.binding` lexicon                         |
| `src/__tests__/`       | Vitest suites — one file per module                             |

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

See "Known gaps / next steps" in the README — check it before adding
features; several TODOs (WebAuthn enrollment factor, `/v1/wallet/bind`,
did:web serving, XRPC aliases) are already scoped there.
