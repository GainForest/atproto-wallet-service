# Stateless TEE architecture review

Date: 2026-07-16

## Implementation status

Phase 0 and Phase 1 are implemented in the current tree:

- production refuses file/env/dev root seeds and fails startup when TEE
  attestation is unavailable;
- `WalletStateRepository` is asynchronous and optimistic;
- SQLite is the development/stateful adapter, with atomic migration from the
  four legacy tables;
- each DID is one fully sealed V2 aggregate;
- create/claim/sign/export/recovery use request IDs, encrypted receipts, and a
  single CAS transition for nonce, server-share, enrollment, and delivery
  state; and
- tests cover exact retries, request-ID collisions, CAS conflicts, concurrent
  nonce consumption, tampering, swapping, and legacy migration.

Phase 2 external CAS storage and Phases 3–5 remain future work. Sealing was
implemented early as part of the SQLite aggregate so the repository boundary
already handles opaque ciphertext.

## Verdict

The service **can and should become a stateless TEE workload**. The wallet
cryptography is already compatible with that model: each wallet has independent
entropy, only one encrypted Shamir share is server-side, and full entropy is
reconstructed transiently. The work is primarily a state-machine, attestation,
and deployment refactor—not a wallet-derivation rewrite.

"Stateless" applies to the wallet workload, not the whole system. Durable
ciphertext, authorization state, anti-replay state, and operation receipts must
still exist outside the enclave. A fresh measured workload must be able to:

1. attest its exact application image and configuration;
2. obtain deterministic sealing keys from an independent, attestation-gated
   KMS;
3. load encrypted state from untrusted external storage;
4. prove that state is the latest version, not a valid old ciphertext; and
5. update it atomically using compare-and-swap (CAS).

The current GCP VM does not meet those requirements. It is a mutable Ubuntu VM
with a local root-seed file and SQLite database. TDX memory isolation is useful,
but a VM administrator can replace the application, read the seed file, or
restore old state.

## Current state inventory

| State                        | Current location                       | Secret?            | Stateless destination                                                         |
| ---------------------------- | -------------------------------------- | ------------------ | ----------------------------------------------------------------------------- |
| Root seed                    | durable-disk file                      | critical           | dstack KMS-derived keys, available only to an authorized measurement          |
| Server Shamir share          | SQLite, AES-GCM under root-derived KEK | yes                | sealed per-DID record in untrusted external storage                           |
| Pregenerated full entropy    | SQLite, AES-GCM under root-derived KEK | critical           | sealed external record; still custodial until claim                           |
| Request public key           | SQLite plaintext                       | integrity-critical | sealed per-DID record                                                         |
| Last accepted nonce          | SQLite plaintext                       | rollback-critical  | sealed record plus independent monotonic witness                              |
| Wallet public keys/addresses | SQLite plaintext                       | integrity-critical | sealed record; optionally mirrored into an untrusted public index             |
| Wallet/share-set version     | SQLite plaintext                       | rollback-critical  | sealed record plus witness                                                    |
| Admin secret                 | environment file                       | privileged         | encrypted dstack configuration or, preferably, admin public-key authorization |
| Rate-limit counters          | process memory                         | no                 | external rate limiter; never an authorization control                         |

The four SQLite tables in `src/store.ts` are therefore not inherently tied to a
local disk. They can be represented by one encrypted state object per DID.

## What is already reusable

- `src/wallet.ts`: independent per-wallet CSPRNG entropy, 2-of-3 splitting,
  reconstruction, derivation, and signing are compatible with stateless
  execution.
- `src/envelope.ts`: signed client envelopes are the right authorization
  primitive, although their payload must gain state version, request ID, and
  chain/policy context.
- Server shares and pregenerated entropy already use AES-256-GCM with
  domain-separated AAD.
- Public-key integrity is checked by re-deriving keys after reconstruction.
- Device and recovery shares are encrypted to a user-controlled request key.
- The wallet-encryption key can be deterministic across fresh enclave replicas.

## Blocking gaps

### 1. The application itself is not a measured workload

Adding a quote agent to the current mutable Ubuntu VM would only establish that
some software is executing in a TDX guest. It does not adequately establish
that the audited `dist/` and configuration are the software handling wallet
material.

Deploy the service as a dstack CVM workload built from a pinned image and
manifest. KMS authorization must allow explicit workload measurements through
a reviewed policy (ideally multisig + timelock), not merely any VM in the GCP
project.

### 2. Root-seed persistence and excessive key reuse

`src/index.ts` currently defaults to a seed file. The optional
`src/dstack-kms.ts` path derives one root seed and then derives the state KEK,
inbound JWE key, and service identity from it.

Use the official dstack SDK and independent versioned paths instead:

- `wallet-service/state-sealing/v2`
- `wallet-service/inbound-jwe/v2`
- `wallet-service/identity/v2`
- `wallet-service/admin-config/v1` (if an encrypted secret remains necessary)

The SDK also exposes the KMS signature chain and workload information. The
current hand-written client discards those materials.

### 3. Local synchronous store API

`SignerStore` is synchronous and exposes operation-shaped methods coupled to
SQLite transactions. A network store must be asynchronous and optimistic.
Introduce an interface such as:

```ts
interface WalletStateRepository {
  load(did: string): Promise<StateSnapshot | null>
  create(did: string, sealed: SealedState): Promise<CreateResult>
  compareAndSwap(
    did: string,
    expectedRevision: string,
    sealed: SealedState,
  ): Promise<CasResult>
}
```

Keep SQLite as a development adapter. Add an external adapter with strongly
consistent conditional writes. A single sealed object per DID makes enrollment,
nonce, wallet, request-key rotation, pregen claim, and recovery one atomic state
transition.

### 4. Encrypted storage does not prevent rollback

A host can restore a valid old AES-GCM ciphertext. This can restore an old
nonce, old server share, or old enrolled request key. `synchronous=FULL` only
protects against accidental crash loss.

A production design needs an **independent monotonic witness**. Recommended
shape:

```text
witness.compareAndSwap(didHash, oldVersion, newVersion, stateHash)
  -> signed receipt
```

The wallet enclave verifies the witness receipt before acting on a state
snapshot. The witness must be a separate trust boundary—ideally another TEE,
operator, or append-only/on-chain checkpoint—not a second process administered
with the same credentials. This component is stateful; the wallet enclave is
still stateless.

A strongly consistent database CAS prevents accidental concurrency but does
not replace the independent witness when the database operator is in scope.

### 5. Create and recovery can strand wallets

Current ordering is unsafe under response loss:

- `create` commits the server share before encrypting/delivering device and
  recovery shares.
- `recover` commits a new server share and rotates enrollment before delivering
  the replacement shares.
- Server-share replacement and enrollment rotation are separate store
  transactions.

Add a random client `requestId` and persist an encrypted operation receipt in
the same CAS transition. Construct user-encrypted response JWEs before commit.
Retries with the same `requestId` return the exact committed receipt.

For create/claim/recovery the state transition and delivery receipt must be
atomic. Keep receipts until explicit client acknowledgement or a conservative
retention period. Storing the JWEs is safe: they are encrypted to the request
key and contain no server-decryptable second share.

### 6. Attestation is incomplete and downgradeable

`src/attestation.ts` currently:

- hashes only the identity public key into `report_data`;
- returns `mode: dev` if quote generation fails;
- omits event logs, KMS signature chains, workload information, policy/version,
  and a verifier challenge; and
- has no client verification implementation.

Production startup must fail closed when attestation/KMS is unavailable.
Attestation should bind a canonical manifest hash containing at least:

```text
service DID
protocol and state-schema versions
workload/app identity and approved measurement
identity public key
inbound wallet-encryption JWK thumbprint
state-key epoch
client challenge
```

Return the manifest, quote, event log/RTMR evidence, and KMS key signature chain.
The browser must verify quote validity, freshness, the expected measurement
policy, report-data recomputation, and the JWK/DID binding before encrypting a
share. Never silently accept `mode: dev` in production.

### 7. Enrollment TOFU and frontend trust remain

Stateless execution does not close these independent gaps:

- A malicious PDS can mint service auth and win first enrollment.
- Malicious served JavaScript can request or authorize an unintended digest.
- `sign` accepts an opaque EVM digest without chain ID, decoded transaction, or
  policy constraints.

Enrollment needs operator-independent WebAuthn verification. High-assurance
signing needs an independently trusted transaction confirmation surface and/or
an enclave policy engine over decoded transactions.

### 8. Pregenerated EOAs remain temporarily custodial

Moving pregenerated entropy into sealed external storage makes the workload
stateless, but does not change custody: any enclave authorized for the sealing
key can reconstruct the entire unclaimed wallet. Counterfactual smart-account
escrow or independent threshold operators are required to remove this property
while preserving send-before-claim UX.

## Proposed sealed state

Use a versioned canonical encoding and encrypt the entire record, not only the
server share. One conceptual plaintext is:

```ts
interface WalletStateV2 {
  schema: 2
  did: string
  stateVersion: bigint
  keyEpoch: number
  status: 'enrolled' | 'pregenerated' | 'active'
  enrollment: {
    requestPubkeyHex: string
    credential?: VerifiedWebAuthnCredential
  } | null
  lastNonce: bigint
  wallet: {
    shareSetVersion: number
    serverShare: Uint8Array
    evmPubkeyHex: string
    evmAddress: string
    solPubkeyHex: string
    solAddress: string
    createdAt: number
  } | null
  pregen: {
    entropy: Uint8Array
    evmPubkeyHex: string
    evmAddress: string
    solPubkeyHex: string
    solAddress: string
    createdAt: number
  } | null
  receipts: OperationReceipt[]
}
```

Seal with AES-256-GCM under the current state-sealing key. AAD must include a
fixed domain, schema version, key epoch, and DID (or DID hash). The external
object header may expose schema/epoch/revision for routing, but all such fields
must be repeated and authenticated inside the ciphertext.

The witness receipt authenticates `(didHash, stateVersion, ciphertextHash)`.

## Request/state transition model

For every mutating operation:

1. Load sealed state and storage revision.
2. Verify witness receipt and decrypt state in the enclave.
3. Verify authorization and expected `stateVersion`.
4. Reconstruct wallet material only when necessary.
5. Build the complete result, including user-encrypted delivery JWEs.
6. Build and seal the next state with `stateVersion + 1` and `requestId` receipt.
7. CAS the witness and external state using a protocol that cannot leave the
   service accepting an unwitnessed state. Define recovery for either-side
   partial failure explicitly.
8. Return the committed receipt. A retry is idempotent.

Multiple replicas can then process different DIDs concurrently. Competing
operations on one DID cause one CAS winner; losers reload and retry or return a
version conflict.

## Existing-wallet migration

There are two different migration goals.

### Continuity-only migration

The existing root seed can be wrapped by a KMS-derived migration key and loaded
only by the new measured workload. Existing SQLite rows can be converted into
sealed V2 records. This preserves addresses and shares.

It **does not provide retroactive operator-proof security**. A current VM
administrator could already have copied the seed file, server-share ciphertext,
and historical inbound device-share JWE. If those were combined, the wallet
entropy is permanently known; re-encryption cannot make it unknown again.

### Strong-security migration (recommended)

Start a new security epoch with new KMS keys and create new wallet entropy/new
addresses inside the measured stateless workload. Users transfer assets from
old wallets after verifying attestation. Old wallets remain exportable during a
bounded migration window.

For wallets known to hold no funds (the current demo/test wallets), reset and
recreate them after cutover. For any funded wallet, present an explicit asset
migration flow. Do not label an address created before attested cutover as
operator-proof.

If preserving addresses is mandatory, user recovery/re-sharding under the new
inbound JWK invalidates old shares but still cannot undo a previously captured
full entropy. It improves future operation security without establishing the
strong historical guarantee.

## Implementation phases

### Phase 0 — make claims accurate

- Document that the current deployment is unattested and operator-accessible.
- Add a production guard that refuses file/env root seeds and refuses
  attestation downgrade.
- Add a frontend fail-closed flag before real funds are permitted.

### Phase 1 — decouple and harden state transitions

- Add async `WalletStateRepository` and retain SQLite as a dev adapter.
- Move to one per-DID state aggregate.
- Add `requestId`, expected state/share-set version, and idempotent receipts.
- Make create, claim, recovery, request-key rotation, and nonce consumption
  atomic CAS transitions.
- Add concurrency and crash-injection tests.

### Phase 2 — external sealed storage

- Add canonical V2 state codec and full-record AEAD sealing.
- Implement an external CAS repository.
- Treat storage as hostile; add tamper, swap, stale-read, and rollback tests.
- Remove runtime dependence on a writable local data disk.

### Phase 3 — measured dstack workload and KMS

- Build a pinned OCI image and dstack application manifest.
- Deploy a separate dstack-kms CVM and authorize explicit measurements.
- Replace hand-written socket calls with the official dstack SDK.
- Use versioned, independent KMS key paths and retain signature chains.
- Fail startup if KMS/attestation requirements are unmet.

### Phase 4 — verifier and monotonic witness

- Implement challenge-bound attestation manifests and browser verification.
- Pin/govern accepted measurements and key epochs.
- Deploy an independent monotonic witness and require signed receipts.
- Test old-state replay across process/VM replacement.

### Phase 5 — security-epoch cutover

- Deploy the stateless workload alongside the current service.
- Test create/sign/export/recovery and a real Sepolia transaction.
- Recreate no-funds wallets; provide explicit migration for funded wallets.
- Switch the service DID endpoint only after browser verification is fail-closed.
- Retire and securely destroy the old seed and database after the migration
  window and backups are explicitly handled.

## Acceptance criteria

The design is complete only when all are true:

- A fresh replica boots with no wallet data disk and serves existing V2 wallets.
- The KMS refuses an unapproved workload measurement.
- The app refuses to start without verified KMS/attestation in production.
- The browser refuses a dev quote, stale quote, wrong measurement, wrong DID,
  wrong protocol, or substituted inbound JWK.
- External storage sees only sealed state and user-encrypted receipts.
- Tampered, swapped, or rolled-back records are rejected.
- Concurrent operations cannot both consume the same state version.
- Lost create/recovery responses are safely retriable.
- No local file contains root, sealing, wallet, device, or recovery secrets.
- Existing pre-cutover wallets are clearly labeled legacy or migrated to new
  post-cutover addresses.

## Primary files affected

- `src/store.ts`: split into repository interface, SQLite dev adapter, and
  external CAS adapter.
- `src/service.ts`: async loads/CAS; idempotent operation state machine.
- `src/wallet.ts`: versioned sealed-record AAD/key epochs; crypto core mostly
  unchanged.
- `src/dstack-kms.ts`: replace with official SDK adapter and independent paths.
- `src/attestation.ts`: manifest/challenge/evidence; no production downgrade.
- `src/index.ts`: stateless bootstrap, production guards, external dependencies.
- Client/MVP: attestation verifier, request IDs/state versions, migration UX.
