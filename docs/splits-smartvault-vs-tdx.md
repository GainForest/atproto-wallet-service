# Splits SmartVault vs. attested TDX wallet

Date: 2026-07-17

Status: architecture decision record; no live TDX deployment exists

## Executive decision

For BumiCerts/GainForest **organization donation wallets**, keep the Splits
SmartVault design and finish its account-abstraction spending and recovery
work. Do not replace it with the TDX wallet solely for UX reasons.

The two designs solve different problems:

- A Splits SmartVault is an ERC-4337 smart account controlled directly by
  passkey or EOA signers. It is well matched to a public organization treasury,
  supports m-of-n authorization, has no always-on wallet backend, and can have a
  deterministic receive address before deployment.
- The TDX service creates ordinary EVM and Solana keys and protects each wallet
  as device/server/recovery 2-of-3 Shamir shares. It is better matched to a
  personal embedded wallet that needs raw-key export, cross-ecosystem signing,
  and explicit share-based recovery.

The deleted four-VM TDX validation topology cost approximately $550–575/month.
The SmartVault adds essentially no fixed wallet infrastructure cost beyond the
application's existing PDS, RPC, and frontend; it incurs gas/bundler/paymaster
costs when the account is deployed or used.

The recommendation is conditional. The current BumiCerts SmartVault integration
is a receive/setup implementation, not yet a complete treasury product. It must
fix the funded-counterfactual-address mutation risk, choose a real organization
threshold, verify passkey possession at registration, and implement deployment,
UserOperation submission, transaction confirmation, and post-deployment signer
management before meaningful funds are accepted.

## Scope and evidence

This comparison reviews:

- BumiCerts/certs-app commit
  [`01b0550acb4a6b26f4aeb1e8ef200f50e02cda29`](https://github.com/GainForest/certs-app/tree/01b0550acb4a6b26f4aeb1e8ef200f50e02cda29);
- Splits contracts commit
  [`71f09d309aabf967994ef623340129f186c340fd`](https://github.com/0xSplits/splits-contracts-monorepo/tree/71f09d309aabf967994ef623340129f186c340fd);
- atproto-wallet-service commit
  [`72720b3069d3c70dd99ed9ba59f1ec5e9ce15f41`](https://github.com/GainForest/atproto-wallet-service/tree/72720b3069d3c70dd99ed9ba59f1ec5e9ce15f41);
- the measured GCP Intel TDX validation completed and then deleted on
  2026-07-17.

“Splits” below means the **Splits SmartVault account-abstraction contracts**,
not the separate Splits revenue-distribution contracts.

## Architecture summaries

### Splits SmartVault

Upstream SmartVaults are ERC-4337 EntryPoint v0.7 accounts with m-of-n passkey
or EOA signers, ERC-1271 verification, modules, fallback handlers, and
merkelized operations
([upstream feature list](https://github.com/0xSplits/splits-contracts-monorepo/blob/71f09d309aabf967994ef623340129f186c340fd/packages/smart-vaults/README.md#L1-L41)).

The factory derives and optionally deploys an ERC-1967 proxy from the
implementation plus `owner`, ordered signer set, threshold, and salt. Its
`getAddress` path validates those inputs and predicts the same deterministic
address without deployment
([factory implementation](https://github.com/0xSplits/splits-contracts-monorepo/blob/71f09d309aabf967994ef623340129f186c340fd/packages/smart-vaults/src/vault/SmartVaultFactory.sol#L43-L109)).
The mainnet deployment file identifies factory
`0x8E6Af8Ed94E87B4402D0272C5D6b0D47F0483e7C`
([deployment record](https://github.com/0xSplits/splits-contracts-monorepo/blob/71f09d309aabf967994ef623340129f186c340fd/packages/smart-vaults/deployments/1.json)).

BumiCerts specializes this design as follows:

- owner is `address(0)`, so no separate superuser bypasses the signer set;
- founding signers are organization members' P-256 WebAuthn public keys;
- the v1 threshold is currently `1`, so any one enrolled signer can act;
- the salt is derived from the organization DID;
- the signer configuration and predicted address are written into the
  organization's ATProto repository.

These choices are explicit in
[`lib/splits-vault/shared.ts`](https://github.com/GainForest/certs-app/blob/01b0550acb4a6b26f4aeb1e8ef200f50e02cda29/lib/splits-vault/shared.ts#L1-L60).
The verification path fetches the PDS record, recomputes the factory address,
checks owner and threshold, and checks whether code has been deployed
([`lib/splits-vault/server.ts`](https://github.com/GainForest/certs-app/blob/01b0550acb4a6b26f4aeb1e8ef200f50e02cda29/lib/splits-vault/server.ts#L37-L104)).

The private passkey key remains in the platform authenticator; BumiCerts sends
only the credential ID and P-256 coordinates to its API
([passkey creation](https://github.com/GainForest/certs-app/blob/01b0550acb4a6b26f4aeb1e8ef200f50e02cda29/lib/splits-vault/passkey.ts#L3-L39)).

### Attested TDX wallet

The TDX design generates independent wallet entropy, derives normal EVM and
Solana accounts, and Shamir-splits entropy into three shares:

1. a sealed server share inside wallet-service state;
2. a device share delivered to the enrolled browser request key; and
3. a recovery share delivered to the user.

Signing, export, and recovery require a user-signed envelope carrying the
device/recovery material encrypted to the measured workload. A service-auth JWT
or admin secret alone is not a signing credential
([protocol and auth tiers](https://github.com/GainForest/atproto-wallet-service/blob/72720b3069d3c70dd99ed9ba59f1ec5e9ce15f41/README.md#L11-L62)).
The create path generates or claims entropy, derives keys, and performs the
2-of-3 split only after request-key enrollment
([create transition](https://github.com/GainForest/atproto-wallet-service/blob/72720b3069d3c70dd99ed9ba59f1ec5e9ce15f41/src/service.ts#L578-L620)).

The validated deployment used a measured dstack workload on GCP Intel TDX, two
self-hosted KMS CVMs, full TDX/vTPM/event-log verification, exact app/compose/OS
pins, and a challenge-bound wallet encryption JWK. Its authorization policy was
a mutable operator-managed static allowlist, so the deployment was not
operator-proof. The complete deployment and all KMS/wallet disks were deleted
on 2026-07-17
([deployment status and cost](https://github.com/GainForest/atproto-wallet-service/blob/72720b3069d3c70dd99ed9ba59f1ec5e9ce15f41/README.md#L74-L108)).

## Side-by-side comparison

| Dimension | Splits SmartVault | Attested TDX wallet |
| --- | --- | --- |
| Account type | ERC-4337 smart contract account | Ordinary EVM EOA plus Solana account |
| Primary authority | On-chain signer set and threshold | Any valid 2-of-3 share combination, mediated by request-key envelopes |
| User key | P-256 passkey private key in authenticator | Passkey-derived request key plus browser-held Shamir share |
| Organization support | Native m-of-n signer model | Not implemented; current state is one enrollment per DID |
| Receive before activation | Deterministic counterfactual address | Admin-pregenerated receive-only EOA |
| Unclaimed custody | No private key exists; future signer config controls deployment | Authorized KMS workload temporarily holds encrypted full pregen entropy |
| Spending | ERC-4337 UserOperation, potentially sponsored | Enclave reconstructs entropy and returns EOA signature |
| Recovery | Synced passkey, additional signers, or on-chain signer/threshold change | Recovery share + server share, local/PDS/file backup, then re-shard |
| Raw-key export | Not applicable; smart account has no single raw private key | Supported; user can export mnemonic/private keys |
| Chain coverage | Contract must be deployed/supported per chain; upstream is multi-chain | EVM and Solana derived from one wallet entropy |
| Fixed infrastructure | No dedicated wallet servers | Wallet, KMS, verifier/policy, durable state, monitoring |
| Marginal cost | Gas/bundler/paymaster and RPC | Low per user after fixed infrastructure; signing service remains online |
| Public verifiability | Contract code, signer set, threshold, and execution are on-chain after deployment | Quote and measurement verification plus public wallet binding record |
| Availability dependency | Chain, RPC, bundler/paymaster, authenticator | Wallet CVM, KMS, verifier, durable state, PDS, authenticator |
| Main trust risk | Contract/integration bugs and passkey recovery policy | KMS policy, verifier/frontend operators, TEE/platform bugs, rollback/availability |

## UX comparison

### Setup and receiving

Splits is the better default setup UX for an organization wallet. The current
modal creates a resident passkey and writes the resulting signer/address record
through one role-gated action
([modal flow](https://github.com/GainForest/certs-app/blob/01b0550acb4a6b26f4aeb1e8ef200f50e02cda29/components/global/modals/wallet/org-vault.tsx#L158-L221)).
No extension, seed phrase, server-side key ceremony, or deployment transaction
is required before displaying a receive address.

The TDX flow can be visually reduced to one button, but the protocol still has
more states: attestation verification, passkey/request-key enrollment, wallet
creation or claim, device-share storage, and recovery-share protection. Hiding
those states does not remove the recovery and availability obligations.

Both can accept funds before activation. Splits does this with a deterministic
counterfactual account. The TDX service does it with a pregenerated EOA, but the
preclaim enclave/KMS authorization domain can reconstruct that wallet, making
it more custodial before claim.

### Spending

Splits offers the better eventual organization UX: named member passkeys,
m-of-n approval, batched calls, gas sponsorship, and account-level policy are
natural ERC-4337 features. Upstream supports threshold signatures and lets the
last signer set current gas within limits
([light UserOperation design](https://github.com/0xSplits/splits-contracts-monorepo/blob/71f09d309aabf967994ef623340129f186c340fd/packages/smart-vaults/README.md#L35-L57)).

That UX is **not complete in the reviewed BumiCerts integration**. The reviewed
code creates/verifies PDS records and manages undeployed signer configurations;
no SmartVault deployment, WebAuthn assertion packaging, bundler/paymaster
submission, or post-deployment signer-management flow was found. The API
explicitly becomes read-only once code is detected
([deployment guard](https://github.com/GainForest/certs-app/blob/01b0550acb4a6b26f4aeb1e8ef200f50e02cda29/app/api/org-wallet/route.ts#L177-L233)).

The TDX prototype already demonstrated EIP-191 signing and ordinary EOA
transactions. It is therefore closer to a working personal hot wallet, but it
has no organization approval UX and requires online attestation/KMS services.

### Recovery and exit

TDX is stronger for a single person's explicit disaster recovery. The user can
recover with a separately protected Shamir share, rotate the share set after
recovery, and export standard mnemonic/private-key material to leave the
service.

Splits is stronger for organizational continuity when configured correctly:
several members can hold independent passkeys and an m-of-n threshold can
survive one device or member loss. It does not offer raw-key export because no
single private key controls the account; exit means authorizing an asset
transfer or changing signers/modules on-chain.

BumiCerts currently sets threshold `1`. Additional signers improve availability
but do **not** provide multisignature protection: every signer can spend alone.
That policy should not be described to users as “multisig” without qualification.

### Donor onboarding

Neither architecture solves the largest donor UX gap by itself: acquiring
USDC. An embedded TDX wallet removes WalletConnect for a logged-in donor but
still needs funding or a fiat on-ramp. For mainstream donors, card/fiat checkout
is likely a larger conversion improvement than replacing the receiving
organization's passkey SmartVault.

## Security and trust comparison

### SmartVault strengths

- Passkey private keys remain in authenticators and are not reconstructed by
  GainForest infrastructure.
- Authorization and execution become publicly auditable on-chain.
- The account continues to exist if GainForest, its PDS, or Splits' frontend is
  unavailable.
- The upstream account supports real m-of-n thresholds. The library rejects a
  zero threshold or one larger than the signer count
  ([threshold validation](https://github.com/0xSplits/splits-contracts-monorepo/blob/71f09d309aabf967994ef623340129f186c340fd/packages/smart-vaults/src/signers/MultiSigner.sol#L150-L175)).
- With owner zero, signer-authorized self-calls can manage signers/modules and
  the signer set remains the effective authority; direct external owner calls
  are unavailable
  ([authorization behavior](https://github.com/0xSplits/splits-contracts-monorepo/blob/71f09d309aabf967994ef623340129f186c340fd/packages/smart-vaults/src/vault/SmartVault.sol#L333-L359)).

### SmartVault risks and BumiCerts gaps

1. **Funded undeployed address can be orphaned.** The signer set is part of the
   CREATE2 address. BumiCerts allows signer additions/removals before deployment
   and recomputes the address, but the PATCH path does not first reject a funded
   old address. Funds sent to the prior counterfactual address can become
   operationally stranded unless the old configuration is retained and later
   deployed. Deletion has a balance guard, but signer mutation does not
   ([mutation path](https://github.com/GainForest/certs-app/blob/01b0550acb4a6b26f4aeb1e8ef200f50e02cda29/app/api/org-wallet/route.ts#L196-L233)).
2. **Threshold is one.** Compromise or unintended use of any single member
   passkey is sufficient to spend.
3. **No registration proof of possession.** The API validates the submitted
   credential ID and coordinates syntactically but does not issue and verify a
   challenge signed by the new credential before recording it
   ([passkey schema/create](https://github.com/GainForest/certs-app/blob/01b0550acb4a6b26f4aeb1e8ef200f50e02cda29/app/api/org-wallet/route.ts#L29-L45)).
4. **User verification is not required on-chain.** Upstream PasskeySigner calls
   WebAuthn verification with `requireUV: false`; user presence is checked, but
   the UV bit is not mandatory
   ([PasskeySigner](https://github.com/0xSplits/splits-contracts-monorepo/blob/71f09d309aabf967994ef623340129f186c340fd/packages/smart-vaults/src/signers/PasskeySigner.sol#L32-L53)).
   Product copy should not promise that every spend necessarily required a
   biometric/PIN unless the integration enforces that property another way.
5. **The on-chain verifier intentionally omits several WebAuthn checks.** It
   relies on the authenticator for origin/RP-ID enforcement and does not verify
   counters, backup state, or attestation
   ([documented assumptions](https://github.com/0xSplits/splits-contracts-monorepo/blob/71f09d309aabf967994ef623340129f186c340fd/packages/smart-vaults/src/library/WebAuthn.sol#L59-L114)).
6. **Upgradeable/module-capable account complexity.** Modules, fallback
   handlers, ERC-1967 upgrades, EntryPoint behavior, bundler/paymaster behavior,
   and transaction-building code expand the trusted code surface.
7. **Frontend transaction substitution remains possible.** A compromised
   frontend can ask the authenticator to approve an unintended call unless the
   confirmation surface independently presents decoded transaction intent.

The upstream repository contains two SmartVault audit reports. The first review
covered commit `1db8acb` in August 2024 and reported three low-severity and four
informational findings, addressed or acknowledged. The second covered commit
`dbc09cd8ed34e5f7003918eeaf8466eaf26cd894` and reported zero high/medium,
two low, and two informational findings
([first report](https://github.com/0xSplits/splits-contracts-monorepo/blob/71f09d309aabf967994ef623340129f186c340fd/audits/smartVaults-first.pdf),
[second report](https://github.com/0xSplits/splits-contracts-monorepo/blob/71f09d309aabf967994ef623340129f186c340fd/audits/smartVaults-second.pdf)).
These are meaningful evidence, not a guarantee, and they do not audit the
GainForest integration or every later upstream change.

### TDX strengths

- The operator cannot sign with only the sealed server share; a valid user
  envelope and second share are required.
- Standard EVM/Solana keys can be exported, audited with ordinary tooling, and
  migrated away from the service.
- Recovery rotates the share set rather than restoring the same browser secret.
- Exact workload measurements can make unauthorized application changes
  detectable when quote verification and key release are independently trusted.
- A normal EOA avoids ERC-4337 account-contract, bundler, module, upgrade, and
  counterfactual-deployment complexity.

### TDX risks

1. **Operator-managed KMS policy.** The validated static allowlist administrator
   could authorize another workload for key release. No blockchain governance
   or independent policy quorum constrained that administrator.
2. **Verifier and frontend trust.** The Vercel application delegated quote
   verification to an operator-run verifier and served the code handling device
   shares. A compromised verifier/frontend could bypass or misrepresent the
   intended policy.
3. **TEE/platform and supply-chain risk.** TDX proves what ran, not that dstack,
   the wallet service, dependencies, firmware, or verifier were vulnerability-free.
4. **Availability and state continuity.** Signing depended on wallet/KMS VMs,
   durable disks, networking, and operational recovery. The final active-wallet
   VM-recreation test was not completed before teardown.
5. **Rollback protection remains incomplete.** A durable encrypted state record
   still needs an independent monotonic witness to prevent restoration of an
   older valid state
   ([design gap](https://github.com/GainForest/atproto-wallet-service/blob/72720b3069d3c70dd99ed9ba59f1ec5e9ce15f41/docs/stateless-tee-design.md#L115-L138)).
6. **Enrollment TOFU.** A malicious PDS can mint service auth and race the
   legitimate user to first enrollment.
7. **Opaque-signing UX.** High assurance requires an independently trusted,
   decoded transaction confirmation surface; attesting an enclave does not
   prove that the user intended a digest supplied by compromised JavaScript.
8. **Unaudited application.** The wallet service remains experimental and was
   not externally audited.

## Cost and operations

### SmartVault

Fixed wallet-specific infrastructure can be near zero when BumiCerts already
pays for its frontend, PDS, and Ethereum RPC. Costs occur when used:

- factory/account deployment gas, often in the first UserOperation;
- bundler fees and optional paymaster sponsorship;
- RPC/indexing and monitoring;
- audits and incident response.

It scales economically with users because idle wallets do not require one VM
or one database row in a custody service. The tradeoff is blockchain gas and
smart-account integration complexity.

### TDX

The deleted validation topology used three standard `c3-standard-4` TDX VMs
(wallet + two KMS) and one Spot TDX VM (verifier/policy/support), plus disks and
public IPs. Estimated list price was $550–575/month before operational labor.
The cost was shared across all wallets, not charged per wallet, but it existed
while idle. The infrastructure now costs $0 because it was deleted.

A smaller topology can cost less, but removing KMS replicas, independent
verification, durable state, or restart automation changes the security and
availability model rather than merely optimizing it.

## Recommended BumiCerts plan

### Keep SmartVault for organization receiving wallets

It better matches public treasury ownership, member succession, on-chain
verification, and low fixed cost. Do not introduce an operator/KMS/TEE trust
boundary merely to make the wallet look embedded; the existing passkey UX is
already embedded.

### Required work before meaningful funds

1. **Freeze funded counterfactual configurations.** Before any undeployed signer
   mutation, check ETH/token balances. If funded, preserve and deploy the old
   configuration or reject the mutation. Store an immutable/versioned founding
   configuration and test recovery from every prior funded address.
2. **Choose governance before deployment.** Decide whether organizations need
   1-of-n, 2-of-n, or policy-dependent thresholds. Changing the founding
   threshold changes the counterfactual address.
3. **Prove credential possession.** Register passkeys through a server-issued
   challenge and verify the WebAuthn assertion before persisting coordinates.
4. **Build the complete spending path.** Implement account deployment,
   UserOperation construction, WebAuthn assertion encoding, simulation,
   bundler/paymaster submission, receipt tracking, and failure recovery.
5. **Build post-deployment governance.** Add signer, remove signer, threshold,
   module, and recovery actions as signer-authorized on-chain self-calls.
6. **Use human-readable confirmations.** Show recipient, asset, amount, chain,
   fees, batch contents, and policy impact before each passkey prompt.
7. **Audit the integration.** Upstream audits do not cover the PDS binding,
   counterfactual lifecycle, frontend transaction builder, bundler/paymaster,
   or organization-role mapping.
8. **Test device loss and member churn.** Include synced and non-synced
   passkeys, lost devices, removed staff, unavailable PDS, unavailable bundler,
   and an already-funded undeployed address.

### Consider TDX only for narrower optional roles

A future TDX wallet can make sense for:

- an optional personal embedded wallet requiring mnemonic/private-key export;
- EVM + Solana signing from one recovery scheme;
- automation/agent wallets with explicit policy and low value limits;
- a recovery service that users opt into and can leave.

It should not be the sole or default organization treasury authority under the
previous operator-managed verifier/KMS design. A hybrid could make a separately
governed service one SmartVault signer or recovery guardian, but that imports
its operator and availability risks into the on-chain account and must not
silently reduce the threshold.

## Decision matrix

| Use case | Preferred design | Reason |
| --- | --- | --- |
| Organization donation receiver | Splits SmartVault | Public signer governance, counterfactual receiving, minimal fixed cost |
| Organization treasury spending | Splits after completion | Native m-of-n and account policy; current Bumi flow is incomplete |
| Personal recoverable EOA | TDX, optionally | Standard exportable keys and explicit 2-of-3 recovery |
| Solana wallet | TDX | Current SmartVault is EVM-only |
| Crypto-native donor | Existing connected wallet | User already has assets; TDX adds another funding step |
| Mainstream donor | Fiat/card checkout | Wallet replacement does not solve USDC acquisition |
| High-value long-term treasury | Audited m-of-n SmartVault with independent signers | Avoid a single cloud/operator trust domain |
| Low-value automation wallet | Limited TDX or smart-account module | Choose based on chain and policy, with strict limits |

## Final conclusion

For BumiCerts, the best UX/security investment is not replacing Splits with
TDX. It is completing and hardening the SmartVault lifecycle while prioritizing
fiat donor onboarding. The TDX prototype demonstrated a useful personal-wallet
recovery model, but at materially higher fixed cost and with additional
operator, verifier, KMS, availability, and TEE trust assumptions.

Revisit TDX only when a concrete requirement cannot be met cleanly by the
SmartVault—for example raw-key export, Solana support, or a narrowly scoped
recoverable personal wallet—and price the operational trust model as part of
the product, not as invisible infrastructure.
