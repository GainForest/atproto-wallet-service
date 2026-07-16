# Production KMS deployment

The wallet workload must use a self-hosted dstack KMS whose authorization
policy is outside the KMS measurement. Do **not** use the public tdxlab KMS or
`auth-simple` controlled by a single operator for production custody.

This deployment uses dstack's on-chain authorization contracts:

1. Build `Dockerfile.kms` and `Dockerfile.auth-eth`; push and reference both by
   OCI digest.
2. Deploy `DstackKms` + `DstackApp` contracts under a multisig/timelock.
3. Register the dstack OS image hash, KMS early `mr_aggregated`, wallet app ID,
   and exact wallet app-compose hash.
4. Render `docker-compose.onchain.yaml.template` with literal image digests,
   contract address, RPC URL, admin-token hash, and image-download URL.
5. Deploy the KMS CVM with `key_provider=tpm`, get
   `Onboard.GetAttestationInfo`, confirm the registered MR, then call
   `Onboard.Bootstrap` and `/finish`.
6. Onboard a second KMS CVM from the first before any wallet receives funds.
   A single TPM-backed KMS is a catastrophic key-availability SPOF if its VM
   and vTPM are destroyed.
7. Enable GCE deletion protection on both KMS instances and retain their
   durable data disks (`auto-delete=no`).

## Required operator secrets

Never commit or paste these values into chat:

- `.secrets/base-sepolia-deployer-key` — funded governance deployer, migrated
  to multisig/timelock ownership after deployment.
- `.secrets/base-sepolia-rpc-url` — provider endpoint that supports
  `web3_clientVersion` for OpenZeppelin deployment tooling.
- KMS admin tokens — random 32-byte values; only hashes enter measured compose.

Base Sepolia is suitable for the MVP/staging validation. A real-value launch
must select an appropriately secured production chain and governance owners.
