# dstack production deployment

This directory defines the **new security epoch** selected for the wallet
service. It does not reuse the unattested demo's file seed or SQLite volume.
Do not point the public hostname here until every cutover check below passes.

## Security properties

- Dedicated GCP Intel TDX CVM booted with dstack OS.
- Separate self-hosted dstack KMS CVM.
- Workload image referenced by OCI digest, never by a mutable tag.
- Production startup fails unless KMS key derivation and TDX quote generation
  both succeed through `/var/run/dstack.sock`.
- The quote report data binds the service DID, protocol version, identity key,
  and wallet-encryption JWK through `AttestationManifestV1`.
- The old operator-readable root seed and wallet state are not imported.

This fixes the service-side quote generation. Production still requires a
browser verifier that validates the quote, event log, accepted measurements,
and manifest before using the wallet-encryption JWK.

## 1. Release the workload image

Tag a reviewed commit. `.github/workflows/release-image.yml` builds an amd64
image, emits SBOM/provenance, pushes it to GHCR, and signs its digest with
GitHub OIDC.

Make the GHCR package public (or configure dstack registry credentials), verify
its cosign identity, then replace `IMAGE_DIGEST_REQUIRED` in
`docker-compose.yaml` with the released digest.

## 2. Deploy the self-hosted KMS

Follow the pinned dstack-cloud GCP KMS procedure from the deployment operator's
Linux host. Production mode requires:

1. a dedicated dstack KMS TDX CVM;
2. a production RPC endpoint and funded governance wallet;
3. deployed KMS/app governance contracts;
4. registration of the KMS OS image, aggregated measurement, and device ID;
5. bootstrap and finish only after independently verifying its quote.

Never place the governance private key, KMS seed, or generated `.env` in this
repository.

## 3. Deploy the wallet workload

Use dstack-cloud on Linux with `key_provider: kms`, `gateway_enabled: false`,
and the self-hosted KMS HTTPS URL. Copy this directory's compose file into the
generated dstack project. Create `.env` from `.env.example`, generate the admin
secret with `openssl rand -hex 32`, and let dstack encrypt the environment for
the measured workload.

The public ingress must proxy only to port 3020 on the dedicated CVM. Keep the
current deployment serving traffic while the new service is tested by direct
IP or a staging hostname.

## 4. Acceptance checks

All must pass before cutover:

- Container logs show KMS key loading and no development-seed path.
- `GET /health` is 200.
- `GET /v1/attestation` returns `mode: "dstack"`, a non-null quote, event log,
  VM config, and the expected manifest.
- An independent verifier validates TDX evidence, RTMR replay, dstack OS image,
  compose hash, and report-data hash.
- KMS denies an image with an unapproved compose measurement.
- Fresh DID smoke test passes enroll, create, sign, export, recovery, replay
  rejection, and a Sepolia transaction.
- Browser refuses dev/null quotes, altered manifests, stale challenges, wrong
  service DID, wrong measurement, and substituted JWKs.
- Monitoring alarms on quote/KMS/health failures.

Only then switch ingress/DNS. Keep the old deployment stopped but recoverable
for a short rollback window; because this is a clean epoch, old demo wallets do
not exist in the new service. Destroy old seed/database copies only after an
explicit backup-retention decision.
