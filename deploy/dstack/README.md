# Measured dstack CVM deployment (GCP TDX)

This directory holds the canonical assets for running the wallet
service as a **measured dstack workload** on a GCP Intel TDX
confidential VM, deployed with the
[`dstack-cloud`](https://github.com/Phala-Network/meta-dstack-cloud)
CLI. In this mode:

- the guest image is the pinned dstack OS image (no SSH, immutable,
  measured into MRTD/RTMR0-2);
- the app (this compose file, with **digest-pinned** images) is
  measured into RTMR3 via the compose-hash;
- the root seed comes from the dstack KMS
  (`WALLET_SERVICE_ROOT_SEED_SOURCE=dstack-kms`), released only after
  remote attestation — deterministic across CVM re-creation, never on
  disk;
- the admin secret arrives through the dstack encrypted-env channel,
  decryptable only by the app-scoped KMS key inside the attested CVM;
- TLS terminates inside the CVM (Caddy with a Let's Encrypt cert for
  the sslip.io hostname of the reserved static IP).

## Files

| File | Role |
| --- | --- |
| `docker-compose.yaml.template` | Measured compose; placeholders for digests + hostname |
| `render-compose.sh` | Renders the template with literal digests (compose-hash pins code) |

## Deploy outline (run on a Linux deploy host)

```bash
# 1. Build + push the pinned image
docker build -t $REGION-docker.pkg.dev/$PROJECT/$REPO/atproto-wallet-service:$GIT_SHA .
docker push ...                      # note the sha256 digest

# 2. dstack-cloud project
dstack-cloud pull <dstack-cloud OS image tarballs>
dstack-cloud new wallet-cvm --os-image dstack-cloud-X.Y.Z --instance-name <name>
cd wallet-cvm

# 3. Render the measured compose
../deploy/dstack/render-compose.sh \
  "<image>@sha256:..." "caddy@sha256:..." "wallet-staging.<ip dashed>.sslip.io"

# 4. Secrets via encrypted env (only the admin secret)
echo "WALLET_SERVICE_ADMIN_SECRET=$(openssl rand -hex 32)" > .env

# 5. Deploy + firewall
dstack-cloud deploy --delete
dstack-cloud fw allow 80 && dstack-cloud fw allow 443
```

## Trust notes

- The compose template interpolates **only**
  `WALLET_SERVICE_ADMIN_SECRET` from the (unmeasured) encrypted env.
  Image digests, hostname, and SERVICE_DID are literal in the measured
  compose — changing any of them changes the compose-hash and
  therefore the attestation.
- The Phala tdxlab KMS endpoints are fine for staging; production
  custody should use a **self-hosted dstack-kms with on-chain
  governance** so that key release is bound to explicitly authorized
  measurements (see `docs/how-to/run-dstack-kms-on-gcp.md` in the
  dstack-cloud docs).
- `dstack-cloud deploy --delete` deletes and re-creates the data disk
  (wallet DB!). Upgrades of a stateful deployment need the data-disk
  preservation runbook (snapshot or auto-delete=no) — see the
  repository README "Known gaps".
