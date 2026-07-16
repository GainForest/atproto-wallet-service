#!/bin/sh
# Render the measured docker-compose from the template, pinning literal
# image digests + hostname so the dstack compose-hash (RTMR3) covers
# the exact code and public endpoint.
#
# Usage:
#   render-compose.sh <IMAGE_DIGEST> <CADDY_DIGEST> <WALLET_HOSTNAME> [out]
#
#   IMAGE_DIGEST     e.g. us-central1-docker.pkg.dev/p/r/wallet@sha256:...
#   CADDY_DIGEST     e.g. caddy@sha256:...
#   WALLET_HOSTNAME  e.g. wallet-staging.1-2-3-4.sslip.io
set -eu
IMAGE_DIGEST="$1"
CADDY_DIGEST="$2"
WALLET_HOSTNAME="$3"
OUT="${4:-docker-compose.yaml}"
TEMPLATE="$(dirname "$0")/docker-compose.yaml.template"

case "$IMAGE_DIGEST" in
  *@sha256:*) ;;
  *) echo "IMAGE_DIGEST must be digest-pinned (…@sha256:…)" >&2; exit 1 ;;
esac
case "$CADDY_DIGEST" in
  *@sha256:*) ;;
  *) echo "CADDY_DIGEST must be digest-pinned (…@sha256:…)" >&2; exit 1 ;;
esac

sed -e "s|@IMAGE_DIGEST@|$IMAGE_DIGEST|g" \
    -e "s|@CADDY_DIGEST@|$CADDY_DIGEST|g" \
    -e "s|@WALLET_HOSTNAME@|$WALLET_HOSTNAME|g" \
    "$TEMPLATE" > "$OUT"
echo "rendered $OUT"
