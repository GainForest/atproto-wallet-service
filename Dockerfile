# syntax=docker/dockerfile:1
# Pinned, reproducible image for the atproto-wallet-service dstack CVM
# deployment. The measured app-compose references this image by sha256
# digest, so the bytes here ARE the trust boundary — keep the build
# deterministic: pinned base images, frozen lockfile, no dev deps.

FROM node:22.21.1-bookworm-slim AS build
WORKDIR /app
RUN corepack enable
# better-sqlite3 needs a compiler toolchain at install time.
RUN apt-get update && apt-get install -y --no-install-recommends \
    python3 make g++ \
    && rm -rf /var/lib/apt/lists/*
COPY package.json pnpm-lock.yaml ./
RUN pnpm install --frozen-lockfile
COPY tsconfig.json ./
COPY src ./src
COPY lexicons ./lexicons
RUN pnpm build
# Prune to production dependencies only.
RUN pnpm prune --prod

FROM node:22.21.1-bookworm-slim
WORKDIR /app
ENV NODE_ENV=production
COPY --from=build /app/node_modules ./node_modules
COPY --from=build /app/dist ./dist
COPY --from=build /app/package.json ./package.json
# Runs as root inside the container: the dstack guest-agent socket
# (/var/run/dstack.sock) is root-owned in the CVM, and the CVM itself
# is the isolation boundary (no SSH, measured image).
EXPOSE 3020
CMD ["node", "dist/index.js"]
