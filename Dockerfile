# MXC on Linux uses the `bubblewrap` backend, which needs `bwrap` >= 0.5.0 and
# working user namespaces. Debian bookworm ships bwrap 0.8.0.
#
# Must be a glibc base image: the SDK ships a prebuilt glibc `lxc-exec`, which
# fails to relocate on Alpine/musl even with gcompat or libc6-compat.
FROM node:22-bookworm-slim

RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        bubblewrap \
        ca-certificates \
        # slirp4netns + iptables are only needed by the schema 0.8 private-
        # namespace network modes; installed so they can be exercised later.
        iptables \
        slirp4netns \
        uidmap \
    && rm -rf /var/lib/apt/lists/*

# Override when npmjs.org is not reachable from the build network, e.g.
#   docker compose build --build-arg NPM_REGISTRY=https://my-proxy/npm/
ARG NPM_REGISTRY=https://registry.npmjs.org/
RUN npm config set registry "$NPM_REGISTRY" && npm install -g pnpm@10.22.0

WORKDIR /app

COPY package.json pnpm-lock.yaml ./
RUN pnpm config set registry "$NPM_REGISTRY" && pnpm install --frozen-lockfile

COPY tsconfig.json ./
COPY src ./src

CMD ["pnpm", "dev"]
