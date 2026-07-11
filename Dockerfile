FROM node:22-bookworm-slim AS build

WORKDIR /opt/vibeguard

COPY package.json package-lock.json ./
RUN npm ci

COPY tsconfig.json ./
COPY scripts ./scripts
COPY src ./src
RUN npm run build

FROM node:22-bookworm-slim

RUN apt-get update \
  && apt-get install --yes --no-install-recommends git \
  && rm -rf /var/lib/apt/lists/*

WORKDIR /workspace
COPY --from=build /opt/vibeguard/dist /opt/vibeguard/dist
COPY scripts/docker-entrypoint.sh /usr/local/bin/vibeguard-entrypoint
RUN chmod 755 /usr/local/bin/vibeguard-entrypoint

ENTRYPOINT ["/usr/local/bin/vibeguard-entrypoint"]
CMD ["scan", ".", "--package-verification", "seed", "--fail-on", "critical"]
