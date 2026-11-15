FROM node:24.22.2-bookworm-slim AS deps

WORKDIR /build

RUN apt-get update \
    && apt-get install -y --no-install-recommends python3 make g++ \
    && rm -rf /var/lib/apt/lists/*

COPY package.json ./

RUN npm install --omit=dev --no-audit --no-fund \
    && npm cache clean --force


FROM node:24.22.2-bookworm-slim

ENV NODE_ENV=production
ENV PORT=4317
ENV DB_PATH=/app/data/safegate.sqlite

WORKDIR /app

COPY --from=deps /build/node_modules ./node_modules
COPY package.json ./
COPY src ./src
COPY test ./test

RUN node --check src/app.js \
    && node --check src/server.js \
    && node --check src/config.js \
    && node --check src/database.js \
    && node --check src/logger.js \
    && node --check src/token-rotator.js \
    && node --check src/api-token-store.js \
    && node --check src/proof-verifier.js \
    && node --test test/api-token-store.test.js test/proof-verifier.test.js test/ingest-api.test.js \
    && rm -rf test

RUN mkdir -p /app/data \
    && chown -R root:root /app \
    && chmod 0555 /app /app/src \
    && chmod 0444 /app/package.json /app/src/*.js \
    && chown -R node:node /app/data \
    && chmod 0750 /app/data

USER node

EXPOSE 4317

CMD ["node", "src/server.js"]
