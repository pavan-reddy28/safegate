FROM node:24.22.2-bookworm-slim AS builder

ENV NODE_OPTIONS="--max-old-space-size=512"
WORKDIR /build

COPY package.json ./
RUN npm install --no-audit --no-fund

COPY index.html vite.config.mjs ./
COPY src ./src
COPY bff ./bff
COPY test ./test

RUN npx vite build \
    && node --check bff/auth.js \
    && node --check bff/vault-client.js \
    && node --check bff/app.js \
    && node --check bff/server.js \
    && node --test test/*.test.js \
    && npm prune --omit=dev \
    && npm cache clean --force

FROM node:24.22.2-bookworm-slim

ENV NODE_ENV=production
ENV PORT=4318

WORKDIR /app

COPY --from=builder /build/node_modules ./node_modules
COPY --from=builder /build/dist ./dist
COPY package.json ./
COPY bff ./bff

RUN chown -R root:root /app \
    && chmod 0555 /app /app/bff \
    && chmod -R a+rX /app/dist \
    && chmod 0444 /app/package.json /app/bff/*.js

USER node

EXPOSE 4318

CMD ["node", "bff/server.js"]
