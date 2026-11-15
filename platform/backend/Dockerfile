

FROM node:24.22.2-bookworm-slim



ENV NODE_ENV=production

ENV PORT=4317

ENV DB_PATH=/app/data/safegate.sqlite



WORKDIR /app



COPY package.json ./



RUN npm install --omit=dev --no-audit --no-fund \

    && npm cache clean --force



COPY src ./src



RUN node --check src/app.js \

    && node --check src/server.js \

    && node --check src/config.js \

    && node --check src/database.js \

    && node --check src/logger.js \

    && node --check src/token-rotator.js \

    && node --check src/api-token-store.js



RUN mkdir -p /app/data \

    && chown -R node:node /app



USER node



EXPOSE 4317



CMD ["node", "src/server.js"]

