FROM node:20-slim
WORKDIR /app
RUN apt-get update && apt-get install -y --no-install-recommends curl && rm -rf /var/lib/apt/lists/*
RUN npm install -g bun
COPY package.json ./
RUN bun install
COPY tsconfig.json ./
COPY index.ts ./
COPY src ./src
COPY start.sh ./start.sh
RUN chmod +x ./start.sh
ENV NODE_ENV=production
EXPOSE 10000
HEALTHCHECK --interval=30s --timeout=10s --retries=3 --start-period=15s CMD curl -f http://localhost:${PORT:-10000}/healthz || exit 1
CMD ["sh", "./start.sh"]
