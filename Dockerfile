FROM node:20-slim
WORKDIR /app
RUN npm install -g bun
COPY package.json ./
RUN bun install
COPY tsconfig.json ./
COPY index.ts ./
COPY src ./src
ENV NODE_ENV=production
RUN echo '{}' > .z-ai-config
CMD ["bun", "index.ts"]
