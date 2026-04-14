# Stage 1: Build
FROM node:20-alpine AS builder
WORKDIR /app

RUN npm install -g pnpm

COPY package.json pnpm-lock.yaml* ./
RUN pnpm install --frozen-lockfile || pnpm install

COPY . .
RUN pnpm build

# Stage 2: Production
FROM node:20-alpine AS production
WORKDIR /app

RUN npm install -g pnpm
RUN addgroup -S appgroup && adduser -S appuser -G appgroup

COPY package.json pnpm-lock.yaml* ./
RUN pnpm install --prod --frozen-lockfile || pnpm install --prod

COPY --from=builder /app/dist ./dist
COPY --from=builder /app/public ./public

RUN chown -R appuser:appgroup /app
USER appuser

EXPOSE 3000
CMD ["node", "dist/server.js"]

# Development stage (default for docker-compose)
FROM node:20-alpine AS development
WORKDIR /app

RUN npm install -g pnpm ts-node-dev

COPY package.json pnpm-lock.yaml* ./
RUN pnpm install || npm install

COPY . .

EXPOSE 3000
CMD ["pnpm", "dev"]
