# File: passwordless-auth/infra/Dockerfile
# Purpose: Multi-stage Dockerfile for building the production-ready Node.js application.

# --- Stage 1: Build Stage ---
FROM node:20-alpine as builder

# Set working directory
WORKDIR /usr/src/app

# Copy package.json and pnpm-lock.yaml to leverage Docker cache
COPY package.json ./
COPY pnpm-lock.yaml ./

# Install pnpm
RUN npm install -g pnpm

# Install dependencies (production dependencies only for the final image)
RUN pnpm install --frozen-lockfile

# Copy the rest of the application source code
COPY . .

# Build the TypeScript code
# The 'build' script should compile TypeScript to JavaScript in a 'dist' directory
RUN pnpm run build

# --- Stage 2: Production Stage ---
FROM node:20-alpine as production

# Set working directory
WORKDIR /usr/src/app

# Copy package.json and pnpm-lock.yaml
COPY package.json ./
COPY pnpm-lock.yaml ./

# Install pnpm
RUN npm install -g pnpm

# Install only production dependencies
# This is crucial for security and image size optimization
RUN pnpm install --prod --frozen-lockfile

# Copy the built application from the builder stage
COPY --from=builder /usr/src/app/dist ./dist

# Copy the infrastructure and migration scripts
COPY infra/ /usr/src/app/infra/
COPY scripts/ /usr/src/app/scripts/

# Expose the application port
EXPOSE 3000

# Set environment variables for the production environment
ENV NODE_ENV=production
ENV PORT=3000

# Healthcheck to ensure the container is running and responsive
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s \
  CMD curl -f http://localhost:$PORT/health || exit 1

# Command to run the application
# Use a process manager like PM2 or simply node to run the compiled index file
CMD ["node", "dist/server.js"]

