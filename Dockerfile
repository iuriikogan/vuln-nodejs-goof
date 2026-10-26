# syntax=docker/dockerfile:1
# Multi-stage hardened container build (Objectives 2.1, 2.2, 5.3)

# Stage 1: Build Go secretguard binary
FROM golang:1.23-bookworm AS go-builder
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY cmd/ ./cmd/
COPY internal/ ./internal/
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -trimpath -ldflags="-s -w" -o /out/secretguard ./cmd/secretguard

# Stage 2: Install production Node.js dependencies
FROM node:20-bookworm-slim AS node-builder
WORKDIR /app
COPY package.json package-lock.json ./
RUN npm ci --omit=dev --ignore-scripts

# Stage 3: Distroless non-root runtime image (UID 65532)
FROM gcr.io/distroless/nodejs20-debian12:nonroot
WORKDIR /app

COPY --from=go-builder /out/secretguard /usr/local/bin/secretguard
COPY --from=node-builder /app/node_modules ./node_modules
COPY app.js mongoose-db.js typeorm-db.js utils.js package.json ./
COPY entity/ ./entity/
COPY public/ ./public/
COPY routes/ ./routes/
COPY service/ ./service/
COPY views/ ./views/

ENV NODE_ENV=production
ENV PORT=3001
USER 65532:65532
EXPOSE 3001

CMD ["app.js"]
