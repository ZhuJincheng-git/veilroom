FROM node:22-slim AS web-builder
WORKDIR /app
COPY . .
RUN npm install -g corepack@latest && corepack pnpm install && corepack pnpm run build:client

FROM golang:1.22-bookworm AS go-builder
WORKDIR /src
COPY server-go/go.mod ./
RUN go mod download
COPY server-go/ ./
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -trimpath -ldflags="-s -w" -o /veilroom .

FROM debian:bookworm-slim
WORKDIR /app
COPY --from=web-builder /app/dist/public ./dist/public
COPY --from=go-builder /veilroom ./veilroom
ENV PORT=3000
EXPOSE 3000
CMD ["/app/veilroom"]
