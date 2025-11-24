FROM golang:1.24-alpine AS builder

WORKDIR /build

COPY go.mod go.sum ./
RUN go mod download

COPY . .

RUN CGO_ENABLED=0 go build -o agent ./cmd/agent

FROM alpine:latest

WORKDIR /app

COPY --from=builder /build/agent .

CMD ["/app/agent"]
