# Build stage
FROM golang:1.27-alpine AS builder

WORKDIR /app

# Copy go mod files
COPY go.mod ./

# Download dependencies (none currently, but good practice)
RUN go mod download

# Copy source code
COPY . .

# Build the binary
RUN CGO_ENABLED=0 GOOS=linux go build -a -installsuffix cgo -o makealongerlink .

# Runtime stage
FROM alpine:3.24

RUN apk --no-cache add ca-certificates \
    && adduser -D -H -u 10001 app

WORKDIR /app

# Copy the binary from builder
COPY --from=builder /app/makealongerlink .

USER app

# Expose port
EXPOSE 60320

HEALTHCHECK --interval=30s --timeout=3s CMD wget -q -O /dev/null http://127.0.0.1:60320/ || exit 1

# Run the binary
CMD ["./makealongerlink"]
