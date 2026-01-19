# Multi-stage Dockerfile for Simplicity Unchained Service

# Stage 1: Builder
FROM rust:1.92-slim as builder

# Install build dependencies
RUN apt-get update && apt-get install -y \
    pkg-config \
    libssl-dev \
    && rm -rf /var/lib/apt/lists/*

# Set working directory
WORKDIR /build

# Copy workspace manifests
COPY Cargo.toml rust-toolchain.toml ./

# Copy all workspace members (required by Cargo workspace)
COPY cli ./cli
COPY core ./core
COPY service ./service

# Build the service in release mode
RUN cargo build --release --package service

# Stage 2: Runtime
FROM debian:bookworm-slim

# Install runtime dependencies
RUN apt-get update && apt-get install -y \
    ca-certificates \
    libssl3 \
    && rm -rf /var/lib/apt/lists/*

# Create a non-root user
RUN useradd -m -u 1000 service

# Set working directory
WORKDIR /app

# Copy the compiled binary from builder
COPY --from=builder /build/target/release/service /app/service

# Copy the configuration file
COPY service/config.toml /app/config.toml

# Change ownership to the service user
RUN chown -R service:service /app

# Switch to non-root user
USER service

# Expose the service port (default: 8080)
EXPOSE 8080

# Set the entrypoint
ENTRYPOINT ["/app/service"]

# Default command arguments
CMD ["start", "--config", "/app/config.toml"]
