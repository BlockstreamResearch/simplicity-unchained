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
COPY Cargo.toml Cargo.lock rust-toolchain.toml ./

# Copy all workspace members (required by Cargo workspace)
COPY cli ./cli
COPY core ./core
COPY service/Cargo.toml ./service/Cargo.toml
COPY service/src ./service/src
COPY jet_plugin_abi ./jet_plugin_abi
COPY plugin_tests ./plugin_tests

# Build the service in release mode
RUN cargo build --locked --release --package service

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

# Change ownership to the service user
RUN chown -R service:service /app

# Switch to non-root user
USER service

# Expose the example configuration's service port
EXPOSE 30431

# Set the entrypoint
ENTRYPOINT ["/app/service"]

# Requires an operator-provided read-only configuration mount
CMD ["start", "--config", "/app/config.toml"]
