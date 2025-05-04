# Multi-stage build for Rust
FROM rust:1.76-slim-bullseye AS builder

# Install system dependencies
RUN apt-get update && apt-get install -y \
    build-essential \
    curl \
    wget \
    git \
    pkg-config \
    libssl-dev \
    && rm -rf /var/lib/apt/lists/*

# Install external security tools
RUN mkdir -p /tools
WORKDIR /tools

# Install Go for additional tools
RUN wget https://golang.org/dl/go1.21.5.linux-amd64.tar.gz \
    && tar -C /usr/local -xzf go1.21.5.linux-amd64.tar.gz \
    && rm go1.21.5.linux-amd64.tar.gz
ENV PATH=$PATH:/usr/local/go/bin:/root/go/bin

# Install Go-based security tools
RUN go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest \
    && go install -v github.com/projectdiscovery/nuclei/v2/cmd/nuclei@latest \
    && go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest \
    && go install -v github.com/tomnomnom/assetfinder@latest

# Install Nuclei templates
RUN mkdir -p /nuclei-templates \
    && nuclei -update-templates -update-directory /nuclei-templates

# Set up Rust project
WORKDIR /app
COPY Cargo.toml Cargo.lock ./

# Create minimal source tree with dummy main
RUN mkdir -p src && \
    echo 'fn main() { println!("Dummy main"); }' > src/main.rs

# Build dependencies first for better caching
RUN cargo build --release

# Remove the dummy source and copy in the real source
RUN rm -rf src
COPY src ./src

# Create necessary directory structure
RUN mkdir -p config/profiles config/templates

# Copy configuration files
COPY config/default.toml ./config/
COPY profiles/base.toml ./config/profiles/
COPY templates/*.html ./config/templates/ 2>/dev/null || true
COPY templates/*.md ./config/templates/ 2>/dev/null || true

# Build the application
RUN cargo build --release

# Final stage
FROM debian:bullseye-slim

# Install runtime dependencies
RUN apt-get update && apt-get install -y \
    ca-certificates \
    libssl-dev \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Copy tools from builder
COPY --from=builder /root/go/bin/subfinder /usr/local/bin/
COPY --from=builder /root/go/bin/nuclei /usr/local/bin/
COPY --from=builder /root/go/bin/httpx /usr/local/bin/
COPY --from=builder /root/go/bin/assetfinder /usr/local/bin/
COPY --from=builder /nuclei-templates /opt/nuclei-templates

# Copy built binary
COPY --from=builder /app/target/release/bbhunt /usr/local/bin/

# Copy config directories
COPY --from=builder /app/config /config

# Create necessary directories
RUN mkdir -p /data/reports /data/targets

# Set working directory
WORKDIR /data

# Create a non-root user
RUN useradd -m bbhunt && \
    chown -R bbhunt:bbhunt /data /config

# Set environment variables for configuration
ENV BBHUNT_GLOBAL_DATA_DIR=/data
ENV BBHUNT_GLOBAL_CONFIG_DIR=/config
ENV BBHUNT_GLOBAL_USER_AGENT="bbhunt-docker/0.1.0"
ENV BBHUNT_GLOBAL_PROFILE=base

# Switch to non-root user
USER bbhunt

# Default command
ENTRYPOINT ["bbhunt"]
CMD ["--help"]