FROM ubuntu:22.04

RUN apt-get update && apt-get install -y \
    build-essential \
    clang \
    llvm \
    libelf-dev \
    libpcap-dev \
    libbpf-dev \
    linux-tools-generic \
    linux-headers-generic \
    pkg-config \
    make \
    git \
    && rm -rf /var/lib/apt/lists/*

# Create work directory
WORKDIR /app

# Copy source code
COPY . /app/

# Build the project
RUN mkdir -p build && make

# Default command
CMD ["/bin/bash"]
