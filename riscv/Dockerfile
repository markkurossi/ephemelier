FROM ubuntu:24.04

ENV DEBIAN_FRONTEND=noninteractive

# Install prebuilt RISC-V toolchains + QEMU
RUN apt-get update && apt-get install -y \
    gcc-riscv64-unknown-elf \
    binutils-riscv64-unknown-elf \
    gcc-riscv64-linux-gnu \
    libc6-dev-riscv64-cross \
    qemu-user \
    qemu-user-static \
    qemu-system-misc \
    gdb-multiarch \
    make \
    git \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /workspace

# Default MPC-friendly flags
ENV RISCV_MPC_FLAGS="-march=rv64im -mabi=lp64 -nostdlib -ffreestanding -O2"
ENV RISCV_LINUX_FLAGS="-march=rv64gc -mabi=lp64d -O2"

# Verify installations
RUN riscv64-unknown-elf-gcc --version && \
    riscv64-linux-gnu-gcc --version && \
    qemu-riscv64 --version
