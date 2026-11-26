ARG BASE_IMAGE=debian:trixie
FROM ${BASE_IMAGE}

COPY apt/ /etc/apt/

RUN apt-get update -o APT::Update::Error-Mode=any && \
    apt-get install -y --no-install-recommends \
        bc bison build-essential busybox-static ca-certificates cpio curl file flex git \
        iproute2 kmod libcap-dev libelf-dev liblzma-dev libssl-dev libzstd-dev \
        openssh-client openssh-server pahole pkg-config procps python3 qemu-system-x86 \
        systemd-sysv udev virtiofsd virtme-ng xz-utils zlib1g-dev zstd && \
    apt-get install -y --no-install-recommends -t trixie-backports \
        cargo clang-21 lld-21 llvm-21 rustc && \
    rm -rf /var/lib/apt/lists/*

ENV PATH=/usr/lib/llvm-21/bin:${PATH}

RUN mkdir -p /usr/lib/modules
