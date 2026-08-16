# Oracle: BIND 9.20.26 with libidn2 enabled (IDN courts).
#
# Same pinned source and build as oracle-bind-9.20.26, but configured with
# `--with-libidn2=yes` so dig's +idnin/+idnout paths are compiled in — the
# configuration the IDN courts (CLI-DIG-0003) must compare against.
#
# Build:
#   docker build -f .../oracle-bind-9.20.26-idn/Dockerfile \
#       -t oracle-bind-9.20.26-idn bind9-rs-tools/forensics/sources/

FROM debian:bookworm-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
        build-essential pkg-config curl ca-certificates \
        libuv1-dev liburcu-dev libmaxminddb-dev liblmdb-dev libcap-dev \
        libidn2-dev libedit-dev libxml2-dev libjson-c-dev zlib1g-dev \
        libssl-dev libnghttp2-dev \
    && rm -rf /var/lib/apt/lists/*

ARG BIND_SHA256=55248def0f870c4c46b3de72978ea972615131516663188a4564dca1d20bf350

COPY bind-9.20.26.tar.xz /usr/src/bind.tar.xz
RUN echo "$BIND_SHA256  /usr/src/bind.tar.xz" | sha256sum -c - \
    && mkdir -p /usr/src/bind \
    && tar -xf /usr/src/bind.tar.xz -C /usr/src/bind --strip-components=1 \
    && cd /usr/src/bind \
    && ./configure --prefix=/opt/bind --with-libidn2=yes \
    && make -j"$(nproc)" \
    && make install \
    && cd / \
    && rm -rf /usr/src/bind /usr/src/bind.tar.xz \
    && find /opt/bind -type f \( -perm -111 -o -name '*.so*' \) -print0 \
       | sort -z | xargs -0 sha256sum > /opt/bind/ORACLE_MANIFEST.sha256

ENV PATH=/opt/bind/bin:/opt/bind/sbin:$PATH
RUN useradd -r -m oracle
WORKDIR /home/oracle
USER oracle
