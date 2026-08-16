# Oracle: BIND 9.20.26 tool suite (addendum §10, §11, §65 step 11).
#
# Hermetic and pinned:
#   - base image: debian:bookworm-slim (glibc 2.36; toolchain gcc-12)
#   - source:     bind-9.20.26.tar.xz COPY'd from the build context; its
#                 sha256 is verified against the pinned source manifest
#                 (forensics/sources/manifest-9.20.26.json) before configure.
#   - configure:  defaults + --prefix=/opt/bind, matching the host oracle
#                 build (which used only a --prefix override).
#   - provenance: /opt/bind/ORACLE_MANIFEST.sha256 records the sha256 of
#                 every installed executable and shared library.
#
# Build (context must contain the pinned tarball):
#   docker build -f bind9-rs-tools/forensics/oracle/docker/oracle-bind-9.20.26/Dockerfile \
#       -t oracle-bind-9.20.26 forensics/sources/
#
# Use:
#   docker run --rm oracle-bind-9.20.26 dig -v
#   docker run --rm oracle-bind-9.20.26 named-checkzone example.com example.zone

FROM debian:bookworm-slim

# Build dependencies satisfying the 9.20.26 configure.ac constraints
# (libuv >= 1.37: bookworm ships 1.44.2; liburcu >= 0.13: 0.14.0;
# json-c >= 0.11: 0.16; libxml2 >= 2.6.0: 2.9.14; libedit/libcap/maxminddb/
# lmdb auto-detected; openssl 3.0).
RUN apt-get update && apt-get install -y --no-install-recommends \
        build-essential pkg-config curl ca-certificates \
        libuv1-dev liburcu-dev libmaxminddb-dev liblmdb-dev libcap-dev \
        libidn2-dev libedit-dev libxml2-dev libjson-c-dev zlib1g-dev \
        libssl-dev libnghttp2-dev \
    && rm -rf /var/lib/apt/lists/*

# sha256 of bind-9.20.26.tar.xz from forensics/sources/manifest-9.20.26.json.
ARG BIND_SHA256=55248def0f870c4c46b3de72978ea972615131516663188a4564dca1d20bf350

COPY bind-9.20.26.tar.xz /usr/src/bind.tar.xz
RUN echo "$BIND_SHA256  /usr/src/bind.tar.xz" | sha256sum -c - \
    && mkdir -p /usr/src/bind \
    && tar -xf /usr/src/bind.tar.xz -C /usr/src/bind --strip-components=1 \
    && cd /usr/src/bind \
    && ./configure --prefix=/opt/bind \
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
