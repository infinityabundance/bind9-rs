# Oracle: liburcu 0.15.6 (Userspace RCU — the concurrency substrate BIND
# 9.20's netmgr/isc depends on; addendum §30).  Pinned source:
# bind9-rs-tools/forensics/sources/liburcu-0.15.6.tar.gz sha256 verified
# before build; installed under /opt/dep with a manifest.  The release
# tarball carries no configure script, so bootstrap (autoreconf) runs first.
# Build context: bind9-rs-tools/forensics/sources/

FROM debian:bookworm-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
        build-essential pkg-config automake autoconf libtool \
    && rm -rf /var/lib/apt/lists/*

ARG SHA256=15c341ce8b93d3b70bec120c1df90b2b02a219d65593cddeb4b52521a950e45e
COPY liburcu-0.15.6.tar.gz /usr/src/src.tar.gz
RUN echo "$SHA256  /usr/src/src.tar.gz" | sha256sum -c - \
    && mkdir -p /usr/src/dep && tar -xf /usr/src/src.tar.gz -C /usr/src/dep --strip-components=1 \
    && cd /usr/src/dep \
    && ./bootstrap \
    && ./configure --prefix=/opt/dep \
    && make -j"$(nproc)" \
    && make install \
    && cd / && rm -rf /usr/src/dep /usr/src/src.tar.gz \
    && find /opt/dep -type f \( -perm -111 -o -name '*.so*' \) -print0 \
       | sort -z | xargs -0 sha256sum > /opt/dep/ORACLE_MANIFEST.sha256

ENV PKG_CONFIG_PATH=/opt/dep/lib/pkgconfig \
    LD_LIBRARY_PATH=/opt/dep/lib \
    PATH=/opt/dep/bin:$PATH
