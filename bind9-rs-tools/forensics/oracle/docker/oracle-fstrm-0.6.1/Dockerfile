# Oracle: fstrm 0.6.1 (Frame Streams; addendum §12, §26)
# Pinned source: bind9-rs-tools/forensics/sources/fstrm-0.6.1.tar.gz
# sha256 verified before build; installed under /opt/dep with a manifest.
# The release tarball ships configure.ac/Makefile.am but no generated
# configure, so autoreconf -i runs first.
# Build context: bind9-rs-tools/forensics/sources/

FROM debian:bookworm-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
        build-essential pkg-config libtool autoconf automake libevent-dev \
    && rm -rf /var/lib/apt/lists/*

ARG SHA256=4f0f7ad2b760119c441aba58271e84de683b3cc138530d02710896641866e2d2
COPY fstrm-0.6.1.tar.gz /usr/src/src.tar.gz
RUN echo "$SHA256  /usr/src/src.tar.gz" | sha256sum -c - \
    && mkdir -p /usr/src/dep && tar -xf /usr/src/src.tar.gz -C /usr/src/dep --strip-components=1 \
    && cd /usr/src/dep \
    && autoreconf -i \
    && ./configure --prefix=/opt/dep \
    && make -j"$(nproc)" \
    && make install \
    && cd / && rm -rf /usr/src/dep /usr/src/src.tar.gz \
    && find /opt/dep -type f \( -perm -111 -o -name '*.so*' \) -print0 \
       | sort -z | xargs -0 sha256sum > /opt/dep/ORACLE_MANIFEST.sha256

ENV PKG_CONFIG_PATH=/opt/dep/lib/pkgconfig \
    LD_LIBRARY_PATH=/opt/dep/lib \
    PATH=/opt/dep/bin:$PATH
