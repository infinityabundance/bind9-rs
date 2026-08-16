# Oracle: zlib 1.3.1 (addendum §12, §34)
# Pinned source: bind9-rs-tools/forensics/sources/zlib-1.3.1.tar.gz
# sha256 verified before build; installed under /opt/dep with a manifest.
# zlib 1.3.1 ships a generated configure (autotools).
# Build context: bind9-rs-tools/forensics/sources/

FROM debian:bookworm-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
        build-essential \
    && rm -rf /var/lib/apt/lists/*

ARG SHA256=17e88863f3600672ab49182f217281b6fc4d3c762bde361935e436a95214d05c
COPY zlib-1.3.1.tar.gz /usr/src/src.tar.gz
RUN echo "$SHA256  /usr/src/src.tar.gz" | sha256sum -c - \
    && mkdir -p /usr/src/dep && tar -xf /usr/src/src.tar.gz -C /usr/src/dep --strip-components=1 \
    && cd /usr/src/dep \
    && ./configure --prefix=/opt/dep --shared \
    && make -j"$(nproc)" \
    && make install \
    && cd / && rm -rf /usr/src/dep /usr/src/src.tar.gz \
    && find /opt/dep -type f \( -perm -111 -o -name '*.so*' \) -print0 \
       | sort -z | xargs -0 sha256sum > /opt/dep/ORACLE_MANIFEST.sha256

ENV PKG_CONFIG_PATH=/opt/dep/lib/pkgconfig \
    LD_LIBRARY_PATH=/opt/dep/lib \
    PATH=/opt/dep/bin:$PATH
