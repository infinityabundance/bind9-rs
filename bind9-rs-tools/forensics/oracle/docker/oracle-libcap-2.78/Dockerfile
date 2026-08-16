# Oracle: libcap 2.78 (Linux capabilities; addendum §12, §27)
# Pinned source: bind9-rs-tools/forensics/sources/libcap-2.78.tar.xz
# libcap has no configure script: `make prefix=/opt/dep install`.
# Build context: bind9-rs-tools/forensics/sources/

FROM debian:bookworm-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
        build-essential \
    && rm -rf /var/lib/apt/lists/*

ARG SHA256=0d621e562fd932ccf67b9660fb018e468a683d7b827541df27813228c996bb11
COPY libcap-2.78.tar.xz /usr/src/src.tar.xz
RUN echo "$SHA256  /usr/src/src.tar.xz" | sha256sum -c - \
    && mkdir -p /usr/src/dep && tar -xf /usr/src/src.tar.xz -C /usr/src/dep --strip-components=1 \
    && cd /usr/src/dep \
    && make -j"$(nproc)" \
    && make prefix=/opt/dep RAISE_SETFCAP=no install \
    && cd / && rm -rf /usr/src/dep /usr/src/src.tar.xz \
    && find /opt/dep -type f \( -perm -111 -o -name '*.so*' \) -print0 \
       | sort -z | xargs -0 sha256sum > /opt/dep/ORACLE_MANIFEST.sha256

ENV PKG_CONFIG_PATH=/opt/dep/lib/pkgconfig \
    LD_LIBRARY_PATH=/opt/dep/lib \
    PATH=/opt/dep/bin:$PATH
