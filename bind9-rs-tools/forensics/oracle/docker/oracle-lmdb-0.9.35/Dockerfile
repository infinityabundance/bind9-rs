# Oracle: LMDB 0.9.35 (Lightning Memory-Mapped Database; addendum §24, §25)
# Pinned source: bind9-rs-tools/forensics/sources/LMDB_0.9.35.tar.gz
# sha256 verified before build; installed under /opt/dep with a manifest.
# The tarball is the upstream LMDB_0.9.35 release archive (libraries/liblmdb).
# Build context: bind9-rs-tools/forensics/sources/

FROM debian:bookworm-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
        build-essential \
    && rm -rf /var/lib/apt/lists/*

ARG SHA256=18b021fd589d30cc08860a9550a30ae51637117451385e9581616da751326632
COPY LMDB_0.9.35.tar.gz /usr/src/src.tar.gz
RUN echo "$SHA256  /usr/src/src.tar.gz" | sha256sum -c - \
    && mkdir -p /usr/src/dep && tar -xf /usr/src/src.tar.gz -C /usr/src/dep --strip-components=1 \
    && cd /usr/src/dep/libraries/liblmdb \
    && make -j"$(nproc)" \
    && make install prefix=/opt/dep \
    && cd / && rm -rf /usr/src/dep /usr/src/src.tar.gz \
    && find /opt/dep -type f \( -perm -111 -o -name '*.so*' \) -print0 \
       | sort -z | xargs -0 sha256sum > /opt/dep/ORACLE_MANIFEST.sha256

ENV PKG_CONFIG_PATH=/opt/dep/lib/pkgconfig \
    LD_LIBRARY_PATH=/opt/dep/lib \
    PATH=/opt/dep/bin:$PATH
