# Oracle: libmaxminddb 1.13.3 (MaxMind DB reader; addendum §12, §33)
# Pinned source: bind9-rs-tools/forensics/sources/libmaxminddb-1.13.3.tar.gz
# Build context: bind9-rs-tools/forensics/sources/

FROM debian:bookworm-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
        build-essential pkg-config \
    && rm -rf /var/lib/apt/lists/*

ARG SHA256=a66502ea76eadbe17f2cd6fd708946777253972d2ae8157dee1b23a2fb528171
COPY libmaxminddb-1.13.3.tar.gz /usr/src/src.tar.gz
RUN echo "$SHA256  /usr/src/src.tar.gz" | sha256sum -c - \
    && mkdir -p /usr/src/dep && tar -xf /usr/src/src.tar.gz -C /usr/src/dep --strip-components=1 \
    && cd /usr/src/dep \
    && ./configure --prefix=/opt/dep \
    && make -j"$(nproc)" \
    && make install \
    && cd / && rm -rf /usr/src/dep /usr/src/src.tar.gz \
    && find /opt/dep -type f \( -perm -111 -o -name '*.so*' \) -print0 \
       | sort -z | xargs -0 sha256sum > /opt/dep/ORACLE_MANIFEST.sha256

ENV PKG_CONFIG_PATH=/opt/dep/lib/pkgconfig \
    LD_LIBRARY_PATH=/opt/dep/lib \
    PATH=/opt/dep/bin:$PATH
