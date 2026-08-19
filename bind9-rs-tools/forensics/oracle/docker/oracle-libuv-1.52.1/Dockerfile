# Oracle: libuv 1.52.1 (the event loop BIND 9.20's netmgr runs on; addendum
# §30).  Pinned source: bind9-rs-tools/forensics/sources/libuv-1.52.1.tar.gz
# sha256 verified before build; installed under /opt/dep with a manifest.
# The tarball is the upstream libuv release archive (autotools + Makefile.am).
# Build context: bind9-rs-tools/forensics/sources/

FROM debian:bookworm-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
        build-essential pkg-config automake libtool \
    && rm -rf /var/lib/apt/lists/*

ARG SHA256=478baf2599bfbc882c355288c9cb6f92e0e7dda435fa04031fa5b607cf3f414c
COPY libuv-1.52.1.tar.gz /usr/src/src.tar.gz
RUN echo "$SHA256  /usr/src/src.tar.gz" | sha256sum -c - \
    && mkdir -p /usr/src/dep && tar -xf /usr/src/src.tar.gz -C /usr/src/dep --strip-components=1 \
    && cd /usr/src/dep \
    && sh autogen.sh \
    && ./configure --prefix=/opt/dep \
    && make -j"$(nproc)" \
    && make install \
    && cd / && rm -rf /usr/src/dep /usr/src/src.tar.gz \
    && find /opt/dep -type f \( -perm -111 -o -name '*.so*' \) -print0 \
       | sort -z | xargs -0 sha256sum > /opt/dep/ORACLE_MANIFEST.sha256

ENV PKG_CONFIG_PATH=/opt/dep/lib/pkgconfig \
    LD_LIBRARY_PATH=/opt/dep/lib \
    PATH=/opt/dep/bin:$PATH
