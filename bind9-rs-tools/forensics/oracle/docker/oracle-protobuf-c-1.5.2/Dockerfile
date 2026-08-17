# Oracle: protobuf-c 1.5.2 (libprotobuf-c runtime, the DNSTAP codec's C
# implementation; addendum §26)
# Pinned source: bind9-rs-tools/forensics/sources/protobuf-c-1.5.2.tar.gz
# sha256 verified before build; installed under /opt/dep with a manifest.
# The tarball is the upstream protobuf-c 1.5.2 release archive; the
# autotools build installs libprotobuf-c (and protoc-gen-c) under /opt/dep.
# Build context: bind9-rs-tools/forensics/sources/

FROM debian:bookworm-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
        build-essential \
        autoconf automake libtool pkg-config \
    && rm -rf /var/lib/apt/lists/*

ARG SHA256=e2c86271873a79c92b58fef7ebf8de1aa0df4738347a8bd5d4e65a80a16d0d24
COPY protobuf-c-1.5.2.tar.gz /usr/src/src.tar.gz
RUN echo "$SHA256  /usr/src/src.tar.gz" | sha256sum -c - \
    && mkdir -p /usr/src/dep && tar -xf /usr/src/src.tar.gz -C /usr/src/dep --strip-components=1 \
    && cd /usr/src/dep \
    && ./configure --prefix=/opt/dep --disable-protoc > /dev/null \
    && make -j"$(nproc)" > /dev/null \
    && make install > /dev/null \
    && cd / && rm -rf /usr/src/dep /usr/src/src.tar.gz \
    && find /opt/dep -type f \( -perm -111 -o -name '*.so*' \) -print0 \
       | sort -z | xargs -0 sha256sum > /opt/dep/ORACLE_MANIFEST.sha256

ENV PKG_CONFIG_PATH=/opt/dep/lib/pkgconfig \
    LD_LIBRARY_PATH=/opt/dep/lib \
    PATH=/opt/dep/bin:$PATH
