# Oracle: json-c 0.19 (JSON-C; addendum §12, §35)
# Pinned source: bind9-rs-tools/forensics/sources/json-c-0.19.tar.gz
# sha256 verified before build; installed under /opt/dep with a manifest.
# json-c 0.19 is cmake-only (no generated configure in the tarball).
# Build context: bind9-rs-tools/forensics/sources/

FROM debian:bookworm-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
        build-essential pkg-config cmake \
    && rm -rf /var/lib/apt/lists/*

ARG SHA256=37ad0249902e301bd9052bf712e511fcc6acff4ecaad4b5900aad9ce564e26de
COPY json-c-0.19.tar.gz /usr/src/src.tar.gz
RUN echo "$SHA256  /usr/src/src.tar.gz" | sha256sum -c - \
    && mkdir -p /usr/src/dep && tar -xf /usr/src/src.tar.gz -C /usr/src/dep --strip-components=1 \
    && mkdir -p /usr/src/build \
    && cd /usr/src/build \
    && cmake /usr/src/dep -DCMAKE_INSTALL_PREFIX=/opt/dep -DBUILD_SHARED_LIBS=ON \
    && make -j"$(nproc)" \
    && make install \
    && cd / && rm -rf /usr/src/build /usr/src/dep /usr/src/src.tar.gz \
    && find /opt/dep -type f \( -perm -111 -o -name '*.so*' \) -print0 \
       | sort -z | xargs -0 sha256sum > /opt/dep/ORACLE_MANIFEST.sha256

ENV PKG_CONFIG_PATH=/opt/dep/lib/pkgconfig \
    LD_LIBRARY_PATH=/opt/dep/lib \
    PATH=/opt/dep/bin:$PATH
