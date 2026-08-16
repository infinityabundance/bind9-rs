# Oracle: libidn2 2.3.8 (IDNA2008; addendum §12, §28)
# Pinned source: bind9-rs-tools/forensics/sources/libidn2-2.3.8.tar.gz
# Requires libunistring; gettext/gperf needed by the autotools build.
# Build context: bind9-rs-tools/forensics/sources/

FROM debian:bookworm-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
        build-essential pkg-config libunistring-dev gettext gperf \
    && rm -rf /var/lib/apt/lists/*

ARG SHA256=f557911bf6171621e1f72ff35f5b1825bb35b52ed45325dcdee931e5d3c0787a
COPY libidn2-2.3.8.tar.gz /usr/src/src.tar.gz
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
