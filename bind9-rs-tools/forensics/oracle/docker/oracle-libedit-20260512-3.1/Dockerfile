# Oracle: libedit 20260512-3.1 (NetBSD editline; BIND nslookup/dig interactive
# line editing; addendum §29)
# Pinned source: bind9-rs-tools/forensics/sources/libedit-20260512-3.1.tar.gz
# sha256 verified before build; installed under /opt/dep with a manifest.
# The tarball is the upstream NetBSD libedit (editline) 3.1 release archive.
# libedit links against ncurses for the termcap/terminfo API (tgetent/tgoto/
# tputs, HAVE_LIBNCURSES); ncurses-term pins the deterministic xterm terminfo
# entry the probes observe, so transcripts are byte-stable for TERM=xterm.
# Build context: bind9-rs-tools/forensics/sources/

FROM debian:bookworm-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
        build-essential \
        libncurses-dev \
        ncurses-term \
    && rm -rf /var/lib/apt/lists/*

ARG SHA256=432d5e7ea8b0116dd39f2eca7bc11d0eed77faa6b77ea526ace89907c23ea4a0
COPY libedit-20260512-3.1.tar.gz /usr/src/src.tar.gz
RUN echo "$SHA256  /usr/src/src.tar.gz" | sha256sum -c - \
    && mkdir -p /usr/src/dep && tar -xf /usr/src/src.tar.gz -C /usr/src/dep --strip-components=1 \
    && cd /usr/src/dep \
    && ./configure --prefix=/opt/dep > /dev/null \
    && make -j"$(nproc)" > /dev/null \
    && make install > /dev/null \
    && cd / && rm -rf /usr/src/dep /usr/src/src.tar.gz \
    && find /opt/dep -type f \( -perm -111 -o -name '*.so*' \) -print0 \
       | sort -z | xargs -0 sha256sum > /opt/dep/ORACLE_MANIFEST.sha256

ENV PKG_CONFIG_PATH=/opt/dep/lib/pkgconfig \
    LD_LIBRARY_PATH=/opt/dep/lib \
    PATH=/opt/dep/bin:$PATH
