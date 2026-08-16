/* probe-zlib.c — zlib 1.3.1 surface probe (§34, §37).
 *
 * Exercises the conservation surface: version/compile flags, zError, the
 * checksums (adler32/crc32 incl. combine), the one-shot API
 * (compress/compress2/uncompress/compressBound), the deflate stream (all
 * levels x strategies, windowBits wrappers, flush modes, dictionary, gzip
 * header incl. a full deflateSetHeader<->inflateGetHeader round trip,
 * deflatePrime/deflatePending/deflateParams/deflateCopy/deflateReset),
 * the inflate stream (wrappers, one-shot/small-out/byte-at-a-time feeding,
 * truncation/corruption error taxonomy + messages, inflateSync/inflatePrime/
 * inflateMark/inflateCopy/inflateReset), and the gz* file layer
 * (gzopen/gzdopen write+read round trips, a glibc-vsnprintf gzprintf
 * battery, gzseek/gztell/gzoffset/gzrewind, gzungetc, gzsetparams,
 * gzerror/gzclearerr and the wrong-mode error paths).
 *
 * Runs in the same oracle-zlib-1.3.1 container as the Rust mirror
 * (bind9-rs-tools/src/bin/zlib-probe.rs); stdout must be byte-identical.
 * All inputs are fixed buffers/strings; nothing wall-clock or address
 * dependent is printed (pointer values are fixed constants).
 */
#include <zlib.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <fcntl.h>
#include <unistd.h>

static void dump(const unsigned char *p, unsigned long n, unsigned long max) {
    unsigned long m = (max == 0 || n < max) ? n : max;
    unsigned long i;
    for (i = 0; i < m; i++)
        printf("%02x", p[i]);
    if (max != 0 && n > m)
        printf("(+%lu)", n - m);
}

static const char *mstr(const char *m) {
    return m ? m : "NULL";
}

static unsigned char corpus[8][2048];
static unsigned long clen[8];

static void build_corpus(void) {
    static const unsigned char fox[] = "The quick brown fox jumps over the lazy dog. ";
    static const unsigned char aaa[] = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    static const unsigned char abc[] = "abcabcabcabcabcabcabcabcabcabcabcabcabcabcabcabc";
    static const unsigned char hello[] = "hello world";
    int i;
    clen[0] = 0;
    clen[1] = 1;
    corpus[1][0] = 'a';
    clen[2] = (unsigned long)strlen((const char *)hello);
    memcpy(corpus[2], hello, clen[2]);
    for (i = 0; i < 20; i++)
        memcpy(corpus[3] + (unsigned long)i * 45, fox, 45);
    clen[3] = 900;
    for (i = 0; i < 30; i++)
        memcpy(corpus[4] + (unsigned long)i * 50, aaa, 50);
    clen[4] = 1500;
    for (i = 0; i < 40; i++)
        memcpy(corpus[5] + (unsigned long)i * 48, abc, 48);
    clen[5] = 1920;
    for (i = 0; i < 1000; i++)
        corpus[6][i] = (unsigned char)(i % 251);
    clen[6] = 1000;
    memset(corpus[7], 'x', 100);
    memset(corpus[7] + 100, 'y', 100);
    memset(corpus[7] + 200, 'z', 100);
    clen[7] = 300;
}

int main(void) {
    unsigned char out[4096];
    unsigned char back[4096];
    unsigned long i, c;
    int e, r;

    build_corpus();

    /* ---------------------------------------------------------- version */
    printf("== version ==\n");
    printf("  zlibVersion %s\n", zlibVersion());
    printf("  ZLIB_VERSION %s\n", ZLIB_VERSION);
    printf("  ZLIB_VERNUM 0x%x\n", ZLIB_VERNUM);
    printf("  zlibCompileFlags %lu\n", (unsigned long)zlibCompileFlags());

    /* ------------------------------------------------------------ zError */
    printf("== zError ==\n");
    for (e = -9; e <= 3; e++)
        printf("  zError(%d) -> %s\n", e, zError(e));
    printf("  zError(99) -> %s\n", zError(99));

    /* ---------------------------------------------------------- checksums */
    printf("== checksums ==\n");
    {
        static const unsigned char hello[] = "hello world";
        unsigned long a1, a2, a3, c1, c2, c3;
        printf("  adler32(1, \"\") = %08lx\n", adler32(1L, NULL, 0));
        printf("  adler32(1, \"a\") = %08lx\n", adler32(1L, corpus[1], 1));
        printf("  adler32(1, hello) = %08lx\n", adler32(1L, hello, 11));
        a1 = adler32(1L, corpus[6], 1000);
        printf("  adler32(1, cycle1000) = %08lx\n", a1);
        /* NMAX = 5552 boundary: two 5552-byte runs + spill */
        {
            unsigned char big[20000];
            for (i = 0; i < sizeof big; i++)
                big[i] = (unsigned char)((i * 7 + 3) % 251);
            a2 = adler32(1L, big, 5552);
            a3 = adler32(1L, big, 5553);
            printf("  adler32(1, big[5552]) = %08lx\n", a2);
            printf("  adler32(1, big[5553]) = %08lx\n", a3);
            printf("  adler32(1, big[20000]) = %08lx\n", adler32(1L, big, 20000));
            c1 = crc32(0L, big, 20000);
            printf("  crc32(0, big[20000]) = %08lx\n", c1);
            printf("  adler32_combine(%08lx,%08lx,%lu) = %08lx\n", a1, a3, 5553UL,
                   adler32_combine(a1, a3, 5553L));
            printf("  crc32_combine(%08lx,%08lx,%lu) = %08lx\n", c1, c1, 10000L,
                   crc32_combine(c1, c1, 10000L));
        }
        printf("  crc32(0, \"\") = %08lx\n", crc32(0L, NULL, 0));
        printf("  crc32(0, \"a\") = %08lx\n", crc32(0L, corpus[1], 1));
        printf("  crc32(0, hello) = %08lx\n", crc32(0L, hello, 11));
        printf("  crc32(crc32(0,\"a\"),\"b\") = %08lx\n", crc32(crc32(0L, corpus[1], 1), corpus[2], 1));
    }

    /* ------------------------------------------------------ compressBound */
    printf("== compressBound ==\n");
    {
        unsigned long ns[5] = {0, 1, 100, 1000, 100000};
        for (i = 0; i < 5; i++)
            printf("  compressBound(%lu) = %lu\n", ns[i], compressBound(ns[i]));
    }

    /* ---------------------------------------------------- compress2 matrix */
    printf("== compress2 levels ==\n");
    for (c = 0; c < 8; c++) {
        for (e = 0; e <= 9; e++) {
            uLongf outlen = sizeof out;
            int err = compress2(out, &outlen, corpus[c], clen[c], e);
            printf("  c%lu l%d err%d len%lu hex ", c, e, err, (unsigned long)outlen);
            dump(out, outlen, 96);
            printf("\n");
        }
    }

    /* ----------------------------------------------- compress vs compress2 */
    printf("== compress vs compress2(6) ==\n");
    {
        uLongf o1 = sizeof out, o2 = sizeof back;
        compress(out, &o1, corpus[3], clen[3]);
        compress2(back, &o2, corpus[3], clen[3], 6);
        printf("  default len %lu, level6 len %lu, identical %d\n", (unsigned long)o1,
               (unsigned long)o2, (o1 == o2 && memcmp(out, back, o1) == 0) ? 1 : 0);
    }

    /* ------------------------------------------------- uncompress round trip */
    printf("== uncompress round trip ==\n");
    for (c = 0; c < 8; c++) {
        uLongf outlen = sizeof out;
        compress2(out, &outlen, corpus[c], clen[c], 6);
        uLongf backlen = sizeof back;
        int err = uncompress(back, &backlen, out, outlen);
        int ok = (err == Z_OK && backlen == clen[c] && memcmp(back, corpus[c], clen[c]) == 0);
        printf("  c%lu err%d backlen%lu ok%d\n", c, err, (unsigned long)backlen, ok);
    }

    /* -------------------------------------------------- uncompress errors */
    printf("== uncompress errors ==\n");
    {
        uLongf outlen = sizeof out;
        compress2(out, &outlen, corpus[3], clen[3], 6);
        {
            uLongf tiny = 1;
            e = uncompress(back, &tiny, out, outlen);
            printf("  tiny dest: err%d\n", e);
        }
        {
            static const unsigned char garbage[] = "hello world this is not compressed data";
            uLongf bl = sizeof back;
            e = uncompress(back, &bl, garbage, sizeof garbage - 1);
            printf("  garbage: err%d\n", e);
        }
        {
            uLongf bl = sizeof back;
            e = uncompress(back, &bl, out, outlen - 5);
            printf("  truncated: err%d\n", e);
        }
    }

    /* ------------------------------------------------- deflate level x strategy */
    printf("== deflate level x strategy ==\n");
    {
        static const int levels[11] = {0, 1, 2, 3, 4, 5, 6, 7, 8, 9, -1};
        static const int strats[5] = {Z_DEFAULT_STRATEGY, Z_FILTERED, Z_HUFFMAN_ONLY, Z_RLE, Z_FIXED};
        int li, si;
        for (li = 0; li < 11; li++) {
            for (si = 0; si < 5; si++) {
                z_stream s;
                memset(&s, 0, sizeof s);
                e = deflateInit2(&s, levels[li], Z_DEFLATED, 15, 8, strats[si]);
                s.next_in = corpus[3];
                s.avail_in = (uInt)clen[3];
                s.next_out = out;
                s.avail_out = sizeof out;
                r = deflate(&s, Z_FINISH);
                printf("  l%2d s%d e%d ret%d out%lu hex ", levels[li], strats[si], e, r,
                       (unsigned long)s.total_out);
                dump(out, s.total_out, 96);
                printf(" end%d\n", deflateEnd(&s));
            }
        }
    }

    /* ------------------------------------------------- deflate windowBits */
    printf("== deflate windowBits ==\n");
    {
        static const int wbs[6] = {9, 15, 31, -15, -9, 8};
        int wi;
        for (wi = 0; wi < 6; wi++) {
            z_stream s;
            memset(&s, 0, sizeof s);
            e = deflateInit2(&s, 6, Z_DEFLATED, wbs[wi], 8, Z_DEFAULT_STRATEGY);
            s.next_in = corpus[3];
            s.avail_in = (uInt)clen[3];
            s.next_out = out;
            s.avail_out = sizeof out;
            r = deflate(&s, Z_FINISH);
            printf("  wb%d e%d ret%d out%lu hex ", wbs[wi], e, r, (unsigned long)s.total_out);
            dump(out, s.total_out, 0);
            printf("\n");
            deflateEnd(&s);
        }
        {
            static const int bad[5] = {7, 16, 0, 48, -16};
            for (wi = 0; wi < 5; wi++) {
                z_stream s;
                memset(&s, 0, sizeof s);
                e = deflateInit2(&s, 6, Z_DEFLATED, bad[wi], 8, Z_DEFAULT_STRATEGY);
                printf("  bad wb%d e%d\n", bad[wi], e);
            }
        }
    }

    /* ------------------------------------------------- deflate flush modes */
    printf("== deflate flush modes ==\n");
    {
        static const int flushes[3] = {Z_SYNC_FLUSH, Z_FULL_FLUSH, Z_BLOCK};
        int fi;
        for (fi = 0; fi < 3; fi++) {
            z_stream s;
            memset(&s, 0, sizeof s);
            deflateInit2(&s, 6, Z_DEFLATED, 15, 8, Z_DEFAULT_STRATEGY);
            /* first half, then the flush, then the rest, then Z_FINISH */
            s.next_in = corpus[3];
            s.avail_in = (uInt)(clen[3] / 2);
            s.next_out = out;
            s.avail_out = sizeof out;
            r = deflate(&s, flushes[fi]);
            printf("  flush%d pass1 ret%d out%lu\n", flushes[fi], r, (unsigned long)s.total_out);
            s.next_in = corpus[3] + clen[3] / 2;
            s.avail_in = (uInt)(clen[3] - clen[3] / 2);
            r = deflate(&s, Z_FINISH);
            printf("  flush%d pass2 ret%d out%lu hex ", flushes[fi], r, (unsigned long)s.total_out);
            dump(out, s.total_out, 0);
            printf("\n");
            deflateEnd(&s);
        }
        /* partial flush == no flush observable behavior: Z_PARTIAL_FLUSH */
        {
            z_stream s;
            memset(&s, 0, sizeof s);
            deflateInit2(&s, 6, Z_DEFLATED, 15, 8, Z_DEFAULT_STRATEGY);
            s.next_in = corpus[3];
            s.avail_in = (uInt)clen[3];
            s.next_out = out;
            s.avail_out = sizeof out;
            r = deflate(&s, Z_PARTIAL_FLUSH);
            printf("  partial ret%d out%lu\n", r, (unsigned long)s.total_out);
            deflateEnd(&s);
        }
    }

    /* ------------------------------------------------- deflate dictionary */
    printf("== deflate dictionary ==\n");
    {
        static const unsigned char dict[] = "the quick brown fox jumps over the lazy dog";
        z_stream s;
        memset(&s, 0, sizeof s);
        deflateInit2(&s, 6, Z_DEFLATED, 15, 8, Z_DEFAULT_STRATEGY);
        e = deflateSetDictionary(&s, dict, sizeof dict - 1);
        printf("  setdict e%d\n", e);
        s.next_in = corpus[3];
        s.avail_in = (uInt)clen[3];
        s.next_out = out;
        s.avail_out = sizeof out;
        r = deflate(&s, Z_FINISH);
        printf("  deflate ret%d out%lu hex ", r, (unsigned long)s.total_out);
        dump(out, s.total_out, 0);
        printf("\n");
        deflateEnd(&s);
        /* read back with dictionary */
        {
            z_stream is;
            unsigned char isout[2048];
            memset(&is, 0, sizeof is);
            inflateInit2(&is, 15);
            is.next_in = out;
            is.avail_in = (uInt)s.total_out;
            is.next_out = isout;
            is.avail_out = sizeof isout;
            r = inflate(&is, Z_NO_FLUSH);
            printf("  inflate ret%d adler %08lx msg %s\n", r, (unsigned long)is.adler, mstr(is.msg));
            e = inflateSetDictionary(&is, dict, sizeof dict - 1);
            printf("  inflateSetDictionary e%d\n", e);
            r = inflate(&is, Z_FINISH);
            printf("  inflate2 ret%d total_out%lu\n", r, (unsigned long)is.total_out);
            inflateEnd(&is);
        }
    }

    /* ----------------------------------------------------- gzip header */
    printf("== gzip header ==\n");
    {
        z_stream s;
        gz_header h;
        unsigned char extra[2] = {0x41, 0x42};
        char name[] = "hello.gz";
        char comment[] = "a comment";
        memset(&s, 0, sizeof s);
        deflateInit2(&s, 6, Z_DEFLATED, 31, 8, Z_DEFAULT_STRATEGY);
        memset(&h, 0, sizeof h);
        h.text = 1;
        h.time = 0x12345678;
        h.xflags = 4;
        h.os = 3;
        h.extra = extra;
        h.extra_len = 2;
        h.extra_max = 2;
        h.name = name;
        h.name_max = 8;
        h.comment = comment;
        h.comm_max = 9;
        h.hcrc = 1;
        e = deflateSetHeader(&s, &h);
        printf("  setheader e%d\n", e);
        s.next_in = corpus[3];
        s.avail_in = (uInt)clen[3];
        s.next_out = out;
        s.avail_out = sizeof out;
        r = deflate(&s, Z_FINISH);
        printf("  deflate ret%d out%lu hex ", r, (unsigned long)s.total_out);
        dump(out, s.total_out, 0);
        printf("\n");
        deflateEnd(&s);
        /* read back */
        {
            z_stream is;
            gz_header ih;
            unsigned char iextra[16];
            char iname[32];
            char icomment[64];
            unsigned char isout[2048];
            memset(&is, 0, sizeof is);
            inflateInit2(&is, 31);
            memset(&ih, 0, sizeof ih);
            ih.extra = iextra;
            ih.extra_max = 16;
            ih.name = iname;
            ih.name_max = 31;
            ih.comment = icomment;
            ih.comm_max = 63;
            e = inflateGetHeader(&is, &ih);
            printf("  inflateGetHeader e%d\n", e);
            is.next_in = out;
            is.avail_in = (uInt)s.total_out;
            is.next_out = isout;
            is.avail_out = sizeof isout;
            r = inflate(&is, Z_FINISH);
            printf("  inflate ret%d out%lu msg %s\n", r, (unsigned long)is.total_out, mstr(is.msg));
            printf("  head done%d text%d time%lu xflags%d os%d hcrc%d extra_len%u name'%s' comment'%s' extra ",
                   ih.done, ih.text, (unsigned long)ih.time, ih.xflags, ih.os, ih.hcrc,
                   ih.extra_len, ih.name, ih.comment);
            dump(iextra, ih.extra_len, 0);
            printf("\n");
            inflateEnd(&is);
        }
    }

    /* ------------------------------------------------- deflate utility calls */
    printf("== deflate utility calls ==\n");
    {
        z_stream s;
        unsigned int bits;
        int pending;
        memset(&s, 0, sizeof s);
        deflateInit2(&s, 6, Z_DEFLATED, 15, 8, Z_DEFAULT_STRATEGY);
        s.next_in = corpus[3];
        s.avail_in = (uInt)clen[3];
        s.next_out = out;
        s.avail_out = sizeof out;
        r = deflate(&s, Z_NO_FLUSH);
        printf("  pass1 ret%d out%lu\n", r, (unsigned long)s.total_out);
        e = deflatePending(&s, &pending, &bits);
        printf("  pending e%d pending%d bits%u\n", e, pending, bits);
        e = deflateParams(&s, 1, Z_FILTERED);
        printf("  params e%d\n", e);
        s.next_in = corpus[3] + clen[3] / 2;
        s.avail_in = (uInt)(clen[3] - clen[3] / 2);
        r = deflate(&s, Z_FINISH);
        printf("  pass2 ret%d out%lu hex ", r, (unsigned long)s.total_out);
        dump(out, s.total_out, 0);
        printf("\n");
        deflateEnd(&s);
    }
    {
        /* deflatePrime: insert 4 bits before a gzip stream */
        z_stream s;
        memset(&s, 0, sizeof s);
        deflateInit2(&s, 6, Z_DEFLATED, 31, 8, Z_DEFAULT_STRATEGY);
        e = deflatePrime(&s, 4, 0x5);
        s.next_in = corpus[2];
        s.avail_in = (uInt)clen[2];
        s.next_out = out;
        s.avail_out = sizeof out;
        r = deflate(&s, Z_FINISH);
        printf("  prime e%d ret%d out%lu hex ", e, r, (unsigned long)s.total_out);
        dump(out, s.total_out, 0);
        printf("\n");
        deflateEnd(&s);
    }
    {
        /* deflateCopy mid-stream */
        z_stream s, d;
        memset(&s, 0, sizeof s);
        memset(&d, 0, sizeof d);
        deflateInit2(&s, 6, Z_DEFLATED, 15, 8, Z_DEFAULT_STRATEGY);
        s.next_in = corpus[3];
        s.avail_in = (uInt)clen[3];
        s.next_out = out;
        s.avail_out = 100;
        r = deflate(&s, Z_NO_FLUSH);
        e = deflateCopy(&d, &s);
        printf("  copy e%d orig ret%d out%lu\n", e, r, (unsigned long)s.total_out);
        /* continue the copy */
        d.next_in = corpus[3] + (clen[3] - s.avail_in);
        d.avail_in = s.avail_in;
        d.next_out = out + s.total_out;
        d.avail_out = sizeof out - (uInt)s.total_out;
        r = deflate(&d, Z_FINISH);
        printf("  copy ret%d out%lu hex ", r, (unsigned long)d.total_out);
        dump(out, d.total_out, 0);
        printf("\n");
        deflateEnd(&s);
        deflateEnd(&d);
    }
    {
        /* deflateReset / deflateResetKeep */
        z_stream s;
        memset(&s, 0, sizeof s);
        deflateInit2(&s, 6, Z_DEFLATED, 15, 8, Z_DEFAULT_STRATEGY);
        s.next_in = corpus[3];
        s.avail_in = (uInt)clen[3];
        s.next_out = out;
        s.avail_out = sizeof out;
        r = deflate(&s, Z_FINISH);
        printf("  first ret%d out%lu\n", r, (unsigned long)s.total_out);
        e = deflateResetKeep(&s);
        printf("  resetKeep e%d\n", e);
        s.next_in = corpus[3];
        s.avail_in = (uInt)clen[3];
        s.next_out = out;
        s.avail_out = sizeof out;
        r = deflate(&s, Z_FINISH);
        printf("  second ret%d out%lu\n", r, (unsigned long)s.total_out);
        e = deflateReset(&s);
        printf("  reset e%d\n", e);
        deflateEnd(&s);
    }
    {
        /* deflate errors: bad level / bad wbits / uninitialized */
        z_stream s;
        memset(&s, 0, sizeof s);
        e = deflateInit2(&s, 10, Z_DEFLATED, 15, 8, Z_DEFAULT_STRATEGY);
        printf("  bad level e%d\n", e);
        memset(&s, 0, sizeof s);
        e = deflateInit2(&s, 6, Z_DEFLATED, 16, 8, Z_DEFAULT_STRATEGY);
        printf("  bad wbits e%d\n", e);
        memset(&s, 0, sizeof s);
        r = deflate(&s, Z_FINISH);
        printf("  uninit deflate ret%d\n", r);
        memset(&s, 0, sizeof s);
        r = deflateEnd(&s);
        printf("  uninit end ret%d\n", r);
    }

    /* -------------------------------------------------- inflate one-shot */
    printf("== inflate one-shot ==\n");
    {
        /* build three blobs: zlib, gzip, raw */
        unsigned char zblob[2048], gblob[2048], rblob[2048];
        uLongf zlen = sizeof zblob, glen = sizeof gblob, rlen = sizeof rblob;
        z_stream s;
        memset(&s, 0, sizeof s);
        deflateInit2(&s, 6, Z_DEFLATED, 15, 8, Z_DEFAULT_STRATEGY);
        s.next_in = corpus[3];
        s.avail_in = (uInt)clen[3];
        s.next_out = zblob;
        s.avail_out = (uInt)zlen;
        deflate(&s, Z_FINISH);
        zlen = (uLongf)s.total_out;
        deflateEnd(&s);
        memset(&s, 0, sizeof s);
        deflateInit2(&s, 6, Z_DEFLATED, 31, 8, Z_DEFAULT_STRATEGY);
        s.next_in = corpus[3];
        s.avail_in = (uInt)clen[3];
        s.next_out = gblob;
        s.avail_out = (uInt)glen;
        deflate(&s, Z_FINISH);
        glen = (uLongf)s.total_out;
        deflateEnd(&s);
        memset(&s, 0, sizeof s);
        deflateInit2(&s, 6, Z_DEFLATED, -15, 8, Z_DEFAULT_STRATEGY);
        s.next_in = corpus[3];
        s.avail_in = (uInt)clen[3];
        s.next_out = rblob;
        s.avail_out = (uInt)rlen;
        deflate(&s, Z_FINISH);
        rlen = (uLongf)s.total_out;
        deflateEnd(&s);

        /* zlib blob with 15, gzip with 31 and 47, raw with -15, and the
           wrong-wrapper errors */
        {
            static const int cases[5] = {15, 31, 47, -15, 15};
            unsigned char *blobs[5] = {zblob, gblob, gblob, rblob, rblob};
            unsigned long lens[5] = {0};
            int k;
            lens[0] = zlen;
            lens[1] = glen;
            lens[2] = glen;
            lens[3] = rlen;
            lens[4] = rlen;
            for (k = 0; k < 5; k++) {
                z_stream is;
                unsigned char isout[2048];
                memset(&is, 0, sizeof is);
                e = inflateInit2(&is, cases[k]);
                is.next_in = blobs[k];
                is.avail_in = (uInt)lens[k];
                is.next_out = isout;
                is.avail_out = sizeof isout;
                r = inflate(&is, Z_FINISH);
                printf("  wb%d ret%d in%lu out%lu avail_in%u adler%08lx msg%s end%d\n", cases[k],
                       r, (unsigned long)is.total_in, (unsigned long)is.total_out, is.avail_in,
                       (unsigned long)is.adler, mstr(is.msg), inflateEnd(&is));
            }
        }
        /* raw blob through auto-detection (47): raw has no header, so
           inflate's auto-detect skips the header check and decodes raw */
        {
            z_stream is;
            unsigned char isout[2048];
            memset(&is, 0, sizeof is);
            inflateInit2(&is, 47);
            is.next_in = rblob;
            is.avail_in = (uInt)rlen;
            is.next_out = isout;
            is.avail_out = sizeof isout;
            r = inflate(&is, Z_FINISH);
            printf("  raw+auto ret%d out%lu msg%s\n", r, (unsigned long)is.total_out, mstr(is.msg));
            inflateEnd(&is);
        }
    }

    /* ------------------------------------------------- inflate small-out */
    printf("== inflate small-out ==\n");
    {
        uLongf zlen = sizeof out;
        compress2(out, &zlen, corpus[3], clen[3], 6);
        z_stream is;
        memset(&is, 0, sizeof is);
        inflateInit2(&is, 15);
        is.next_in = out;
        is.avail_in = (uInt)zlen;
        for (i = 0; i < 400; i++) {
            unsigned char small[5];
            is.next_out = small;
            is.avail_out = sizeof small;
            r = inflate(&is, Z_NO_FLUSH);
            if (r != Z_OK && r != Z_BUF_ERROR)
                break;
            if (r == Z_BUF_ERROR && is.avail_in == 0)
                break;
        }
        r = inflate(&is, Z_FINISH);
        printf("  ret%d out%lu avail_in%u\n", r, (unsigned long)is.total_out, is.avail_in);
        inflateEnd(&is);
    }

    /* ------------------------------------------------- inflate byte-at-a-time */
    printf("== inflate byte-at-a-time ==\n");
    {
        uLongf zlen = sizeof out;
        compress2(out, &zlen, corpus[3], clen[3], 6);
        z_stream is;
        unsigned char isout[2048];
        memset(&is, 0, sizeof is);
        inflateInit2(&is, 15);
        is.next_out = isout;
        is.avail_out = sizeof isout;
        for (i = 0; i < zlen; i++) {
            unsigned char one = out[i];
            is.next_in = &one;
            is.avail_in = 1;
            r = inflate(&is, Z_NO_FLUSH);
            if (r != Z_OK)
                break;
        }
        r = inflate(&is, Z_FINISH);
        printf("  ret%d out%lu consumed%lu\n", r, (unsigned long)is.total_out,
               (unsigned long)is.total_in);
        inflateEnd(&is);
    }

    /* -------------------------------------------------- inflate errors */
    printf("== inflate errors ==\n");
    {
        uLongf zlen = sizeof out;
        compress2(out, &zlen, corpus[3], clen[3], 6);
        /* truncated */
        {
            z_stream is;
            unsigned char isout[2048];
            memset(&is, 0, sizeof is);
            inflateInit2(&is, 15);
            is.next_in = out;
            is.avail_in = (uInt)zlen - 3;
            is.next_out = isout;
            is.avail_out = sizeof isout;
            r = inflate(&is, Z_FINISH);
            printf("  truncated ret%d msg%s avail_in%u\n", r, mstr(is.msg), is.avail_in);
            inflateEnd(&is);
        }
        /* corrupted: flip a byte in the middle */
        {
            z_stream is;
            unsigned char isout[2048];
            unsigned char cpy[2048];
            memcpy(cpy, out, zlen);
            cpy[20] ^= 0x5a;
            memset(&is, 0, sizeof is);
            inflateInit2(&is, 15);
            is.next_in = cpy;
            is.avail_in = (uInt)zlen;
            is.next_out = isout;
            is.avail_out = sizeof isout;
            r = inflate(&is, Z_FINISH);
            printf("  corrupt ret%d msg%s\n", r, mstr(is.msg));
            inflateEnd(&is);
        }
        /* garbage */
        {
            z_stream is;
            unsigned char isout[2048];
            static const unsigned char garbage[] = "hello world this is not compressed data";
            memset(&is, 0, sizeof is);
            inflateInit2(&is, 15);
            is.next_in = garbage;
            is.avail_in = sizeof garbage - 1;
            is.next_out = isout;
            is.avail_out = sizeof isout;
            r = inflate(&is, Z_FINISH);
            printf("  garbage ret%d msg%s\n", r, mstr(is.msg));
            inflateEnd(&is);
        }
        /* raw stream with windowBits 15 (header check) */
        {
            z_stream is;
            unsigned char isout[2048];
            uLongf rlen = sizeof out;
            memset(&is, 0, sizeof is);
            inflateInit2(&is, 15);
            /* make a raw blob first */
            {
                z_stream s2;
                unsigned char rblob[2048];
                memset(&s2, 0, sizeof s2);
                deflateInit2(&s2, 6, Z_DEFLATED, -15, 8, Z_DEFAULT_STRATEGY);
                s2.next_in = corpus[3];
                s2.avail_in = (uInt)clen[3];
                s2.next_out = rblob;
                s2.avail_out = sizeof rblob;
                deflate(&s2, Z_FINISH);
                rlen = (uLongf)s2.total_out;
                deflateEnd(&s2);
                is.next_in = rblob;
                is.avail_in = (uInt)rlen;
            }
            is.next_out = isout;
            is.avail_out = sizeof isout;
            r = inflate(&is, Z_FINISH);
            printf("  raw-as-zlib ret%d msg%s\n", r, mstr(is.msg));
            inflateEnd(&is);
        }
        /* bad windowBits init */
        {
            z_stream is;
            memset(&is, 0, sizeof is);
            e = inflateInit2(&is, 16);
            printf("  init wb16 e%d msg%s\n", e, mstr(is.msg));
            memset(&is, 0, sizeof is);
            e = inflateInit2(&is, 7);
            printf("  init wb7 e%d msg%s\n", e, mstr(is.msg));
        }
        /* uninitialized */
        {
            z_stream is;
            memset(&is, 0, sizeof is);
            r = inflate(&is, Z_FINISH);
            printf("  uninit inflate ret%d\n", r);
            memset(&is, 0, sizeof is);
            r = inflateEnd(&is);
            printf("  uninit end ret%d\n", r);
        }
    }

    /* ---------------------------------------------------- inflateSync */
    printf("== inflateSync ==\n");
    {
        uLongf zlen = sizeof out;
        unsigned char mixed[4096];
        static const unsigned char garbage[] = "garbage garbage garbage garbage garbage";
        compress2(out, &zlen, corpus[3], clen[3], 6);
        memcpy(mixed, garbage, sizeof garbage - 1);
        memcpy(mixed + sizeof garbage - 1, out, zlen);
        z_stream is;
        unsigned char isout[2048];
        memset(&is, 0, sizeof is);
        inflateInit2(&is, 15);
        is.next_in = mixed;
        is.avail_in = (uInt)(sizeof garbage - 1 + zlen);
        is.next_out = isout;
        is.avail_out = sizeof isout;
        r = inflate(&is, Z_NO_FLUSH);
        printf("  first ret%d msg%s\n", r, mstr(is.msg));
        e = inflateSync(&is);
        printf("  sync e%d\n", e);
        r = inflate(&is, Z_FINISH);
        printf("  second ret%d out%lu msg%s\n", r, (unsigned long)is.total_out, mstr(is.msg));
        e = inflateSyncPoint(&is);
        printf("  syncPoint e%d\n", e);
        inflateEnd(&is);
    }

    /* ------------------------------------------------ inflatePrime/Mark */
    printf("== inflatePrime / inflateMark ==\n");
    {
        uLongf zlen = sizeof out;
        compress2(out, &zlen, corpus[3], clen[3], 6);
        z_stream is;
        unsigned char isout[2048];
        memset(&is, 0, sizeof is);
        inflateInit2(&is, 15);
        e = inflatePrime(&is, 8, 0x78);
        printf("  prime8 e%d\n", e);
        e = inflatePrime(&is, 9, 0);
        printf("  prime9 e%d\n", e);
        is.next_in = out;
        is.avail_in = (uInt)zlen;
        is.next_out = isout;
        is.avail_out = sizeof isout;
        r = inflate(&is, Z_FINISH);
        printf("  inflate ret%d out%lu\n", r, (unsigned long)is.total_out);
        inflateEnd(&is);
    }
    {
        uLongf zlen = sizeof out;
        unsigned char isout[2048];
        compress2(out, &zlen, corpus[3], clen[3], 6);
        z_stream is;
        memset(&is, 0, sizeof is);
        inflateInit2(&is, 15);
        is.next_in = out;
        is.avail_in = (uInt)zlen;
        is.next_out = isout;
        is.avail_out = sizeof isout;
        for (i = 0; i < 5; i++) {
            r = inflate(&is, Z_NO_FLUSH);
            printf("  mark step%lu ret%d mark%ld\n", i, r, (long)inflateMark(&is));
            if (r != Z_OK)
                break;
        }
        inflateEnd(&is);
    }

    /* ---------------------------------------------- inflate reset/copy */
    printf("== inflate reset/copy ==\n");
    {
        uLongf zlen = sizeof out;
        compress2(out, &zlen, corpus[3], clen[3], 6);
        z_stream is, ic;
        unsigned char isout[2048], icout[2048];
        memset(&is, 0, sizeof is);
        inflateInit2(&is, 15);
        is.next_in = out;
        is.avail_in = 30;
        is.next_out = isout;
        is.avail_out = sizeof isout;
        r = inflate(&is, Z_NO_FLUSH);
        e = inflateCopy(&ic, &is);
        printf("  copy e%d ret%d out%lu\n", e, r, (unsigned long)is.total_out);
        /* finish the original */
        is.next_in = out + 30;
        is.avail_in = (uInt)(zlen - 30);
        r = inflate(&is, Z_FINISH);
        printf("  orig ret%d out%lu\n", r, (unsigned long)is.total_out);
        /* finish the copy */
        ic.next_in = out + 30;
        ic.avail_in = (uInt)(zlen - 30);
        ic.next_out = icout;
        ic.avail_out = sizeof icout;
        r = inflate(&ic, Z_FINISH);
        printf("  copy ret%d out%lu\n", r, (unsigned long)ic.total_out);
        inflateEnd(&is);
        inflateEnd(&ic);
    }
    {
        uLongf zlen = sizeof out;
        compress2(out, &zlen, corpus[3], clen[3], 6);
        z_stream is;
        unsigned char isout[2048];
        memset(&is, 0, sizeof is);
        inflateInit2(&is, 15);
        is.next_in = out;
        is.avail_in = (uInt)zlen;
        is.next_out = isout;
        is.avail_out = sizeof isout;
        inflate(&is, Z_FINISH);
        printf("  total1 %lu\n", (unsigned long)is.total_out);
        e = inflateReset(&is);
        printf("  reset e%d\n", e);
        is.next_in = out;
        is.avail_in = (uInt)zlen;
        is.next_out = isout;
        is.avail_out = sizeof isout;
        inflate(&is, Z_FINISH);
        printf("  total2 %lu\n", (unsigned long)is.total_out);
        e = inflateReset2(&is, 31);
        printf("  reset2 wb31 e%d\n", e);
        inflateEnd(&is);
    }
    {
        /* inflateSetDictionary without a pending dictionary */
        uLongf zlen = sizeof out;
        static const unsigned char dict[] = "dictionary that is not needed";
        compress2(out, &zlen, corpus[3], clen[3], 6);
        z_stream is;
        memset(&is, 0, sizeof is);
        inflateInit2(&is, 15);
        e = inflateSetDictionary(&is, dict, sizeof dict - 1);
        printf("  setdict-not-needed e%d\n", e);
        inflateEnd(&is);
    }

    /* --------------------------------------------------------- gz layer */
    printf("== gz layer ==\n");
    {
        gzFile gz;
        unsigned char rbuf[4096];
        char line[256];
        int n;
        /* write */
        gz = gzopen("/tmp/zwork/a.gz", "wb6");
        printf("  open write %s\n", gz ? "ok" : "NULL");
        n = gzwrite(gz, corpus[3], (unsigned int)clen[3]);
        printf("  gzwrite %d\n", n);
        n = gzputs(gz, "\nline of text\n");
        printf("  gzputs %d\n", n);
        n = gzputc(gz, 'Z');
        printf("  gzputc %d\n", n);
        n = gzprintf(gz, "fmt int%d neg%d plus%+d sp% d zero%05d left%-6d| prec%.3d hex%x %X %#x oct%o %#o\n",
                     42, -42, 42, 42, 42, 42, 42, 255, 255, 255, 8, 8);
        printf("  gzprintf1 %d\n", n);
        n = gzprintf(gz, "str %s prec%.3s pad%8s left%-8s|\n", "hello", "hello", "hi", "hi");
        printf("  gzprintf2 %d\n", n);
        n = gzprintf(gz, "char %c%c\n", 'A', 'B');
        printf("  gzprintf3 %d\n", n);
        n = gzprintf(gz, "long %ld %lu %lx\n", -123456789L, 123456789UL, 0xdeadbeefUL);
        printf("  gzprintf4 %d\n", n);
        n = gzprintf(gz, "ll %lld %llu %llx\n", -1234567890123LL, 1234567890123ULL, 0xdeadbeefcafeULL);
        printf("  gzprintf5 %d\n", n);
        n = gzprintf(gz, "zu %zu zd %zd\n", (size_t)123456, (ptrdiff_t)-789);
        printf("  gzprintf6 %d\n", n);
        n = gzprintf(gz, "ptr %p %p\n", (void *)0x1234, (void *)0);
        printf("  gzprintf7 %d\n", n);
        n = gzprintf(gz, "flt %f %.2f %+8.2f %e %.3e %g %.3g %#g\n",
                     3.14159, 3.14159, 3.14159, 1234567.0, 1234567.0, 1234567.0, 1234567.0, 1234.5);
        printf("  gzprintf8 %d\n", n);
        n = gzprintf(gz, "pct %% star %*d %.*d\n", 6, 42, 4, 42);
        printf("  gzprintf9 %d\n", n);
        e = gzflush(gz, Z_SYNC_FLUSH);
        printf("  flush sync e%d\n", e);
        printf("  tell %ld offset %ld\n", (long)gztell(gz), (long)gzoffset(gz));
        e = gzclose_w(gz);
        printf("  close_w e%d\n", e);
        /* raw file bytes */
        {
            FILE *f = fopen("/tmp/zwork/a.gz", "rb");
            size_t got = fread(rbuf, 1, sizeof rbuf, f);
            fclose(f);
            printf("  rawfile len%lu hex ", (unsigned long)got);
            dump(rbuf, got, 0);
            printf("\n");
        }
        /* read back */
        gz = gzopen("/tmp/zwork/a.gz", "rb");
        printf("  open read %s\n", gz ? "ok" : "NULL");
        n = gzread(gz, rbuf, 37);
        printf("  gzread37 %d\n", n);
        if (gzgets(gz, line, sizeof line) == NULL) {
            printf("  gzgets -> NULL\n");
        } else {
            printf("  gzgets -> %s", line);
            if (line[0] == 0 || line[strlen(line) - 1] != '\n')
                printf("\n");
        }
        n = gzgetc(gz);
        printf("  gzgetc %d\n", n);
        n = gzungetc('Q', gz);
        printf("  gzungetc %d\n", n);
        n = gzgetc(gz);
        printf("  gzgetc-after-ungetc %d\n", n);
        printf("  tell %ld offset %ld\n", (long)gztell(gz), (long)gzoffset(gz));
        n = gzseek(gz, 10, SEEK_SET);
        printf("  seek_set %d\n", n);
        n = gzread(gz, rbuf, 20);
        printf("  gzread20 %d '%.*s'\n", n, n, rbuf);
        n = gzseek(gz, 5, SEEK_CUR);
        printf("  seek_cur %d\n", n);
        n = gzseek(gz, 0, SEEK_END);
        printf("  seek_end %d\n", n);
        n = gzseek(gz, -1, SEEK_SET);
        printf("  seek_neg %d\n", n);
        e = gzrewind(gz);
        printf("  rewind e%d\n", e);
        n = gzread(gz, rbuf, (unsigned int)clen[3] + 100);
        printf("  gzread-all %d\n", n);
        n = gzread(gz, rbuf, 10);
        printf("  gzread-eof %d eof%d\n", n, gzeof(gz));
        e = gzclose_r(gz);
        printf("  close_r e%d\n", e);
    }
    {
        /* error paths */
        int n;
        gzFile gz = gzopen("/tmp/zwork/does-not-exist.gz", "rb");
        printf("  open-nonexistent %s\n", gz ? "ok" : "NULL");
        gz = gzopen("/tmp/zwork/b.gz", "wb");
        printf("  open-b %s\n", gz ? "ok" : "NULL");
        {
            unsigned char tmp[32];
            memset(tmp, 'q', sizeof tmp);
            n = gzwrite(gz, tmp, sizeof tmp);
            printf("  b gzwrite %d\n", n);
            e = gzsetparams(gz, 9, Z_DEFAULT_STRATEGY);
            printf("  b setparams e%d\n", e);
            e = gzflush(gz, Z_FINISH);
            printf("  b flush-finish e%d\n", e);
            e = gzclose_w(gz);
            printf("  b close_w e%d\n", e);
        }
        /* read-only file: write-side ops fail with gzerror messages */
        gz = gzopen("/tmp/zwork/b.gz", "rb");
        {
            int errnum = 0;
            const char *msg;
            n = gzwrite(gz, (const void *)corpus[1], 1);
            msg = gzerror(gz, &errnum);
            printf("  ro gzwrite %d err%d msg'%s'\n", n, errnum, mstr(msg));
            n = gzputs(gz, "x");
            msg = gzerror(gz, &errnum);
            printf("  ro gzputs %d err%d msg'%s'\n", n, errnum, mstr(msg));
            n = gzprintf(gz, "x");
            msg = gzerror(gz, &errnum);
            printf("  ro gzprintf %d err%d msg'%s'\n", n, errnum, mstr(msg));
            e = gzsetparams(gz, 9, Z_DEFAULT_STRATEGY);
            msg = gzerror(gz, &errnum);
            printf("  ro setparams %d err%d msg'%s'\n", e, errnum, mstr(msg));
            e = gzclose_w(gz);
            msg = gzerror(gz, &errnum);
            printf("  ro close_w %d err%d msg'%s'\n", e, errnum, mstr(msg));
            e = gzclose_r(gz);
            printf("  ro close_r e%d\n", e);
        }
        /* write-only file: read-side ops fail */
        gz = gzopen("/tmp/zwork/b.gz", "wb");
        {
            int errnum = 0;
            const char *msg;
            unsigned char tmp[16];
            n = gzread(gz, tmp, sizeof tmp);
            msg = gzerror(gz, &errnum);
            printf("  wo gzread %d err%d msg'%s'\n", n, errnum, mstr(msg));
            n = gzgetc(gz);
            msg = gzerror(gz, &errnum);
            printf("  wo gzgetc %d err%d msg'%s'\n", n, errnum, mstr(msg));
            gzclearerr(gz);
            msg = gzerror(gz, &errnum);
            printf("  wo after clearerr err%d msg'%s'\n", errnum, mstr(msg));
            e = gzclose_w(gz);
            printf("  wo close_w e%d\n", e);
        }
        /* gzdopen */
        {
            int fd = open("/tmp/zwork/c.gz", O_WRONLY | O_CREAT | O_TRUNC, 0644);
            gzFile gz2 = gzdopen(fd, "wb");
            n = gzputs(gz2, "dopen content\n");
            printf("  gzdopen puts %d\n", n);
            e = gzclose_w(gz2);
            printf("  gzdopen close e%d\n", e);
        }
        /* gzbuffer on a fresh read file */
        {
            gzFile gz2 = gzopen("/tmp/zwork/c.gz", "rb");
            e = gzbuffer(gz2, 8192);
            printf("  gzbuffer e%d\n", e);
            {
                unsigned char tmp[64];
                n = gzread(gz2, tmp, sizeof tmp);
                printf("  gzbuffer read %d\n", n);
            }
            e = gzclose_r(gz2);
            printf("  gzbuffer close e%d\n", e);
        }
        /* gzread from /dev/null -> immediate EOF */
        {
            gzFile gz2 = gzopen("/dev/null", "rb");
            unsigned char tmp[8];
            n = gzread(gz2, tmp, sizeof tmp);
            printf("  devnull read %d eof%d\n", n, gzeof(gz2));
            e = gzclose_r(gz2);
            printf("  devnull close e%d\n", e);
        }
    }

    return 0;
}
