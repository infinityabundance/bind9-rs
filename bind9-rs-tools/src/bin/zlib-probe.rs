//! zlib-probe — Rust mirror of `forensics/oracle/probes/probe-zlib.c` for
//! the ZLIB-0001 court (§34, §37).  Runs in the same oracle-zlib-1.3.1
//! container; stdout must be byte-identical.
//!
//! Usage: zlib-probe

use bind9_rs_tools::compat::zlib::*;

fn dump(p: &[u8], max: usize) {
    let m = if max == 0 { p.len() } else { p.len().min(max) };
    for b in &p[..m] {
        print!("{b:02x}");
    }
    if max != 0 && p.len() > m {
        print!("(+{})", p.len() - m);
    }
}

fn mstr(m: Option<&'static str>) -> &'static str {
    m.unwrap_or("NULL")
}

/// Corpus mirror of build_corpus() in the C probe.
fn build_corpus() -> Vec<Vec<u8>> {
    let fox = b"The quick brown fox jumps over the lazy dog. ";
    let aaa = b"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    let abc = b"abcabcabcabcabcabcabcabcabcabcabcabcabcabcabcabc";
    let mut c = Vec::new();
    c.push(Vec::new());
    c.push(vec![b'a']);
    c.push(b"hello world".to_vec());
    let mut fox20 = Vec::new();
    for _ in 0..20 {
        fox20.extend_from_slice(fox);
    }
    c.push(fox20);
    let mut aaa30 = Vec::new();
    for _ in 0..30 {
        aaa30.extend_from_slice(aaa);
    }
    c.push(aaa30);
    let mut abc40 = Vec::new();
    for _ in 0..40 {
        abc40.extend_from_slice(abc);
    }
    c.push(abc40);
    c.push((0..1000).map(|i| (i % 251) as u8).collect());
    let mut xyz = Vec::new();
    xyz.extend(std::iter::repeat(b'x').take(100));
    xyz.extend(std::iter::repeat(b'y').take(100));
    xyz.extend(std::iter::repeat(b'z').take(100));
    c.push(xyz);
    c
}

fn main() {
    let corpus = build_corpus();
    let mut out = vec![0u8; 4096];
    let mut back = vec![0u8; 4096];

    /* ---------------------------------------------------------- version */
    println!("== version ==");
    println!("  zlibVersion {}", zlib_version());
    println!("  ZLIB_VERSION {ZLIB_VERSION}");
    println!("  ZLIB_VERNUM 0x{ZLIB_VERNUM:x}");
    println!("  zlibCompileFlags {}", zlib_compile_flags());

    /* ------------------------------------------------------------ zError */
    println!("== zError ==");
    for e in -9..=3 {
        println!("  zError({e}) -> {}", z_error(e));
    }
    println!("  zError(99) -> {}", z_error(99));

    /* ---------------------------------------------------------- checksums */
    println!("== checksums ==");
    {
        let hello = b"hello world";
        println!("  adler32(1, \"\") = {:08x}", adler32(1, &[]));
        println!("  adler32(1, \"a\") = {:08x}", adler32(1, &corpus[1]));
        println!("  adler32(1, hello) = {:08x}", adler32(1, hello));
        let a1 = adler32(1, &corpus[6]);
        println!("  adler32(1, cycle1000) = {a1:08x}");
        let mut big = Vec::new();
        for i in 0..20000usize {
            big.push(((i * 7 + 3) % 251) as u8);
        }
        let a2 = adler32(1, &big[..5552]);
        let a3 = adler32(1, &big[..5553]);
        println!("  adler32(1, big[5552]) = {a2:08x}");
        println!("  adler32(1, big[5553]) = {a3:08x}");
        println!("  adler32(1, big[20000]) = {:08x}", adler32(1, &big));
        let c1 = crc32(0, &big);
        println!("  crc32(0, big[20000]) = {c1:08x}");
        println!(
            "  adler32_combine({a1:08x},{a3:08x},5553) = {:08x}",
            adler32_combine(a1, a3, 5553)
        );
        println!(
            "  crc32_combine({c1:08x},{c1:08x},10000) = {:08x}",
            crc32_combine(c1, c1, 10000)
        );
        println!("  crc32(0, \"\") = {:08x}", crc32(0, &[]));
        println!("  crc32(0, \"a\") = {:08x}", crc32(0, &corpus[1]));
        println!("  crc32(0, hello) = {:08x}", crc32(0, hello));
        println!(
            "  crc32(crc32(0,\"a\"),\"b\") = {:08x}",
            crc32(crc32(0, &corpus[1]), &corpus[2][..1])
        );
    }

    /* ------------------------------------------------------ compressBound */
    println!("== compressBound ==");
    for n in [0u64, 1, 100, 1000, 100000] {
        println!("  compressBound({n}) = {}", compress_bound(n));
    }

    /* ---------------------------------------------------- compress2 matrix */
    println!("== compress2 levels ==");
    for (c, data) in corpus.iter().enumerate() {
        for level in 0..=9 {
            let (err, outlen) = compress2(&mut out, data, level);
            print!("  c{c} l{level} err{err} len{outlen} hex ");
            dump(&out[..outlen as usize], 96);
            println!();
        }
    }

    /* ----------------------------------------------- compress vs compress2 */
    println!("== compress vs compress2(6) ==");
    {
        let (_, o1) = compress(&mut out, &corpus[3]);
        let (_, o2) = compress2(&mut back, &corpus[3], 6);
        let identical = if o1 == o2 && out[..o1 as usize] == back[..o2 as usize] {
            1
        } else {
            0
        };
        println!("  default len {o1}, level6 len {o2}, identical {identical}");
    }

    /* ------------------------------------------------- uncompress round trip */
    println!("== uncompress round trip ==");
    for (c, data) in corpus.iter().enumerate() {
        let (_, outlen) = compress2(&mut out, data, 6);
        let (err, backlen) = uncompress(&mut back, &out[..outlen as usize]);
        let ok = if err == Z_OK && backlen == data.len() as u64 && &back[..backlen as usize] == data
        {
            1
        } else {
            0
        };
        println!("  c{c} err{err} backlen{backlen} ok{ok}");
    }

    /* -------------------------------------------------- uncompress errors */
    println!("== uncompress errors ==");
    {
        let (_, outlen) = compress2(&mut out, &corpus[3], 6);
        {
            let mut tiny = [0u8; 1];
            let (e, _) = uncompress(&mut tiny, &out[..outlen as usize]);
            println!("  tiny dest: err{e}");
        }
        {
            let garbage = b"hello world this is not compressed data";
            let (e, _) = uncompress(&mut back, garbage);
            println!("  garbage: err{e}");
        }
        {
            let (e, _) = uncompress(&mut back, &out[..outlen as usize - 5]);
            println!("  truncated: err{e}");
        }
    }

    /* ------------------------------------------------- deflate level x strategy */
    println!("== deflate level x strategy ==");
    {
        let levels = [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, -1];
        let strats = [
            Z_DEFAULT_STRATEGY,
            Z_FILTERED,
            Z_HUFFMAN_ONLY,
            Z_RLE,
            Z_FIXED,
        ];
        for level in levels {
            for strat in strats {
                let mut s = ZStream::default();
                let e = deflate_init2(&mut s, level, Z_DEFLATED, 15, 8, strat);
                let r = deflate(&mut s, &corpus[3], &mut out, Z_FINISH);
                print!("  l{level:2} s{strat} e{e} ret{r} out{} hex ", s.total_out);
                dump(&out[..s.total_out as usize], 96);
                println!(" end{}", deflate_end(&mut s));
            }
        }
    }

    /* ------------------------------------------------- deflate windowBits */
    println!("== deflate windowBits ==");
    {
        let wbs = [9, 15, 31, -15, -9, 8];
        for wb in wbs {
            let mut s = ZStream::default();
            let e = deflate_init2(&mut s, 6, Z_DEFLATED, wb, 8, Z_DEFAULT_STRATEGY);
            let r = deflate(&mut s, &corpus[3], &mut out, Z_FINISH);
            print!("  wb{wb} e{e} ret{r} out{} hex ", s.total_out);
            dump(&out[..s.total_out as usize], 0);
            println!();
            deflate_end(&mut s);
        }
        for wb in [7, 16, 0, 48, -16] {
            let mut s = ZStream::default();
            let e = deflate_init2(&mut s, 6, Z_DEFLATED, wb, 8, Z_DEFAULT_STRATEGY);
            println!("  bad wb{wb} e{e}");
        }
    }

    /* ------------------------------------------------- deflate flush modes */
    println!("== deflate flush modes ==");
    {
        let flushes = [Z_SYNC_FLUSH, Z_FULL_FLUSH, Z_BLOCK];
        for fl in flushes {
            let mut s = ZStream::default();
            deflate_init2(&mut s, 6, Z_DEFLATED, 15, 8, Z_DEFAULT_STRATEGY);
            let half = corpus[3].len() / 2;
            let r = deflate(&mut s, &corpus[3][..half], &mut out, fl);
            println!("  flush{fl} pass1 ret{r} out{}", s.total_out);
            let to = s.total_out as usize;
            let r = deflate(&mut s, &corpus[3][half..], &mut out[to..], Z_FINISH);
            print!("  flush{fl} pass2 ret{r} out{} hex ", s.total_out);
            dump(&out[..s.total_out as usize], 0);
            println!();
            deflate_end(&mut s);
        }
        {
            let mut s = ZStream::default();
            deflate_init2(&mut s, 6, Z_DEFLATED, 15, 8, Z_DEFAULT_STRATEGY);
            let r = deflate(&mut s, &corpus[3], &mut out, Z_PARTIAL_FLUSH);
            println!("  partial ret{r} out{}", s.total_out);
            deflate_end(&mut s);
        }
    }

    /* ------------------------------------------------- deflate dictionary */
    println!("== deflate dictionary ==");
    {
        let dict = b"the quick brown fox jumps over the lazy dog";
        let mut s = ZStream::default();
        deflate_init2(&mut s, 6, Z_DEFLATED, 15, 8, Z_DEFAULT_STRATEGY);
        let e = deflate_set_dictionary(&mut s, dict);
        println!("  setdict e{e}");
        let r = deflate(&mut s, &corpus[3], &mut out, Z_FINISH);
        print!("  deflate ret{r} out{} hex ", s.total_out);
        dump(&out[..s.total_out as usize], 0);
        println!();
        let zlen = s.total_out;
        deflate_end(&mut s);
        let mut is = ZStream::default();
        inflate_init2(&mut is, 15);
        let mut isout = vec![0u8; 2048];
        let r = inflate(&mut is, &out[..zlen as usize], &mut isout, Z_NO_FLUSH);
        println!(
            "  inflate ret{r} adler {:08x} msg {}",
            is.adler,
            mstr(is.msg)
        );
        let consumed = zlen as usize - is.avail_in as usize;
        let e = inflate_set_dictionary(&mut is, dict);
        println!("  inflateSetDictionary e{e}");
        let r = inflate(&mut is, &out[consumed..zlen as usize], &mut isout, Z_FINISH);
        println!("  inflate2 ret{r} total_out{}", is.total_out);
        inflate_end(&mut is);
    }

    /* ----------------------------------------------------- gzip header */
    println!("== gzip header ==");
    {
        let mut s = ZStream::default();
        deflate_init2(&mut s, 6, Z_DEFLATED, 31, 8, Z_DEFAULT_STRATEGY);
        let head = GzHeader {
            text: true,
            time: 0x12345678,
            xflags: 4,
            os: 3,
            extra: Some(vec![0x41, 0x42]),
            extra_len: 2,
            extra_max: 2,
            name: Some(b"hello.gz".to_vec()),
            name_max: 8,
            comment: Some(b"a comment".to_vec()),
            comm_max: 9,
            hcrc: true,
            done: 0,
        };
        let e = deflate_set_header(&mut s, head);
        println!("  setheader e{e}");
        let r = deflate(&mut s, &corpus[3], &mut out, Z_FINISH);
        print!("  deflate ret{r} out{} hex ", s.total_out);
        dump(&out[..s.total_out as usize], 0);
        println!();
        let zlen = s.total_out;
        deflate_end(&mut s);
        let mut is = ZStream::default();
        inflate_init2(&mut is, 31);
        let reg = GzHeader {
            extra: Some(vec![0u8; 16]),
            extra_max: 16,
            name: Some(vec![0u8; 32]),
            name_max: 31,
            comment: Some(vec![0u8; 64]),
            comm_max: 63,
            ..GzHeader::default()
        };
        let (e, _h) = inflate_get_header(&mut is, Some(reg));
        println!("  inflateGetHeader e{e}");
        let mut isout = vec![0u8; 2048];
        let r = inflate(&mut is, &out[..zlen as usize], &mut isout, Z_FINISH);
        println!("  inflate ret{r} out{} msg {}", is.total_out, mstr(is.msg));
        let (_, h) = inflate_get_header(&mut is, None);
        let name = h
            .name
            .as_deref()
            .map(|v| {
                let n = v.iter().position(|&b| b == 0).unwrap_or(v.len());
                String::from_utf8_lossy(&v[..n]).into_owned()
            })
            .unwrap_or_default();
        let comment = h
            .comment
            .as_deref()
            .map(|v| {
                let n = v.iter().position(|&b| b == 0).unwrap_or(v.len());
                String::from_utf8_lossy(&v[..n]).into_owned()
            })
            .unwrap_or_default();
        let extra = h.extra.clone().unwrap_or_default();
        print!(
            "  head done{} text{} time{} xflags{} os{} hcrc{} extra_len{} name'{name}' comment'{comment}' extra ",
            h.done,
            h.text as i32,
            h.time,
            h.xflags,
            h.os,
            h.hcrc as i32,
            h.extra_len
        );
        dump(&extra[..h.extra_len as usize], 0);
        println!();
        inflate_end(&mut is);
    }

    /* ------------------------------------------------- deflate utility calls */
    println!("== deflate utility calls ==");
    {
        let mut s = ZStream::default();
        deflate_init2(&mut s, 6, Z_DEFLATED, 15, 8, Z_DEFAULT_STRATEGY);
        let half = corpus[3].len() / 2;
        let r = deflate(&mut s, &corpus[3], &mut out, Z_NO_FLUSH);
        println!("  pass1 ret{r} out{}", s.total_out);
        let (e, pending, bits) = deflate_pending(&s);
        println!("  pending e{e} pending{pending} bits{bits}");
        let e = deflate_params(&mut s, 1, Z_FILTERED);
        println!("  params e{e}");
        let to = s.total_out as usize;
        let r = deflate(&mut s, &corpus[3][half..], &mut out[to..], Z_FINISH);
        print!("  pass2 ret{r} out{} hex ", s.total_out);
        dump(&out[..s.total_out as usize], 0);
        println!();
        deflate_end(&mut s);
    }
    {
        let mut s = ZStream::default();
        deflate_init2(&mut s, 6, Z_DEFLATED, 31, 8, Z_DEFAULT_STRATEGY);
        let e = deflate_prime(&mut s, 4, 0x5);
        let r = deflate(&mut s, &corpus[2], &mut out, Z_FINISH);
        print!("  prime e{e} ret{r} out{} hex ", s.total_out);
        dump(&out[..s.total_out as usize], 0);
        println!();
        deflate_end(&mut s);
    }
    {
        let mut s = ZStream::default();
        let mut d = ZStream::default();
        deflate_init2(&mut s, 6, Z_DEFLATED, 15, 8, Z_DEFAULT_STRATEGY);
        let r = deflate(&mut s, &corpus[3], &mut out[..100], Z_NO_FLUSH);
        let e = deflate_copy(&mut d, &s);
        println!("  copy e{e} orig ret{r} out{}", s.total_out);
        let consumed = corpus[3].len() - s.avail_in as usize;
        let r = deflate(
            &mut d,
            &corpus[3][consumed..],
            &mut out[s.total_out as usize..],
            Z_FINISH,
        );
        print!("  copy ret{r} out{} hex ", d.total_out);
        dump(&out[..d.total_out as usize], 0);
        println!();
        deflate_end(&mut s);
        deflate_end(&mut d);
    }
    {
        let mut s = ZStream::default();
        deflate_init2(&mut s, 6, Z_DEFLATED, 15, 8, Z_DEFAULT_STRATEGY);
        let r = deflate(&mut s, &corpus[3], &mut out, Z_FINISH);
        println!("  first ret{r} out{}", s.total_out);
        let e = deflate_reset_keep(&mut s);
        println!("  resetKeep e{e}");
        let r = deflate(&mut s, &corpus[3], &mut out, Z_FINISH);
        println!("  second ret{r} out{}", s.total_out);
        let e = deflate_reset(&mut s);
        println!("  reset e{e}");
        deflate_end(&mut s);
    }
    {
        let mut s = ZStream::default();
        let e = deflate_init2(&mut s, 10, Z_DEFLATED, 15, 8, Z_DEFAULT_STRATEGY);
        println!("  bad level e{e}");
        let mut s = ZStream::default();
        let e = deflate_init2(&mut s, 6, Z_DEFLATED, 16, 8, Z_DEFAULT_STRATEGY);
        println!("  bad wbits e{e}");
        let mut s = ZStream::default();
        let r = deflate(&mut s, &[], &mut out, Z_FINISH);
        println!("  uninit deflate ret{r}");
        let mut s = ZStream::default();
        let r = deflate_end(&mut s);
        println!("  uninit end ret{r}");
    }

    /* -------------------------------------------------- inflate one-shot */
    println!("== inflate one-shot ==");
    {
        let mut zblob = vec![0u8; 2048];
        let mut gblob = vec![0u8; 2048];
        let mut rblob = vec![0u8; 2048];
        let mut s = ZStream::default();
        deflate_init2(&mut s, 6, Z_DEFLATED, 15, 8, Z_DEFAULT_STRATEGY);
        deflate(&mut s, &corpus[3], &mut zblob, Z_FINISH);
        let zlen = s.total_out;
        deflate_end(&mut s);
        let mut s = ZStream::default();
        deflate_init2(&mut s, 6, Z_DEFLATED, 31, 8, Z_DEFAULT_STRATEGY);
        deflate(&mut s, &corpus[3], &mut gblob, Z_FINISH);
        let glen = s.total_out;
        deflate_end(&mut s);
        let mut s = ZStream::default();
        deflate_init2(&mut s, 6, Z_DEFLATED, -15, 8, Z_DEFAULT_STRATEGY);
        deflate(&mut s, &corpus[3], &mut rblob, Z_FINISH);
        let rlen = s.total_out;
        deflate_end(&mut s);

        let cases: [(i32, &[u8]); 5] = [
            (15, &zblob[..zlen as usize]),
            (31, &gblob[..glen as usize]),
            (47, &gblob[..glen as usize]),
            (-15, &rblob[..rlen as usize]),
            (15, &rblob[..rlen as usize]),
        ];
        for (wb, blob) in cases {
            let mut is = ZStream::default();
            let e = inflate_init2(&mut is, wb);
            let mut isout = vec![0u8; 2048];
            let r = inflate(&mut is, blob, &mut isout, Z_FINISH);
            let (ti, to, ai, ad, msg) = (is.total_in, is.total_out, is.avail_in, is.adler, is.msg);
            let end = inflate_end(&mut is);
            println!(
                "  wb{wb} ret{r} in{ti} out{to} avail_in{ai} adler{ad:08x} msg{} end{end}",
                mstr(msg)
            );
            let _ = e;
        }
        {
            let mut is = ZStream::default();
            inflate_init2(&mut is, 47);
            let mut isout = vec![0u8; 2048];
            let r = inflate(&mut is, &rblob[..rlen as usize], &mut isout, Z_FINISH);
            println!("  raw+auto ret{r} out{} msg{}", is.total_out, mstr(is.msg));
            inflate_end(&mut is);
        }
    }

    /* ------------------------------------------------- inflate small-out */
    println!("== inflate small-out ==");
    {
        let (_, zlen) = compress2(&mut out, &corpus[3], 6);
        let mut is = ZStream::default();
        inflate_init2(&mut is, 15);
        let mut pos = 0usize;
        let mut r = 0;
        for _ in 0..400usize {
            let mut small = [0u8; 5];
            let inp = &out[pos..zlen as usize];
            r = inflate(&mut is, inp, &mut small, Z_NO_FLUSH);
            pos = zlen as usize - is.avail_in as usize;
            if r != Z_OK && r != Z_BUF_ERROR {
                break;
            }
            if r == Z_BUF_ERROR && is.avail_in == 0 {
                break;
            }
        }
        let mut small = [0u8; 5];
        r = inflate(&mut is, &out[pos..zlen as usize], &mut small, Z_FINISH);
        println!("  ret{r} out{} avail_in{}", is.total_out, is.avail_in);
        inflate_end(&mut is);
    }

    /* ------------------------------------------------- inflate byte-at-a-time */
    println!("== inflate byte-at-a-time ==");
    {
        let (_, zlen) = compress2(&mut out, &corpus[3], 6);
        let mut is = ZStream::default();
        inflate_init2(&mut is, 15);
        let mut isout = vec![0u8; 2048];
        let mut pos = 0usize;
        let mut r = 0;
        while pos < zlen as usize {
            let one = [out[pos]];
            let opos = is.total_out as usize;
            r = inflate(&mut is, &one, &mut isout[opos..], Z_NO_FLUSH);
            pos += 1 - is.avail_in as usize;
            if r != Z_OK {
                break;
            }
        }
        let opos = is.total_out as usize;
        r = inflate(
            &mut is,
            &out[pos..zlen as usize],
            &mut isout[opos..],
            Z_FINISH,
        );
        println!("  ret{r} out{} consumed{}", is.total_out, is.total_in);
        inflate_end(&mut is);
    }

    /* -------------------------------------------------- inflate errors */
    println!("== inflate errors ==");
    {
        let (_, zlen) = compress2(&mut out, &corpus[3], 6);
        {
            let mut is = ZStream::default();
            inflate_init2(&mut is, 15);
            let mut isout = vec![0u8; 2048];
            let r = inflate(&mut is, &out[..zlen as usize - 3], &mut isout, Z_FINISH);
            println!(
                "  truncated ret{r} msg{} avail_in{}",
                mstr(is.msg),
                is.avail_in
            );
            inflate_end(&mut is);
        }
        {
            let mut cpy = out[..zlen as usize].to_vec();
            cpy[20] ^= 0x5a;
            let mut is = ZStream::default();
            inflate_init2(&mut is, 15);
            let mut isout = vec![0u8; 2048];
            let r = inflate(&mut is, &cpy, &mut isout, Z_FINISH);
            println!("  corrupt ret{r} msg{}", mstr(is.msg));
            inflate_end(&mut is);
        }
        {
            let garbage = b"hello world this is not compressed data";
            let mut is = ZStream::default();
            inflate_init2(&mut is, 15);
            let mut isout = vec![0u8; 2048];
            let r = inflate(&mut is, garbage, &mut isout, Z_FINISH);
            println!("  garbage ret{r} msg{}", mstr(is.msg));
            inflate_end(&mut is);
        }
        {
            let mut s2 = ZStream::default();
            deflate_init2(&mut s2, 6, Z_DEFLATED, -15, 8, Z_DEFAULT_STRATEGY);
            let mut rblob = vec![0u8; 2048];
            deflate(&mut s2, &corpus[3], &mut rblob, Z_FINISH);
            let rlen = s2.total_out;
            deflate_end(&mut s2);
            let mut is = ZStream::default();
            inflate_init2(&mut is, 15);
            let mut isout = vec![0u8; 2048];
            let r = inflate(&mut is, &rblob[..rlen as usize], &mut isout, Z_FINISH);
            println!("  raw-as-zlib ret{r} msg{}", mstr(is.msg));
            inflate_end(&mut is);
        }
        {
            let mut is = ZStream::default();
            let e = inflate_init2(&mut is, 16);
            println!("  init wb16 e{e} msg{}", mstr(is.msg));
            let mut is = ZStream::default();
            let e = inflate_init2(&mut is, 7);
            println!("  init wb7 e{e} msg{}", mstr(is.msg));
        }
        {
            let mut is = ZStream::default();
            let r = inflate(&mut is, &[], &mut out, Z_FINISH);
            println!("  uninit inflate ret{r}");
            let mut is = ZStream::default();
            let r = inflate_end(&mut is);
            println!("  uninit end ret{r}");
        }
    }

    /* ---------------------------------------------------- inflateSync */
    println!("== inflateSync ==");
    {
        let (_, zlen) = compress2(&mut out, &corpus[3], 6);
        let garbage = b"garbage garbage garbage garbage garbage";
        let mut mixed = Vec::new();
        mixed.extend_from_slice(garbage);
        mixed.extend_from_slice(&out[..zlen as usize]);
        let mut is = ZStream::default();
        inflate_init2(&mut is, 15);
        let mut isout = vec![0u8; 2048];
        let r = inflate(&mut is, &mixed, &mut isout, Z_NO_FLUSH);
        println!("  first ret{r} msg{}", mstr(is.msg));
        let consumed = mixed.len() - is.avail_in as usize;
        let e = inflate_sync(&mut is, &mixed[consumed..]);
        println!("  sync e{e}");
        let consumed = mixed.len() - is.avail_in as usize;
        let r = inflate(&mut is, &mixed[consumed..], &mut isout, Z_FINISH);
        println!("  second ret{r} out{} msg{}", is.total_out, mstr(is.msg));
        let e = inflate_sync_point(&is);
        println!("  syncPoint e{e}");
        inflate_end(&mut is);
    }

    /* ------------------------------------------------ inflatePrime/Mark */
    println!("== inflatePrime / inflateMark ==");
    {
        let (_, zlen) = compress2(&mut out, &corpus[3], 6);
        let mut is = ZStream::default();
        inflate_init2(&mut is, 15);
        let e = inflate_prime(&mut is, 8, 0x78);
        println!("  prime8 e{e}");
        let e = inflate_prime(&mut is, 9, 0);
        println!("  prime9 e{e}");
        let mut isout = vec![0u8; 2048];
        let r = inflate(&mut is, &out[..zlen as usize], &mut isout, Z_FINISH);
        println!("  inflate ret{r} out{}", is.total_out);
        inflate_end(&mut is);
    }
    {
        let (_, zlen) = compress2(&mut out, &corpus[3], 6);
        let mut is = ZStream::default();
        inflate_init2(&mut is, 15);
        let mut isout = vec![0u8; 2048];
        let mut pos = 0usize;
        let mut r = 0;
        for i in 0..5usize {
            let inp = &out[pos..zlen as usize];
            let opos = is.total_out as usize;
            r = inflate(&mut is, inp, &mut isout[opos..], Z_NO_FLUSH);
            pos = zlen as usize - is.avail_in as usize;
            println!("  mark step{i} ret{r} mark{}", inflate_mark(&is));
            if r != Z_OK {
                break;
            }
        }
        inflate_end(&mut is);
    }

    /* ---------------------------------------------- inflate reset/copy */
    println!("== inflate reset/copy ==");
    {
        let (_, zlen) = compress2(&mut out, &corpus[3], 6);
        let mut is = ZStream::default();
        inflate_init2(&mut is, 15);
        let mut isout = vec![0u8; 2048];
        let r = inflate(&mut is, &out[..30], &mut isout, Z_NO_FLUSH);
        let mut ic = ZStream::default();
        let e = inflate_copy(&mut ic, &is);
        println!("  copy e{e} ret{r} out{}", is.total_out);
        let to = is.total_out as usize;
        let r = inflate(&mut is, &out[30..zlen as usize], &mut isout[to..], Z_FINISH);
        println!("  orig ret{r} out{}", is.total_out);
        let mut icout = vec![0u8; 2048];
        let r = inflate(&mut ic, &out[30..zlen as usize], &mut icout, Z_FINISH);
        println!("  copy ret{r} out{}", ic.total_out);
        inflate_end(&mut is);
        inflate_end(&mut ic);
    }
    {
        let (_, zlen) = compress2(&mut out, &corpus[3], 6);
        let mut is = ZStream::default();
        inflate_init2(&mut is, 15);
        let mut isout = vec![0u8; 2048];
        inflate(&mut is, &out[..zlen as usize], &mut isout, Z_FINISH);
        println!("  total1 {}", is.total_out);
        let e = inflate_reset(&mut is);
        println!("  reset e{e}");
        inflate(&mut is, &out[..zlen as usize], &mut isout, Z_FINISH);
        println!("  total2 {}", is.total_out);
        let e = inflate_reset2(&mut is, 31);
        println!("  reset2 wb31 e{e}");
        inflate_end(&mut is);
    }
    {
        let (_, zlen) = compress2(&mut out, &corpus[3], 6);
        let dict = b"dictionary that is not needed";
        let mut is = ZStream::default();
        inflate_init2(&mut is, 15);
        let _ = &out[..zlen as usize];
        let e = inflate_set_dictionary(&mut is, dict);
        println!("  setdict-not-needed e{e}");
        inflate_end(&mut is);
    }

    /* --------------------------------------------------------- gz layer */
    println!("== gz layer ==");
    {
        let mut rbuf = vec![0u8; 4096];
        let mut line = vec![0u8; 256];
        let gz = gz_open("/tmp/zwork/a.gz", "wb6");
        println!("  open write {}", if gz.is_some() { "ok" } else { "NULL" });
        let mut gz = gz.unwrap();
        let n = gz_write(Some(&mut gz), &corpus[3]);
        println!("  gzwrite {n}");
        let n = gz_puts(Some(&mut gz), "\nline of text\n");
        println!("  gzputs {n}");
        let n = gz_putc(Some(&mut gz), 'Z' as i32);
        println!("  gzputc {n}");
        let n = gz_printf(
            Some(&mut gz),
            "fmt int%d neg%d plus%+d sp% d zero%05d left%-6d| prec%.3d hex%x %X %#x oct%o %#o\n",
            &[
                GzPrintfArg::I(42),
                GzPrintfArg::I(-42),
                GzPrintfArg::I(42),
                GzPrintfArg::I(42),
                GzPrintfArg::I(42),
                GzPrintfArg::I(42),
                GzPrintfArg::I(42),
                GzPrintfArg::I(255),
                GzPrintfArg::I(255),
                GzPrintfArg::I(255),
                GzPrintfArg::I(8),
                GzPrintfArg::I(8),
            ],
        );
        println!("  gzprintf1 {n}");
        let n = gz_printf(
            Some(&mut gz),
            "str %s prec%.3s pad%8s left%-8s|\n",
            &[
                GzPrintfArg::S("hello".to_string()),
                GzPrintfArg::S("hello".to_string()),
                GzPrintfArg::S("hi".to_string()),
                GzPrintfArg::S("hi".to_string()),
            ],
        );
        println!("  gzprintf2 {n}");
        let n = gz_printf(
            Some(&mut gz),
            "char %c%c\n",
            &[GzPrintfArg::I('A' as i64), GzPrintfArg::I('B' as i64)],
        );
        println!("  gzprintf3 {n}");
        let n = gz_printf(
            Some(&mut gz),
            "long %ld %lu %lx\n",
            &[
                GzPrintfArg::I(-123456789),
                GzPrintfArg::U(123456789),
                GzPrintfArg::U(0xdeadbeef),
            ],
        );
        println!("  gzprintf4 {n}");
        let n = gz_printf(
            Some(&mut gz),
            "ll %lld %llu %llx\n",
            &[
                GzPrintfArg::I(-1234567890123),
                GzPrintfArg::U(1234567890123),
                GzPrintfArg::U(0xdeadbeefcafe),
            ],
        );
        println!("  gzprintf5 {n}");
        let n = gz_printf(
            Some(&mut gz),
            "zu %zu zd %zd\n",
            &[GzPrintfArg::U(123456), GzPrintfArg::I(-789)],
        );
        println!("  gzprintf6 {n}");
        let n = gz_printf(
            Some(&mut gz),
            "ptr %p %p\n",
            &[GzPrintfArg::P(0x1234), GzPrintfArg::P(0)],
        );
        println!("  gzprintf7 {n}");
        let n = gz_printf(
            Some(&mut gz),
            "flt %f %.2f %+8.2f %e %.3e %g %.3g %#g\n",
            &[
                GzPrintfArg::D(3.14159),
                GzPrintfArg::D(3.14159),
                GzPrintfArg::D(3.14159),
                GzPrintfArg::D(1234567.0),
                GzPrintfArg::D(1234567.0),
                GzPrintfArg::D(1234567.0),
                GzPrintfArg::D(1234567.0),
                GzPrintfArg::D(1234.5),
            ],
        );
        println!("  gzprintf8 {n}");
        let n = gz_printf(
            Some(&mut gz),
            "pct %% star %*d %.*d\n",
            &[
                GzPrintfArg::I(6),
                GzPrintfArg::I(42),
                GzPrintfArg::I(4),
                GzPrintfArg::I(42),
            ],
        );
        println!("  gzprintf9 {n}");
        let e = gz_flush(Some(&mut gz), Z_SYNC_FLUSH);
        println!("  flush sync e{e}");
        println!(
            "  tell {} offset {}",
            gz_tell(Some(&gz)),
            gz_offset(Some(&gz))
        );
        let e = gz_close_w(Some(&mut gz));
        println!("  close_w e{e}");
        let raw = std::fs::read("/tmp/zwork/a.gz").unwrap_or_default();
        print!("  rawfile len{} hex ", raw.len());
        dump(&raw, 0);
        println!();
        let gz = gz_open("/tmp/zwork/a.gz", "rb");
        println!("  open read {}", if gz.is_some() { "ok" } else { "NULL" });
        let mut gz = gz.unwrap();
        let n = gz_read(Some(&mut gz), &mut rbuf[..37]);
        println!("  gzread37 {n}");
        let got = gz_gets(Some(&mut gz), &mut line);
        if got.is_none() {
            println!("  gzgets -> NULL");
        } else {
            let len = got.unwrap();
            print!("  gzgets -> {}", String::from_utf8_lossy(&line[..len]));
            if len == 0 || line[len - 1] != b'\n' {
                println!();
            }
        }
        let n = gz_getc(Some(&mut gz));
        println!("  gzgetc {n}");
        let n = gz_ungetc(Some(&mut gz), 'Q' as i32);
        println!("  gzungetc {n}");
        let n = gz_getc(Some(&mut gz));
        println!("  gzgetc-after-ungetc {n}");
        println!(
            "  tell {} offset {}",
            gz_tell(Some(&gz)),
            gz_offset(Some(&gz))
        );
        let n = gz_seek(Some(&mut gz), 10, 0);
        println!("  seek_set {n}");
        let n = gz_read(Some(&mut gz), &mut rbuf[..20]);
        println!(
            "  gzread20 {n} '{}'",
            String::from_utf8_lossy(&rbuf[..n.max(0) as usize])
        );
        let n = gz_seek(Some(&mut gz), 5, 1);
        println!("  seek_cur {n}");
        let n = gz_seek(Some(&mut gz), 0, 2);
        println!("  seek_end {n}");
        let n = gz_seek(Some(&mut gz), -1, 0);
        println!("  seek_neg {n}");
        let e = gz_rewind(Some(&mut gz));
        println!("  rewind e{e}");
        let n = gz_read(Some(&mut gz), &mut rbuf[..1000]);
        println!("  gzread-all {n}");
        let n = gz_read(Some(&mut gz), &mut rbuf[..10]);
        println!("  gzread-eof {n} eof{}", gz_eof(Some(&gz)));
        let e = gz_close_r(Some(&mut gz));
        println!("  close_r e{e}");
    }
    {
        let gz = gz_open("/tmp/zwork/does-not-exist.gz", "rb");
        println!(
            "  open-nonexistent {}",
            if gz.is_some() { "ok" } else { "NULL" }
        );
        let gz = gz_open("/tmp/zwork/b.gz", "wb");
        println!("  open-b {}", if gz.is_some() { "ok" } else { "NULL" });
        let mut gz = gz.unwrap();
        {
            let tmp = vec![b'q'; 32];
            let n = gz_write(Some(&mut gz), &tmp);
            println!("  b gzwrite {n}");
            let e = gz_setparams(Some(&mut gz), 9, Z_DEFAULT_STRATEGY);
            println!("  b setparams e{e}");
            let e = gz_flush(Some(&mut gz), Z_FINISH);
            println!("  b flush-finish e{e}");
            let e = gz_close_w(Some(&mut gz));
            println!("  b close_w e{e}");
        }
        let gz = gz_open("/tmp/zwork/b.gz", "rb");
        let mut gz = gz.unwrap();
        {
            let n = gz_write(Some(&mut gz), &corpus[1]);
            let (errnum, msg) = gz_error_string(Some(&gz));
            println!("  ro gzwrite {n} err{errnum} msg'{msg}'");
            let n = gz_puts(Some(&mut gz), "x");
            let (errnum, msg) = gz_error_string(Some(&gz));
            println!("  ro gzputs {n} err{errnum} msg'{msg}'");
            let n = gz_printf(Some(&mut gz), "x", &[]);
            let (errnum, msg) = gz_error_string(Some(&gz));
            println!("  ro gzprintf {n} err{errnum} msg'{msg}'");
            let e = gz_setparams(Some(&mut gz), 9, Z_DEFAULT_STRATEGY);
            let (errnum, msg) = gz_error_string(Some(&gz));
            println!("  ro setparams {e} err{errnum} msg'{msg}'");
            let e = gz_close_w(Some(&mut gz));
            let (errnum, msg) = gz_error_string(Some(&gz));
            println!("  ro close_w {e} err{errnum} msg'{msg}'");
            let e = gz_close_r(Some(&mut gz));
            println!("  ro close_r e{e}");
        }
        let gz = gz_open("/tmp/zwork/b.gz", "wb");
        let mut gz = gz.unwrap();
        {
            let mut tmp = vec![0u8; 16];
            let n = gz_read(Some(&mut gz), &mut tmp);
            let (errnum, msg) = gz_error_string(Some(&gz));
            println!("  wo gzread {n} err{errnum} msg'{msg}'");
            let n = gz_getc(Some(&mut gz));
            let (errnum, msg) = gz_error_string(Some(&gz));
            println!("  wo gzgetc {n} err{errnum} msg'{msg}'");
            gz_clearerr(Some(&mut gz));
            let (errnum, msg) = gz_error_string(Some(&gz));
            println!("  wo after clearerr err{errnum} msg'{msg}'");
            let e = gz_close_w(Some(&mut gz));
            println!("  wo close_w e{e}");
        }
        {
            use std::os::unix::io::IntoRawFd;
            let f = std::fs::OpenOptions::new()
                .write(true)
                .create(true)
                .truncate(true)
                .open("/tmp/zwork/c.gz")
                .unwrap();
            let fd = f.into_raw_fd();
            let gz2 = gzdopen(fd, "wb");
            let mut gz2 = gz2.unwrap();
            let n = gz_puts(Some(&mut gz2), "dopen content\n");
            println!("  gzdopen puts {n}");
            let e = gz_close_w(Some(&mut gz2));
            println!("  gzdopen close e{e}");
        }
        {
            let gz2 = gz_open("/tmp/zwork/c.gz", "rb");
            let mut gz2 = gz2.unwrap();
            let e = gz_buffer(Some(&mut gz2), 8192);
            println!("  gzbuffer e{e}");
            let mut tmp = vec![0u8; 64];
            let n = gz_read(Some(&mut gz2), &mut tmp);
            println!("  gzbuffer read {n}");
            let e = gz_close_r(Some(&mut gz2));
            println!("  gzbuffer close e{e}");
        }
        {
            let gz2 = gz_open("/dev/null", "rb");
            let mut gz2 = gz2.unwrap();
            let mut tmp = vec![0u8; 8];
            let n = gz_read(Some(&mut gz2), &mut tmp);
            println!("  devnull read {n} eof{}", gz_eof(Some(&gz2)));
            let e = gz_close_r(Some(&mut gz2));
            println!("  devnull close e{e}");
        }
    }
}
