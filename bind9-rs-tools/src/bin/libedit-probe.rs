//! libedit-probe — the LE-0001 Rust probe.
//!
//! Mirrors `forensics/oracle/probes/probe-libedit.c` byte-for-byte: 29 pty
//! sessions (emacs/vi editing, history, prompts, dumb terminal, UTF-8,
//! readline layer) plus 7 direct API sessions.  The engine's `out`/`err`
//! sinks model the pty line discipline (ONLCR output translation, INLCR/
//! ICRNL input identity for this corpus), so the printed transcript equals
//! the oracle's captured pty bytes.

use bind9_rs_tools::compat::libedit::*;

fn cprintf_bytes(el: &mut Engine, s: &[u8]) {
    for &b in s {
        if b == b'\n' {
            el.out.push(b'\r');
        }
        el.out.push(b);
    }
}

fn escape_bytes(out: &mut String, buf: &[u8]) {
    for &c in buf {
        match c {
            0x1b => out.push_str("ESC"),
            0x08 => out.push_str("BS"),
            0x7f => out.push_str("DEL"),
            b'\r' => out.push_str("\\r"),
            b'\n' => out.push_str("\\n\n"),
            b'\t' => out.push_str("\\t"),
            0x07 => out.push_str("BEL"),
            0x20..=0x7e => out.push(c as char),
            _ => out.push_str(&format!("<{:02x}>", c)),
        }
    }
    out.push('\n');
}

struct Session {
    id: &'static str,
    name: &'static str,
    kind: SessionKind,
    input: &'static [u8],
}

#[derive(PartialEq)]
enum SessionKind {
    Emacs,
    Vi,
    Rprompt,
    PromptEsc,
    Noedit,
    EmptyPrompt,
    Readline,
}

fn pty_session(s: &Session, term: &str, env: Vec<(String, String)>) {
    let mut el = match el_init("probe", true, s.input.to_vec(), env) {
        Some(e) => e,
        None => {
            println!("el_init failed");
            return;
        }
    };
    el.merge_err = true; // child stderr = pty
    let mut hist: Option<History> = None;
    match s.kind {
        SessionKind::Emacs => {
            el_set_narrow(&mut el, EL_PROMPT, &[SetArg::Prompt(Some(0))]);
            el_set_narrow(&mut el, EL_EDITOR, &[SetArg::Str(b"emacs".to_vec())]);
            let h = history_init();
            hist = Some(h.clone());
            el_set_narrow(&mut el, EL_HIST, &[SetArg::Hist(history_w_fun, h)]);
        }
        SessionKind::Vi => {
            el_set_narrow(&mut el, EL_PROMPT, &[SetArg::Prompt(Some(0))]);
            el_set_narrow(&mut el, EL_EDITOR, &[SetArg::Str(b"vi".to_vec())]);
            let h = history_init();
            hist = Some(h.clone());
            el_set_narrow(&mut el, EL_HIST, &[SetArg::Hist(history_w_fun, h)]);
        }
        SessionKind::Rprompt => {
            el_set_narrow(&mut el, EL_PROMPT, &[SetArg::Prompt(Some(0))]);
            el_set_narrow(&mut el, EL_EDITOR, &[SetArg::Str(b"emacs".to_vec())]);
            el_set_narrow(&mut el, EL_RPROMPT, &[SetArg::Prompt(Some(3))]);
        }
        SessionKind::PromptEsc => {
            el_set_narrow(
                &mut el,
                EL_PROMPT_ESC,
                &[SetArg::Prompt(Some(2)), SetArg::I32(0x01)],
            );
            el_set_narrow(&mut el, EL_EDITOR, &[SetArg::Str(b"emacs".to_vec())]);
        }
        SessionKind::Noedit => {
            el_set_narrow(&mut el, EL_PROMPT, &[SetArg::Prompt(Some(0))]);
            el_set_narrow(&mut el, EL_EDITOR, &[SetArg::Str(b"emacs".to_vec())]);
            el_set_narrow(&mut el, EL_EDITMODE, &[SetArg::I32(0)]);
        }
        SessionKind::EmptyPrompt => {
            el_set_narrow(&mut el, EL_PROMPT, &[SetArg::Prompt(Some(1))]);
            el_set_narrow(&mut el, EL_EDITOR, &[SetArg::Str(b"emacs".to_vec())]);
        }
        SessionKind::Readline => {
            // handled separately
        }
    }
    // the child's prompt functions
    if el.user_prompts.is_empty() {
        let p = b"p> ".to_vec();
        el.user_prompts
            .push(Box::new(move |_| p.iter().map(|&b| b as u32).collect()));
        el.user_prompts.push(Box::new(|_| Vec::new())); // empty prompt
        let esc = b"a\x01HIDDEN\x02b> ".to_vec();
        el.user_prompts
            .push(Box::new(move |_| esc.iter().map(|&b| b as u32).collect()));
        el.user_prompts
            .push(Box::new(|_| "<<".chars().map(|c| c as u32).collect()));
    }
    if s.kind == SessionKind::Readline {
        // handled by readline_session() in main
        return;
    }
    loop {
        let mut n = 0i32;
        let line = el_gets(&mut el, &mut n);
        match line {
            None => break,
            Some(line) => {
                // the C child does printf("LINE: %s (%d)\n", line, n) with
                // the raw el_gets buffer (which ends in '\n'); the pty's
                // ONLCR turns that newline into \r\n on the wire
                let mut msg = Vec::new();
                msg.extend_from_slice(b"LINE: ");
                msg.extend_from_slice(&line);
                msg.extend_from_slice(format!(" ({})\n", n).as_bytes());
                cprintf_bytes(&mut el, &msg);
                if let Some(h) = hist.as_mut() {
                    let mut ev = HistEventN {
                        num: _HE_OK,
                        str: Some(b"OK".to_vec()),
                    };
                    history(h, &mut ev, H_ENTER, &[HistoryArg::Str(line.clone())]);
                }
                if line.starts_with(b"quit") {
                    break;
                }
            }
        }
    }
    let _ = term;
    let total = el.out.len();
    println!("=== {} {} ({} bytes) ===", s.id, s.name, total);
    let mut esc = String::new();
    escape_bytes(&mut esc, &el.out);
    print!("{}", esc);
}

fn env_for_rl() -> Vec<(String, String)> {
    vec![("TERM".to_string(), "xterm".to_string())]
}

/// The S29 readline session: mirrors the C child's readline() sequence.
fn readline_session() -> (Vec<u8>, Vec<u8>) {
    let mut rl = RlState::new();
    rl.rl_echo_off = true;
    // the C child calls rl_initialize() (which sees ECHO off and disables
    // editmode), pins the editing termios, then reads the input stream
    let env = vec![("TERM".to_string(), "xterm".to_string())];
    rl.rl_initialize(env.clone());
    rl.rl_set_input(b"alpha\nbeta\n".to_vec());
    let mut out = Vec::new();
    let emit = |s: &str, o: &mut Vec<u8>| {
        for &b in s.as_bytes() {
            if b == b'\n' {
                o.push(b'\r');
            }
            o.push(b);
        }
    };
    let mut line = rl.readline(b"> ", env.clone());
    out.extend(rl.rl_drain_out());
    emit(
        &format!(
            "rl1={} point={} end={}\n",
            line.as_deref()
                .map(|l| String::from_utf8_lossy(l).to_string())
                .unwrap_or_else(|| "(null)".to_string()),
            rl.rl_point,
            rl.rl_end
        ),
        &mut out,
    );
    line = rl.readline(b"> ", env.clone());
    out.extend(rl.rl_drain_out());
    emit(
        &format!(
            "rl2={} point={} end={}\n",
            line.as_deref()
                .map(|l| String::from_utf8_lossy(l).to_string())
                .unwrap_or_else(|| "(null)".to_string()),
            rl.rl_point,
            rl.rl_end
        ),
        &mut out,
    );
    rl.add_history(b"alpha");
    rl.add_history(b"beta");
    emit(
        &format!(
            "history_length={} history_base={}\n",
            rl.history_length, rl.history_base
        ),
        &mut out,
    );
    emit(&format!("where_history={}\n", rl.history_offset), &mut out);
    let he1 = rl.history_get(1);
    emit(
        &format!(
            "history_get(1)={}\n",
            he1.map(|s| String::from_utf8_lossy(&s).to_string())
                .unwrap_or_else(|| "(null)".to_string())
        ),
        &mut out,
    );
    let he2 = rl.history_get(2);
    emit(
        &format!(
            "history_get(2)={}\n",
            he2.map(|s| String::from_utf8_lossy(&s).to_string())
                .unwrap_or_else(|| "(null)".to_string())
        ),
        &mut out,
    );
    let cur = rl.current_history();
    emit(
        &format!(
            "current={}\n",
            cur.map(|s| String::from_utf8_lossy(&s).to_string())
                .unwrap_or_else(|| "(null)".to_string())
        ),
        &mut out,
    );
    let prev = rl.previous_history();
    emit(
        &format!(
            "previous={} where={}\n",
            prev.map(|s| String::from_utf8_lossy(&s).to_string())
                .unwrap_or_else(|| "(null)".to_string()),
            rl.history_offset
        ),
        &mut out,
    );
    let prev2 = rl.previous_history();
    emit(
        &format!(
            "previous={} where={}\n",
            prev2
                .map(|s| String::from_utf8_lossy(&s).to_string())
                .unwrap_or_else(|| "(null)".to_string()),
            rl.history_offset
        ),
        &mut out,
    );
    let next = rl.next_history();
    emit(
        &format!(
            "next={} where={}\n",
            next.map(|s| String::from_utf8_lossy(&s).to_string())
                .unwrap_or_else(|| "(null)".to_string()),
            rl.history_offset
        ),
        &mut out,
    );
    let r = rl.history_search_prefix(b"al", -1);
    emit(&format!("search_prefix(al)={}\n", r), &mut out);
    let r = rl.history_search(b"bet", 1);
    emit(&format!("search(bet)={}\n", r), &mut out);
    let (r, o) = rl.history_expand(b"!1");
    emit(
        &format!(
            "expand(!1) -> r={} out={}\n",
            r,
            o.map(|s| String::from_utf8_lossy(&s).to_string())
                .unwrap_or_else(|| "(null)".to_string())
        ),
        &mut out,
    );
    let (r, o) = rl.history_expand(b"!!");
    emit(
        &format!(
            "expand(!!) -> r={} out={}\n",
            r,
            o.map(|s| String::from_utf8_lossy(&s).to_string())
                .unwrap_or_else(|| "(null)".to_string())
        ),
        &mut out,
    );
    let (r, o) = rl.history_expand(b"^a^A");
    emit(
        &format!(
            "expand(^a^A) -> r={} out={}\n",
            r,
            o.map(|s| String::from_utf8_lossy(&s).to_string())
                .unwrap_or_else(|| "(null)".to_string())
        ),
        &mut out,
    );
    rl.clear_history();
    emit(
        &format!(
            "after clear: length={} where={}\n",
            rl.history_length, rl.history_offset
        ),
        &mut out,
    );
    (out, Vec::new())
}

fn main() {
    let sessions: Vec<Session> = vec![
        Session { id: "S01", name: "plain", kind: SessionKind::Emacs, input: b"hello world\nquit\n" },
        Session { id: "S02", name: "backspace", kind: SessionKind::Emacs, input: b"abc\x08\x08z\nquit\n" },
        Session { id: "S03", name: "killline", kind: SessionKind::Emacs, input: b"hello world\n\x01\x0b\nquit\n" },
        Session { id: "S04", name: "killu-yank", kind: SessionKind::Emacs, input: b"abcdef\n\x15\x19\nquit\n" },
        Session { id: "S05", name: "mid-insert", kind: SessionKind::Emacs, input: b"abcdef\n\x01gh\x05\nquit\n" },
        Session { id: "S06", name: "transpose", kind: SessionKind::Emacs, input: b"ab\n\x02\nquit\n" },
        Session { id: "S07", name: "killword", kind: SessionKind::Emacs, input: b"one two three\n\x17\x01\x17\nquit\n" },
        Session { id: "S08", name: "word-motion", kind: SessionKind::Emacs, input: b"one two three\n\x1bf\x1bb\x1bd\nquit\n" },
        Session { id: "S09", name: "case", kind: SessionKind::Emacs, input: b"hello world\n\x01\x1bu\x1bc\x1bl\nquit\n" },
        Session { id: "S10", name: "ctrl-d", kind: SessionKind::Emacs, input: b"abc\x04\nquit\n" },
        Session { id: "S11", name: "history", kind: SessionKind::Emacs, input: b"one\ntwo\nthree\n\x10\x10\x0e\nquit\n" },
        Session { id: "S12", name: "hist-search", kind: SessionKind::Emacs, input: b"hello one\nhello two\n\x01\x1bp\nquit\n" },
        Session { id: "S13", name: "arrows", kind: SessionKind::Emacs, input: b"ab\n\x1b[D\x1b[Dc\n\x1b[C\nquit\n" },
        Session { id: "S14", name: "kill-ring", kind: SessionKind::Emacs, input: b"abc def\n\x01\x0b\x19\nquit\n" },
        Session { id: "S15", name: "vi", kind: SessionKind::Vi, input: b"hello world\n\x1bhx\x1bddiXX\nquit\n" },
        Session { id: "S16", name: "vi-search", kind: SessionKind::Vi, input: b"hello\nworld\n\x1b/ell\nn\nquit\n" },
        Session { id: "S17", name: "rprompt", kind: SessionKind::Rprompt, input: b"hi\nquit\n" },
        Session { id: "S18", name: "prompt-esc", kind: SessionKind::PromptEsc, input: b"xy\nquit\n" },
        Session { id: "S19", name: "dumb", kind: SessionKind::Emacs, input: b"hello world\n\x08\x08!\nquit\n" },
        Session { id: "S20", name: "utf8", kind: SessionKind::Emacs, input: "héllo wörld\nquit\n".as_bytes() },
        Session { id: "S21", name: "noedit", kind: SessionKind::Noedit, input: b"raw line\nquit\n" },
        Session { id: "S22", name: "longline", kind: SessionKind::Emacs, input: b"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\n\x01\x1bw\x1bd\nquit\n" },
        Session { id: "S23", name: "clearscreen", kind: SessionKind::Emacs, input: b"abc\n\x0c\nquit\n" },
        Session { id: "S24", name: "quoted-insert", kind: SessionKind::Emacs, input: b"ab\n\x16\x1bcd\nquit\n" },
        Session { id: "S25", name: "empty-prompt", kind: SessionKind::EmptyPrompt, input: b"abc\nquit\n" },
        Session { id: "S26", name: "vi-yank-put", kind: SessionKind::Vi, input: b"one two\n\x1b0dw\x1bP\x1b0dw\x1bp\nquit\n" },
        Session { id: "S27", name: "vi-undo", kind: SessionKind::Vi, input: b"abc def\n\x1b0cwXX\x1b\x1bu\nquit\n" },
        Session { id: "S28", name: "ed-command", kind: SessionKind::Emacs, input: b"abc\n\x1bxecho hi\nquit\n" },
        Session { id: "S29", name: "readline", kind: SessionKind::Readline, input: b"alpha\nbeta\n" },
    ];
    for (i, s) in sessions.iter().enumerate() {
        if s.kind == SessionKind::Readline {
            let (out, _err) = readline_session();
            println!("=== {} {} ({} bytes) ===", s.id, s.name, out.len());
            let mut esc = String::new();
            escape_bytes(&mut esc, &out);
            print!("{}", esc);
        } else {
            let term = if i + 1 == 19 { "dumb" } else { "xterm" };
            pty_session(s, term, vec![("TERM".to_string(), term.to_string())]);
        }
    }
    // ---------------- direct sessions ----------------
    d01_history_api();
    d02_to_d05();
    d06_tokenizer();
    d07_no_tty();
}

fn d01_history_api() {
    println!("=== D01 history API ===");
    let mut hw = history_init();
    let mut ev = HistEventW {
        num: _HE_OK,
        str: Some(b"OK".to_vec()),
    };
    let mut r = history_w(&mut hw, &mut ev, H_GETSIZE, &[]);
    println!("getsize -> {} num={} str={}", r, ev.num, ev_str(&ev));
    r = history_w(&mut hw, &mut ev, H_SETSIZE, &[HistoryArg::I32(5)]);
    println!("setsize(5) -> {} num={} str={}", r, ev.num, ev_str(&ev));
    r = history_w(
        &mut hw,
        &mut ev,
        H_ENTER,
        &[HistoryArg::Str(b"alpha".to_vec())],
    );
    println!("enter alpha -> {} num={} str={}", r, ev.num, ev_str(&ev));
    r = history_w(
        &mut hw,
        &mut ev,
        H_ENTER,
        &[HistoryArg::Str(b"beta".to_vec())],
    );
    println!("enter beta -> {} num={} str={}", r, ev.num, ev_str(&ev));
    r = history_w(
        &mut hw,
        &mut ev,
        H_ENTER,
        &[HistoryArg::Str(b"gamma".to_vec())],
    );
    println!("enter gamma -> {} num={} str={}", r, ev.num, ev_str(&ev));
    r = history_w(&mut hw, &mut ev, H_ADD, &[HistoryArg::Str(b"2".to_vec())]);
    println!("add 2 -> {} num={} str={}", r, ev.num, ev_str(&ev));
    hist_dump(&mut hw, "after enter x3 + add");
    r = history_w(
        &mut hw,
        &mut ev,
        H_APPEND,
        &[HistoryArg::Str(b"!?".to_vec())],
    );
    println!("append -> {} num={} str={}", r, ev.num, ev_str(&ev));
    hist_dump(&mut hw, "after append");
    r = history_w(&mut hw, &mut ev, H_PREV, &[]);
    println!("prev -> {} num={} str={}", r, ev.num, ev_str(&ev));
    r = history_w(&mut hw, &mut ev, H_PREV, &[]);
    println!("prev -> {} num={} str={}", r, ev.num, ev_str(&ev));
    r = history_w(&mut hw, &mut ev, H_PREV, &[]);
    println!("prev -> {} num={} str={}", r, ev.num, ev_str(&ev));
    r = history_w(&mut hw, &mut ev, H_PREV, &[]);
    println!("prev -> {} num={} str={}", r, ev.num, ev_str(&ev));
    r = history_w(&mut hw, &mut ev, H_PREV, &[]);
    println!("prev -> {} num={} str={}", r, ev.num, ev_str(&ev));
    r = history_w(&mut hw, &mut ev, H_NEXT, &[]);
    println!("next -> {} num={} str={}", r, ev.num, ev_str(&ev));
    r = history_w(&mut hw, &mut ev, H_CURR, &[]);
    println!("curr -> {} num={} str={}", r, ev.num, ev_str(&ev));
    r = history_w(&mut hw, &mut ev, H_FIRST, &[]);
    println!("first -> {} num={} str={}", r, ev.num, ev_str(&ev));
    r = history_w(&mut hw, &mut ev, H_LAST, &[]);
    println!("last -> {} num={} str={}", r, ev.num, ev_str(&ev));
    r = history_w(&mut hw, &mut ev, H_SET, &[HistoryArg::I32(2)]);
    println!("set(2) -> {} num={} str={}", r, ev.num, ev_str(&ev));
    r = history_w(&mut hw, &mut ev, H_CURR, &[]);
    println!("curr -> {} num={} str={}", r, ev.num, ev_str(&ev));
    r = history_w(
        &mut hw,
        &mut ev,
        H_PREV_STR,
        &[HistoryArg::Str(b"b".to_vec())],
    );
    println!("prev_str(b) -> {} num={} str={}", r, ev.num, ev_str(&ev));
    r = history_w(
        &mut hw,
        &mut ev,
        H_NEXT_STR,
        &[HistoryArg::Str(b"g".to_vec())],
    );
    println!("next_str(g) -> {} num={} str={}", r, ev.num, ev_str(&ev));
    r = history_w(&mut hw, &mut ev, H_PREV_EVENT, &[HistoryArg::I32(1)]);
    println!("prev_event(1) -> {} num={} str={}", r, ev.num, ev_str(&ev));
    r = history_w(&mut hw, &mut ev, H_NEXT_EVENT, &[HistoryArg::I32(3)]);
    println!("next_event(3) -> {} num={} str={}", r, ev.num, ev_str(&ev));
    r = history_w(&mut hw, &mut ev, H_DEL, &[HistoryArg::I32(2)]);
    println!("del(2) -> {} num={} str={}", r, ev.num, ev_str(&ev));
    hist_dump(&mut hw, "after del");
    r = history_w(&mut hw, &mut ev, H_CLEAR, &[]);
    println!("clear -> {}", r);
    hist_dump(&mut hw, "after clear");
    r = history_w(&mut hw, &mut ev, H_SETSIZE, &[HistoryArg::I32(-1)]);
    println!("setsize(-1) -> {} num={} str={}", r, ev.num, ev_str(&ev));
    r = history_w(&mut hw, &mut ev, H_SETUNIQUE, &[HistoryArg::I32(1)]);
    println!("setunique(1) -> {}", r);
    r = history_w(
        &mut hw,
        &mut ev,
        H_ENTER,
        &[HistoryArg::Str(b"dup".to_vec())],
    );
    println!("enter dup -> {} num={}", r, ev.num);
    r = history_w(
        &mut hw,
        &mut ev,
        H_ENTER,
        &[HistoryArg::Str(b"dup".to_vec())],
    );
    println!("enter dup -> {} num={}", r, ev.num);
    r = history_w(&mut hw, &mut ev, H_GETUNIQUE, &[]);
    println!("getunique -> {} num={}", r, ev.num);
    hist_dump(&mut hw, "after unique");
}

fn ev_str(ev: &HistEventW) -> String {
    ev.str
        .as_deref()
        .map(|s| String::from_utf8_lossy(s).to_string())
        .unwrap_or_default()
}

/// C-locale `%ls` on a narrow buffer.  The C probe's `el_get(EL_EDITOR,
/// &ws)` calls the NARROW getter, which stores a narrow encoding ("emacs")
/// into the `wchar_t *` slot; the first wchar_t read from those bytes is
/// 0x63616d65 (little-endian) > 0xFF, glibc's C-locale conversion fails, and
/// printf swallows the value AND the rest of the format string (the trailing
/// \n).  Reproduce: print the prefix, then emit nothing and no newline, so
/// the next printf continues on the same line.
fn cprint_narrow_as_wide(prefix: &str, bytes: &[u8]) {
    print!("{}", prefix);
    let mut w: u32 = 0;
    for (i, &b) in bytes.iter().take(4).enumerate() {
        w |= (b as u32) << (8 * i);
    }
    if w <= 0xff {
        // convertible in the C locale: emit the bytes and a newline
        let mut s = String::new();
        for &b in bytes {
            if b == 0 {
                break;
            }
            s.push(b as char);
        }
        println!("{}", s);
    }
    // else: swallowed; no newline
}

fn hist_dump(hw: &mut History, label: &str) {
    let mut ev = HistEventW {
        num: _HE_OK,
        str: Some(b"OK".to_vec()),
    };
    print!("{}:", label);
    if history_w(hw, &mut ev, H_GETSIZE, &[]) == 0 {
        print!(" size={}", ev.num);
    } else {
        // the C's %s on the wide error string prints only the first byte
        print!(" size=ERR({} {})", ev.num, first_byte(&ev));
    }
    if history_w(hw, &mut ev, H_FIRST, &[]) == 0 {
        print!(" first={}:{}", ev.num, ev_str(&ev));
        while history_w(hw, &mut ev, H_NEXT, &[]) == 0 {
            print!(" | {}:{}", ev.num, ev_str(&ev));
        }
    } else {
        // %s on the wide error string: first byte only
        print!(" first=ERR({} {})", ev.num, first_byte(&ev));
    }
    println!();
}

/// The C prints `%s` where the wide API wrote a `wchar_t *`; the narrow read
/// stops at the first NUL byte, i.e. it shows just the first byte.
fn first_byte(ev: &HistEventW) -> String {
    ev.str
        .as_deref()
        .and_then(|s| s.first())
        .map(|&b| (b as char).to_string())
        .unwrap_or_default()
}

fn d02_to_d05() {
    // the direct API sessions run against an editor whose stdio is a pipe
    // (NO_TTY); outputs go to the probe stdout directly.
    let mut el = el_init(
        "probe",
        false,
        Vec::new(),
        vec![("TERM".to_string(), "xterm".to_string())],
    )
    .unwrap();
    el_set_narrow(&mut el, EL_PROMPT, &[SetArg::Prompt(Some(0))]);
    el_set_narrow(&mut el, EL_EDITOR, &[SetArg::Str(b"emacs".to_vec())]);
    d02_el_get(&mut el);
    d03_el_set_errors(&mut el);
    d04_line_ops(&mut el);
    d05_parse_source(&mut el);
    // the child's el_errfile is stderr: the el_set(EL_TERMINAL,
    // "nosuchterm") message lands there (the harness captures it separately
    // from stdout, so the interleaving is not observable)
    eprint!("{}", String::from_utf8_lossy(&el.err));
}

fn d02_el_get(el: &mut Engine) {
    println!("=== D02 el_get battery ===");
    let mut o = GetOut::None;
    el_get_narrow(el, EL_EDITOR, &mut o);
    let editor = match &o {
        GetOut::Str(s) => s.clone(),
        _ => Vec::new(),
    };
    cprint_narrow_as_wide("editor=", &editor);
    el_get_narrow(el, EL_TERMINAL, &mut o);
    let term = match &o {
        GetOut::Str(s) => String::from_utf8_lossy(s).to_string(),
        _ => String::new(),
    };
    println!("terminal={}", term);
    el_get_narrow(el, EL_SIGNAL, &mut o);
    let v = match &o {
        GetOut::I32(v) => *v,
        _ => 0,
    };
    println!("signal={}", v);
    el_get_narrow(el, EL_EDITMODE, &mut o);
    let v = match &o {
        GetOut::I32(v) => *v,
        _ => 0,
    };
    println!("editmode={}", v);
    el_get_narrow(el, EL_SAFEREAD, &mut o);
    let v = match &o {
        GetOut::I32(v) => *v,
        _ => 0,
    };
    println!("saferead={}", v);
    el_get_narrow(el, EL_UNBUFFERED, &mut o);
    let v = match &o {
        GetOut::I32(v) => *v,
        _ => 0,
    };
    println!("unbuffered={}", v);
    el_get_narrow(el, EL_WORDCHARS, &mut o);
    let wc = match &o {
        GetOut::Str(s) => s.clone(),
        _ => Vec::new(),
    };
    cprint_narrow_as_wide("wordchars=", &wc);
    match el_gettc(el, "co") {
        Ok(GetTcOut::I32(v)) => println!("gettc co={}", v),
        _ => println!("gettc co=ERR"),
    }
    match el_gettc(el, "li") {
        Ok(GetTcOut::I32(v)) => println!("gettc li={}", v),
        _ => println!("gettc li=ERR"),
    }
    match el_gettc(el, "am") {
        Ok(GetTcOut::Str(s)) => println!("gettc am={}", String::from_utf8_lossy(&s)),
        _ => println!("gettc am=ERR"),
    }
    match el_gettc(el, "ce") {
        Ok(GetTcOut::Str(s)) => println!("gettc ce={}", String::from_utf8_lossy(&s)),
        _ => println!("gettc ce=ERR"),
    }
    match el_gettc(el, "bl") {
        Ok(GetTcOut::Str(s)) => println!("gettc bl={}", String::from_utf8_lossy(&s)),
        _ => println!("gettc bl=ERR"),
    }
    match el_gettc(el, "nosuch") {
        Ok(_) => println!("gettc nosuch=?"),
        Err(_) => println!("gettc nosuch=ERR"),
    }
}

fn d03_el_set_errors(el: &mut Engine) {
    println!("=== D03 el_set errors ===");
    let r = el_set_narrow(el, EL_EDITOR, &[SetArg::Str(b"junk".to_vec())]);
    println!("editor junk -> {}", r);
    let r = el_set_narrow(el, EL_EDITOR, &[SetArg::Str(b"emacs".to_vec())]);
    println!("editor emacs -> {}", r);
    let mut o = GetOut::None;
    el_get_narrow(el, EL_EDITOR, &mut o);
    let editor = match &o {
        GetOut::Str(s) => s.clone(),
        _ => Vec::new(),
    };
    cprint_narrow_as_wide("editor=", &editor);
    let r = el_set_narrow(el, EL_TERMINAL, &[SetArg::Str(b"nosuchterm".to_vec())]);
    println!("terminal nosuchterm -> {}", r);
    let r = el_set_narrow(el, EL_EDITMODE, &[SetArg::I32(0)]);
    println!("editmode 0 -> {}", r);
    el_get_narrow(el, EL_EDITMODE, &mut o);
    let v = match &o {
        GetOut::I32(v) => *v,
        _ => 0,
    };
    println!("editmode={}", v);
    let r = el_set_narrow(el, EL_EDITMODE, &[SetArg::I32(1)]);
    println!("editmode 1 -> {}", r);
    let r = el_set_narrow(el, EL_SAFEREAD, &[SetArg::I32(1)]);
    println!("saferead 1 -> {}", r);
    el_get_narrow(el, EL_SAFEREAD, &mut o);
    let v = match &o {
        GetOut::I32(v) => *v,
        _ => 0,
    };
    println!("saferead={}", v);
}

fn d04_line_ops(el: &mut Engine) {
    println!("=== D04 line ops ===");
    let r = el_winsertstr(el, Some(&str_to_w(b"hello")));
    println!("insertstr hello -> {}", r);
    let (_, cur, last) = el_wline(el);
    println!("line buf=<{}> cur={} last={}", line_buf_str(el), cur, last);
    let r = el_winsertstr(el, Some(&str_to_w(b" world")));
    println!("insertstr ' world' -> {}", r);
    let (_, cur, last) = el_wline(el);
    println!("line buf=<{}> cur={} last={}", line_buf_str(el), cur, last);
    el_deletestr(el, 6);
    let (_, cur, last) = el_wline(el);
    println!(
        "deletestr(6): buf=<{}> cur={} last={}",
        line_buf_str(el),
        cur,
        last
    );
    let r = el_cursor(el, -1);
    println!("cursor(-1) -> {}", r);
    let r = el_deletestr1(el, 1, 3);
    println!("deletestr1(1,3) -> {}", r);
    let (_, cur, last) = el_wline(el);
    println!("line buf=<{}> cur={} last={}", line_buf_str(el), cur, last);
    let r = el_wreplacestr(el, Some(&str_to_w(b"replaced")));
    println!("replacestr -> {}", r);
    let (_, cur, last) = el_wline(el);
    println!("line buf=<{}> cur={} last={}", line_buf_str(el), cur, last);
    let r = el_winsertstr(el, Some(&[]));
    println!("insertstr '' -> {}", r);
    let r = el_wreplacestr(el, Some(&[]));
    println!("replacestr '' -> {}", r);
}

fn str_to_w(s: &[u8]) -> Vec<u32> {
    s.iter().map(|&b| b as u32).collect()
}

fn line_buf_str(el: &Engine) -> String {
    // The C probe prints li->buffer with %s: the narrow encoding of the wide
    // line buffer walks to the first NUL wchar, which includes stale bytes
    // past lastchar (el_deletestr1 leaves them).
    let end = el
        .line
        .buf
        .iter()
        .position(|&c| c == 0)
        .unwrap_or(el.line.buf.len());
    let mut s = String::new();
    for &c in &el.line.buf[..end] {
        if c >= 0x20 && c < 0x7f {
            s.push(c as u8 as char);
        } else {
            s.push_str(&format!("\\x{:02x}", c));
        }
    }
    s
}

fn d05_parse_source(el: &mut Engine) {
    println!("=== D05 parse + source ===");
    let argv: Vec<Vec<u8>> = vec![b"bind".to_vec(), b"-e".to_vec()];
    let r = el_parse(el, &argv);
    println!("el_parse bind -e -> {}", r);
    let mut o = GetOut::None;
    el_get_narrow(el, EL_EDITOR, &mut o);
    let editor = match &o {
        GetOut::Str(s) => s.clone(),
        _ => Vec::new(),
    };
    cprint_narrow_as_wide("editor=", &editor);
    let path = "/tmp/le-editrc-probe";
    std::fs::write(
        path,
        b"bind \"^X\" ed-move-to-beg\nbind -s \"^A\" \"pre\"\n",
    )
    .unwrap();
    let r = el_source(el, Some(path));
    println!("el_source -> {}", r);
    let _ = std::fs::remove_file(path);
    el_set_narrow(el, EL_EDITOR, &[SetArg::Str(b"emacs".to_vec())]);
    let argv2: Vec<Vec<u8>> = vec![b"bind".to_vec(), b"^X".to_vec()];
    el_parse(el, &argv2);
}

fn d06_tokenizer() {
    println!("=== D06 tokenizer ===");
    // the C probe's array is NULL-terminated; the empty-string entry sits
    // between "under\"double" and "tab\there" (12 lines total)
    let lines: [&[u8]; 12] = [
        b"one two three",
        b"  spaced   out  ",
        b"a 'quoted string' here",
        b"pre\"mid\"post",
        b"back\\slash and \\'quote\\'",
        b"unterminated 'quote",
        b"under\"double",
        b"",
        b"tab\there",
        b"a\\\ncontinuation",
        b"x''y",
        b"M-a b",
    ];
    let mut t = Tokenizer::tok_init(None);
    // The C probe's argc/argv variables persist across tok_str calls: a
    // failed parse (r=1/2) returns without updating them, so the next print
    // shows the previous call's argc.  The caller's argv is the tokenizer's
    // LIVE argv array (the C passes tok->argv by pointer), so the failed
    // parse's partial writes are visible through it; display from t.argv.
    let mut argc = 0i32;
    for line in lines.iter() {
        let wide: Vec<u32> = line.iter().map(|&b| b as u32).collect();
        let mut argv: Vec<Option<usize>> = Vec::new();
        let r = t.tok_str(&wide, &mut argc, &mut argv);
        let disp = String::from_utf8_lossy(line);
        print!("tok_str({}) -> r={} argc={}:", disp, r, argc);
        for j in 0..argc.max(0) as usize {
            // the caller's argv is the tokenizer's live argv array: on a
            // failed parse (r=1/2) argc keeps its stale value while the
            // array shows the partial writes of the failed parse
            match t.argv.get(j).copied().flatten() {
                Some(start) => {
                    let s = &t.wspace[start..];
                    let end = s.iter().position(|&c| c == 0).unwrap_or(s.len());
                    print!(
                        " [{}]",
                        String::from_utf8_lossy(&ct_encode_string(&s[..end]))
                    );
                }
                None => print!(" [(null)]"),
            }
        }
        println!();
        t.tok_reset();
    }
}

fn d07_no_tty() {
    println!("=== D07 NO_TTY ===");
    let mut el = el_init("probe", false, b"line one\nline two\n".to_vec(), vec![]).unwrap();
    el_set_narrow(&mut el, EL_PROMPT, &[SetArg::Prompt(Some(0))]);
    let mut n = 0i32;
    let l1 = el_gets(&mut el, &mut n);
    println!(
        "gets1={}({})",
        l1.as_deref()
            .map(|l| String::from_utf8_lossy(l).to_string())
            .unwrap_or_default(),
        n
    );
    let l2 = el_gets(&mut el, &mut n);
    println!(
        "gets2={}({})",
        l2.as_deref()
            .map(|l| String::from_utf8_lossy(l).to_string())
            .unwrap_or_default(),
        n
    );
    let l3 = el_gets(&mut el, &mut n);
    println!(
        "gets3={}({})",
        if l3.is_some() {
            String::from_utf8_lossy(&l3.unwrap()).to_string()
        } else {
            "(nil)".to_string() // glibc %p of NULL
        },
        n
    );
}
