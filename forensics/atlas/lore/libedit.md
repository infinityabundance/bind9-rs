# Lore Archive (addendum §29)

Knowledge conventional documentation loses, kept with the code that depends
on it.  Each entry records *why* an observed behavior exists.

## LE-LORE-0001 — the pty court is a byte-stable transcript, not an API echo

The LE-0001 court captures the *master side* of a pty whose slave runs real
libedit under a pinned raw termios (VMIN=1/VTIME=0, c_cflag CS8, all c_cc
disabled) with a pinned 80x24 winsize, and prints the captured bytes escaped
(ESC/BS/DEL/`\r`/`\n`/`\t`/BEL/hex).  Two things make it deterministic where
earlier attempts were not: (1) the probe's own stdin is *not* a tty in the
court container, so `tcgetattr(0)` fails and the original code seeded the
editing termios from uninitialized stack bytes — `deterministic_raw()` now
builds the termios from constants; (2) `el_gets` only applies the editing
termios (`ttyperm[ED_IO]`) at its first read, so input written before that
would land under the kernel's cooked echo — `pin_editing_termios()` applies
INLCR|ICRNL + OPOST|ONLCR + ISIG on the slave *before* the readiness byte,
so every input byte lands under ECHO/ICANON off.  Court: LE-0001.

## LE-LORE-0002 — the Rust engine models the pty line discipline in its sinks

The C never translates newlines in the editor: the pty kernel does.  Input
`\n` becomes `\r` and `\r` becomes `\n` (INLCR wins over ICRNL), so every
editor function must accept both (the C switches on `case L'\r': case L'\n':`
everywhere); output `\n` becomes `\r\n` (OPOST|ONLCR).  The Rust engine
applies the input translation in `read_char` (only when the input models a
pty — `tty_is_tty` — NO_TTY/pipe input is raw), and the output translation
in `terminal__putc`.  A byte >= 0x80 is an invalid single-byte sequence in
the C locale and is silently discarded by `read_char` (the C's `cbuf=0;
goto again`), which is why the S20 UTF-8 line arrives as "hllo wrld".
Court: LE-0001.

## LE-LORE-0003 — `re_nextline()` emits nothing; the newline bytes come from `terminal_move_to_line`

The C `re_nextline` only advances the *drawing* cursor (`r_cursor.v++`); the
physical newline for the next display row is written by
`terminal_move_to_line()` at the top of the next `re_update_line()` call
(one `\n` per row, ONLCR'd to `\r\n`), or by `re_fastputc()`'s wrap handling
(`' '`+`\b` for terminals with auto+magic margins).  Writing the newline in
`re_nextline` double-emits `\r\n\r` sequences and corrupts every multi-row
redraw — the c_gets prompt (`"\n: "`, `"\n/"`) is what exposes it.  Court:
LE-0001 (S16/S28).

## LE-LORE-0004 — `re_update_line` relies on mutating the old row's end to NUL

The first-diff scan stops at `old[i] != new[i]`; the end-of-old scan then
walks to the row's NUL and *strips trailing blanks*, and the C writes
`*oe = '\0'` into the row buffer itself.  That mutation is what makes a
space-padded old row ("p> " + 77 spaces + NUL) compare equal to a
NUL-terminated new row ("p> " + NUL): without it `old[ofd]` is a space, the
"no difference" check fails, and every unchanged row is redrawn.  The same
applies to `*ne = '\0'` on the new row.  Court: LE-0001.

## LE-LORE-0005 — `re_refresh` starts and ends with cursor moves, so even a no-op refresh writes bytes

`re_refresh` begins with `terminal_move_to_char(0)` (a bare `\r` when the
cursor is not in column 0) and ends with `terminal_move_to_line(cur.v)` +
`terminal_move_to_char(cur.h)`, where `cur` is the position of the *cursor
character* (captured before `re_addc` draws it).  A refresh whose rows are
all "no difference" therefore still emits `\r` + the overwrite of the old
display content up to `cur.h` — which is how an idle C-p (S11) reprints
"p> ".  Because the final move lands ON the trailing space of the c_gets
prompt (cur.h = column of the `' '` at the cursor), no trailing space is
written after "/" — the transcript shows `/\r/e\r/el\r/ell\r` with the
prefixes coming from `terminal_move_to_char(nfd)`'s overwrite-from-display
during the insert.  Court: LE-0001 (S16/S28/S11).

## LE-LORE-0006 — the narrow `el_get` stores a narrow buffer into a `wchar_t *` slot; C-locale `%ls` swallows the value and the newline

`el_get(EL_EDITOR, &ws)` with a `const wchar_t *` is the *narrow* getter
(eln.c), which calls `el_wget` and stores `ct_encode_string("emacs")` — a
narrow byte buffer — through the wide pointer.  Reading those bytes as a
`wchar_t` yields 0x63616d65 > 0xFF on little-endian; glibc's C-locale `%ls`
conversion fails and printf swallows the value AND the rest of the format
string (the trailing `\n`).  The observable line is `editor=terminal=xterm`
— the editor value contributes nothing and the next printf continues on the
same line.  The Rust probe reproduces this (`cprint_narrow_as_wide`), and
the same mechanism explains `wordchars=gettc co=80` and `first=ERR(3 f)`
(the `%s` narrow print of the wide "first event not found" stops at the
first NUL byte, showing just "f").  Court: LE-0001 (D01/D02/D03/D05).

## LE-LORE-0007 — the tokenizer's argv array is live; failed parses leak their partial writes

`tok_str`'s caller receives `tok->argv` *by pointer*.  A failed parse
(unmatched `'` or `"`) returns 1/2 from inside the state machine *before*
the outok update, so the caller's `argc` keeps its previous value while the
argv array shows the failed parse's partial writes (the finished word, then
NULLs) and the wspace shows the residue.  `tok_finish` writes the NUL and
then does `wstart = ++wptr` — the next word starts *after* the NUL; skipping
the increment overwrites the NUL and merges every word.  Court: LE-0001
(D06).

## LE-LORE-0008 — the history list is newest-first; H_FIRST is the newest, H_PREV walks toward the newer entries

`history_def_insert` pushes new entries at the head (`list.next`), so
H_FIRST returns the *newest* event and `prev` walks from the oldest toward
the newest.  `!!` in readline's `get_history_event` therefore expands to the
newest event (H_FIRST), and `!n` resolves through readline's `history_get`,
which uses the H_DELDATA *position-only* magic: `history_set_nth` walks
`n` steps back from the oldest (0-based) and, when the data argument is the
`(void **)-1` sentinel, stops without deleting.  The `history_get(2)` after
`history_get(1)` works only because the cursor is saved/restored around each
call.  Court: LE-0001 (S29/D01).

## LE-LORE-0009 — a `history_init()` history has max=0, so every H_ENTER deletes its own entry

`history_def_init(p, 0)` sets `max = 0`, and `history_def_enter` trims
`while (cur > max)` — every entered event is immediately deleted.  The pty
sessions' attached history is therefore *always empty*: the vi `/ell`
search and the `n` repetition both fail with CC_ERROR (two bells), and the
S11 C-p/C-n recalls only redraw the empty line and beep.  Court: LE-0001
(S11/S16).

## LE-LORE-0010 — `el_deletestr1` leaves stale bytes past the new lastchar, and the narrow `el_line()` walks to the NUL

`el_deletestr1(start, end)` memmoves `end-start` chars down and decrements
`lastchar` without writing a NUL at the new end; the bytes past it keep
their old values.  The probe prints `li->buffer` with `%s`, which walks the
*narrow encoding* to the next NUL — so "hello" with 1..3 deleted prints
`<hlolo>` (the stale "lo" leaks through), and `cur=4 last=3` (the cursor is
not clamped).  The Rust line buffer must not truncate on delete.  Court:
LE-0001 (D04).

## LE-LORE-0011 — readline's `^a^b` substitution requires a closing delimiter; the failure still returns an empty string

`history_expand("^a^A")` rewrites the input to `"!!:s^a^A"` and parses the
modifiers: `getfrom` consumes `a` up to the first `^` (delimiter consumed),
then `getto` scans for the *next* `^` — there is none — and returns -1, so
`_history_expand_command` fails with `*result` untouched.  The outer loop
returns -1 with the accumulated (empty) result string, so the caller sees
`r=-1 out=` (an empty string, not NULL).  A well-formed `^a^A^` substitutes
into the newest event via `_rl_compat_sub`.  Court: LE-0001 (S29).

## LE-LORE-0012 — readline runs with EDIT_DISABLED and never updates rl_point/rl_end

`rl_initialize()` checks `tcgetattr && !(c_lflag & ECHO)` on the pty (raw
after cfmakeraw) and sets EL_EDITMODE 0, so `readline()`'s `el_gets` takes
the noedit path; the prompt still appears because `read_prepare` refreshes
before the EDIT_DISABLED branch.  `rl_point`/`rl_end` are set once, at
`rl_initialize` time (0 for an empty line), and `readline()` never calls
`_rl_update_pos()` again — the corpus pins `point=0 end=0` for both reads.
The INLCR translation puts a `\r` in the returned line ("alpha\r"), and the
chop only removes a trailing `\n`, so the printf shows the `\r` on the wire.
`tty_end` at the end of `rl_initialize` restores the (raw) termios, but the
probe's `pin_editing_termios` had already re-applied OPOST|ONLCR, and each
`readline()`'s `tty_init` re-saves it — so the whole session's output is
ONLCR'd.  Court: LE-0001 (S29).
