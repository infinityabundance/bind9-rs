/* probe-libedit.c — LE-0001 oracle probe.
 *
 * Drives libedit 20260512-3.1 deterministically and reports the observable
 * surface byte-exactly:
 *
 *   pty sessions: the child runs real libedit against a pty whose initial
 *   termios is raw (ECHO/ICANON off, 80x24); the parent waits for a
 *   readiness byte (the child's el_init has already applied its t_ex
 *   settings, so the canonical-echo race is gone) and writes the fixed
 *   script; the raw pty transcript is captured and printed escaped.
 *   The child prints "LINE: ..." after every el_gets and H_ENTERs the
 *   returned line into an attached history (the BIND nslookup pattern),
 *   so the transcript includes the engine's own refresh output AND the
 *   caller's printf — the exact byte stream a BIND user sees.
 *
 *   direct sessions: the probe calls the API in-process and prints
 *   observations (history opcodes, el_get values, tokenizer, line ops)
 *   with plain newlines.
 *
 * All inputs are fixed byte constants; TERM is pinned; the pty winsize is
 * pinned at 80x24; the initial termios is pinned (cfmakeraw) so the output
 * is byte-deterministic across machines with the same terminfo entry.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <pty.h>
#include <fcntl.h>
#include <termios.h>
#include <sys/wait.h>
#include <sys/ioctl.h>
#include <histedit.h>
#include <editline/readline.h>
#include <signal.h>

static void dbg_alarm(int sig) { (void)sig; _exit(0); }
static void child_watchdog(void) { signal(SIGALRM, dbg_alarm); alarm(6); }

static History *g_hist;
static HistEvent g_ev;
static HistoryW *g_hw;

static const char *prompt_p(EditLine *el) { (void)el; return "p> "; }
static const char *prompt_empty(EditLine *el) { (void)el; return ""; }
static const char *prompt_esc(EditLine *el) {
	(void)el;
	return "a\001HIDDEN\002b> ";
}
static const char *rprompt_rr(EditLine *el) { (void)el; return "<<"; }

static void dump_bytes(const unsigned char *buf, ssize_t n) {
	for (ssize_t i = 0; i < n; i++) {
		unsigned char c = buf[i];
		if (c == 0x1b) printf("ESC");
		else if (c == 0x08) printf("BS");
		else if (c == 0x7f) printf("DEL");
		else if (c == '\r') printf("\\r");
		else if (c == '\n') printf("\\n\n");
		else if (c == '\t') printf("\\t");
		else if (c == 0x07) printf("BEL");
		else if (c >= 0x20 && c < 0x7f) putchar(c);
		else printf("<%02x>", c);
	}
	printf("\n");
}

/* ---------------- pty sessions ---------------- */

struct session {
	const char *id;
	const char *name;
	void (*config)(EditLine *);
	const char *input;
};

static void cfg_emacs(EditLine *el) {
	el_set(el, EL_PROMPT, prompt_p);
	el_set(el, EL_EDITOR, "emacs");
	g_hist = history_init();
	el_set(el, EL_HIST, history, g_hist);
}
static void cfg_vi(EditLine *el) {
	el_set(el, EL_PROMPT, prompt_p);
	el_set(el, EL_EDITOR, "vi");
	g_hist = history_init();
	el_set(el, EL_HIST, history, g_hist);
}
static void cfg_rprompt(EditLine *el) {
	el_set(el, EL_PROMPT, prompt_p);
	el_set(el, EL_EDITOR, "emacs");
	el_set(el, EL_RPROMPT, rprompt_rr);
}
static void cfg_esc(EditLine *el) {
	el_set(el, EL_PROMPT_ESC, prompt_esc, '\001');
	el_set(el, EL_EDITOR, "emacs");
}
static void cfg_noedit(EditLine *el) {
	el_set(el, EL_PROMPT, prompt_p);
	el_set(el, EL_EDITOR, "emacs");
	el_set(el, EL_EDITMODE, 0);
}
static void cfg_empty_prompt(EditLine *el) {
	el_set(el, EL_PROMPT, prompt_empty);
	el_set(el, EL_EDITOR, "emacs");
}
static void cfg_readline(EditLine *el) { (void)el; }

/* Build the deterministic initial pty termios.  The probe's own stdin is not
 * a tty (the court container runs it with stdin redirected), so tcgetattr(0)
 * fails and a cfmakeraw() over that garbage would seed libedit's t_or/t_ex/
 * t_ed with stack bytes — the transcript's newline translation would depend
 * on the compiler's stack layout.  Build the termios from constants instead:
 * a fully raw line discipline (all c_cc disabled, VMIN=1/VTIME=0). */
static void deterministic_raw(struct termios *raw) {
	memset(raw, 0, sizeof(*raw));
	raw->c_iflag = 0;
	raw->c_oflag = 0;
	raw->c_lflag = 0;
	raw->c_cflag = CS8;
	for (size_t i = 0; i < NCCS; i++)
		raw->c_cc[i] = _POSIX_VDISABLE;
	raw->c_cc[VMIN] = 1;
	raw->c_cc[VTIME] = 0;
}

/* Pin the editing termios (libedit ttyperm[ED_IO] + ttychar): el_init leaves
 * the tty cooked (t_ex: ECHO|ICANON on), and el_gets only switches to the
 * editing termios at its first read.  If the parent's input landed in that
 * window the kernel would echo it and the transcript would depend on a race
 * between the child's tcsetattr and the parent's write.  Applying the
 * editing termios here, before the readiness byte, makes the input land
 * under ECHO/ICANON off deterministically: the transcript contains only
 * libedit's own writes. */
	static void pin_editing_termios(void) {
	struct termios ed;
	tcgetattr(0, &ed);
	ed.c_iflag = INLCR | ICRNL;
	ed.c_oflag = OPOST | ONLCR;
	ed.c_lflag = ISIG;
	ed.c_cc[VINTR] = 0x03;
	ed.c_cc[VQUIT] = 0x1c;
	ed.c_cc[VERASE] = 0x7f;
	ed.c_cc[VKILL] = 0x15;
	ed.c_cc[VEOF] = 0x04;
	ed.c_cc[VSTART] = 0x11;
	ed.c_cc[VSTOP] = 0x13;
	ed.c_cc[VSUSP] = 0x1a;
	ed.c_cc[VMIN] = 1;
	ed.c_cc[VTIME] = 0;
	tcsetattr(0, TCSADRAIN, &ed);
}

static void run_pty_session(const struct session *s, const char *term) {
	int master, slave, ready[2];
	struct termios raw;
	struct winsize ws;
	pipe(ready);
	memset(&ws, 0, sizeof(ws));
	ws.ws_col = 80; ws.ws_row = 24;
	deterministic_raw(&raw);
	if (openpty(&master, &slave, NULL, &raw, &ws) < 0) { perror("openpty"); exit(1); }
	pid_t pid = fork();
	if (pid == 0) {
		setsid();
		ioctl(slave, TIOCSCTTY, 0);
		dup2(slave, 0); dup2(slave, 1); dup2(slave, 2);
		close(master); close(slave); close(ready[0]);
		setenv("TERM", term, 1);
		if (s->config == cfg_readline) {
			/* readline() self-initializes; force that init now (it
			 * restores the original raw termios via tty_end, so the
			 * pty is raw with OPOST off for the whole readline
			 * session — the transcript's newlines are bare) and pin
			 * the editing termios so the input lands with ECHO off
			 * before the parent writes. */
			rl_initialize();
			pin_editing_termios();
			/* BIND nslookup surface: readline("> ") + add_history */
			char ok = 'R';
			write(ready[1], &ok, 1);
			close(ready[1]);
			char *line;
			line = readline("> ");
			printf("rl1=%s point=%d end=%d\n", line ? line : "(null)", rl_point, rl_end);
			free(line);
			line = readline("> ");
			printf("rl2=%s point=%d end=%d\n", line ? line : "(null)", rl_point, rl_end);
			free(line);
			add_history("alpha");
			add_history("beta");
			printf("history_length=%d history_base=%d\n", history_length, history_base);
			printf("where_history=%d\n", where_history());
			HIST_ENTRY *he = history_get(1);
			printf("history_get(1)=%s\n", he ? he->line : "(null)");
			he = history_get(2);
			printf("history_get(2)=%s\n", he ? he->line : "(null)");
			he = current_history();
			printf("current=%s\n", he ? he->line : "(null)");
			he = previous_history();
			printf("previous=%s where=%d\n", he ? he->line : "(null)", where_history());
			he = previous_history();
			printf("previous=%s where=%d\n", he ? he->line : "(null)", where_history());
			he = next_history();
			printf("next=%s where=%d\n", he ? he->line : "(null)", where_history());
			int r = history_search_prefix("al", -1);
			printf("search_prefix(al)=%d\n", r);
			r = history_search("bet", 1);
			printf("search(bet)=%d\n", r);
			char *out;
			r = history_expand("!1", &out);
			printf("expand(!1) -> r=%d out=%s\n", r, out ? out : "(null)");
			free(out);
			r = history_expand("!!", &out);
			printf("expand(!!) -> r=%d out=%s\n", r, out ? out : "(null)");
			free(out);
			r = history_expand("^a^A", &out);
			printf("expand(^a^A) -> r=%d out=%s\n", r, out ? out : "(null)");
			free(out);
			clear_history();
			printf("after clear: length=%d where=%d\n", history_length, where_history());
			_exit(0);
		}
		EditLine *el = el_init("probe", stdin, stdout, stderr);
		s->config(el);
		child_watchdog();
		pin_editing_termios();
		/* el_gets applies its t_ex termios here; only now signal the
		 * parent so the input bytes land under a deterministic termios
		 * (INLCR|ICRNL, ECHO/ICANON off). */
		/* el_gets applies its t_ex termios here; only now signal the
		 * parent so the input bytes land under a deterministic termios
		 * (INLCR|ICRNL, ECHO/ICANON off). */
		{
			char ok = 'R';
			write(ready[1], &ok, 1);
			close(ready[1]);
		}
		int n;
		const char *line;
		while ((line = el_gets(el, &n)) != NULL) {
			printf("LINE: %s (%d)\n", line, n);
			if (g_hist) {
				history(g_hist, &g_ev, H_ENTER, line);
			}
			if (strncmp(line, "quit", 4) == 0) break;
		}
		el_end(el);
		_exit(0);
	}
	close(slave); close(ready[1]);
	char ok; read(ready[0], &ok, 1); close(ready[0]);
	write(master, s->input, strlen(s->input));
	char buf[262144];
	ssize_t total = 0;
	while (1) {
		ssize_t r = read(master, buf + total, sizeof(buf) - total);
		if (r <= 0) break;
		total += r;
	}
	int st; waitpid(pid, &st, 0);
	(void)st;
	printf("=== %s %s (%zd bytes) ===\n", s->id, s->name, total);
	dump_bytes((unsigned char *)buf, total);
	fflush(stdout);
}

/* ---------------- direct sessions ---------------- */

static void hist_dump(const char *label) {
	HistEventW ev;
	printf("%s:", label);
	if (history_w(g_hw, &ev, H_GETSIZE) == 0)
		printf(" size=%d", ev.num);
	else
		printf(" size=ERR(%d %s)", ev.num, ev.str);
	if (history_w(g_hw, &ev, H_FIRST) == 0) {
		printf(" first=%d:%ls", ev.num, ev.str);
		while (history_w(g_hw, &ev, H_NEXT) == 0)
			printf(" | %d:%ls", ev.num, ev.str);
	} else {
		printf(" first=ERR(%d %s)", ev.num, ev.str);
	}
	printf("\n");
}

static void d01_history_api(void) {
	printf("=== D01 history API ===\n");
	HistoryW *hw = history_winit();
	g_hw = hw;
	HistEventW ev;
	int r;
	r = history_w(hw, &ev, H_GETSIZE); printf("getsize -> %d num=%d str=%ls\n", r, ev.num, ev.str);
	r = history_w(hw, &ev, H_SETSIZE, 5); printf("setsize(5) -> %d num=%d str=%ls\n", r, ev.num, ev.str);
	r = history_w(hw, &ev, H_ENTER, L"alpha"); printf("enter alpha -> %d num=%d str=%ls\n", r, ev.num, ev.str);
	r = history_w(hw, &ev, H_ENTER, L"beta"); printf("enter beta -> %d num=%d str=%ls\n", r, ev.num, ev.str);
	r = history_w(hw, &ev, H_ENTER, L"gamma"); printf("enter gamma -> %d num=%d str=%ls\n", r, ev.num, ev.str);
	r = history_w(hw, &ev, H_ADD, L"2"); printf("add 2 -> %d num=%d str=%ls\n", r, ev.num, ev.str);
	hist_dump("after enter x3 + add");
	r = history_w(hw, &ev, H_APPEND, L"!?"); printf("append -> %d num=%d str=%ls\n", r, ev.num, ev.str);
	hist_dump("after append");
	r = history_w(hw, &ev, H_PREV); printf("prev -> %d num=%d str=%ls\n", r, ev.num, ev.str);
	r = history_w(hw, &ev, H_PREV); printf("prev -> %d num=%d str=%ls\n", r, ev.num, ev.str);
	r = history_w(hw, &ev, H_PREV); printf("prev -> %d num=%d str=%ls\n", r, ev.num, ev.str);
	r = history_w(hw, &ev, H_PREV); printf("prev -> %d num=%d str=%ls\n", r, ev.num, ev.str);
	r = history_w(hw, &ev, H_PREV); printf("prev -> %d num=%d str=%ls\n", r, ev.num, ev.str);
	r = history_w(hw, &ev, H_NEXT); printf("next -> %d num=%d str=%ls\n", r, ev.num, ev.str);
	r = history_w(hw, &ev, H_CURR); printf("curr -> %d num=%d str=%ls\n", r, ev.num, ev.str);
	r = history_w(hw, &ev, H_FIRST); printf("first -> %d num=%d str=%ls\n", r, ev.num, ev.str);
	r = history_w(hw, &ev, H_LAST); printf("last -> %d num=%d str=%ls\n", r, ev.num, ev.str);
	r = history_w(hw, &ev, H_SET, 2); printf("set(2) -> %d num=%d str=%ls\n", r, ev.num, ev.str);
	r = history_w(hw, &ev, H_CURR); printf("curr -> %d num=%d str=%ls\n", r, ev.num, ev.str);
	r = history_w(hw, &ev, H_PREV_STR, L"b"); printf("prev_str(b) -> %d num=%d str=%ls\n", r, ev.num, ev.str);
	r = history_w(hw, &ev, H_NEXT_STR, L"g"); printf("next_str(g) -> %d num=%d str=%ls\n", r, ev.num, ev.str);
	r = history_w(hw, &ev, H_PREV_EVENT, 1); printf("prev_event(1) -> %d num=%d str=%ls\n", r, ev.num, ev.str);
	r = history_w(hw, &ev, H_NEXT_EVENT, 3); printf("next_event(3) -> %d num=%d str=%ls\n", r, ev.num, ev.str);
	r = history_w(hw, &ev, H_DEL, 2); printf("del(2) -> %d num=%d str=%ls\n", r, ev.num, ev.str);
	hist_dump("after del");
	r = history_w(hw, &ev, H_CLEAR); printf("clear -> %d\n", r);
	hist_dump("after clear");
	r = history_w(hw, &ev, H_SETSIZE, -1); printf("setsize(-1) -> %d num=%d str=%ls\n", r, ev.num, ev.str);
	r = history_w(hw, &ev, H_SETUNIQUE, 1); printf("setunique(1) -> %d\n", r);
	r = history_w(hw, &ev, H_ENTER, L"dup"); printf("enter dup -> %d num=%d\n", r, ev.num);
	r = history_w(hw, &ev, H_ENTER, L"dup"); printf("enter dup -> %d num=%d\n", r, ev.num);
	r = history_w(hw, &ev, H_GETUNIQUE); printf("getunique -> %d num=%d\n", r, ev.num);
	hist_dump("after unique");
	history_wend(hw);
}

static void d02_el_get(EditLine *el) {
	printf("=== D02 el_get battery ===\n");
	const char *s;
	int i;
	const wchar_t *ws;
	el_get(el, EL_EDITOR, &ws);
	printf("editor=%ls\n", ws);
	el_get(el, EL_TERMINAL, &s);
	printf("terminal=%s\n", s);
	el_get(el, EL_SIGNAL, &i); printf("signal=%d\n", i);
	el_get(el, EL_EDITMODE, &i); printf("editmode=%d\n", i);
	el_get(el, EL_SAFEREAD, &i); printf("saferead=%d\n", i);
	el_get(el, EL_UNBUFFERED, &i); printf("unbuffered=%d\n", i);
	el_get(el, EL_WORDCHARS, &ws);
	printf("wordchars=%ls\n", ws);
	char *cap;
	int ival;
	if (el_get(el, EL_GETTC, "co", &ival) == 0) printf("gettc co=%d\n", ival);
	if (el_get(el, EL_GETTC, "li", &ival) == 0) printf("gettc li=%d\n", ival);
	if (el_get(el, EL_GETTC, "am", &cap) == 0) printf("gettc am=%s\n", cap);
	if (el_get(el, EL_GETTC, "ce", &cap) == 0) printf("gettc ce=%s\n", cap);
	if (el_get(el, EL_GETTC, "bl", &cap) == 0) printf("gettc bl=%s\n", cap);
	if (el_get(el, EL_GETTC, "nosuch", &cap) == 0) printf("gettc nosuch=%s\n", cap);
	else printf("gettc nosuch=ERR\n");
}

static void d03_el_set_errors(EditLine *el) {
	printf("=== D03 el_set errors ===\n");
	int r = el_set(el, EL_EDITOR, "junk");
	printf("editor junk -> %d\n", r);
	r = el_set(el, EL_EDITOR, "emacs");
	printf("editor emacs -> %d\n", r);
	const wchar_t *ws;
	el_get(el, EL_EDITOR, &ws);
	printf("editor=%ls\n", ws);
	r = el_set(el, EL_TERMINAL, "nosuchterm");
	printf("terminal nosuchterm -> %d\n", r);
	r = el_set(el, EL_EDITMODE, 0);
	printf("editmode 0 -> %d\n", r);
	el_get(el, EL_EDITMODE, &r);
	printf("editmode=%d\n", r);
	r = el_set(el, EL_EDITMODE, 1);
	printf("editmode 1 -> %d\n", r);
	r = el_set(el, EL_SAFEREAD, 1);
	printf("saferead 1 -> %d\n", r);
	el_get(el, EL_SAFEREAD, &r);
	printf("saferead=%d\n", r);
}

static void d04_line_ops(EditLine *el) {
	printf("=== D04 line ops ===\n");
	const LineInfo *li;
	int r = el_insertstr(el, "hello");
	printf("insertstr hello -> %d\n", r);
	li = el_line(el);
	printf("line buf=<%s> cur=%td last=%td\n", li->buffer,
	    li->cursor - li->buffer, li->lastchar - li->buffer);
	r = el_insertstr(el, " world");
	printf("insertstr ' world' -> %d\n", r);
	li = el_line(el);
	printf("line buf=<%s> cur=%td last=%td\n", li->buffer,
	    li->cursor - li->buffer, li->lastchar - li->buffer);
	el_deletestr(el, 6);
	li = el_line(el);
	printf("deletestr(6): buf=<%s> cur=%td last=%td\n", li->buffer,
	    li->cursor - li->buffer, li->lastchar - li->buffer);
	r = el_cursor(el, -1);
	printf("cursor(-1) -> %d\n", r);
	r = el_deletestr1(el, 1, 3);
	printf("deletestr1(1,3) -> %d\n", r);
	li = el_line(el);
	printf("line buf=<%s> cur=%td last=%td\n", li->buffer,
	    li->cursor - li->buffer, li->lastchar - li->buffer);
	r = el_replacestr(el, "replaced");
	printf("replacestr -> %d\n", r);
	li = el_line(el);
	printf("line buf=<%s> cur=%td last=%td\n", li->buffer,
	    li->cursor - li->buffer, li->lastchar - li->buffer);
	r = el_insertstr(el, "");
	printf("insertstr '' -> %d\n", r);
	r = el_replacestr(el, "");
	printf("replacestr '' -> %d\n", r);
}

static void d05_parse_source(EditLine *el) {
	printf("=== D05 parse + source ===\n");
	const char *argv1[] = { "bind", "-e", NULL };
	int r = el_parse(el, 2, argv1);
	printf("el_parse bind -e -> %d\n", r);
	const wchar_t *ws;
	el_get(el, EL_EDITOR, &ws);
	printf("editor=%ls\n", ws);
	char path[] = "/tmp/le-editrc-XXXXXX";
	int fd = mkstemp(path);
	write(fd, "bind \"^X\" ed-move-to-beg\nbind -s \"^A\" \"pre\"\n",
	    strlen("bind \"^X\" ed-move-to-beg\nbind -s \"^A\" \"pre\"\n"));
	close(fd);
	r = el_source(el, path);
	printf("el_source -> %d\n", r);
	unlink(path);
	el_set(el, EL_EDITOR, "emacs");
	/* verify the bindings landed: C-x should now be ed-move-to-beg */
	const char *argv2[] = { "bind", "^X", NULL };
	el_parse(el, 2, argv2);
}

static void d06_tokenizer(void) {
	printf("=== D06 tokenizer ===\n");
	Tokenizer *t = tok_init(NULL);
	const char *lines[] = {
	    "one two three",
	    "  spaced   out  ",
	    "a 'quoted string' here",
	    "pre\"mid\"post",
	    "back\\slash and \\'quote\\'",
	    "unterminated 'quote",
	    "under\"double",
	    "",
	    "tab\there",
	    "a\\\ncontinuation",
	    "x''y",
	    "M-a b",
	    NULL,
	};
	for (int i = 0; lines[i]; i++) {
		int argc;
		const char **argv;
		int r = tok_str(t, lines[i], &argc, &argv);
		printf("tok_str(%s) -> r=%d argc=%d:", lines[i], r, argc);
		for (int j = 0; j < argc; j++)
			printf(" [%s]", argv[j]);
		printf("\n");
		tok_reset(t);
	}
	tok_end(t);
}

static void d07_no_tty(void) {
	printf("=== D07 NO_TTY ===\n");
	int fds[2];
	pipe(fds);
	FILE *fin = fdopen(fds[0], "r");
	EditLine *el = el_init("probe", fin, stdout, stderr);
	el_set(el, EL_PROMPT, prompt_p);
	write(fds[1], "line one\nline two\n", 18);
	close(fds[1]);
	int n;
	const char *line;
	line = el_gets(el, &n);
	printf("gets1=%s(%d)\n", line, n);
	line = el_gets(el, &n);
	printf("gets2=%s(%d)\n", line, n);
	line = el_gets(el, &n);
	printf("gets3=%p(%d)\n", (void *)line, n);
	el_end(el);
	fclose(fin);
	close(fds[0]);
}

/* ---------------- main ---------------- */

int main(void) {
	setbuf(stdout, NULL);
	setenv("TERM", "xterm", 1);
	struct session s;

	s = (struct session){ "S01", "plain", cfg_emacs, "hello world\nquit\n" };
	run_pty_session(&s, "xterm");
	s = (struct session){ "S02", "backspace", cfg_emacs, "abc\x08\x08z\nquit\n" };
	run_pty_session(&s, "xterm");
	s = (struct session){ "S03", "killline", cfg_emacs, "hello world\n\x01\x0b\nquit\n" };
	run_pty_session(&s, "xterm");
	s = (struct session){ "S04", "killu-yank", cfg_emacs, "abcdef\n\x15\x19\nquit\n" };
	run_pty_session(&s, "xterm");
	s = (struct session){ "S05", "mid-insert", cfg_emacs, "abcdef\n\x01gh\x05\nquit\n" };
	run_pty_session(&s, "xterm");
	s = (struct session){ "S06", "transpose", cfg_emacs, "ab\n\x02\nquit\n" };
	run_pty_session(&s, "xterm");
	s = (struct session){ "S07", "killword", cfg_emacs, "one two three\n\x17\x01\x17\nquit\n" };
	run_pty_session(&s, "xterm");
	s = (struct session){ "S08", "word-motion", cfg_emacs, "one two three\n\x1b" "f\x1b" "b\x1b" "d\nquit\n" };
	run_pty_session(&s, "xterm");
	s = (struct session){ "S09", "case", cfg_emacs, "hello world\n\x01\x1b" "u\x1b" "c\x1b" "l\nquit\n" };
	run_pty_session(&s, "xterm");
	s = (struct session){ "S10", "ctrl-d", cfg_emacs, "abc\x04\nquit\n" };
	run_pty_session(&s, "xterm");
	s = (struct session){ "S11", "history", cfg_emacs, "one\ntwo\nthree\n\x10\x10\x0e\nquit\n" };
	run_pty_session(&s, "xterm");
	s = (struct session){ "S12", "hist-search", cfg_emacs, "hello one\nhello two\n\x01\x1bp\nquit\n" };
	run_pty_session(&s, "xterm");
	s = (struct session){ "S13", "arrows", cfg_emacs, "ab\n\x1b[D\x1b[Dc\n\x1b[C\nquit\n" };
	run_pty_session(&s, "xterm");
	s = (struct session){ "S14", "kill-ring", cfg_emacs, "abc def\n\x01\x0b\x19\nquit\n" };
	run_pty_session(&s, "xterm");
	s = (struct session){ "S15", "vi", cfg_vi, "hello world\n\x1b" "hx\x1b" "ddiXX\nquit\n" };
	run_pty_session(&s, "xterm");
	s = (struct session){ "S16", "vi-search", cfg_vi, "hello\nworld\n\x1b/ell\nn\nquit\n" };
	run_pty_session(&s, "xterm");
	s = (struct session){ "S17", "rprompt", cfg_rprompt, "hi\nquit\n" };
	run_pty_session(&s, "xterm");
	s = (struct session){ "S18", "prompt-esc", cfg_esc, "xy\nquit\n" };
	run_pty_session(&s, "xterm");
	s = (struct session){ "S19", "dumb", cfg_emacs, "hello world\n\x08\x08!\nquit\n" };
	run_pty_session(&s, "dumb");
	s = (struct session){ "S20", "utf8", cfg_emacs, "h\xc3\xa9llo w\xc3\xb6rld\nquit\n" };
	run_pty_session(&s, "xterm");
	s = (struct session){ "S21", "noedit", cfg_noedit, "raw line\nquit\n" };
	run_pty_session(&s, "xterm");
	s = (struct session){ "S22", "longline", cfg_emacs,
	    "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\n"
	    "\x01\x1b" "w\x1b" "d\nquit\n" };
	run_pty_session(&s, "xterm");
	s = (struct session){ "S23", "clearscreen", cfg_emacs, "abc\n\x0c\nquit\n" };
	run_pty_session(&s, "xterm");
	s = (struct session){ "S24", "quoted-insert", cfg_emacs, "ab\n\x16\x1b" "cd\nquit\n" };
	run_pty_session(&s, "xterm");
	s = (struct session){ "S25", "empty-prompt", cfg_empty_prompt, "abc\nquit\n" };
	run_pty_session(&s, "xterm");
	s = (struct session){ "S26", "vi-yank-put", cfg_vi, "one two\n\x1b" "0dw\x1b" "P\x1b" "0dw\x1b" "p\nquit\n" };
	run_pty_session(&s, "xterm");
	s = (struct session){ "S27", "vi-undo", cfg_vi, "abc def\n\x1b" "0cwXX\x1b" "\x1b" "u\nquit\n" };
	run_pty_session(&s, "xterm");
	s = (struct session){ "S28", "ed-command", cfg_emacs, "abc\n\x1bxecho hi\nquit\n" };
	run_pty_session(&s, "xterm");
	s = (struct session){ "S29", "readline", cfg_readline, "alpha\nbeta\n" };
	run_pty_session(&s, "xterm");

	/* direct sessions */
	d01_history_api();
	{
		int p[2];
		pipe(p);
		FILE *fin = fdopen(p[0], "r");
		FILE *fout = fdopen(p[1], "w");
		EditLine *el = el_init("probe", fin, fout, stderr);
		el_set(el, EL_PROMPT, prompt_p);
		el_set(el, EL_EDITOR, "emacs");
		d02_el_get(el);
		d03_el_set_errors(el);
		d04_line_ops(el);
		d05_parse_source(el);
		el_end(el);
		fclose(fout); fclose(fin);
		close(p[1]); close(p[0]);
	}
	d06_tokenizer();
	d07_no_tty();
	return 0;
}
