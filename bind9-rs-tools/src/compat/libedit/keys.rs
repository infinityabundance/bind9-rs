//! Keymap tables for the libedit conservation (§29).
//!
//! Faithful transcriptions of `map.c`'s `el_map_emacs`, `el_map_vi_insert`
//! (KSHVI variant) and `el_map_vi_command`, plus the `fcns.h` function ids
//! and the `help.h` name/description table.  The C sources are generated
//! `static const` tables in the pinned libedit-20260512-3.1 tarball; the
//! values below are byte-for-byte copies (function ids 0..95 per `fcns.h`).
//!
//! One C quirk is preserved deliberately: `el_map_emacs` has 255
//! initializers, and `map_init_emacs` copies `N_KEYS` (256) entries, reading
//! one byte past the array.  That OOB byte resolves to the first element of
//! the following table (`el_map_vi_insert[0]` = `ED_UNASSIGNED`) in the
//! oracle binary's `.rodata` layout; it is behaviorally inert (index 255 is
//! only reachable as M-^?, which errors identically either way), so the
//! table below records `ED_UNASSIGNED` there.

#![allow(dead_code)]

pub const ED_ARGUMENT_DIGIT: u8 = 0;
pub const ED_CLEAR_SCREEN: u8 = 1;
pub const ED_COMMAND: u8 = 2;
pub const ED_DELETE_NEXT_CHAR: u8 = 3;
pub const ED_DELETE_PREV_CHAR: u8 = 4;
pub const ED_DELETE_PREV_WORD: u8 = 5;
pub const ED_DIGIT: u8 = 6;
pub const ED_END_OF_FILE: u8 = 7;
pub const ED_IGNORE: u8 = 8;
pub const ED_INSERT: u8 = 9;
pub const ED_KILL_LINE: u8 = 10;
pub const ED_MOVE_TO_BEG: u8 = 11;
pub const ED_MOVE_TO_END: u8 = 12;
pub const ED_NEWLINE: u8 = 13;
pub const ED_NEXT_CHAR: u8 = 14;
pub const ED_NEXT_HISTORY: u8 = 15;
pub const ED_NEXT_LINE: u8 = 16;
pub const ED_PREV_CHAR: u8 = 17;
pub const ED_PREV_HISTORY: u8 = 18;
pub const ED_PREV_LINE: u8 = 19;
pub const ED_PREV_WORD: u8 = 20;
pub const ED_QUOTED_INSERT: u8 = 21;
pub const ED_REDISPLAY: u8 = 22;
pub const ED_SEARCH_NEXT_HISTORY: u8 = 23;
pub const ED_SEARCH_PREV_HISTORY: u8 = 24;
pub const ED_SEQUENCE_LEAD_IN: u8 = 25;
pub const ED_START_OVER: u8 = 26;
pub const ED_TRANSPOSE_CHARS: u8 = 27;
pub const ED_UNASSIGNED: u8 = 28;
pub const EM_CAPITOL_CASE: u8 = 29;
pub const EM_COPY_PREV_WORD: u8 = 30;
pub const EM_COPY_REGION: u8 = 31;
pub const EM_DELETE_NEXT_WORD: u8 = 32;
pub const EM_DELETE_OR_LIST: u8 = 33;
pub const EM_DELETE_PREV_CHAR: u8 = 34;
pub const EM_EXCHANGE_MARK: u8 = 35;
pub const EM_GOSMACS_TRANSPOSE: u8 = 36;
pub const EM_INC_SEARCH_NEXT: u8 = 37;
pub const EM_INC_SEARCH_PREV: u8 = 38;
pub const EM_KILL_LINE: u8 = 39;
pub const EM_KILL_REGION: u8 = 40;
pub const EM_LOWER_CASE: u8 = 41;
pub const EM_META_NEXT: u8 = 42;
pub const EM_NEXT_WORD: u8 = 43;
pub const EM_SET_MARK: u8 = 44;
pub const EM_TOGGLE_OVERWRITE: u8 = 45;
pub const EM_UNIVERSAL_ARGUMENT: u8 = 46;
pub const EM_UPPER_CASE: u8 = 47;
pub const EM_YANK: u8 = 48;
pub const VI_ADD: u8 = 49;
pub const VI_ADD_AT_EOL: u8 = 50;
pub const VI_ALIAS: u8 = 51;
pub const VI_CHANGE_CASE: u8 = 52;
pub const VI_CHANGE_META: u8 = 53;
pub const VI_CHANGE_TO_EOL: u8 = 54;
pub const VI_COMMAND_MODE: u8 = 55;
pub const VI_COMMENT_OUT: u8 = 56;
pub const VI_DELETE_META: u8 = 57;
pub const VI_DELETE_PREV_CHAR: u8 = 58;
pub const VI_END_BIG_WORD: u8 = 59;
pub const VI_END_WORD: u8 = 60;
pub const VI_HISTEDIT: u8 = 61;
pub const VI_HISTORY_WORD: u8 = 62;
pub const VI_INSERT: u8 = 63;
pub const VI_INSERT_AT_BOL: u8 = 64;
pub const VI_KILL_LINE_PREV: u8 = 65;
pub const VI_LIST_OR_EOF: u8 = 66;
pub const VI_MATCH: u8 = 67;
pub const VI_NEXT_BIG_WORD: u8 = 68;
pub const VI_NEXT_CHAR: u8 = 69;
pub const VI_NEXT_WORD: u8 = 70;
pub const VI_PASTE_NEXT: u8 = 71;
pub const VI_PASTE_PREV: u8 = 72;
pub const VI_PREV_BIG_WORD: u8 = 73;
pub const VI_PREV_CHAR: u8 = 74;
pub const VI_PREV_WORD: u8 = 75;
pub const VI_REDO: u8 = 76;
pub const VI_REPEAT_NEXT_CHAR: u8 = 77;
pub const VI_REPEAT_PREV_CHAR: u8 = 78;
pub const VI_REPEAT_SEARCH_NEXT: u8 = 79;
pub const VI_REPEAT_SEARCH_PREV: u8 = 80;
pub const VI_REPLACE_CHAR: u8 = 81;
pub const VI_REPLACE_MODE: u8 = 82;
pub const VI_SEARCH_NEXT: u8 = 83;
pub const VI_SEARCH_PREV: u8 = 84;
pub const VI_SUBSTITUTE_CHAR: u8 = 85;
pub const VI_SUBSTITUTE_LINE: u8 = 86;
pub const VI_TO_COLUMN: u8 = 87;
pub const VI_TO_HISTORY_LINE: u8 = 88;
pub const VI_TO_NEXT_CHAR: u8 = 89;
pub const VI_TO_PREV_CHAR: u8 = 90;
pub const VI_UNDO: u8 = 91;
pub const VI_UNDO_LINE: u8 = 92;
pub const VI_YANK: u8 = 93;
pub const VI_YANK_END: u8 = 94;
pub const VI_ZERO: u8 = 95;
pub const EL_NUM_FCNS: usize = 96;

pub const N_KEYS: usize = 256;

/// `el_map_emacs` from map.c (255 initializers; index 255 resolves to
/// `ED_UNASSIGNED`, see module comment).
pub static EMACS_MAP: [u8; N_KEYS] = {
    let mut m = [ED_INSERT; N_KEYS];
    m[0] = EM_SET_MARK;
    m[1] = ED_MOVE_TO_BEG;
    m[2] = ED_PREV_CHAR;
    m[3] = ED_IGNORE;
    m[4] = EM_DELETE_OR_LIST;
    m[5] = ED_MOVE_TO_END;
    m[6] = ED_NEXT_CHAR;
    m[7] = ED_UNASSIGNED;
    m[8] = EM_DELETE_PREV_CHAR;
    m[9] = ED_UNASSIGNED;
    m[10] = ED_NEWLINE;
    m[11] = ED_KILL_LINE;
    m[12] = ED_CLEAR_SCREEN;
    m[13] = ED_NEWLINE;
    m[14] = ED_NEXT_HISTORY;
    m[15] = ED_IGNORE;
    m[16] = ED_PREV_HISTORY;
    m[17] = ED_IGNORE;
    m[18] = EM_INC_SEARCH_PREV;
    m[19] = ED_IGNORE;
    m[20] = ED_TRANSPOSE_CHARS;
    m[21] = EM_KILL_LINE;
    m[22] = ED_QUOTED_INSERT;
    m[23] = ED_DELETE_PREV_WORD;
    m[24] = ED_SEQUENCE_LEAD_IN;
    m[25] = EM_YANK;
    m[26] = ED_IGNORE;
    m[27] = EM_META_NEXT;
    m[28] = ED_IGNORE;
    m[29] = ED_IGNORE;
    m[30] = ED_UNASSIGNED;
    m[31] = ED_UNASSIGNED;
    let mut i = 48;
    while i <= 57 {
        m[i] = ED_DIGIT;
        i += 1;
    }
    m[127] = EM_DELETE_PREV_CHAR;
    // meta entries 0x80-0xFF: default ED_UNASSIGNED; the C table binds
    // exactly the entries below (verified against the oracle's `bind`
    // output: "\U+0088" -> ed-delete-prev-word, "\U+00E6" -> em-next-word,
    // ... and "^[b"/"^[u" etc. via map_init_meta's (i & 0177) encoding).
    let mut i = 128;
    while i <= 255 {
        m[i] = ED_UNASSIGNED;
        i += 1;
    }
    m[136] = ED_DELETE_PREV_WORD; // M-^H
    m[140] = ED_CLEAR_SCREEN; // M-^L
    m[159] = EM_COPY_PREV_WORD; // M-^_
    i = 176;
    while i <= 185 {
        m[i] = ED_ARGUMENT_DIGIT; // M-0 .. M-9
        i += 1;
    }
    m[194] = ED_PREV_WORD; // M-B
    m[195] = EM_CAPITOL_CASE; // M-C
    m[196] = EM_DELETE_NEXT_WORD; // M-D
    m[198] = EM_NEXT_WORD; // M-F
    m[204] = EM_LOWER_CASE; // M-L
    m[206] = ED_SEARCH_NEXT_HISTORY; // M-N
    m[207] = ED_SEQUENCE_LEAD_IN; // M-O
    m[208] = ED_SEARCH_PREV_HISTORY; // M-P
    m[213] = EM_UPPER_CASE; // M-U
    m[215] = EM_COPY_REGION; // M-W
    m[216] = ED_COMMAND; // M-X
    m[219] = ED_SEQUENCE_LEAD_IN; // M-[
    m[226] = ED_PREV_WORD; // M-b
    m[227] = EM_CAPITOL_CASE; // M-c
    m[228] = EM_DELETE_NEXT_WORD; // M-d
    m[230] = EM_NEXT_WORD; // M-f
    m[236] = EM_LOWER_CASE; // M-l
    m[238] = ED_SEARCH_NEXT_HISTORY; // M-n
    m[240] = ED_SEARCH_PREV_HISTORY; // M-p
    m[245] = EM_UPPER_CASE; // M-u
    m[247] = EM_COPY_REGION; // M-w
    m[248] = ED_COMMAND; // M-x
    m[255] = ED_DELETE_PREV_WORD; // M-^?
    m
};

/// `el_map_vi_insert` (KSHVI) from map.c.
pub static VI_INSERT_MAP: [u8; N_KEYS] = {
    let mut m = [ED_INSERT; N_KEYS];
    m[0] = ED_UNASSIGNED;
    m[3] = ED_INSERT;
    m[4] = VI_LIST_OR_EOF;
    m[8] = VI_DELETE_PREV_CHAR; // ^H backspace
    m[10] = ED_NEWLINE;
    m[13] = ED_NEWLINE;
    m[17] = ED_IGNORE;
    m[19] = ED_IGNORE;
    m[21] = VI_KILL_LINE_PREV; // ^U
    m[22] = ED_QUOTED_INSERT; // ^V
    m[23] = ED_DELETE_PREV_WORD; // ^W
    m[27] = VI_COMMAND_MODE; // ESC
    m[28] = ED_IGNORE;
    m[127] = VI_DELETE_PREV_CHAR;
    m
};

/// `el_map_vi_command` from map.c.
pub static VI_COMMAND_MAP: [u8; N_KEYS] = {
    let mut m = [ED_UNASSIGNED; N_KEYS];
    m[1] = ED_MOVE_TO_BEG;
    m[3] = ED_IGNORE;
    m[5] = ED_MOVE_TO_END;
    m[8] = ED_DELETE_PREV_CHAR;
    m[10] = ED_NEWLINE;
    m[11] = ED_KILL_LINE;
    m[12] = ED_CLEAR_SCREEN;
    m[13] = ED_NEWLINE;
    m[14] = ED_NEXT_HISTORY;
    m[15] = ED_IGNORE;
    m[16] = ED_PREV_HISTORY;
    m[17] = ED_IGNORE;
    m[18] = ED_REDISPLAY;
    m[19] = ED_IGNORE;
    m[21] = VI_KILL_LINE_PREV;
    m[23] = ED_DELETE_PREV_WORD;
    m[27] = EM_META_NEXT;
    m[28] = ED_IGNORE;
    m[32] = ED_NEXT_CHAR;
    m[35] = VI_COMMENT_OUT;
    m[36] = ED_MOVE_TO_END;
    m[37] = VI_MATCH;
    m[43] = ED_NEXT_HISTORY;
    m[44] = VI_REPEAT_PREV_CHAR;
    m[45] = ED_PREV_HISTORY;
    m[46] = VI_REDO;
    m[47] = VI_SEARCH_PREV;
    m[48] = VI_ZERO;
    let mut i = 49;
    while i <= 57 {
        m[i] = ED_ARGUMENT_DIGIT;
        i += 1;
    }
    m[58] = ED_COMMAND;
    m[59] = VI_REPEAT_NEXT_CHAR;
    m[63] = VI_SEARCH_NEXT;
    m[64] = VI_ALIAS;
    m[65] = VI_ADD_AT_EOL;
    m[66] = VI_PREV_BIG_WORD;
    m[67] = VI_CHANGE_TO_EOL;
    m[68] = ED_KILL_LINE;
    m[69] = VI_END_BIG_WORD;
    m[70] = VI_PREV_CHAR;
    m[71] = VI_TO_HISTORY_LINE;
    m[73] = VI_INSERT_AT_BOL;
    m[74] = ED_SEARCH_NEXT_HISTORY;
    m[75] = ED_SEARCH_PREV_HISTORY;
    m[78] = VI_REPEAT_SEARCH_PREV;
    m[79] = ED_SEQUENCE_LEAD_IN;
    m[80] = VI_PASTE_PREV;
    m[82] = VI_REPLACE_MODE;
    m[83] = VI_SUBSTITUTE_LINE;
    m[84] = VI_TO_PREV_CHAR;
    m[85] = VI_UNDO_LINE;
    m[87] = VI_NEXT_BIG_WORD;
    m[88] = ED_DELETE_PREV_CHAR;
    m[89] = VI_YANK_END;
    m[91] = ED_SEQUENCE_LEAD_IN;
    m[94] = ED_MOVE_TO_BEG;
    m[95] = VI_HISTORY_WORD;
    m[97] = VI_ADD;
    m[98] = VI_PREV_WORD;
    m[99] = VI_CHANGE_META;
    m[100] = VI_DELETE_META;
    m[101] = VI_END_WORD;
    m[102] = VI_NEXT_CHAR;
    m[104] = ED_PREV_CHAR;
    m[105] = VI_INSERT;
    m[106] = ED_NEXT_HISTORY;
    m[107] = ED_PREV_HISTORY;
    m[108] = ED_NEXT_CHAR;
    m[110] = VI_REPEAT_SEARCH_NEXT;
    m[112] = VI_PASTE_NEXT;
    m[114] = VI_REPLACE_CHAR;
    m[115] = VI_SUBSTITUTE_CHAR;
    m[116] = VI_TO_NEXT_CHAR;
    m[117] = VI_UNDO;
    m[118] = VI_HISTEDIT;
    m[119] = VI_NEXT_WORD;
    m[120] = ED_DELETE_NEXT_CHAR;
    m[121] = VI_YANK;
    m[124] = VI_TO_COLUMN;
    m[126] = VI_CHANGE_CASE;
    m[127] = ED_DELETE_PREV_CHAR;
    m[207] = ED_SEQUENCE_LEAD_IN; // M-O
    m[219] = ED_SEQUENCE_LEAD_IN; // M-[
    m
};

/// The `help.h` table: (function id, name, description) — used by
/// `map_print_key`, `bind -l`, `parse_cmd`.  Order matches `help.h` exactly
/// (the table is searched linearly and first match wins).
pub static HELP: [(u8, &str, &str); EL_NUM_FCNS] = [
    (
        VI_PASTE_NEXT,
        "vi-paste-next",
        "Vi paste previous deletion to the right of the cursor",
    ),
    (
        VI_PASTE_PREV,
        "vi-paste-prev",
        "Vi paste previous deletion to the left of the cursor",
    ),
    (
        VI_PREV_BIG_WORD,
        "vi-prev-big-word",
        "Vi move to the previous space delimited word",
    ),
    (VI_PREV_WORD, "vi-prev-word", "Vi move to the previous word"),
    (
        VI_NEXT_BIG_WORD,
        "vi-next-big-word",
        "Vi move to the next space delimited word",
    ),
    (VI_NEXT_WORD, "vi-next-word", "Vi move to the next word"),
    (
        VI_CHANGE_CASE,
        "vi-change-case",
        "Vi change case of character under the cursor and advance one character",
    ),
    (VI_CHANGE_META, "vi-change-meta", "Vi change prefix command"),
    (
        VI_INSERT_AT_BOL,
        "vi-insert-at-bol",
        "Vi enter insert mode at the beginning of line",
    ),
    (
        VI_REPLACE_CHAR,
        "vi-replace-char",
        "Vi replace character under the cursor with the next character typed",
    ),
    (VI_REPLACE_MODE, "vi-replace-mode", "Vi enter replace mode"),
    (
        VI_SUBSTITUTE_CHAR,
        "vi-substitute-char",
        "Vi replace character under the cursor and enter insert mode",
    ),
    (
        VI_SUBSTITUTE_LINE,
        "vi-substitute-line",
        "Vi substitute entire line",
    ),
    (
        VI_CHANGE_TO_EOL,
        "vi-change-to-eol",
        "Vi change to end of line",
    ),
    (VI_INSERT, "vi-insert", "Vi enter insert mode"),
    (VI_ADD, "vi-add", "Vi enter insert mode after the cursor"),
    (
        VI_ADD_AT_EOL,
        "vi-add-at-eol",
        "Vi enter insert mode at end of line",
    ),
    (VI_DELETE_META, "vi-delete-meta", "Vi delete prefix command"),
    (
        VI_END_BIG_WORD,
        "vi-end-big-word",
        "Vi move to the end of the current space delimited word",
    ),
    (
        VI_END_WORD,
        "vi-end-word",
        "Vi move to the end of the current word",
    ),
    (VI_UNDO, "vi-undo", "Vi undo last change"),
    (
        VI_COMMAND_MODE,
        "vi-command-mode",
        "Vi enter command mode (use alternative key bindings)",
    ),
    (VI_ZERO, "vi-zero", "Vi move to the beginning of line"),
    (
        VI_DELETE_PREV_CHAR,
        "vi-delete-prev-char",
        "Vi move to previous character (backspace)",
    ),
    (
        VI_LIST_OR_EOF,
        "vi-list-or-eof",
        "Vi list choices for completion or indicate end of file if empty line",
    ),
    (
        VI_KILL_LINE_PREV,
        "vi-kill-line-prev",
        "Vi cut from beginning of line to cursor",
    ),
    (
        VI_SEARCH_PREV,
        "vi-search-prev",
        "Vi search history previous",
    ),
    (VI_SEARCH_NEXT, "vi-search-next", "Vi search history next"),
    (
        VI_REPEAT_SEARCH_NEXT,
        "vi-repeat-search-next",
        "Vi repeat current search in the same search direction",
    ),
    (
        VI_REPEAT_SEARCH_PREV,
        "vi-repeat-search-prev",
        "Vi repeat current search in the opposite search direction",
    ),
    (
        VI_NEXT_CHAR,
        "vi-next-char",
        "Vi move to the character specified next",
    ),
    (
        VI_PREV_CHAR,
        "vi-prev-char",
        "Vi move to the character specified previous",
    ),
    (
        VI_TO_NEXT_CHAR,
        "vi-to-next-char",
        "Vi move up to the character specified next",
    ),
    (
        VI_TO_PREV_CHAR,
        "vi-to-prev-char",
        "Vi move up to the character specified previous",
    ),
    (
        VI_REPEAT_NEXT_CHAR,
        "vi-repeat-next-char",
        "Vi repeat current character search in the same search direction",
    ),
    (
        VI_REPEAT_PREV_CHAR,
        "vi-repeat-prev-char",
        "Vi repeat current character search in the opposite search direction",
    ),
    (VI_MATCH, "vi-match", "Vi go to matching () {} or []"),
    (VI_UNDO_LINE, "vi-undo-line", "Vi undo all changes to line"),
    (VI_TO_COLUMN, "vi-to-column", "Vi go to specified column"),
    (VI_YANK_END, "vi-yank-end", "Vi yank to end of line"),
    (VI_YANK, "vi-yank", "Vi yank"),
    (
        VI_COMMENT_OUT,
        "vi-comment-out",
        "Vi comment out current command",
    ),
    (VI_ALIAS, "vi-alias", "Vi include shell alias"),
    (
        VI_TO_HISTORY_LINE,
        "vi-to-history-line",
        "Vi go to specified history file line.",
    ),
    (VI_HISTEDIT, "vi-histedit", "Vi edit history line with vi"),
    (
        VI_HISTORY_WORD,
        "vi-history-word",
        "Vi append word from previous input line",
    ),
    (VI_REDO, "vi-redo", "Vi redo last non-motion command"),
    (
        EM_DELETE_OR_LIST,
        "em-delete-or-list",
        "Delete character under cursor or list completions if at end of line",
    ),
    (
        EM_DELETE_NEXT_WORD,
        "em-delete-next-word",
        "Cut from cursor to end of current word",
    ),
    (EM_YANK, "em-yank", "Paste cut buffer at cursor position"),
    (
        EM_KILL_LINE,
        "em-kill-line",
        "Cut the entire line and save in cut buffer",
    ),
    (
        EM_KILL_REGION,
        "em-kill-region",
        "Cut area between mark and cursor and save in cut buffer",
    ),
    (
        EM_COPY_REGION,
        "em-copy-region",
        "Copy area between mark and cursor to cut buffer",
    ),
    (
        EM_GOSMACS_TRANSPOSE,
        "em-gosmacs-transpose",
        "Exchange the two characters before the cursor",
    ),
    (
        EM_NEXT_WORD,
        "em-next-word",
        "Move next to end of current word",
    ),
    (
        EM_UPPER_CASE,
        "em-upper-case",
        "Uppercase the characters from cursor to end of current word",
    ),
    (
        EM_CAPITOL_CASE,
        "em-capitol-case",
        "Capitalize the characters from cursor to end of current word",
    ),
    (
        EM_LOWER_CASE,
        "em-lower-case",
        "Lowercase the characters from cursor to end of current word",
    ),
    (EM_SET_MARK, "em-set-mark", "Set the mark at cursor"),
    (
        EM_EXCHANGE_MARK,
        "em-exchange-mark",
        "Exchange the cursor and mark",
    ),
    (
        EM_UNIVERSAL_ARGUMENT,
        "em-universal-argument",
        "Universal argument (argument times 4)",
    ),
    (
        EM_META_NEXT,
        "em-meta-next",
        "Add 8th bit to next character typed",
    ),
    (
        EM_TOGGLE_OVERWRITE,
        "em-toggle-overwrite",
        "Switch from insert to overwrite mode or vice versa",
    ),
    (
        EM_COPY_PREV_WORD,
        "em-copy-prev-word",
        "Copy current word to cursor",
    ),
    (
        EM_INC_SEARCH_NEXT,
        "em-inc-search-next",
        "Emacs incremental next search",
    ),
    (
        EM_INC_SEARCH_PREV,
        "em-inc-search-prev",
        "Emacs incremental reverse search",
    ),
    (
        EM_DELETE_PREV_CHAR,
        "em-delete-prev-char",
        "Delete the character to the left of the cursor",
    ),
    (ED_END_OF_FILE, "ed-end-of-file", "Indicate end of file"),
    (ED_INSERT, "ed-insert", "Add character to the line"),
    (
        ED_DELETE_PREV_WORD,
        "ed-delete-prev-word",
        "Delete from beginning of current word to cursor",
    ),
    (
        ED_DELETE_NEXT_CHAR,
        "ed-delete-next-char",
        "Delete character under cursor",
    ),
    (ED_KILL_LINE, "ed-kill-line", "Cut to the end of line"),
    (
        ED_MOVE_TO_END,
        "ed-move-to-end",
        "Move cursor to the end of line",
    ),
    (
        ED_MOVE_TO_BEG,
        "ed-move-to-beg",
        "Move cursor to the beginning of line",
    ),
    (
        ED_TRANSPOSE_CHARS,
        "ed-transpose-chars",
        "Exchange the character to the left of the cursor with the one under it",
    ),
    (
        ED_NEXT_CHAR,
        "ed-next-char",
        "Move to the right one character",
    ),
    (
        ED_PREV_WORD,
        "ed-prev-word",
        "Move to the beginning of the current word",
    ),
    (
        ED_PREV_CHAR,
        "ed-prev-char",
        "Move to the left one character",
    ),
    (
        ED_QUOTED_INSERT,
        "ed-quoted-insert",
        "Add the next character typed verbatim",
    ),
    (ED_DIGIT, "ed-digit", "Adds to argument or enters a digit"),
    (
        ED_ARGUMENT_DIGIT,
        "ed-argument-digit",
        "Digit that starts argument",
    ),
    (
        ED_UNASSIGNED,
        "ed-unassigned",
        "Indicates unbound character",
    ),
    (
        ED_IGNORE,
        "ed-ignore",
        "Input characters that have no effect",
    ),
    (ED_NEWLINE, "ed-newline", "Execute command"),
    (
        ED_DELETE_PREV_CHAR,
        "ed-delete-prev-char",
        "Delete the character to the left of the cursor",
    ),
    (
        ED_CLEAR_SCREEN,
        "ed-clear-screen",
        "Clear screen leaving current line at the top",
    ),
    (ED_REDISPLAY, "ed-redisplay", "Redisplay everything"),
    (
        ED_START_OVER,
        "ed-start-over",
        "Erase current line and start from scratch",
    ),
    (
        ED_SEQUENCE_LEAD_IN,
        "ed-sequence-lead-in",
        "First character in a bound sequence",
    ),
    (
        ED_PREV_HISTORY,
        "ed-prev-history",
        "Move to the previous history line",
    ),
    (
        ED_NEXT_HISTORY,
        "ed-next-history",
        "Move to the next history line",
    ),
    (
        ED_SEARCH_PREV_HISTORY,
        "ed-search-prev-history",
        "Search previous in history for a line matching the current",
    ),
    (
        ED_SEARCH_NEXT_HISTORY,
        "ed-search-next-history",
        "Search next in history for a line matching the current",
    ),
    (ED_PREV_LINE, "ed-prev-line", "Move up one line"),
    (ED_NEXT_LINE, "ed-next-line", "Move down one line"),
    (ED_COMMAND, "ed-command", "Editline extended command"),
];
