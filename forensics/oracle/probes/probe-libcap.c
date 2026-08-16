/* probe-libcap.c — forensic C probe for the libcap conservation module
 * (§37 C probe courts).  Compiles against the pinned oracle libcap and
 * prints deterministic observations of the library surface: text
 * round-trips, name lookups, flag ops, compare, external format bytes,
 * error cases.  The Rust side mirrors this probe via compat::libcap.
 *
 * Build:   gcc -I/opt/dep/include -o probe-libcap probe-libcap.c \
 *              -L/opt/dep/lib64 -lcap
 * Run:     ./probe-libcap
 */
#include <sys/capability.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>

static void p_text(const char *txt) {
    cap_t c = cap_from_text(txt);
    if (!c) {
        printf("from_text(%s) -> NULL errno=%d\n", txt, errno);
        return;
    }
    ssize_t len = -1;
    char *out = cap_to_text(c, &len);
    printf("from_text(%s) -> [%s] len=%ld\n", txt, out ? out : "(null)", (long)len);
    cap_free(out);
    cap_free(c);
}

static void p_name(const char *name) {
    cap_value_t v = -1;
    int r = cap_from_name(name, &v);
    printf("cap_from_name(%s) -> %d v=%d\n", name, r, v);
}

static void dump_ext(cap_t c) {
    ssize_t sz = cap_size(c);
    printf("cap_size = %ld\n", (long)sz);
    unsigned char buf[128];
    memset(buf, 0, sizeof(buf));
    ssize_t n = cap_copy_ext(buf, c, sizeof(buf));
    printf("cap_copy_ext -> %ld bytes:", (long)n);
    for (ssize_t i = 0; i < n && i < 32; i++) {
        printf(" %02x", buf[i]);
    }
    printf("\n");
}

int main(void) {
    printf("cap_max_bits = %d\n", cap_max_bits());

    /* text grammar */
    p_text("cap_kill=ep");
    p_text("cap_kill=ep cap_net_bind_service+i");
    p_text("=ep");
    p_text("all=eip");
    p_text("=ep cap_net_raw+p");
    p_text("cap_chown,cap_net_bind_service+eip");
    p_text("5=ep");            /* numeric cap in text */
    p_text("cap_kill=ep cap_kill+ip");
    p_text("cap_kill=ep cap_kill-i");
    p_text("=eip cap_kill-e");
    p_text("cap_kill+ep");     /* no preceding = */
    p_text("= cap_kill+ep");   /* blank = then add */
    p_text("!cap_kill");       /* invalid op */
    p_text("cap_kill=");       /* clear a cap */
    p_text("cap_kill= cap_net_raw+ep");
    p_text("cap_kill+");       /* op without flags */
    p_text("=ep ");
    p_text("cap_unknownname+ep");
    p_text("cap_kill==ep");    /* double op */
    p_text("cap_kill=eip,");   /* trailing comma */
    p_text("41+ep");           /* unnamed numeric cap */
    p_text("cap_kill=ep,");    /* trailing comma after name */

    /* names */
    p_name("chown");
    p_name("cap_chown");
    p_name("CAP_CHOWN");
    p_name("ChOwN");
    p_name("12");
    p_name("0x2");
    p_name("kill");
    p_name("cap_kill");
    p_name("nonsense");
    p_name("41");
    p_name("64");
    p_name("chownx");
    p_name("chow");

    printf("cap_to_name(0) = %s\n", cap_to_name(0));
    printf("cap_to_name(12) = %s\n", cap_to_name(12));
    printf("cap_to_name(41) = %s\n", cap_to_name(41));
    printf("cap_to_name(64) = %s\n", cap_to_name(64));
    printf("cap_to_name(-1) = %s\n", cap_to_name(-1));

    /* flag ops + compare */
    cap_t a = cap_init();
    cap_t b = cap_init();
    cap_value_t caps[] = { CAP_CHOWN, CAP_NET_BIND_SERVICE };
    printf("cap_compare(empty,empty) = %d\n", cap_compare(a, b));
    cap_set_flag(a, CAP_EFFECTIVE, 2, caps, CAP_SET);
    printf("cap_compare(a,a) = %d\n", cap_compare(a, a));
    printf("cap_compare(a,b) = %d\n", cap_compare(a, b));
    cap_set_flag(b, CAP_EFFECTIVE, 2, caps, CAP_SET);
    cap_set_flag(b, CAP_PERMITTED, 1, caps, CAP_SET);
    printf("cap_compare(a,b) = %d\n", cap_compare(a, b));
    cap_flag_value_t v;
    cap_get_flag(a, CAP_CHOWN, CAP_EFFECTIVE, &v);
    printf("get_flag(chown,eff) = %d\n", v);
    cap_get_flag(a, CAP_CHOWN, CAP_PERMITTED, &v);
    printf("get_flag(chown,perm) = %d\n", v);
    /* out-of-range cap in set_flag is skipped (no error) */
    int bad = cap_set_flag(a, CAP_EFFECTIVE, 1, (cap_value_t[]){ 500 }, CAP_SET);
    printf("set_flag(500) ret = %d\n", bad);
    int r = cap_set_flag(a, CAP_EFFECTIVE, 0, caps, CAP_SET);
    printf("set_flag(0 values) ret = %d errno=%d\n", r, errno);
    /* clear */
    cap_clear(a);
    printf("after clear, get_flag(chown,eff) = %d\n", (cap_get_flag(a, CAP_CHOWN, CAP_EFFECTIVE, &v), v));
    /* fill */
    cap_t c = cap_init();
    cap_fill_flag(c, CAP_EFFECTIVE, b, CAP_PERMITTED);
    cap_get_flag(c, CAP_CHOWN, CAP_EFFECTIVE, &v);
    printf("fill_flag(perm->eff) chown = %d\n", v);
    cap_fill(c, CAP_INHERITABLE, CAP_EFFECTIVE);
    cap_get_flag(c, CAP_CHOWN, CAP_INHERITABLE, &v);
    printf("fill(inh<-eff) chown = %d\n", v);
    cap_free(c);

    /* external format */
    cap_t e = cap_init();
    cap_set_flag(e, CAP_EFFECTIVE, 2, caps, CAP_SET);
    dump_ext(e);
    cap_clear(e);
    dump_ext(e);  /* all-clear: minimum size 8 */
    cap_set_flag(e, CAP_PERMITTED, 1, (cap_value_t[]){ 63 }, CAP_SET);
    dump_ext(e);
    cap_free(e);

    /* external round-trip */
    cap_t f = cap_init();
    cap_set_flag(f, CAP_EFFECTIVE, 1, caps, CAP_SET);
    cap_set_flag(f, CAP_INHERITABLE, 1, caps, CAP_SET);
    unsigned char ext[64];
    memset(ext, 0, sizeof(ext));
    cap_copy_ext(ext, f, sizeof(ext));
    cap_t g = cap_copy_int(ext);
    printf("copy_int compare = %d\n", cap_compare(f, g));
    cap_free(g);
    /* bad magic */
    ext[0] ^= 0xff;
    errno = 0;
    g = cap_copy_int(ext);
    printf("copy_int badmagic -> %s errno=%d\n", g ? "OK?!" : "NULL", errno);
    cap_free(g);
    /* short buffer copy_ext */
    errno = 0;
    unsigned char tiny[4];
    memset(tiny, 0, sizeof(tiny));
    ssize_t ssz = cap_copy_ext(tiny, f, sizeof(tiny));
    printf("copy_ext too small -> %ld errno=%d\n", (long)ssz, errno);
    cap_free(f);

    /* iab text */
    cap_iab_t iab = cap_iab_init();
    printf("iab init to_text = [%s]\n", cap_iab_to_text(iab));
    cap_iab_set_vector(iab, CAP_IAB_INH, CAP_CHOWN, CAP_SET);
    printf("iab inh chown to_text = [%s]\n", cap_iab_to_text(iab));
    cap_iab_set_vector(iab, CAP_IAB_AMB, CAP_NET_RAW, CAP_SET);
    printf("iab amb net_raw to_text = [%s]\n", cap_iab_to_text(iab));
    cap_iab_set_vector(iab, CAP_IAB_BOUND, CAP_SYS_ADMIN, CAP_SET);
    printf("iab bound sys_admin to_text = [%s]\n", cap_iab_to_text(iab));
    cap_free(iab);
    cap_iab_t iab2 = cap_iab_from_text("^cap_chown cap_kill !cap_net_raw");
    printf("iab from_text -> [%s]\n", iab2 ? cap_iab_to_text(iab2) : "(null)");
    cap_free(iab2);

    /* modes + secbits (read-only observations) */
    printf("cap_get_mode = %u\n", cap_get_mode());
    printf("cap_mode_name(0..4) = %s %s %s %s %s\n",
           cap_mode_name(0), cap_mode_name(1), cap_mode_name(2),
           cap_mode_name(3), cap_mode_name(4));
    printf("cap_get_secbits = %u\n", cap_get_secbits());

    cap_free(a);
    cap_free(b);
    return 0;
}
