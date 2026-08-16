/* probe-libcap-proc.c — process-observable libcap surface (§37, CAP-PROC
 * courts).  Prints cap_get_proc/cap_get_pid, cap_get_bound, cap_get_mode,
 * cap_get_secbits, cap_iab_get_proc for the *current* process.  Must be run
 * in the SAME environment as the Rust mirror (same container → same kernel
 * state) so the outputs are comparable.
 *
 * Build:   gcc -I/opt/dep/include -o probe-libcap-proc probe-libcap-proc.c \
 *              -L/opt/dep/lib64 -lcap
 */
#include <sys/capability.h>
#include <stdio.h>
#include <stdlib.h>

static void dump_cap(cap_t c) {
    cap_flag_value_t v;
    for (int i = 0; i < 64; i++) {
        int any = 0;
        for (int f = 0; f < 3; f++) {
            if (cap_get_flag(c, i, (cap_flag_t)f, &v) == 0 && v == CAP_SET) {
                any = 1;
            }
        }
        if (any) {
            printf("cap%d", i);
            if (cap_get_flag(c, i, CAP_EFFECTIVE, &v) == 0 && v == CAP_SET) printf("e");
            if (cap_get_flag(c, i, CAP_PERMITTED, &v) == 0 && v == CAP_SET) printf("p");
            if (cap_get_flag(c, i, CAP_INHERITABLE, &v) == 0 && v == CAP_SET) printf("i");
            printf(" ");
        }
    }
    printf("\n");
}

int main(void) {
    cap_t c = cap_get_proc();
    if (!c) { perror("cap_get_proc"); return 1; }
    printf("cap_get_proc: ");
    dump_cap(c);
    cap_free(c);

    printf("cap_get_bound:");
    for (int i = 0; i < 64; i++) {
        int r = cap_get_bound(i);
        if (r < 0) break;
        printf(" %d=%d", i, r);
    }
    printf("\n");

    printf("cap_get_ambient:");
    for (int i = 0; i < 64; i++) {
        int r = cap_get_ambient(i);
        if (r < 0) break;
        printf(" %d=%d", i, r);
    }
    printf("\n");

    printf("cap_get_mode = %u\n", cap_get_mode());
    printf("cap_get_secbits = %u\n", cap_get_secbits());
    printf("cap_max_bits = %d\n", cap_max_bits());

    cap_iab_t iab = cap_iab_get_proc();
    printf("cap_iab_get_proc = [%s]\n", iab ? cap_iab_to_text(iab) : "(null)");
    cap_free(iab);
    return 0;
}
