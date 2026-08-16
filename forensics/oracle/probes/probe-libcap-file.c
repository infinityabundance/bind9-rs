/* probe-libcap-file.c — file-capability surface (§38 four-corner courts,
 * CAP-FILE-*).  Exercises cap_set_file/cap_get_file and the
 * security.capability xattr bytes in a container that holds CAP_SETFCAP.
 *
 * Four-corner protocol: the C probe and the Rust mirror run in the same
 * container on the same /tmp directory:
 *   - each side writes its own file (cap-set) and reads the OTHER side's
 *     file (cross-read), printing the parsed state and the raw xattr hex.
 *
 * Build:   gcc -I/opt/dep/include -o probe-libcap-file probe-libcap-file.c \
 *              -L/opt/dep/lib64 -lcap
 * Usage:   probe-libcap-file <self-file> <other-file>
 */
#include <sys/capability.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/xattr.h>

static void dump_state(cap_t c) {
    if (!c) { printf("  (null)\n"); return; }
    cap_flag_value_t v;
    printf("  ");
    for (int i = 0; i < 64; i++) {
        int any = 0;
        for (int f = 0; f < 3; f++) {
            if (cap_get_flag(c, i, (cap_flag_t)f, &v) == 0 && v == CAP_SET) any = 1;
        }
        if (any) {
            printf("%s", cap_to_name(i));
            if (cap_get_flag(c, i, CAP_EFFECTIVE, &v) == 0 && v == CAP_SET) printf("e");
            if (cap_get_flag(c, i, CAP_PERMITTED, &v) == 0 && v == CAP_SET) printf("p");
            if (cap_get_flag(c, i, CAP_INHERITABLE, &v) == 0 && v == CAP_SET) printf("i");
            printf(" ");
        }
    }
    printf("(rootid=%u)\n", cap_get_nsowner(c));
    cap_free(c);
}

static void dump_xattr(const char *path) {
    unsigned char buf[64];
    ssize_t n = getxattr(path, "security.capability", buf, sizeof(buf));
    if (n < 0) { printf("  xattr: (error %d)\n", errno); return; }
    printf("  xattr(%ld):", (long)n);
    for (ssize_t i = 0; i < n; i++) printf(" %02x", buf[i]);
    printf("\n");
}

int main(int argc, char **argv) {
    if (argc < 3) { fprintf(stderr, "usage: %s <self> <other>\n", argv[0]); return 2; }
    const char *self = argv[1];
    const char *other = argv[2];

    /* the files must exist (cap_set_file opens O_PATH|O_NOFOLLOW) */
    int fd = open(self, O_CREAT|O_WRONLY, 0644);
    if (fd < 0) { perror("open self"); return 1; }
    close(fd);
    fd = open(other, O_CREAT|O_WRONLY, 0644);
    if (fd < 0) { perror("open other"); return 1; }
    close(fd);

    /* write our own file: net_bind_service in permitted+effective */
    cap_t c = cap_init();
    cap_value_t caps[] = { CAP_NET_BIND_SERVICE };
    cap_set_flag(c, CAP_PERMITTED, 1, caps, CAP_SET);
    cap_set_flag(c, CAP_EFFECTIVE, 1, caps, CAP_SET);
    int r = cap_set_file(self, c);
    printf("cap_set_file(self) = %d\n", r);
    dump_state(cap_get_file(self));
    dump_xattr(self);
    cap_free(c);

    /* cross-read the OTHER side's file */
    printf("cross-read:\n");
    dump_state(cap_get_file(other));
    dump_xattr(other);

    /* a symlink must be rejected (fresh cap_t: c was freed above) */
    if (symlink(self, "/tmp/fcap-link") == 0) {
        cap_t linkcap = cap_init();
        cap_set_flag(linkcap, CAP_PERMITTED, 1, caps, CAP_SET);
        errno = 0;
        r = cap_set_file("/tmp/fcap-link", linkcap);
        printf("cap_set_file(symlink) = %d errno=%d\n", r, errno);
        cap_free(linkcap);
        unlink("/tmp/fcap-link");
    }

    /* remove caps */
    r = cap_set_file(self, NULL);
    printf("cap_set_file(self,NULL) = %d\n", r);
    dump_xattr(self);

    /* rootid (v3) form */
    c = cap_init();
    cap_set_flag(c, CAP_PERMITTED, 1, caps, CAP_SET);
    cap_set_nsowner(c, 1000);
    r = cap_set_file(self, c);
    printf("cap_set_file(v3 rootid) = %d\n", r);
    dump_state(cap_get_file(self));
    dump_xattr(self);
    cap_free(c);
    return 0;
}
