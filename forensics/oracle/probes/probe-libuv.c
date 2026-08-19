/*
 * probe-libuv.c — the libuv 1.52.1 oracle probe (court LIBUV-0001).
 *
 * A deterministic, single-threaded op sequence (plus one helper thread for
 * the async-wakeup and barrier phases) over the surface BIND 9.20's
 * netmgr/isc depends on.
 *
 * Transcript determinism contract (the Rust mirror must reproduce the
 * stdout byte-for-byte in the SAME oracle-libuv-1.52.1 container):
 *  - only logical events, byte contents, sizes and error name/strerror
 *    pairs are printed; never wall-clock values, kernel-assigned ports,
 *    fds, pointers, pids or thread ids;
 *  - every address is the loopback literal 127.0.0.1; kernel-assigned
 *    ports are consumed internally and never printed;
 *  - libuv's genuinely-specified orderings are courted directly: the
 *    timer heap order (timeout, then start_id), the once-per-iteration
 *    idle/prepare/check sequence (idle before prepare in 1.52.1), the
 *    pending immediate-callback pass after the poll round, close_cb LIFO
 *    order, the handle walk order, async coalescing, one signal callback
 *    per raised signal, and the send-before-receive iteration boundary;
 *  - TCP stream reads are accumulated (the kernel may deliver a stream in
 *    arbitrary chunk sizes); the transcript prints the cumulative totals;
 *  - I/O phases are split into separate uv_run calls so each run's event
 *    set is ordered; the one genuinely unspecified intra-round order (the
 *    TCP connect_cb vs accept_cb of two different fds in one epoll round)
 *    is printed in a fixed documented order after the run;
 *  - a reusable silent stop timer bounds each run (uv_stop from its
 *    callback); loopback I/O completes in microseconds, far before it;
 *  - the helper thread prints nothing; the main thread joins it and
 *    prints the recorded results, so the transcript order is fixed.
 */

#include <uv.h>
#include <pthread.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* ------------------------------------------------------------------ */
/* transcript helpers                                                 */
/* ------------------------------------------------------------------ */

/* A 0 status is success, not a libuv error name. */
static const char *SNAME(int st) {
    return st == 0 ? "0" : uv_err_name(st);
}

static void PERR(const char *tag, int rc) {
    printf("%s rc=%s (%s)\n", tag, uv_err_name(rc), uv_strerror(rc));
}

/* ------------------------------------------------------------------ */
/* shared: the silent stop timer                                      */
/* ------------------------------------------------------------------ */

static uv_timer_t stop_t;

static void stop_cb(uv_timer_t *h) { (void) h; uv_stop(h->loop); }

static void arm_stop(uv_loop_t *loop) {
    uv_timer_init(loop, &stop_t);
    uv_timer_start(&stop_t, stop_cb, 30, 0);
}

/* ------------------------------------------------------------------ */
/* phase 2: timers                                                    */
/* ------------------------------------------------------------------ */

static uv_timer_t t1, t2, t3, rep, stopper, ta, tb, t8, t10, t11;

static void cb_t1(uv_timer_t *h) { (void) h; printf("    t1 fired (due 50)\n"); }
static void cb_t2(uv_timer_t *h) { (void) h; printf("    t2 fired (due 10)\n"); }
static void cb_t3(uv_timer_t *h) { (void) h; printf("    t3 fired (due 10)\n"); }

static int rep_count = 0;
static void cb_rep(uv_timer_t *h) {
    (void) h;
    rep_count++;
    printf("    repeat fired (%d)\n", rep_count);
}
static void cb_stopper(uv_timer_t *h) {
    (void) h;
    printf("    stopper fired; stopping repeat\n");
    uv_timer_stop(&rep);
}

static void cb_ta(uv_timer_t *h); /* fwd */
static void cb_tb(uv_timer_t *h); /* fwd */
static void cb_ta(uv_timer_t *h) {
    (void) h;
    printf("    a fired (starting b with 5ms)\n");
    uv_timer_start(&tb, cb_tb, 5, 0);
}
static void cb_tb(uv_timer_t *h) { (void) h; printf("    b fired (5ms after a)\n"); }
static int t8_count = 0;
static void cb_t8(uv_timer_t *h) {
    (void) h;
    t8_count++;
    printf("    t8 fired (%d); uv_timer_again -> no repeat, no re-arm\n", t8_count);
    uv_timer_again(h);
}
static void cb_never(uv_timer_t *h) { (void) h; printf("    UNEXPECTED timer fire\n"); }

static void phase2_timers(uv_loop_t *loop) {
    printf("=== PHASE 2: timers ===\n");
    uv_timer_init(loop, &t1);
    uv_timer_init(loop, &t2);
    uv_timer_init(loop, &t3);
    uv_timer_start(&t1, cb_t1, 50, 0);
    uv_timer_start(&t2, cb_t2, 10, 0);
    uv_timer_start(&t3, cb_t3, 10, 0);
    /* NULL callback -> UV_EINVAL (the check runs before uv_timer_stop) */
    PERR("  uv_timer_start(NULL cb)", uv_timer_start(&t1, NULL, 10, 0));
    printf("  uv_run(DEFAULT) returned %d\n", uv_run(loop, UV_RUN_DEFAULT));

    /* repeat timer with a stopper; repeat re-arms BEFORE the callback */
    uv_timer_init(loop, &rep);
    uv_timer_init(loop, &stopper);
    rep_count = 0;
    uv_timer_start(&rep, cb_rep, 10, 10);
    uv_timer_start(&stopper, cb_stopper, 45, 0);
    printf("  uv_timer_get_repeat(rep)=%llu\n",
           (unsigned long long) uv_timer_get_repeat(&rep));
    printf("  uv_run(DEFAULT) returned %d\n", uv_run(loop, UV_RUN_DEFAULT));

    /* restart a timer from another timer's callback */
    uv_timer_init(loop, &ta);
    uv_timer_init(loop, &tb);
    uv_timer_start(&ta, cb_ta, 30, 0);
    printf("  uv_run(DEFAULT) returned %d\n", uv_run(loop, UV_RUN_DEFAULT));

    /* uv_timer_again on a one-shot: no repeat -> fires once */
    uv_timer_init(loop, &t8);
    t8_count = 0;
    uv_timer_start(&t8, cb_t8, 10, 0);
    printf("  uv_run(DEFAULT) returned %d\n", uv_run(loop, UV_RUN_DEFAULT));

    /* stop an inactive timer -> 0; a started-then-stopped timer and a
     * closed timer never fire */
    printf("  uv_timer_stop(inactive)=%d\n", uv_timer_stop(&t8));
    uv_timer_init(loop, &t10);
    uv_timer_start(&t10, cb_never, 10, 0);
    uv_timer_stop(&t10);
    uv_timer_init(loop, &t11);
    uv_timer_start(&t11, cb_never, 10, 0);
    uv_close((uv_handle_t *) &t11, NULL);
    printf("  uv_run(DEFAULT) returned %d (stopped/closed timers never fired)\n",
           uv_run(loop, UV_RUN_DEFAULT));
}

/* ------------------------------------------------------------------ */
/* phase 3: idle/prepare/check ordering                               */
/* ------------------------------------------------------------------ */

static uv_idle_t id1, id2;
static uv_prepare_t pr1;
static uv_check_t ch1;

static void cb_idle1(uv_idle_t *h) { (void) h; printf("    idle\n"); }
static void cb_prep1(uv_prepare_t *h) { (void) h; printf("    prepare\n"); }
static void cb_check1(uv_check_t *h) {
    (void) h;
    printf("    check; stopping idle/prepare/check\n");
    uv_idle_stop(&id1);
    uv_prepare_stop(&pr1);
    uv_check_stop(&ch1);
}
static void cb_idle2(uv_idle_t *h) { (void) h; printf("    idle2\n"); }

static void phase3_watchers(uv_loop_t *loop) {
    printf("=== PHASE 3: idle/prepare/check ===\n");
    uv_idle_init(loop, &id1);
    uv_prepare_init(loop, &pr1);
    uv_check_init(loop, &ch1);
    uv_idle_start(&id1, cb_idle1);
    uv_prepare_start(&pr1, cb_prep1);
    uv_check_start(&ch1, cb_check1);
    /* the check handle stops everything inside the FIRST iteration, so
     * the loop cannot spin (idle handles force a zero poll timeout) */
    printf("  uv_run(DEFAULT) returned %d\n", uv_run(loop, UV_RUN_DEFAULT));
    /* starting an already-active watcher is a no-op */
    printf("  uv_idle_start(active)=%d\n", uv_idle_start(&id1, cb_idle1));
    uv_idle_stop(&id1);

    /* one callback per iteration (UV_RUN_NOWAIT) */
    uv_idle_init(loop, &id2);
    uv_idle_start(&id2, cb_idle2);
    printf("  run1(NOWAIT) returned %d\n", uv_run(loop, UV_RUN_NOWAIT));
    printf("  run2(NOWAIT) returned %d\n", uv_run(loop, UV_RUN_NOWAIT));
    uv_idle_stop(&id2);
    printf("  run3(NOWAIT) returned %d\n", uv_run(loop, UV_RUN_NOWAIT));
}

/* ------------------------------------------------------------------ */
/* phase 4: async                                                     */
/* ------------------------------------------------------------------ */

static uv_async_t a1, a2;
static uv_timer_t sig_timer, stop4;
static volatile int helper_sent = 0;
static pthread_t helper_thread;

static void cb_a1(uv_async_t *h) {
    (void) h;
    printf("    a1 fired (3 sends coalesced into one callback)\n");
}
static void cb_a2(uv_async_t *h) {
    (void) h;
    printf("    a2 fired (cross-thread send)\n");
}
static void cb_sig_timer(uv_timer_t *h) {
    (void) h;
    printf("    timer fired; releasing helper thread\n");
    helper_sent = 1; /* the helper spins on this flag */
}

static void *helper_main(void *arg) {
    (void) arg;
    while (!helper_sent) {
        /* spin until the loop thread signals us */
    }
    uv_async_send(&a2);
    return NULL;
}

static void phase4_async(uv_loop_t *loop) {
    printf("=== PHASE 4: async ===\n");
    uv_async_init(loop, &a1, cb_a1);
    uv_async_init(loop, &a2, cb_a2);
    /* three sends before the run -> one callback (coalescing) */
    uv_async_send(&a1);
    uv_async_send(&a1);
    uv_async_send(&a1);
    printf("  uv_run(NOWAIT) returned %d\n", uv_run(loop, UV_RUN_NOWAIT));
    uv_close((uv_handle_t *) &a1, NULL);
    printf("  uv_run(NOWAIT) returned %d (a2 still active)\n",
           uv_run(loop, UV_RUN_NOWAIT));

    /* cross-thread send: a timer releases the helper, which sends a2 once */
    uv_timer_init(loop, &sig_timer);
    uv_timer_init(loop, &stop4);
    uv_timer_start(&sig_timer, cb_sig_timer, 20, 0);
    uv_timer_start(&stop4, stop_cb, 100, 0);
    if (pthread_create(&helper_thread, NULL, helper_main, NULL) != 0) {
        printf("  pthread_create failed\n");
        exit(2);
    }
    printf("  uv_run(DEFAULT) returned %d\n", uv_run(loop, UV_RUN_DEFAULT));
    pthread_join(helper_thread, NULL);
    printf("  helper thread joined\n");
    uv_close((uv_handle_t *) &a2, NULL);
    printf("  uv_run(NOWAIT) returned %d (a2 closed)\n", uv_run(loop, UV_RUN_NOWAIT));
}

/* ------------------------------------------------------------------ */
/* phase 5: signal                                                    */
/* ------------------------------------------------------------------ */

static uv_signal_t sig1;
static int sig_count = 0;

static void cb_sig(uv_signal_t *h, int signum) {
    (void) h;
    sig_count++;
    printf("    signal %d caught (%d)\n", signum, sig_count);
}

static void phase5_signal(uv_loop_t *loop) {
    printf("=== PHASE 5: signal ===\n");
    uv_signal_init(loop, &sig1);
    PERR("  uv_signal_start(signum=0)", uv_signal_start(&sig1, cb_sig, 0));
    printf("  uv_signal_start(SIGUSR1)=%d\n", uv_signal_start(&sig1, cb_sig, SIGUSR1));
    raise(SIGUSR1);
    raise(SIGUSR1);
    arm_stop(loop);
    printf("  uv_run(DEFAULT) returned %d\n", uv_run(loop, UV_RUN_DEFAULT));
    printf("  uv_signal_stop=%d\n", uv_signal_stop(&sig1));
    /* same-signum restart only replaces the callback */
    printf("  uv_signal_start(same signum)=%d\n", uv_signal_start(&sig1, cb_sig, SIGUSR1));
    uv_signal_stop(&sig1);
    uv_close((uv_handle_t *) &sig1, NULL);
    printf("  uv_run(NOWAIT) returned %d\n", uv_run(loop, UV_RUN_NOWAIT));
}

/* ------------------------------------------------------------------ */
/* phase 6: UDP                                                       */
/* ------------------------------------------------------------------ */

static uv_udp_t ua, ub, uc;
static int ub_send_cbs = 0;

static void alloc_cb(uv_handle_t *handle, size_t suggested, uv_buf_t *buf) {
    (void) handle;
    printf("    alloc suggested=%zu\n", suggested);
    buf->base = malloc(suggested);
    buf->len = (unsigned int) suggested;
}
static void cb_ub_send(uv_udp_send_t *req, int status) {
    (void) req;
    ub_send_cbs++;
    printf("    send_cb (%d) status=%s queue=%zu\n", ub_send_cbs,
           SNAME(status), uv_udp_get_send_queue_size(&ub));
}
static void cb_ua_recv(uv_udp_t *h, ssize_t nread, const uv_buf_t *buf,
                       const struct sockaddr *addr, unsigned flags) {
    (void) h;
    (void) flags;
    char ip[17];
    if (nread < 0) {
        printf("    ua recv nread=%s\n", uv_err_name((int) nread));
        return;
    }
    if (addr != NULL) {
        uv_ip4_name((const struct sockaddr_in *) addr, ip, sizeof(ip));
        printf("    ua recv nread=%zd content=%.*s addr=%s\n",
               nread, (int) nread, buf->base, ip);
    } else {
        /* nread == 0 with addr == NULL is the EAGAIN drain marker libuv
         * emits when the socket buffer is exhausted */
        printf("    ua recv nread=%zd addr=null(eagain-drain)\n", nread);
    }
    free(buf->base);
}

static void phase6_udp(uv_loop_t *loop) {
    struct sockaddr_in a_addr;
    uv_udp_send_t send_req1, send_req2, send_req3;
    uv_buf_t bufs[2];
    char p1[] = "ping";
    char p2[] = "pong";
    char p3[] = "ab";
    char p4[] = "cd";
    char big[600];
    int alen;
    int n;

    printf("=== PHASE 6: UDP ===\n");

    PERR("  uv_udp_init_ex(bad domain)", uv_udp_init_ex(loop, &uc, 999));
    PERR("  uv_udp_init_ex(bad extra flags)", uv_udp_init_ex(loop, &uc, AF_INET | 0x200));
    uv_udp_init(loop, &uc);
    uv_close((uv_handle_t *) &uc, NULL);
    printf("  uv_run(NOWAIT) returned %d\n", uv_run(loop, UV_RUN_NOWAIT));

    uv_udp_init(loop, &ua);
    uv_udp_init(loop, &ub);
    memset(&a_addr, 0, sizeof(a_addr));
    a_addr.sin_family = AF_INET;
    a_addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    a_addr.sin_port = 0;
    printf("  uv_udp_bind(ua)=%d\n", uv_udp_bind(&ua, (const struct sockaddr *) &a_addr, 0));
    alen = sizeof(a_addr);
    printf("  uv_udp_getsockname(ua)=%d\n",
           uv_udp_getsockname(&ua, (struct sockaddr *) &a_addr, &alen));

    /* try_send without an address on an unconnected socket -> EDESTADDRREQ */
    bufs[0] = uv_buf_init(p1, 4);
    PERR("  ub try_send(no addr, unconnected)",
         uv_udp_try_send(&ub, bufs, 1, NULL));

    /* try_send to ua's address: synchronous byte count */
    n = uv_udp_try_send(&ub, bufs, 1, (const struct sockaddr *) &a_addr);
    printf("  ub try_send(to ua) sent=%d\n", n);

    /* connect ub to ua; send with an address -> EISCONN; queue stays 0 */
    printf("  uv_udp_connect(ub)=%d\n",
           uv_udp_connect(&ub, (const struct sockaddr *) &a_addr));
    PERR("  ub send(addr, connected)", uv_udp_send(&send_req1, &ub, bufs, 1,
                                                   (const struct sockaddr *) &a_addr,
                                                   cb_ub_send));
    PERR("  ub try_send(addr, connected)", uv_udp_try_send(&ub, bufs, 1,
                                                           (const struct sockaddr *) &a_addr));

    /* run 1: ua recv_start; the earlier try_send'd "ping" is already in
     * the socket buffer and is the only event in this run */
    uv_udp_recv_start(&ua, alloc_cb, cb_ua_recv);
    arm_stop(loop);
    printf("  uv_run1(DEFAULT) returned %d\n", uv_run(loop, UV_RUN_DEFAULT));

    /* queue a scatter send (two buffers -> one datagram) and a 600-byte
     * send; the send_cbs fire in the pending pass of the round that
     * writes them, the recv_cbs in later iterations, in datagram order */
    bufs[0] = uv_buf_init(p3, 2);
    bufs[1] = uv_buf_init(p4, 2);
    uv_udp_send(&send_req1, &ub, bufs, 2, NULL, cb_ub_send);
    printf("  queue size after 2 bufs=%zu\n", uv_udp_get_send_queue_size(&ub));
    memset(big, 'x', sizeof(big));
    bufs[0] = uv_buf_init(big, sizeof(big));
    uv_udp_send(&send_req2, &ub, bufs, 1, NULL, cb_ub_send);
    printf("  queue size after 600b=%zu\n", uv_udp_get_send_queue_size(&ub));
    arm_stop(loop);
    printf("  uv_run2(DEFAULT) returned %d\n", uv_run(loop, UV_RUN_DEFAULT));

    /* disconnect semantics (no sends pending) */
    printf("  uv_udp_connect(ub, NULL)=%d\n", uv_udp_connect(&ub, NULL));
    PERR("  uv_udp_connect(ub, NULL) again", uv_udp_connect(&ub, NULL));
    PERR("  ub send(NULL addr, unconnected)", uv_udp_send(&send_req3, &ub, bufs, 1,
                                                          NULL, cb_ub_send));
    printf("  uv_udp_recv_stop(ua)=%d\n", uv_udp_recv_stop(&ua));
    printf("  uv_udp_recv_stop again=%d\n", uv_udp_recv_stop(&ua));

    /* connected recv: ua connects to its own address; ub connects to ua
     * and sends without an address; ua's recv_cb still gets the peer
     * address (only the EAGAIN drain marker has addr == NULL) */
    printf("  uv_udp_connect(ua)=%d\n",
           uv_udp_connect(&ua, (const struct sockaddr *) &a_addr));
    uv_udp_recv_start(&ua, alloc_cb, cb_ua_recv);
    printf("  uv_udp_connect(ub)=%d\n",
           uv_udp_connect(&ub, (const struct sockaddr *) &a_addr));
    bufs[0] = uv_buf_init(p2, 4);
    uv_udp_send(&send_req1, &ub, bufs, 1, NULL, cb_ub_send);
    arm_stop(loop);
    printf("  uv_run3(DEFAULT) returned %d\n", uv_run(loop, UV_RUN_DEFAULT));

    uv_close((uv_handle_t *) &ua, NULL);
    uv_close((uv_handle_t *) &ub, NULL);
    printf("  uv_run(NOWAIT) returned %d\n", uv_run(loop, UV_RUN_NOWAIT));
}

/* ------------------------------------------------------------------ */
/* phase 7: TCP                                                       */
/* ------------------------------------------------------------------ */

static uv_tcp_t srv, cli, conn, cli2;
static int connect_status = -999;
static int accept_status = -999;
static int accept_rc = -999;
static int shutdown_status = -999;
static char conn_buf[64];
static size_t conn_total = 0;
static char cli_buf[64];
static size_t cli_total = 0;
static int cli_eof = 0;

static void conn_alloc(uv_handle_t *h, size_t suggested, uv_buf_t *buf) {
    (void) h;
    buf->base = malloc(suggested);
    buf->len = (unsigned int) suggested;
}
static void conn_read(uv_stream_t *s, ssize_t nread, const uv_buf_t *buf) {
    (void) s;
    if (nread < 0) {
        free(buf->base);
        return;
    }
    if (conn_total < sizeof(conn_buf) - 1) {
        size_t take = (size_t) nread;
        if (conn_total + take > sizeof(conn_buf) - 1)
            take = sizeof(conn_buf) - 1 - conn_total;
        memcpy(conn_buf + conn_total, buf->base, take);
    }
    conn_total += (size_t) nread;
    free(buf->base);
}
static void cli_alloc(uv_handle_t *h, size_t suggested, uv_buf_t *buf) {
    (void) h;
    buf->base = malloc(suggested);
    buf->len = (unsigned int) suggested;
}
static void cli_read(uv_stream_t *s, ssize_t nread, const uv_buf_t *buf) {
    (void) s;
    if (nread < 0) {
        if (nread == UV_EOF)
            cli_eof = 1;
        free(buf->base);
        return;
    }
    if (cli_total < sizeof(cli_buf) - 1) {
        size_t take = (size_t) nread;
        if (cli_total + take > sizeof(cli_buf) - 1)
            take = sizeof(cli_buf) - 1 - cli_total;
        memcpy(cli_buf + cli_total, buf->base, take);
    }
    cli_total += (size_t) nread;
    free(buf->base);
}
static void cb_cli_write(uv_write_t *req, int status) {
    (void) req;
    printf("    cli write_cb status=%s queue=%zu\n", SNAME(status),
           uv_stream_get_write_queue_size((uv_stream_t *) &cli));
}
static void cb_conn_shutdown(uv_shutdown_t *req, int status) {
    (void) req;
    shutdown_status = status;
}
static void cb_conn_close(uv_handle_t *h) { (void) h; printf("    conn close_cb\n"); }
static void cb_cli_close(uv_handle_t *h) { (void) h; printf("    cli close_cb\n"); }
static void cb_srv_close(uv_handle_t *h) { (void) h; printf("    srv close_cb\n"); }
static void cb_cli2_close(uv_handle_t *h) { (void) h; printf("    cli2 close_cb\n"); }

static void cb_srv_conn(uv_stream_t *server, int status) {
    (void) server;
    accept_status = status;
    if (status == 0) {
        accept_rc = uv_accept(server, (uv_stream_t *) &conn);
        uv_read_start((uv_stream_t *) &conn, conn_alloc, conn_read);
    }
}
static uv_connect_t cli_req, cli2_req;
static uv_write_t write_req;
static uv_shutdown_t shutdown_req;

static void cb_cli_connect(uv_connect_t *req, int status) {
    (void) req;
    connect_status = status;
}
static void cb_cli2_connect(uv_connect_t *req, int status) {
    (void) req;
    printf("    cli2 connect_cb status=%s\n", SNAME(status));
    uv_close((uv_handle_t *) req->handle, cb_cli2_close);
}

static void phase7_tcp(uv_loop_t *loop) {
    struct sockaddr_in addr;
    uv_buf_t b;
    int n, rc, bufsize, alen;

    printf("=== PHASE 7: TCP ===\n");
    uv_tcp_init(loop, &srv);
    uv_tcp_init(loop, &cli);
    uv_tcp_init(loop, &conn);
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    addr.sin_port = 0;
    printf("  uv_tcp_bind(srv)=%d\n", uv_tcp_bind(&srv, (const struct sockaddr *) &addr, 0));
    alen = sizeof(addr);
    printf("  uv_tcp_getsockname(srv)=%d\n",
           uv_tcp_getsockname(&srv, (struct sockaddr *) &addr, &alen));
    printf("  uv_listen(srv)=%d\n", uv_listen((uv_stream_t *) &srv, 8, cb_srv_conn));
    printf("  uv_listen(srv) again=%d\n", uv_listen((uv_stream_t *) &srv, 8, cb_srv_conn));
    PERR("  uv_accept(no pending)", uv_accept((uv_stream_t *) &srv, (uv_stream_t *) &conn));

    /* socket buffer size get/set/get roundtrip (srv is alive) */
    bufsize = 0;
    rc = uv_recv_buffer_size((uv_handle_t *) &srv, &bufsize);
    printf("  uv_recv_buffer_size(get)=%d value=%d\n", rc, bufsize);
    bufsize = 65536;
    rc = uv_recv_buffer_size((uv_handle_t *) &srv, &bufsize);
    printf("  uv_recv_buffer_size(set 65536)=%d\n", rc);
    bufsize = 0;
    rc = uv_recv_buffer_size((uv_handle_t *) &srv, &bufsize);
    printf("  uv_recv_buffer_size(get after set)=%d value=%d\n", rc, bufsize);
    bufsize = 0;
    rc = uv_send_buffer_size((uv_handle_t *) &srv, &bufsize);
    printf("  uv_send_buffer_size(get)=%d value=%d\n", rc, bufsize);

    /* run 1: connect + accept (two fds, one epoll round; the intra-round
     * order is unspecified, so the observations are printed in the fixed
     * order documented in the manifest) */
    uv_tcp_connect(&cli_req, &cli, (const struct sockaddr *) &addr, cb_cli_connect);
    arm_stop(loop);
    printf("  uv_run1(DEFAULT) returned %d\n", uv_run(loop, UV_RUN_DEFAULT));
    printf("  [run1 fixed order] cli connect_cb status=%s\n",
           SNAME(connect_status));
    printf("  [run1 fixed order] srv accept_cb status=%s; uv_accept rc=%s\n",
           SNAME(accept_status), SNAME(accept_rc));
    printf("  [run1] conn read total=%zu content=%.*s (nothing yet)\n",
           conn_total, (int) conn_total, conn_buf);

    /* write "ping" from the client; on a fresh loopback connection the
     * write completes immediately (the fast path) without entering the
     * write queue; the write_cb still fires via the pending pass */
    b = uv_buf_init("ping", 4);
    printf("  queue size before uv_write=%zu\n",
           uv_stream_get_write_queue_size((uv_stream_t *) &cli));
    uv_write(&write_req, (uv_stream_t *) &cli, &b, 1, cb_cli_write);
    printf("  queue size after uv_write=%zu (immediate write path)\n",
           uv_stream_get_write_queue_size((uv_stream_t *) &cli));
    n = uv_try_write((uv_stream_t *) &cli, &b, 1);
    printf("  cli try_write returned %d (second ping)\n", n);
    arm_stop(loop);
    printf("  uv_run2(DEFAULT) returned %d\n", uv_run(loop, UV_RUN_DEFAULT));
    printf("  [run2] conn read total=%zu content=%.*s\n",
           conn_total, (int) conn_total, conn_buf);

    /* server try_write -> synchronous byte count */
    b = uv_buf_init("pong", 4);
    n = uv_try_write((uv_stream_t *) &conn, &b, 1);
    printf("  conn try_write returned %d\n", n);

    /* client reads the pong (already in the buffer), then the shutdown
     * writes the FIN -> the client reads EOF; the shutdown_cb is an
     * immediate callback */
    uv_read_start((uv_stream_t *) &cli, cli_alloc, cli_read);
    printf("  uv_shutdown(conn)=%d\n", uv_shutdown(&shutdown_req, (uv_stream_t *) &conn,
                                                   cb_conn_shutdown));
    arm_stop(loop);
    printf("  uv_run3(DEFAULT) returned %d\n", uv_run(loop, UV_RUN_DEFAULT));
    printf("  [run3] conn shutdown_cb status=%s\n", SNAME(shutdown_status));
    printf("  [run3] cli read total=%zu content=%.*s\n",
           cli_total, (int) cli_total, cli_buf);
    printf("  [run3] cli read nread=%s (EOF)\n", cli_eof ? "UV_EOF" : "MISSING");

    /* connect to a closed port -> ECONNREFUSED in the connect_cb */
    uv_tcp_init(loop, &cli2);
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    addr.sin_port = htons(1);
    uv_tcp_connect(&cli2_req, &cli2, (const struct sockaddr *) &addr, cb_cli2_connect);
    arm_stop(loop);
    printf("  uv_run4(DEFAULT) returned %d\n", uv_run(loop, UV_RUN_DEFAULT));

    uv_tcp_close_reset(&conn, cb_conn_close);
    uv_close((uv_handle_t *) &cli, cb_cli_close);
    uv_close((uv_handle_t *) &srv, cb_srv_close);
    arm_stop(loop);
    printf("  uv_run5(DEFAULT) returned %d\n", uv_run(loop, UV_RUN_DEFAULT));
}

/* ------------------------------------------------------------------ */
/* phase 8: handle utilities (fresh loop)                             */
/* ------------------------------------------------------------------ */

static uv_timer_t w_t;
static uv_prepare_t w_p;
static uv_async_t w_a;
static int walk_count = 0;

static void walk_cb(uv_handle_t *h, void *arg) {
    (void) arg;
    walk_count++;
    printf("    walk: %s active=%d closing=%d\n",
           uv_handle_type_name(h->type), uv_is_active(h), uv_is_closing(h));
}

static void cb_w_t(uv_timer_t *h) { (void) h; }
static void cb_w_p(uv_prepare_t *h) { (void) h; }
static void cb_w_a(uv_async_t *h) { (void) h; }
static void close_cb_x(uv_handle_t *h) {
    printf("    close_cb: %s\n", uv_handle_type_name(h->type));
}

static void phase8_handles(void) {
    uv_loop_t loop;
    uv_timer_t c1, c2, c3;
    uv_os_fd_t fd;
    int bs, rc;

    printf("=== PHASE 8: handle utilities ===\n");
    uv_loop_init(&loop);
    uv_timer_init(&loop, &w_t);
    uv_prepare_init(&loop, &w_p);
    uv_async_init(&loop, &w_a, cb_w_a);
    uv_timer_start(&w_t, cb_w_t, 1000, 0);
    uv_prepare_start(&w_p, cb_w_p);
    walk_count = 0;
    uv_walk(&loop, walk_cb, NULL);
    printf("  walked %d handles\n", walk_count);

    uv_timer_stop(&w_t);
    uv_prepare_stop(&w_p);
    uv_close((uv_handle_t *) &w_t, NULL);
    uv_close((uv_handle_t *) &w_p, NULL);
    uv_close((uv_handle_t *) &w_a, NULL);
    printf("  is_closing before run=%d\n", uv_is_closing((uv_handle_t *) &w_t));
    printf("  uv_run(NOWAIT) returned %d\n", uv_run(&loop, UV_RUN_NOWAIT));

    /* close_cb LIFO order: c1,c2,c3 closed -> c3,c2,c1 */
    uv_timer_init(&loop, &c1);
    uv_timer_init(&loop, &c2);
    uv_timer_init(&loop, &c3);
    uv_timer_start(&c1, cb_w_t, 1000, 0);
    uv_timer_start(&c2, cb_w_t, 1000, 0);
    uv_timer_start(&c3, cb_w_t, 1000, 0);
    uv_close((uv_handle_t *) &c1, close_cb_x);
    uv_close((uv_handle_t *) &c2, close_cb_x);
    uv_close((uv_handle_t *) &c3, close_cb_x);
    printf("  uv_run(NOWAIT) returned %d\n", uv_run(&loop, UV_RUN_NOWAIT));

    /* fileno: timer -> EINVAL; closed tcp (srv, phase 7) -> EBADF */
    PERR("  uv_fileno(timer)", uv_fileno((uv_handle_t *) &c1, NULL));
    fd = 0;
    rc = uv_fileno((uv_handle_t *) &srv, &fd);
    printf("  uv_fileno(closed tcp)=%d\n", rc);
    bs = 0;
    rc = uv_recv_buffer_size((uv_handle_t *) &srv, &bs);
    printf("  uv_recv_buffer_size(closed) rc=%s\n", uv_err_name(rc));
    printf("  uv_loop_close(walk loop)=%d\n", uv_loop_close(&loop));
}

/* ------------------------------------------------------------------ */
/* phase 9: dlopen                                                    */
/* ------------------------------------------------------------------ */

static void phase9_dl(void) {
    uv_lib_t lib;
    void *fn = NULL;

    printf("=== PHASE 9: dl ===\n");
    printf("  uv_dlopen(libc)=%d\n", uv_dlopen("/lib/x86_64-linux-gnu/libc.so.6", &lib));
    printf("  uv_dlsym(getpid)=%d\n", uv_dlsym(&lib, "getpid", &fn));
    printf("  uv_dlsym(bogus symbol)=%d\n", uv_dlsym(&lib, "getpid_bogus", &fn));
    printf("  uv_dlerror: %s\n", uv_dlerror(&lib));
    uv_dlclose(&lib);
    printf("  dlclose ok\n");
    printf("  uv_dlopen(nonexistent)=%d\n", uv_dlopen("/nonexistent/lib.so", &lib));
    printf("  uv_dlerror: %s\n", uv_dlerror(&lib));
    uv_dlclose(&lib);
    printf("  dlclose ok\n");
}

/* ------------------------------------------------------------------ */
/* phase 10: random + sleep                                           */
/* ------------------------------------------------------------------ */

static uv_random_t rnd_req;

static void cb_random(uv_random_t *req, int status, void *buf, size_t buflen) {
    (void) req;
    (void) buf;
    printf("    random cb status=%s len=%zu\n", SNAME(status), buflen);
}

static void phase10_random(uv_loop_t *loop) {
    char rbuf[16];
    printf("=== PHASE 10: random + sleep ===\n");
    printf("  uv_random=%d\n", uv_random(loop, &rnd_req, rbuf, sizeof(rbuf), 0, cb_random));
    arm_stop(loop);
    printf("  uv_run(DEFAULT) returned %d\n", uv_run(loop, UV_RUN_DEFAULT));
    uv_sleep(30);
    printf("  slept 30ms\n");
}

/* ------------------------------------------------------------------ */
/* phase 12: barrier                                                  */
/* ------------------------------------------------------------------ */

static uv_barrier_t bar;
static int helper_rc = -1;

static void *barrier_helper(void *arg) {
    (void) arg;
    helper_rc = uv_barrier_wait(&bar);
    return NULL;
}

static void phase12_barrier(void) {
    printf("=== PHASE 12: barrier ===\n");
    /* NOTE: on glibc uv_barrier_init is a bare pthread_barrier_init (no
     * NULL guard), so only the count==0 EINVAL is portable */
    PERR("  uv_barrier_init(&b, 0)", uv_barrier_init(&bar, 0));
    printf("  uv_barrier_init(&b, 2)=%d\n", uv_barrier_init(&bar, 2));
    if (pthread_create(&helper_thread, NULL, barrier_helper, NULL) != 0) {
        printf("  pthread_create failed\n");
        exit(2);
    }
    uv_sleep(20); /* the helper is blocked on the barrier by now */
    printf("  main uv_barrier_wait=%d\n", uv_barrier_wait(&bar));
    pthread_join(helper_thread, NULL);
    printf("  helper uv_barrier_wait=%d (serial=1 on the last releaser)\n", helper_rc);
    uv_barrier_destroy(&bar);
    printf("  barrier destroyed\n");
}

/* ------------------------------------------------------------------ */
/* phase 13: allocator                                                */
/* ------------------------------------------------------------------ */

static int m_alloc = 0, m_realloc = 0, m_calloc = 0, m_free = 0;

static void *my_malloc(size_t size) { m_alloc++; return malloc(size); }
static void *my_realloc(void *ptr, size_t size) { m_realloc++; return realloc(ptr, size); }
static void *my_calloc(size_t n, size_t size) { m_calloc++; return calloc(n, size); }
static void my_free(void *ptr) { m_free++; free(ptr); }

static void phase13_allocator(void) {
    uv_loop_t aloop;
    printf("=== PHASE 13: allocator ===\n");
    PERR("  uv_replace_allocator(NULLs)",
         uv_replace_allocator(NULL, NULL, NULL, NULL));
    printf("  uv_replace_allocator(custom)=%d\n",
           uv_replace_allocator(my_malloc, my_realloc, my_calloc, my_free));
    /* every libuv allocation now goes through the customs: uv_loop_init
     * callocs the internal fields exactly once, uv_loop_close frees them */
    printf("  uv_loop_init after replace=%d\n", uv_loop_init(&aloop));
    printf("  counts after loop_init malloc=%d realloc=%d calloc=%d free=%d\n",
           m_alloc, m_realloc, m_calloc, m_free);
    printf("  uv_loop_close after replace=%d\n", uv_loop_close(&aloop));
    printf("  counts after loop_close malloc=%d realloc=%d calloc=%d free=%d\n",
           m_alloc, m_realloc, m_calloc, m_free);
}

/* ------------------------------------------------------------------ */
/* phase 15: uv_stop + run-return semantics                           */
/* ------------------------------------------------------------------ */

static uv_timer_t st1, st2;
static int st1_fired = 0;

static void cb_st1(uv_timer_t *h) {
    (void) h;
    st1_fired++;
    printf("    st1 fired; calling uv_stop\n");
    uv_stop(h->loop);
}
static void cb_st2(uv_timer_t *h) { (void) h; printf("    st2 fired\n"); }

static void phase15_stop(uv_loop_t *loop) {
    printf("=== PHASE 15: uv_stop ===\n");
    uv_timer_init(loop, &st1);
    uv_timer_init(loop, &st2);
    uv_timer_start(&st1, cb_st1, 10, 0);
    uv_timer_start(&st2, cb_st2, 20, 0);
    printf("  uv_run(DEFAULT) returned %d (alive: st2 still pending)\n",
           uv_run(loop, UV_RUN_DEFAULT));
    printf("  uv_run(DEFAULT) returned %d\n", uv_run(loop, UV_RUN_DEFAULT));
    printf("  st1 fired %d time(s)\n", st1_fired);
}

/* ------------------------------------------------------------------ */
/* phase 16: cancel                                                   */
/* ------------------------------------------------------------------ */

static void phase16_cancel(uv_loop_t *loop) {
    (void) loop;
    printf("=== PHASE 16: uv_cancel ===\n");
    /* non-work request types are UV_EINVAL in 1.52.1 (threadpool.c) */
    PERR("  uv_cancel(completed WRITE req)", uv_cancel((uv_req_t *) &write_req));
    /* a completed RANDOM work req is no longer cancellable -> UV_EBUSY */
    PERR("  uv_cancel(completed RANDOM req)", uv_cancel((uv_req_t *) &rnd_req));
}

/* ------------------------------------------------------------------ */
/* phase 17: error battery                                            */
/* ------------------------------------------------------------------ */

#define ERR(name)  do {                                                    \
    int e = UV_ ## name;                                                    \
    printf("  UV_%-14s %-6d %s | %s\n", #name, e,                          \
           uv_err_name(e), uv_strerror(e));                                \
} while (0)

static void phase17_errors(void) {
    printf("=== PHASE 17: error battery ===\n");
    ERR(E2BIG); ERR(EACCES); ERR(EADDRINUSE); ERR(EADDRNOTAVAIL);
    ERR(EAFNOSUPPORT); ERR(EAGAIN); ERR(EAI_ADDRFAMILY); ERR(EAI_AGAIN);
    ERR(EAI_BADFLAGS); ERR(EAI_BADHINTS); ERR(EAI_CANCELED); ERR(EAI_FAIL);
    ERR(EAI_FAMILY); ERR(EAI_MEMORY); ERR(EAI_NODATA); ERR(EAI_NONAME);
    ERR(EAI_OVERFLOW); ERR(EAI_PROTOCOL); ERR(EAI_SERVICE); ERR(EAI_SOCKTYPE);
    ERR(EALREADY); ERR(EBADF); ERR(EBUSY); ERR(ECANCELED); ERR(ECHARSET);
    ERR(ECONNABORTED); ERR(ECONNREFUSED); ERR(ECONNRESET); ERR(EDESTADDRREQ);
    ERR(EEXIST); ERR(EFAULT); ERR(EFBIG); ERR(EHOSTUNREACH); ERR(EINTR);
    ERR(EINVAL); ERR(EIO); ERR(EISCONN); ERR(EISDIR); ERR(ELOOP); ERR(EMFILE);
    ERR(EMSGSIZE); ERR(ENAMETOOLONG); ERR(ENETDOWN); ERR(ENETUNREACH);
    ERR(ENFILE); ERR(ENOBUFS); ERR(ENODEV); ERR(ENOENT); ERR(ENOMEM);
    ERR(ENONET); ERR(ENOPROTOOPT); ERR(ENOSPC); ERR(ENOSYS); ERR(ENOTCONN);
    ERR(ENOTDIR); ERR(ENOTEMPTY); ERR(ENOTSOCK); ERR(ENOTSUP); ERR(EOVERFLOW);
    ERR(EPERM); ERR(EPIPE); ERR(EPROTO); ERR(EPROTONOSUPPORT); ERR(EPROTOTYPE);
    ERR(ERANGE); ERR(EROFS); ERR(ESHUTDOWN); ERR(ESPIPE); ERR(ESRCH);
    ERR(ETIMEDOUT); ERR(ETXTBSY); ERR(EXDEV); ERR(UNKNOWN); ERR(EOF);
    ERR(ENXIO); ERR(EMLINK); ERR(EHOSTDOWN); ERR(EREMOTEIO); ERR(ENOTTY);
    ERR(EFTYPE); ERR(EILSEQ); ERR(ESOCKTNOSUPPORT); ERR(ENODATA); ERR(EUNATCH);
    ERR(ENOEXEC);
    {
        int e = -12345;
        printf("  UV_UNKNOWN-12345   %-6d %s | %s\n", e,
               uv_err_name(e), uv_strerror(e));
    }
}

/* ------------------------------------------------------------------ */
/* main                                                               */
/* ------------------------------------------------------------------ */

int main(void) {
    uv_loop_t loop, loop2;

    printf("=== PHASE 0: version ===\n");
    printf("  uv_version=%u\n", uv_version());
    printf("  uv_version_string=%s\n", uv_version_string());

    printf("=== PHASE 1: loop basics ===\n");
    printf("  uv_loop_init=%d\n", uv_loop_init(&loop));
    printf("  uv_run(NOWAIT, empty)=%d\n", uv_run(&loop, UV_RUN_NOWAIT));
    printf("  uv_loop_alive=%d\n", uv_loop_alive(&loop));
    printf("  uv_loop_close=%d\n", uv_loop_close(&loop));

    uv_loop_init(&loop2);
    phase2_timers(&loop2);
    phase3_watchers(&loop2);
    phase4_async(&loop2);
    phase5_signal(&loop2);
    phase6_udp(&loop2);
    phase7_tcp(&loop2);
    phase8_handles();
    phase9_dl();
    phase10_random(&loop2);
    phase12_barrier();
    phase15_stop(&loop2);
    phase16_cancel(&loop2);
    /* the leftover handles (never closed) make this UV_EBUSY */
    printf("  uv_loop_close(loop2 with leftover handles)=%d (EBUSY)\n",
           uv_loop_close(&loop2));
    phase17_errors();
    phase13_allocator();
    uv_library_shutdown();
    printf("  uv_library_shutdown called\n");
    return 0;
}
