/*
 * probe-netmgr.c — the netmgr oracle probe (court NETMGR-0001).
 *
 * A deterministic op sequence over the public isc_nm_* surface BIND 9.20's
 * query pipeline depends on, plus internal-state observations through
 * netmgr-int.h.  Both the C probe and the Rust mirror run in the SAME
 * oracle-bind-9.20.26 container; stdout must be byte-identical.
 *
 * Transcript determinism contract:
 *  - only logical events, byte contents, sizes, results and internal state
 *    values are printed; never wall-clock values, kernel-assigned ports,
 *    fds, pointers, pids or thread ids (the loop tids 0/1/2 are fixed by
 *    construction);
 *  - every address is the loopback literal 127.0.0.1 with a fixed port;
 *    client source ports are fixed so the server sees deterministic peer
 *    addresses;
 *  - the loop manager runs 3 loops; loops 1 and 2 are idle except for the
 *    load-balance phase, whose callbacks never print (only aggregate
 *    counters are printed, from the loop-0 client side);
 *  - the one genuinely unspecified intra-round order — the client's TCP
 *    connect_cb vs the server's accept_cb, two events of the same epoll
 *    round on the same loop — is recorded by each callback and printed by
 *    a chained job in a fixed documented order (connect first, then
 *    accept);
 *  - TCP stream reads are accumulated to a known message length before
 *    printing (the kernel may deliver a stream in arbitrary chunks);
 *  - every internal-state print happens on the socket's owning thread at
 *    a quiescent point (callback entry or a chained loop-0 job);
 *  - I/O is loopback and completes in microseconds; the idle loops 1/2
 *    print nothing, so the transcript order is fixed.
 */

#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include <isc/async.h>
#include <isc/atomic.h>
#include <isc/loop.h>
#include <isc/mem.h>
#include <isc/netmgr.h>
#include <isc/refcount.h>
#include <isc/result.h>
#include <isc/sockaddr.h>
#include <isc/tid.h>
#include <isc/util.h>

/* internal state observability (the tests include this the same way) */
#include "netmgr/netmgr-int.h"

static isc_mem_t *mctx;
static isc_loopmgr_t *loopmgr;
static isc_nm_t *netmgr;
static isc_loop_t *mainloop;

/* ------------------------------------------------------------------ */
/* transcript helpers                                                 */
/* ------------------------------------------------------------------ */

static const char *
SNAME(isc_result_t r) {
	switch (r) {
	case ISC_R_SUCCESS:
		return "success";
	case ISC_R_TIMEDOUT:
		return "timed out";
	case ISC_R_CANCELED:
		return "canceled";
	case ISC_R_SHUTTINGDOWN:
		return "shutting down";
	case ISC_R_ADDRINUSE:
		return "address in use";
	case ISC_R_NOTIMPLEMENTED:
		return "not implemented";
	case ISC_R_CONNREFUSED:
		return "connection refused";
	case ISC_R_EOF:
		return "eof";
	case ISC_R_CONNECTIONRESET:
		return "connection reset";
	default:
		return isc_result_totext(r);
	}
}

static void
PADDR(const char *tag, isc_sockaddr_t sa) {
	char buf[ISC_SOCKADDR_FORMATSIZE];
	isc_sockaddr_format(&sa, buf, sizeof(buf));
	printf("%s=%s", tag, buf);
}

static const char *
STYPE(isc_nmsocket_type_t t) {
	switch (t) {
	case isc_nm_udpsocket:
		return "udpsocket";
	case isc_nm_udplistener:
		return "udplistener";
	case isc_nm_tcpsocket:
		return "tcpsocket";
	case isc_nm_tcplistener:
		return "tcplistener";
	default:
		return "other";
	}
}

static void
next_job(void (*cb)(void *), void *arg) {
	isc_async_run(mainloop, cb, arg);
}

/* phase driver forward declarations */
static void phase2_checkaddr(void *arg);
static void phase3_udp(void *arg);
static void phase4_maxudp(void *arg);
static void phase5_timeout(void *arg);
static void phase6_cancelread(void *arg);
static void phase7_udp_stop(void *arg);
static void phase8_tcp(void *arg);
static void phase8_conn2(void *arg);
static void phase8_conn3(void *arg);
static void phase9_tcp_timeout(void *arg);
static void phase10_refused(void *arg);
static void phase11_tcp_stop(void *arg);
static void phase12_udp(void *arg);
static void phase12_tcp(void *arg);
static void phase13_teardown(void *arg);

/* ------------------------------------------------------------------ */
/* phase 1: netmgr lifecycle                                           */
/* ------------------------------------------------------------------ */

static void
phase1_setup(void *arg) {
	uint32_t init, idle, keepalive, advertised;
	isc_nm_t *tmp = NULL;

	UNUSED(arg);

	printf("tid=%u\n", isc_tid());
	printf("nloops=%u\n", netmgr->nloops);

	isc_nm_gettimeouts(netmgr, &init, &idle, &keepalive, &advertised);
	printf("default timeouts: init=%u idle=%u keepalive=%u advertised=%u\n",
	       init, idle, keepalive, advertised);
	printf("getloadbalancesockets=%s\n",
	       isc_nm_getloadbalancesockets(netmgr) ? "true" : "false");

	isc_nm_settimeouts(netmgr, 700, 800, 900, 1000);
	isc_nm_gettimeouts(netmgr, &init, &idle, &keepalive, &advertised);
	printf("settimeouts(700,800,900,1000); gettimeouts: init=%u idle=%u "
	       "keepalive=%u advertised=%u\n",
	       init, idle, keepalive, advertised);

	isc_nm_setnetbuffers(netmgr, 1024, 2048, 4096, 8192);
	printf("setnetbuffers(1024,2048,4096,8192) ok\n");

	isc_nm_maxudp(netmgr, 0);
	printf("maxudp=0\n");

	printf("netmgr refs=%u\n", (unsigned)isc_refcount_current(&netmgr->references));
	isc_nm_attach(netmgr, &tmp);
	printf("netmgr refs after attach=%u\n",
	       (unsigned)isc_refcount_current(&netmgr->references));
	isc_nm_detach(&tmp);
	printf("netmgr refs after detach=%u\n",
	       (unsigned)isc_refcount_current(&netmgr->references));

	next_job(phase2_checkaddr, NULL);
}

/* ------------------------------------------------------------------ */
/* phase 2: isc_nm_checkaddr                                           */
/* ------------------------------------------------------------------ */

static void
phase2_checkaddr(void *arg) {
	isc_sockaddr_t addr;
	struct in_addr in;
	int fd;
	struct sockaddr_in sin;
	isc_result_t r;

	UNUSED(arg);

	printf("=== PHASE 2: isc_nm_checkaddr ===\n");

	inet_pton(AF_INET, "127.0.0.1", &in);
	isc_sockaddr_fromin(&addr, &in, 19153);

	r = isc_nm_checkaddr(&addr, isc_socktype_tcp);
	printf("checkaddr(127.0.0.1#19153, tcp) -> %s\n", SNAME(r));

	fd = socket(AF_INET, SOCK_STREAM, 0);
	memset(&sin, 0, sizeof(sin));
	sin.sin_family = AF_INET;
	sin.sin_port = htons(19153);
	sin.sin_addr = in;
	RUNTIME_CHECK(bind(fd, (struct sockaddr *)&sin, sizeof(sin)) == 0);
	printf("bound a plain tcp socket to 19153\n");

	r = isc_nm_checkaddr(&addr, isc_socktype_tcp);
	printf("checkaddr(127.0.0.1#19153, tcp) -> %s\n", SNAME(r));

	close(fd);
	printf("closed the plain socket\n");

	r = isc_nm_checkaddr(&addr, isc_socktype_tcp);
	printf("checkaddr(127.0.0.1#19153, tcp) -> %s\n", SNAME(r));

	r = isc_nm_checkaddr(&addr, isc_socktype_raw);
	printf("checkaddr(127.0.0.1#19153, raw) -> %s\n", SNAME(r));

	next_job(phase3_udp, NULL);
}

/* ------------------------------------------------------------------ */
/* phase 3: UDP echo (LISTEN_ONE)                                      */
/* ------------------------------------------------------------------ */

static isc_nmsocket_t *udp_listen_sock;
static isc_nmhandle_t *udp_keep;
static isc_nmhandle_t *udp_client_send;
static isc_nmhandle_t *udp_server_send;
static int udp_round = 0;
static bool udp_no_reply = false;

static void udp_client_send_cb(isc_nmhandle_t *handle, isc_result_t eresult,
			       void *cbarg);
static void udp_server_send_cb(isc_nmhandle_t *handle, isc_result_t eresult,
			       void *cbarg);
static void udp_client_recv_cb(isc_nmhandle_t *handle, isc_result_t eresult,
			       isc_region_t *region, void *cbarg);

static void
udp_client_send_cb(isc_nmhandle_t *handle, isc_result_t eresult,
		   void *cbarg) {
	UNUSED(eresult);
	UNUSED(cbarg);

	printf("  client send cb: eresult=%s handle refs=%u\n", SNAME(eresult),
	       (unsigned)isc_refcount_current(&handle->references));
	isc_nmhandle_detach(&udp_client_send);
	printf("  client send cb: after detach refs=%u\n",
	       (unsigned)isc_refcount_current(&handle->references));
}

static void
udp_server_send_cb(isc_nmhandle_t *handle, isc_result_t eresult,
		   void *cbarg) {
	UNUSED(eresult);
	UNUSED(cbarg);

	printf("  server send cb: handle refs=%u\n",
	       (unsigned)isc_refcount_current(&handle->references));
	isc_nmhandle_detach(&udp_server_send);
}

static void
udp_server_recv_cb(isc_nmhandle_t *handle, isc_result_t eresult,
		   isc_region_t *region, void *cbarg) {
	isc_nmsocket_t *sock = handle->sock;
	static char echo[16];
	isc_region_t rgn;

	UNUSED(cbarg);

	if (eresult != ISC_R_SUCCESS) {
		return;
	}

	if (udp_no_reply) {
		printf("  server recv: data=\"%.*s\" (no reply)\n",
		       (int)region->length, (char *)region->base);
		return;
	}

	printf("  server recv: data=\"%.*s\" ", (int)region->length,
	       (char *)region->base);
	PADDR("peer", isc_nmhandle_peeraddr(handle));
	printf(" handle refs=%u sock refs=%u active_handles=%u\n",
	       (unsigned)isc_refcount_current(&handle->references),
	       (unsigned)isc_refcount_current(&sock->references),
	       (unsigned)sock->active_handles_cur);

	/* echo back (upper-cased first byte) */
	memcpy(echo, region->base, (size_t)region->length);
	((char *)echo)[0] = (char)(((char *)echo)[0] ^ 0x20);
	rgn.base = (unsigned char *)echo;
	rgn.length = (unsigned)region->length;
	isc_nmhandle_attach(handle, &udp_server_send);
	isc_nm_send(udp_server_send, &rgn, udp_server_send_cb, NULL);
}

static void
udp_client_recv_cb(isc_nmhandle_t *handle, isc_result_t eresult,
		   isc_region_t *region, void *cbarg) {
	static char msg[16];
	isc_region_t rgn;

	UNUSED(cbarg);

	printf("  client recv: eresult=%s data=\"%.*s\" handle refs=%u\n",
	       SNAME(eresult), (int)region->length, (char *)region->base,
	       (unsigned)isc_refcount_current(&handle->references));

	if (eresult != ISC_R_SUCCESS) {
		return;
	}

	/* a UDP client gets exactly one datagram per isc_nm_read; re-arm */
	isc_nm_read(handle, udp_client_recv_cb, NULL);

	udp_round++;
	if (udp_round < 3) {
		snprintf(msg, sizeof(msg), "ping-%d", udp_round + 1);
		rgn.base = (unsigned char *)msg;
		rgn.length = (unsigned)strlen(msg);
		isc_nmhandle_attach(handle, &udp_client_send);
		isc_nm_send(udp_client_send, &rgn, udp_client_send_cb, NULL);
		printf("  client sent \"%s\"\n", msg);
	} else {
		isc_nmsocket_t *sock = handle->sock;
		printf("  client state: handle refs=%u sock refs=%u "
		       "statichandle=%s active_handles=%u\n",
		       (unsigned)isc_refcount_current(&handle->references),
		       (unsigned)isc_refcount_current(&sock->references),
		       sock->statichandle != NULL ? "true" : "false",
		       (unsigned)sock->active_handles_cur);
		next_job(phase4_maxudp, NULL);
	}
}

static void
udp_connect_cb(isc_nmhandle_t *handle, isc_result_t eresult, void *cbarg) {
	isc_nmsocket_t *sock = handle->sock;
	isc_region_t rgn;
	static char msg[16];

	UNUSED(cbarg);

	printf("  connect cb: eresult=%s\n", SNAME(eresult));
	if (eresult != ISC_R_SUCCESS) {
		return;
	}

	PADDR("    handle peer", isc_nmhandle_peeraddr(handle));
	printf(" ");
	PADDR("local", isc_nmhandle_localaddr(handle));
	printf(" is_stream=%s netmgr_match=%s\n",
	       isc_nmhandle_is_stream(handle) ? "true" : "false",
	       isc_nmhandle_netmgr(handle) == netmgr ? "true" : "false");
	printf("    handle refs=%u (entry)\n",
	       (unsigned)isc_refcount_current(&handle->references));
	isc_nmhandle_attach(handle, &udp_keep);
	printf("    handle refs after attach=%u\n",
	       (unsigned)isc_refcount_current(&handle->references));
	printf("    client sock: refs=%u active=%s connected=%s "
	       "connecting=%s reading=%s statichandle=%s active_handles=%u\n",
	       (unsigned)isc_refcount_current(&sock->references),
	       isc__nmsocket_active(sock) ? "true" : "false",
	       sock->connected ? "true" : "false",
	       sock->connecting ? "true" : "false",
	       sock->reading ? "true" : "false",
	       sock->statichandle != NULL ? "true" : "false",
	       (unsigned)sock->active_handles_cur);

	isc_nm_read(handle, udp_client_recv_cb, NULL);
	printf("    read started; timer_running=%s\n",
	       isc__nmsocket_timer_running(sock) ? "true" : "false");

	snprintf(msg, sizeof(msg), "ping-1");
	rgn.base = (unsigned char *)msg;
	rgn.length = (unsigned)strlen(msg);
	isc_nmhandle_attach(handle, &udp_client_send);
	isc_nm_send(udp_client_send, &rgn, udp_client_send_cb, NULL);
	printf("  client sent \"ping-1\"\n");
}

static void
phase3_udp(void *arg) {
	isc_sockaddr_t iface, local;
	struct in_addr in;
	isc_result_t r;

	UNUSED(arg);

	printf("=== PHASE 3: UDP echo (LISTEN_ONE) ===\n");

	inet_pton(AF_INET, "127.0.0.1", &in);
	isc_sockaddr_fromin(&iface, &in, 19153);

	r = isc_nm_listenudp(netmgr, ISC_NM_LISTEN_ONE, &iface,
			     udp_server_recv_cb, NULL, &udp_listen_sock);
	printf("listenudp(workers=1, 127.0.0.1#19153) -> %s\n", SNAME(r));
	if (r != ISC_R_SUCCESS) {
		return;
	}
	printf("  server type=%s active=%s closing=%s closed=%s nchildren=%u\n",
	       STYPE(udp_listen_sock->type),
	       udp_listen_sock->active ? "true" : "false",
	       udp_listen_sock->closing ? "true" : "false",
	       udp_listen_sock->closed ? "true" : "false",
	       (unsigned)udp_listen_sock->nchildren);
	for (uint32_t i = 0; i < udp_listen_sock->nchildren; i++) {
		printf("  child[%u]: tid=%u result=%s\n", i,
		       (unsigned)udp_listen_sock->children[i].tid,
		       SNAME(udp_listen_sock->children[i].result));
	}

	isc_sockaddr_fromin(&local, &in, 19155);
	printf("udpconnect(local=127.0.0.1#19155 -> 127.0.0.1#19153, "
	       "timeout=5000)\n");
	isc_nm_udpconnect(netmgr, &local, &iface, udp_connect_cb, NULL, 5000);
}

/* ------------------------------------------------------------------ */
/* phase 4: UDP maxudp firewall simulation                             */
/* ------------------------------------------------------------------ */

static int udp_blocked_send_calls = 0;

static void
udp_blocked_send_cb(isc_nmhandle_t *handle, isc_result_t eresult,
		    void *cbarg) {
	UNUSED(handle);
	UNUSED(eresult);
	UNUSED(cbarg);
	udp_blocked_send_calls++;
}

static void
udp_ok_recv_cb(isc_nmhandle_t *handle, isc_result_t eresult,
	       isc_region_t *region, void *cbarg) {
	UNUSED(cbarg);

	printf("  client recv: eresult=%s data=\"%.*s\"\n", SNAME(eresult),
	       (int)region->length, (char *)region->base);
	if (eresult == ISC_R_SUCCESS && region->length == 2 &&
	    memcmp(region->base, "Ok", 2) == 0)
	{
		/* close the phase-3/4 client before the next connection */
		isc_nmhandle_detach(&udp_keep);
		udp_keep = NULL;
		next_job(phase5_timeout, NULL);
	}
}

static void
phase4_maxudp(void *arg) {
	isc_nmhandle_t *handle = udp_keep;
	isc_region_t rgn;
	static char big[16];
	static char ok[4] = { 'o', 'k', 0, 0 };

	UNUSED(arg);

	printf("=== PHASE 4: UDP maxudp firewall ===\n");

	isc_nm_maxudp(netmgr, 4);
	printf("maxudp=4\n");

	memcpy(big, "1234567890", 11);
	rgn.base = (unsigned char *)big;
	rgn.length = 10;
	udp_blocked_send_calls = 0;
	isc_nmhandle_attach(handle, &udp_client_send);
	isc_nm_send(udp_client_send, &rgn, udp_blocked_send_cb, NULL);
	/* the blocked send consumed our ref (isc__nm_udp_send detached the
	 * handle internally); the send cb never fires, so drop the pointer */
	udp_client_send = NULL;
	printf("  send 10 bytes while maxudp=4: blocked, send cb calls=%d\n",
	       udp_blocked_send_calls);

	isc_nm_maxudp(netmgr, 0);
	printf("maxudp=0\n");

	isc_nm_read(handle, udp_ok_recv_cb, NULL);
	rgn.base = (unsigned char *)ok;
	rgn.length = 2;
	isc_nmhandle_attach(handle, &udp_client_send);
	isc_nm_send(udp_client_send, &rgn, udp_client_send_cb, NULL);
	printf("  client sent \"ok\"\n");
}

/* ------------------------------------------------------------------ */
/* phase 5: UDP read timeout                                           */
/* ------------------------------------------------------------------ */

static void
udp_timeout_recv_cb(isc_nmhandle_t *handle, isc_result_t eresult,
		    isc_region_t *region, void *cbarg) {
	UNUSED(region);
	UNUSED(cbarg);

	printf("  client recv: eresult=%s handle refs=%u\n", SNAME(eresult),
	       (unsigned)isc_refcount_current(&handle->references));
	if (eresult == ISC_R_TIMEDOUT) {
		isc_nmhandle_detach(&udp_keep);
		udp_keep = NULL;
		next_job(phase6_cancelread, NULL);
	}
}

static void
udp_timeout_connect_cb(isc_nmhandle_t *handle, isc_result_t eresult,
		       void *cbarg) {
	isc_region_t rgn;
	static char msg[16];

	UNUSED(cbarg);

	printf("  connect cb: eresult=%s\n", SNAME(eresult));
	if (eresult != ISC_R_SUCCESS) {
		return;
	}
	isc_nmhandle_attach(handle, &udp_keep);
	isc_nm_read(handle, udp_timeout_recv_cb, NULL);
	snprintf(msg, sizeof(msg), "no-reply");
	rgn.base = (unsigned char *)msg;
	rgn.length = (unsigned)strlen(msg);
	isc_nmhandle_attach(handle, &udp_client_send);
	isc_nm_send(udp_client_send, &rgn, udp_client_send_cb, NULL);
	printf("  client sent \"no-reply\" (read timeout=50ms)\n");
}

static void
phase5_timeout(void *arg) {
	isc_sockaddr_t local, peer;
	struct in_addr in;

	UNUSED(arg);

	printf("=== PHASE 5: UDP read timeout ===\n");
	udp_round = 0;
	udp_no_reply = true;

	inet_pton(AF_INET, "127.0.0.1", &in);
	isc_sockaddr_fromin(&local, &in, 19156);
	isc_sockaddr_fromin(&peer, &in, 19153);
	isc_nm_udpconnect(netmgr, &local, &peer, udp_timeout_connect_cb,
			  NULL, 50);
}

/* ------------------------------------------------------------------ */
/* phase 6: UDP cancelread                                             */
/* ------------------------------------------------------------------ */

static void
udp_cancel_recv_cb(isc_nmhandle_t *handle, isc_result_t eresult,
		   isc_region_t *region, void *cbarg) {
	UNUSED(region);
	UNUSED(cbarg);

	printf("  client recv: eresult=%s handle refs=%u\n", SNAME(eresult),
	       (unsigned)isc_refcount_current(&handle->references));
	if (eresult == ISC_R_CANCELED) {
		isc_nmhandle_detach(&udp_keep);
		udp_keep = NULL;
		next_job(phase7_udp_stop, NULL);
	}
}

static void
udp_cancel_connect_cb(isc_nmhandle_t *handle, isc_result_t eresult,
		      void *cbarg) {
	UNUSED(cbarg);

	printf("  connect cb: eresult=%s\n", SNAME(eresult));
	if (eresult != ISC_R_SUCCESS) {
		return;
	}
	isc_nmhandle_attach(handle, &udp_keep);
	isc_nm_read(handle, udp_cancel_recv_cb, NULL);
	printf("  read started; calling isc_nm_cancelread\n");
	isc_nm_cancelread(handle);
}

static void
phase6_cancelread(void *arg) {
	isc_sockaddr_t local, peer;
	struct in_addr in;

	UNUSED(arg);

	printf("=== PHASE 6: UDP cancelread ===\n");

	inet_pton(AF_INET, "127.0.0.1", &in);
	isc_sockaddr_fromin(&local, &in, 19157);
	isc_sockaddr_fromin(&peer, &in, 19153);
	isc_nm_udpconnect(netmgr, &local, &peer, udp_cancel_connect_cb,
			  NULL, 5000);
}

/* ------------------------------------------------------------------ */
/* phase 7: UDP stoplistening                                          */
/* ------------------------------------------------------------------ */

static void
phase7_udp_stop(void *arg) {
	isc_nmsocket_t *sock = udp_listen_sock;

	UNUSED(arg);

	printf("=== PHASE 7: UDP stoplistening ===\n");

	isc_nm_stoplistening(sock);
	printf("  stoplistening: parent active=%s closing=%s closed=%s\n",
	       sock->active ? "true" : "false",
	       sock->closing ? "true" : "false",
	       sock->closed ? "true" : "false");
	if (sock->nchildren > 0) {
		isc_nmsocket_t *c = &sock->children[0];
		printf("  child[0]: active=%s closing=%s closed=%s\n",
		       c->active ? "true" : "false",
		       c->closing ? "true" : "false",
		       c->closed ? "true" : "false");
	}

	isc_nmsocket_close(&udp_listen_sock);
	printf("  nmsocket_close ok\n");

	next_job(phase8_tcp, NULL);
}

/* ------------------------------------------------------------------ */
/* phase 8: TCP echo (LISTEN_ONE)                                      */
/* ------------------------------------------------------------------ */

static isc_nmsocket_t *tcp_listen_sock;
static isc_nmhandle_t *tcp_keep;
static isc_nmhandle_t *tcp_client_send;
static isc_nmhandle_t *tcp_server_send;
static int tcp_conn = 0;

/* record-and-print for the connect/accept pair */
static isc_sockaddr_t rec_conn_peer, rec_conn_local;
static isc_sockaddr_t rec_acc_peer, rec_acc_local;
static int rec_conn_refs, rec_conn_sock_refs;
static int rec_conn_ready, rec_acc_ready;
static uint32_t rec_conn_ah, rec_acc_ah;
static bool rec_conn_connected, rec_acc_client;

static void tcp_client_recv_cb(isc_nmhandle_t *handle, isc_result_t eresult,
			       isc_region_t *region, void *cbarg);
static void tcp_server_send_cb(isc_nmhandle_t *handle, isc_result_t eresult,
			       void *cbarg);
static void tcp_conn2_connect_cb(isc_nmhandle_t *handle, isc_result_t eresult,
				 void *cbarg);
static void tcp_conn3_client_connect_cb(isc_nmhandle_t *handle,
					isc_result_t eresult, void *cbarg);
static void tcp_timeout_connect_cb(isc_nmhandle_t *handle,
				   isc_result_t eresult, void *cbarg);
static void tcp_server_recv_cb(isc_nmhandle_t *handle, isc_result_t eresult,
			       isc_region_t *region, void *cbarg);
static void tcp_big_server_recv_cb(isc_nmhandle_t *handle,
				   isc_result_t eresult, isc_region_t *region,
				   void *cbarg);
static void tcp_conn3_server_recv_cb(isc_nmhandle_t *handle,
				     isc_result_t eresult, isc_region_t *region,
				     void *cbarg);
static void tcp_timeout_server_recv_cb(isc_nmhandle_t *handle,
				       isc_result_t eresult, isc_region_t *region,
				       void *cbarg);
static void phase8_conn2(void *arg);
static void phase8_conn3(void *arg);
static void phase9_tcp_timeout(void *arg);
static void tcp_conn3_recheck(void *arg);

static void
tcp_client_send_cb(isc_nmhandle_t *handle, isc_result_t eresult,
		   void *cbarg) {
	UNUSED(eresult);
	UNUSED(cbarg);

	printf("  client send cb: eresult=%s handle refs=%u\n", SNAME(eresult),
	       (unsigned)isc_refcount_current(&handle->references));
	isc_nmhandle_detach(&tcp_client_send);
}

/* print the recorded connect/accept pair in the fixed documented order */
static void
tcp_print_pair(void *arg) {
	UNUSED(arg);

	printf("  connect cb: eresult=success ");
	PADDR("peer", rec_conn_peer);
	printf(" ");
	PADDR("local", rec_conn_local);
	printf(" is_stream=true handle refs=%u sock refs=%u connected=%s "
	       "active_handles=%u\n",
	       (unsigned)rec_conn_refs, (unsigned)rec_conn_sock_refs,
	       rec_conn_connected ? "true" : "false", rec_conn_ah);
	printf("  accept cb: eresult=success ");
	PADDR("peer", rec_acc_peer);
	printf(" ");
	PADDR("local", rec_acc_local);
	printf(" is_stream=true client=%s active_handles=%u\n",
	       rec_acc_client ? "true" : "false", rec_acc_ah);
}

static void
tcp_server_recv_cb(isc_nmhandle_t *handle, isc_result_t eresult,
		   isc_region_t *region, void *cbarg) {
	static char echo[16];
	isc_region_t rgn;

	UNUSED(cbarg);

	if (eresult == ISC_R_SUCCESS) {
		printf("  server recv: data=\"%.*s\" handle refs=%u\n",
		       (int)region->length, (char *)region->base,
		       (unsigned)isc_refcount_current(&handle->references));
		memcpy(echo, region->base, (size_t)region->length);
		((char *)echo)[0] = (char)(((char *)echo)[0] ^ 0x20);
		rgn.base = (unsigned char *)echo;
		rgn.length = (unsigned)region->length;
		isc_nmhandle_attach(handle, &tcp_server_send);
		isc_nm_send(tcp_server_send, &rgn, tcp_server_send_cb, NULL);
	} else {
		printf("  server recv: eresult=%s\n", SNAME(eresult));
		isc_nmhandle_detach(&handle);
		next_job(phase8_conn2, NULL);
	}
}

static void
tcp_server_send_cb(isc_nmhandle_t *handle, isc_result_t eresult,
		   void *cbarg) {
	UNUSED(eresult);
	UNUSED(cbarg);

	printf("  server send cb: eresult=%s handle refs=%u\n", SNAME(eresult),
	       (unsigned)isc_refcount_current(&handle->references));
	isc_nmhandle_detach(&tcp_server_send);
}

/* --- connection 1: small echo + timeout/keepalive observations --- */

static void
tcp_conn1_client_done(void *arg) {
	isc_nmsocket_t *sock;

	UNUSED(arg);

	sock = tcp_keep->sock;

	printf("  client handle: timer_running=%s read_timeout=%u\n",
	       isc_nmhandle_timer_running(tcp_keep) ? "true" : "false",
	       (unsigned)sock->read_timeout);
	isc_nmhandle_cleartimeout(tcp_keep);
	printf("  cleartimeout: timer_running=%s read_timeout=%u\n",
	       isc_nmhandle_timer_running(tcp_keep) ? "true" : "false",
	       (unsigned)sock->read_timeout);
	isc_nmhandle_settimeout(tcp_keep, 500);
	printf("  settimeout(500): timer_running=%s read_timeout=%u\n",
	       isc_nmhandle_timer_running(tcp_keep) ? "true" : "false",
	       (unsigned)sock->read_timeout);
	isc_nmhandle_keepalive(tcp_keep, true);
	printf("  keepalive(true): read_timeout=%u\n",
	       (unsigned)sock->read_timeout);
	isc_nmhandle_keepalive(tcp_keep, false);
	printf("  keepalive(false): read_timeout=%u\n",
	       (unsigned)sock->read_timeout);
	isc_nmhandle_cleartimeout(tcp_keep);

	isc_nmhandle_close(tcp_keep);
	isc_nmhandle_detach(&tcp_keep);
	tcp_keep = NULL;
	printf("  client handle closed\n");
}

static void
tcp_conn1_go(void *arg) {
	isc_region_t rgn;
	static char msg[16];

	UNUSED(arg);

	snprintf(msg, sizeof(msg), "tcp-1");
	rgn.base = (unsigned char *)msg;
	rgn.length = (unsigned)strlen(msg);
	isc_nmhandle_attach(tcp_keep, &tcp_client_send);
	isc_nm_send(tcp_client_send, &rgn, tcp_client_send_cb, NULL);
	printf("  client sent \"tcp-1\"\n");
}

static void
tcp_client_recv_cb(isc_nmhandle_t *handle, isc_result_t eresult,
		   isc_region_t *region, void *cbarg) {
	UNUSED(cbarg);

	printf("  client recv: eresult=%s data=\"%.*s\" handle refs=%u\n",
	       SNAME(eresult), (int)region->length, (char *)region->base,
	       (unsigned)isc_refcount_current(&handle->references));

	if (eresult != ISC_R_SUCCESS) {
		return;
	}
	if (tcp_conn == 1) {
		next_job(tcp_conn1_client_done, NULL);
	}
}

/* --- connection 2: large echo (uv_write path) --- */

static size_t tcp_big_server_got = 0;
static size_t tcp_big_client_got = 0;

static void
tcp_big_server_recv_cb(isc_nmhandle_t *handle, isc_result_t eresult,
		       isc_region_t *region, void *cbarg) {
	static char big[131072];
	isc_region_t rgn;

	UNUSED(cbarg);

	if (eresult != ISC_R_SUCCESS) {
		printf("  server recv: eresult=%s\n", SNAME(eresult));
		isc_nmhandle_detach(&handle);
		next_job(phase8_conn3, NULL);
		return;
	}

	tcp_big_server_got += (size_t)region->length;
	if (tcp_big_server_got >= sizeof(big)) {
		printf("  server: received full message (131072 bytes)\n");
		memset(big, 'E', sizeof(big));
		rgn.base = (unsigned char *)big;
		rgn.length = sizeof(big);
		isc_nmhandle_attach(handle, &tcp_server_send);
		isc_nm_send(tcp_server_send, &rgn, tcp_server_send_cb, NULL);
	}
}

static void
tcp_big_client_recv_cb(isc_nmhandle_t *handle, isc_result_t eresult,
		       isc_region_t *region, void *cbarg) {
	UNUSED(cbarg);

	if (eresult != ISC_R_SUCCESS) {
		return;
	}
	tcp_big_client_got += (size_t)region->length;
	if (tcp_big_client_got >= 131072) {
		printf("  client: received full echo (131072 bytes)\n");
		isc_nmhandle_close(tcp_keep);
		isc_nmhandle_detach(&tcp_keep);
		tcp_keep = NULL;
		printf("  client handle closed\n");
	}
}

static void
tcp_conn2_go(void *arg) {
	static char big[131072];
	isc_region_t rgn;

	UNUSED(arg);

	memset(big, 'L', sizeof(big));
	rgn.base = (unsigned char *)big;
	rgn.length = sizeof(big);
	isc_nmhandle_attach(tcp_keep, &tcp_client_send);
	isc_nm_send(tcp_client_send, &rgn, tcp_client_send_cb, NULL);
	printf("  client sent 131072 bytes\n");
}

static void
tcp_conn2_connect_cb(isc_nmhandle_t *handle, isc_result_t eresult,
		     void *cbarg) {
	isc_nmsocket_t *sock = handle->sock;

	UNUSED(cbarg);

	if (eresult != ISC_R_SUCCESS) {
		printf("  connect cb: eresult=%s\n", SNAME(eresult));
		return;
	}

	rec_conn_peer = isc_nmhandle_peeraddr(handle);
	rec_conn_local = isc_nmhandle_localaddr(handle);
	rec_conn_refs = (int)(unsigned)isc_refcount_current(&handle->references);
	rec_conn_sock_refs = (int)(unsigned)isc_refcount_current(&sock->references);
	rec_conn_connected = sock->connected;
	rec_conn_ah = (uint32_t)sock->active_handles_cur;
	rec_conn_ready = 1;

	isc_nmhandle_attach(handle, &tcp_keep);
	isc_nm_read(handle, tcp_big_client_recv_cb, NULL);

	if (rec_conn_ready && rec_acc_ready) {
		rec_conn_ready = 0;
		rec_acc_ready = 0;
		next_job(tcp_print_pair, NULL);
		next_job(tcp_conn2_go, NULL);
	}
}

static void
phase8_conn2(void *arg) {
	isc_sockaddr_t local, peer;
	struct in_addr in;

	UNUSED(arg);

	printf("=== PHASE 8b: TCP large echo (uv_write path) ===\n");
	tcp_conn = 2;
	tcp_big_server_got = 0;
	tcp_big_client_got = 0;

	inet_pton(AF_INET, "127.0.0.1", &in);
	isc_sockaddr_fromin(&local, &in, 19161);
	isc_sockaddr_fromin(&peer, &in, 19154);
	isc_nm_tcpconnect(netmgr, &local, &peer, tcp_conn2_connect_cb, NULL,
			  5000);
}

/* --- connection 3: read_stop --- */

static int tcp_conn3_recv_calls = 0;

static void
tcp_conn3_server_recv_cb(isc_nmhandle_t *handle, isc_result_t eresult,
			 isc_region_t *region, void *cbarg) {
	UNUSED(region);
	UNUSED(cbarg);

	if (eresult != ISC_R_SUCCESS) {
		printf("  server recv: eresult=%s\n", SNAME(eresult));
		isc_nmhandle_detach(&handle);
		next_job(phase9_tcp_timeout, NULL);
		return;
	}

	printf("  server recv: data=\"%.*s\" (holding handle)\n",
	       (int)region->length, (char *)region->base);
	isc_nmhandle_attach(handle, &tcp_server_send);
}

static void
tcp_conn3_server_send_cb(isc_nmhandle_t *handle, isc_result_t eresult,
			 void *cbarg) {
	UNUSED(eresult);
	UNUSED(cbarg);

	printf("  server send cb: eresult=%s handle refs=%u\n", SNAME(eresult),
	       (unsigned)isc_refcount_current(&handle->references));
	isc_nmhandle_detach(&tcp_server_send);
	next_job(tcp_conn3_recheck, NULL);
}

static void
tcp_conn3_server_send(void *arg) {
	isc_region_t rgn;
	static char stop1[8] = { 'S', 'T', 'O', 'P', '1', 0, 0, 0 };

	UNUSED(arg);

	rgn.base = (unsigned char *)stop1;
	rgn.length = 5;
	isc_nm_send(tcp_server_send, &rgn, tcp_conn3_server_send_cb, NULL);
	printf("  server sent \"STOP1\"\n");
}

static void
tcp_conn3_stop_read(void *arg) {
	UNUSED(arg);

	isc_nm_read_stop(tcp_keep);
	printf("  client read_stop ok\n");

	next_job(tcp_conn3_server_send, NULL);
}

static void
tcp_conn3_client_send_cb(isc_nmhandle_t *handle, isc_result_t eresult,
			 void *cbarg) {
	UNUSED(eresult);
	UNUSED(cbarg);

	printf("  client send cb: eresult=%s handle refs=%u\n", SNAME(eresult),
	       (unsigned)isc_refcount_current(&handle->references));
	isc_nmhandle_detach(&tcp_client_send);
	next_job(tcp_conn3_stop_read, NULL);
}

static void
tcp_conn3_client_recv_cb(isc_nmhandle_t *handle, isc_result_t eresult,
			 isc_region_t *region, void *cbarg) {
	UNUSED(cbarg);

	tcp_conn3_recv_calls++;
	printf("  client recv: eresult=%s data=\"%.*s\" calls=%d\n",
	       SNAME(eresult), (int)region->length, (char *)region->base,
	       tcp_conn3_recv_calls);
	if (eresult == ISC_R_SUCCESS && region->length == 5 &&
	    memcmp(region->base, "STOP1", 5) == 0)
	{
		isc_nmhandle_close(tcp_keep);
		isc_nmhandle_detach(&tcp_keep);
		tcp_keep = NULL;
		printf("  client handle closed\n");
	}
}

static void
tcp_conn3_recheck(void *arg) {
	UNUSED(arg);

	printf("  state: client recv calls=%d (read stopped)\n",
	       tcp_conn3_recv_calls);
	isc_nm_read(tcp_keep, tcp_conn3_client_recv_cb, NULL);
	printf("  client re-read: data arrives\n");
}

static void
tcp_conn3_go(void *arg) {
	isc_region_t rgn;
	static char msg[16];

	UNUSED(arg);

	snprintf(msg, sizeof(msg), "stop-test");
	rgn.base = (unsigned char *)msg;
	rgn.length = (unsigned)strlen(msg);
	isc_nmhandle_attach(tcp_keep, &tcp_client_send);
	isc_nm_send(tcp_client_send, &rgn, tcp_conn3_client_send_cb, NULL);
	printf("  client sent \"stop-test\"\n");
}

static void
tcp_conn3_client_connect_cb(isc_nmhandle_t *handle, isc_result_t eresult,
			    void *cbarg) {
	isc_nmsocket_t *sock = handle->sock;

	UNUSED(cbarg);

	if (eresult != ISC_R_SUCCESS) {
		printf("  connect cb: eresult=%s\n", SNAME(eresult));
		return;
	}

	rec_conn_peer = isc_nmhandle_peeraddr(handle);
	rec_conn_local = isc_nmhandle_localaddr(handle);
	rec_conn_refs = (int)(unsigned)isc_refcount_current(&handle->references);
	rec_conn_sock_refs = (int)(unsigned)isc_refcount_current(&sock->references);
	rec_conn_connected = sock->connected;
	rec_conn_ah = (uint32_t)sock->active_handles_cur;
	rec_conn_ready = 1;

	isc_nmhandle_attach(handle, &tcp_keep);
	isc_nm_read(handle, tcp_conn3_client_recv_cb, NULL);

	if (rec_conn_ready && rec_acc_ready) {
		rec_conn_ready = 0;
		rec_acc_ready = 0;
		next_job(tcp_print_pair, NULL);
		next_job(tcp_conn3_go, NULL);
	}
}

static void
phase8_conn3(void *arg) {
	isc_sockaddr_t local, peer;
	struct in_addr in;

	UNUSED(arg);

	printf("=== PHASE 8c: TCP read_stop ===\n");
	tcp_conn = 3;
	tcp_conn3_recv_calls = 0;

	inet_pton(AF_INET, "127.0.0.1", &in);
	isc_sockaddr_fromin(&local, &in, 19162);
	isc_sockaddr_fromin(&peer, &in, 19154);
	isc_nm_tcpconnect(netmgr, &local, &peer, tcp_conn3_client_connect_cb,
			  NULL, 5000);
}

/* --- connection 1: connect + accept callbacks (used by phase 8) --- */

static void
tcp_connect_cb(isc_nmhandle_t *handle, isc_result_t eresult, void *cbarg) {
	isc_nmsocket_t *sock = handle->sock;

	UNUSED(cbarg);

	if (eresult != ISC_R_SUCCESS) {
		printf("  connect cb: eresult=%s\n", SNAME(eresult));
		return;
	}

	rec_conn_peer = isc_nmhandle_peeraddr(handle);
	rec_conn_local = isc_nmhandle_localaddr(handle);
	rec_conn_refs = (int)(unsigned)isc_refcount_current(&handle->references);
	rec_conn_sock_refs = (int)(unsigned)isc_refcount_current(&sock->references);
	rec_conn_connected = sock->connected;
	rec_conn_ah = (uint32_t)sock->active_handles_cur;
	rec_conn_ready = 1;

	isc_nmhandle_attach(handle, &tcp_keep);
	isc_nm_read(handle, tcp_client_recv_cb, NULL);

	if (rec_conn_ready && rec_acc_ready) {
		rec_conn_ready = 0;
		rec_acc_ready = 0;
		next_job(tcp_print_pair, NULL);
		next_job(tcp_conn1_go, NULL);
	}
}

static isc_result_t
tcp_accept_cb(isc_nmhandle_t *handle, isc_result_t eresult, void *cbarg) {
	isc_nmhandle_t *readhandle = NULL;

	UNUSED(cbarg);

	if (eresult != ISC_R_SUCCESS) {
		return eresult;
	}

	rec_acc_peer = isc_nmhandle_peeraddr(handle);
	rec_acc_local = isc_nmhandle_localaddr(handle);
	rec_acc_ah = (uint32_t)handle->sock->active_handles_cur;
	rec_acc_client = handle->sock->client;
	rec_acc_ready = 1;

	isc_nmhandle_attach(handle, &readhandle);
	switch (tcp_conn) {
	case 1:
		isc_nm_read(handle, tcp_server_recv_cb, readhandle);
		break;
	case 2:
		isc_nm_read(handle, tcp_big_server_recv_cb, readhandle);
		break;
	case 3:
		isc_nm_read(handle, tcp_conn3_server_recv_cb, readhandle);
		break;
	case 4:
		isc_nm_read(handle, tcp_timeout_server_recv_cb, readhandle);
		break;
	default:
		break;
	}

	return ISC_R_SUCCESS;
}

static void
phase8_tcp(void *arg) {
	isc_sockaddr_t iface, local, peer;
	struct in_addr in;
	isc_result_t r;

	UNUSED(arg);

	printf("=== PHASE 8: TCP echo (LISTEN_ONE) ===\n");

	inet_pton(AF_INET, "127.0.0.1", &in);
	isc_sockaddr_fromin(&iface, &in, 19154);

	r = isc_nm_listentcp(netmgr, ISC_NM_LISTEN_ONE, &iface, tcp_accept_cb,
			     NULL, 10, NULL, &tcp_listen_sock);
	printf("listentcp(workers=1, 127.0.0.1#19154, backlog=10) -> %s\n",
	       SNAME(r));
	if (r != ISC_R_SUCCESS) {
		return;
	}
	printf("  server type=%s active=%s closing=%s closed=%s nchildren=%u\n",
	       STYPE(tcp_listen_sock->type),
	       tcp_listen_sock->active ? "true" : "false",
	       tcp_listen_sock->closing ? "true" : "false",
	       tcp_listen_sock->closed ? "true" : "false",
	       (unsigned)tcp_listen_sock->nchildren);
	for (uint32_t i = 0; i < tcp_listen_sock->nchildren; i++) {
		printf("  child[%u]: tid=%u result=%s\n", i,
		       (unsigned)tcp_listen_sock->children[i].tid,
		       SNAME(tcp_listen_sock->children[i].result));
	}

	tcp_conn = 1;
	isc_sockaddr_fromin(&local, &in, 19160);
	isc_sockaddr_fromin(&peer, &in, 19154);
	isc_nm_tcpconnect(netmgr, &local, &peer, tcp_connect_cb, NULL, 5000);
}

/* ------------------------------------------------------------------ */
/* phase 9: TCP read timeout                                           */
/* ------------------------------------------------------------------ */

static void
tcp_timeout_server_recv_cb(isc_nmhandle_t *handle, isc_result_t eresult,
			   isc_region_t *region, void *cbarg) {
	UNUSED(region);
	UNUSED(cbarg);

	if (eresult != ISC_R_SUCCESS) {
		printf("  server recv: eresult=%s\n", SNAME(eresult));
		isc_nmhandle_detach(&handle);
		return;
	}
	printf("  server recv: data=\"%.*s\" (no reply)\n",
	       (int)region->length, (char *)region->base);
}

static void
tcp_timeout_recv_cb(isc_nmhandle_t *handle, isc_result_t eresult,
		    isc_region_t *region, void *cbarg) {
	UNUSED(region);
	UNUSED(cbarg);

	printf("  client recv: eresult=%s handle refs=%u\n", SNAME(eresult),
	       (unsigned)isc_refcount_current(&handle->references));
	if (eresult == ISC_R_TIMEDOUT) {
		isc_nmhandle_detach(&tcp_keep);
		tcp_keep = NULL;
		next_job(phase10_refused, NULL);
	}
}

static void
tcp_timeout_connect_cb(isc_nmhandle_t *handle, isc_result_t eresult,
		       void *cbarg) {
	isc_nmsocket_t *sock = handle->sock;
	isc_region_t rgn;
	static char msg[16];

	UNUSED(cbarg);

	if (eresult != ISC_R_SUCCESS) {
		printf("  connect cb: eresult=%s\n", SNAME(eresult));
		return;
	}

	rec_conn_peer = isc_nmhandle_peeraddr(handle);
	rec_conn_local = isc_nmhandle_localaddr(handle);
	rec_conn_refs = (int)(unsigned)isc_refcount_current(&handle->references);
	rec_conn_sock_refs = (int)(unsigned)isc_refcount_current(&sock->references);
	rec_conn_connected = sock->connected;
	rec_conn_ah = (uint32_t)sock->active_handles_cur;
	rec_conn_ready = 1;

	isc_nmhandle_attach(handle, &tcp_keep);
	isc_nmhandle_settimeout(handle, 50);
	isc_nm_read(handle, tcp_timeout_recv_cb, NULL);
	snprintf(msg, sizeof(msg), "slow");
	rgn.base = (unsigned char *)msg;
	rgn.length = (unsigned)strlen(msg);
	isc_nmhandle_attach(handle, &tcp_client_send);
	isc_nm_send(tcp_client_send, &rgn, tcp_client_send_cb, NULL);
	printf("  client sent \"slow\" (read timeout=50ms)\n");

	if (rec_conn_ready && rec_acc_ready) {
		rec_conn_ready = 0;
		rec_acc_ready = 0;
		next_job(tcp_print_pair, NULL);
	}
}

static void
phase9_tcp_timeout(void *arg) {
	isc_sockaddr_t local, peer;
	struct in_addr in;

	UNUSED(arg);

	printf("=== PHASE 9: TCP read timeout ===\n");
	tcp_conn = 4;

	inet_pton(AF_INET, "127.0.0.1", &in);
	isc_sockaddr_fromin(&local, &in, 19163);
	isc_sockaddr_fromin(&peer, &in, 19154);
	isc_nm_tcpconnect(netmgr, &local, &peer, tcp_timeout_connect_cb, NULL,
			  5000);
}

/* ------------------------------------------------------------------ */
/* phase 10: TCP connect refused                                       */
/* ------------------------------------------------------------------ */

static void
tcp_refused_connect_cb(isc_nmhandle_t *handle, isc_result_t eresult,
		       void *cbarg) {
	UNUSED(cbarg);

	printf("  connect cb: eresult=%s handle=%s refs=%u\n",
	       SNAME(eresult), handle != NULL ? "non-null" : "null",
	       handle != NULL ? (unsigned)isc_refcount_current(&handle->references) : 0);
	next_job(phase11_tcp_stop, NULL);
}

static void
phase10_refused(void *arg) {
	isc_sockaddr_t local, peer;
	struct in_addr in;

	UNUSED(arg);

	printf("=== PHASE 10: TCP connect refused ===\n");

	inet_pton(AF_INET, "127.0.0.1", &in);
	isc_sockaddr_fromin(&local, &in, 19164);
	isc_sockaddr_fromin(&peer, &in, 19159);
	isc_nm_tcpconnect(netmgr, &local, &peer, tcp_refused_connect_cb, NULL,
			  5000);
}

/* ------------------------------------------------------------------ */
/* phase 11: TCP stoplistening                                         */
/* ------------------------------------------------------------------ */

static void
phase11_tcp_stop(void *arg) {
	isc_nmsocket_t *sock = tcp_listen_sock;

	UNUSED(arg);

	printf("=== PHASE 11: TCP stoplistening ===\n");

	isc_nm_stoplistening(sock);
	printf("  stoplistening: parent active=%s closing=%s closed=%s\n",
	       sock->active ? "true" : "false",
	       sock->closing ? "true" : "false",
	       sock->closed ? "true" : "false");
	if (sock->nchildren > 0) {
		isc_nmsocket_t *c = &sock->children[0];
		printf("  child[0]: active=%s closing=%s closed=%s\n",
		       c->active ? "true" : "false",
		       c->closing ? "true" : "false",
		       c->closed ? "true" : "false");
	}

	isc_nmsocket_close(&tcp_listen_sock);
	printf("  nmsocket_close ok\n");

	next_job(phase12_udp, NULL);
}

/* ------------------------------------------------------------------ */
/* phase 12: load-balanced listeners (LISTEN_ALL)                      */
/* ------------------------------------------------------------------ */

static isc_nmsocket_t *lb_udp_sock;
static isc_nmsocket_t *lb_tcp_sock;
static isc_nmhandle_t *lb_keep;
static isc_nmhandle_t *lb_send;
static atomic_int_fast64_t lb_tcp_accepts = 0;
static int lb_udp_round = 0;
static int lb_tcp_round = 0;
static isc_region_t lb_send_region;

static void lb_udp_send_cb(isc_nmhandle_t *handle, isc_result_t eresult,
			   void *cbarg);
static void lb_tcp_connect_cb(isc_nmhandle_t *handle, isc_result_t eresult,
			      void *cbarg);
static void lb_tcp_send_cb(isc_nmhandle_t *handle, isc_result_t eresult,
			   void *cbarg);

static void
lb_udp_server_send_cb(isc_nmhandle_t *handle, isc_result_t eresult,
		      void *cbarg) {
	UNUSED(eresult);
	UNUSED(cbarg);

	isc_nmhandle_detach(&handle);
}

static void
lb_udp_recv_cb(isc_nmhandle_t *handle, isc_result_t eresult,
	       isc_region_t *region, void *cbarg) {
	isc_nmhandle_t *sendhandle = NULL;
	isc_region_t rgn;

	UNUSED(cbarg);

	if (eresult != ISC_R_SUCCESS) {
		return;
	}

	/* echo back, no prints (runs on any worker loop) */
	rgn.base = region->base;
	rgn.length = region->length;
	isc_nmhandle_attach(handle, &sendhandle);
	isc_nm_send(sendhandle, &rgn, lb_udp_server_send_cb, NULL);
}

static void
lb_udp_client_recv_cb(isc_nmhandle_t *handle, isc_result_t eresult,
		      isc_region_t *region, void *cbarg) {
	static char msg[8];
	isc_region_t rgn;

	UNUSED(cbarg);

	if (eresult != ISC_R_SUCCESS) {
		return;
	}
	printf("  client recv: data=\"%.*s\"\n", (int)region->length,
	       (char *)region->base);
	lb_udp_round++;
	if (lb_udp_round < 3) {
		isc_nm_read(handle, lb_udp_client_recv_cb, NULL);
		snprintf(msg, sizeof(msg), "lb-%d", lb_udp_round + 1);
		rgn.base = (unsigned char *)msg;
		rgn.length = (unsigned)strlen(msg);
		isc_nmhandle_attach(handle, &lb_send);
		isc_nm_send(lb_send, &rgn, lb_udp_send_cb, NULL);
		printf("  client sent \"%s\"\n", msg);
	} else {
		printf("  UDP load balance: echoes=%d\n", lb_udp_round);
		isc_nmhandle_detach(&lb_keep);
		lb_keep = NULL;
		isc_nm_stoplistening(lb_udp_sock);
		isc_nmsocket_close(&lb_udp_sock);
		lb_udp_sock = NULL;
		next_job(phase12_tcp, NULL);
	}
}

static void
lb_udp_send_cb(isc_nmhandle_t *handle, isc_result_t eresult, void *cbarg) {
	UNUSED(eresult);
	UNUSED(cbarg);

	isc_nmhandle_detach(&lb_send);
}

static void
lb_udp_connect_cb(isc_nmhandle_t *handle, isc_result_t eresult,
		  void *cbarg) {
	static char msg[8];
	isc_region_t rgn;

	UNUSED(cbarg);

	printf("  connect cb: eresult=%s\n", SNAME(eresult));
	if (eresult != ISC_R_SUCCESS) {
		return;
	}

	isc_nmhandle_attach(handle, &lb_keep);
	isc_nm_read(handle, lb_udp_client_recv_cb, NULL);

	snprintf(msg, sizeof(msg), "lb-1");
	rgn.base = (unsigned char *)msg;
	rgn.length = (unsigned)strlen(msg);
	isc_nmhandle_attach(handle, &lb_send);
	isc_nm_send(lb_send, &rgn, lb_udp_send_cb, NULL);
	printf("  client sent \"lb-1\"\n");
}

static void
phase12_udp(void *arg) {
	isc_sockaddr_t iface, local, peer;
	struct in_addr in;

	UNUSED(arg);

	printf("=== PHASE 12: load-balanced listeners (LISTEN_ALL) ===\n");
	printf("  UDP listen: ");

	inet_pton(AF_INET, "127.0.0.1", &in);
	isc_sockaddr_fromin(&iface, &in, 19165);

	if (isc_nm_listenudp(netmgr, ISC_NM_LISTEN_ALL, &iface,
			     lb_udp_recv_cb, NULL, &lb_udp_sock) !=
	    ISC_R_SUCCESS)
	{
		printf("listenudp failed\n");
		return;
	}
	printf("success nchildren=%u child tids: ",
	       (unsigned)lb_udp_sock->nchildren);
	for (uint32_t i = 0; i < lb_udp_sock->nchildren; i++) {
		printf("%u ", (unsigned)lb_udp_sock->children[i].tid);
	}
	printf("\n");

	lb_udp_round = 0;
	isc_sockaddr_fromin(&local, &in, 19166);
	isc_sockaddr_fromin(&peer, &in, 19165);
	isc_nm_udpconnect(netmgr, &local, &peer, lb_udp_connect_cb, NULL,
			  5000);
}

/* TCP load balance */
static void lb_tcp_conn_go(void *arg);

static void
lb_tcp_client_recv_cb(isc_nmhandle_t *handle, isc_result_t eresult,
		      isc_region_t *region, void *cbarg) {
	UNUSED(cbarg);

	if (eresult != ISC_R_SUCCESS) {
		return;
	}
	printf("  client recv: data=\"%.*s\"\n", (int)region->length,
	       (char *)region->base);
	lb_tcp_round++;
	if (lb_tcp_round < 4) {
		isc_nmhandle_close(lb_keep);
		isc_nmhandle_detach(&lb_keep);
		lb_keep = NULL;
		lb_tcp_conn_go(NULL);
	} else {
		printf("  TCP load balance: connects=%d echoes=%d "
		       "accepts=%" PRIdFAST64 "\n",
		       lb_tcp_round, lb_tcp_round,
		       atomic_load(&lb_tcp_accepts));
		isc_nmhandle_close(lb_keep);
		isc_nmhandle_detach(&lb_keep);
		lb_keep = NULL;
		isc_nm_stoplistening(lb_tcp_sock);
		isc_nmsocket_close(&lb_tcp_sock);
		lb_tcp_sock = NULL;
		next_job(phase13_teardown, NULL);
	}
}

static void
lb_tcp_conn_go(void *arg) {
	isc_sockaddr_t local, peer;
	struct in_addr in;
	static char msg[8];
	isc_region_t rgn;

	UNUSED(arg);

	inet_pton(AF_INET, "127.0.0.1", &in);
	isc_sockaddr_fromin(&local, &in, (in_port_t)(19170 + lb_tcp_round));
	isc_sockaddr_fromin(&peer, &in, 19167);

	snprintf(msg, sizeof(msg), "lt-%d", lb_tcp_round + 1);
	rgn.base = (unsigned char *)msg;
	rgn.length = (unsigned)strlen(msg);
	lb_send_region = rgn;

	printf("  client connect %d (local=127.0.0.1#%u -> "
	       "127.0.0.1#19167)\n",
	       lb_tcp_round + 1, (unsigned)(19170 + lb_tcp_round));
	isc_nm_tcpconnect(netmgr, &local, &peer, lb_tcp_connect_cb, NULL,
			  5000);
}

static void
lb_tcp_connect_cb(isc_nmhandle_t *handle, isc_result_t eresult,
		  void *cbarg) {
	UNUSED(cbarg);

	printf("  connect cb %d: eresult=%s\n", lb_tcp_round + 1,
	       SNAME(eresult));
	if (eresult != ISC_R_SUCCESS) {
		return;
	}

	isc_nmhandle_attach(handle, &lb_keep);
	isc_nm_read(handle, lb_tcp_client_recv_cb, NULL);
	isc_nmhandle_attach(handle, &lb_send);
	isc_nm_send(lb_send, &lb_send_region, lb_tcp_send_cb, NULL);
	printf("  client sent \"%.*s\"\n", (int)lb_send_region.length,
	       (char *)lb_send_region.base);
}

static void
lb_tcp_send_cb(isc_nmhandle_t *handle, isc_result_t eresult, void *cbarg) {
	UNUSED(eresult);
	UNUSED(cbarg);

	isc_nmhandle_detach(&lb_send);
}

static void
lb_tcp_server_send_cb(isc_nmhandle_t *handle, isc_result_t eresult,
		      void *cbarg) {
	UNUSED(eresult);
	UNUSED(cbarg);

	isc_nmhandle_detach(&handle);
}

static void
lb_tcp_server_recv_cb(isc_nmhandle_t *handle, isc_result_t eresult,
		      isc_region_t *region, void *cbarg) {
	isc_nmhandle_t *sendhandle = NULL;
	isc_region_t rgn;
	static char echo[8];

	UNUSED(cbarg);

	if (eresult != ISC_R_SUCCESS) {
		isc_nmhandle_detach(&handle);
		return;
	}

	/* echo (uppercase first byte), no prints */
	memcpy(echo, region->base, (size_t)region->length);
	((char *)echo)[0] = (char)(((char *)echo)[0] ^ 0x20);
	rgn.base = (unsigned char *)echo;
	rgn.length = (unsigned)region->length;
	isc_nmhandle_attach(handle, &sendhandle);
	isc_nm_send(sendhandle, &rgn, lb_tcp_server_send_cb, NULL);
}

static isc_result_t
lb_tcp_accept_cb(isc_nmhandle_t *handle, isc_result_t eresult, void *cbarg) {
	isc_nmhandle_t *readhandle = NULL;

	UNUSED(cbarg);

	if (eresult != ISC_R_SUCCESS) {
		return eresult;
	}

	atomic_fetch_add(&lb_tcp_accepts, 1);

	isc_nmhandle_attach(handle, &readhandle);
	isc_nm_read(handle, lb_tcp_server_recv_cb, readhandle);

	return ISC_R_SUCCESS;
}

static void
phase12_tcp(void *arg) {
	isc_sockaddr_t iface;
	struct in_addr in;

	UNUSED(arg);

	printf("  TCP listen: ");

	inet_pton(AF_INET, "127.0.0.1", &in);
	isc_sockaddr_fromin(&iface, &in, 19167);

	if (isc_nm_listentcp(netmgr, ISC_NM_LISTEN_ALL, &iface,
			     lb_tcp_accept_cb, NULL, 10, NULL,
			     &lb_tcp_sock) != ISC_R_SUCCESS)
	{
		printf("listentcp failed\n");
		return;
	}
	printf("success nchildren=%u child tids: ",
	       (unsigned)lb_tcp_sock->nchildren);
	for (uint32_t i = 0; i < lb_tcp_sock->nchildren; i++) {
		printf("%u ", (unsigned)lb_tcp_sock->children[i].tid);
	}
	printf("\n");

	lb_tcp_round = 0;
	lb_tcp_conn_go(NULL);
}

/* ------------------------------------------------------------------ */
/* phase 13: teardown                                                  */
/* ------------------------------------------------------------------ */

static void
loop0_teardown(void *arg) {
	UNUSED(arg);
	printf("loop 0 teardown cb\n");
}

static void
phase13_teardown(void *arg) {
	UNUSED(arg);
	printf("=== PHASE 13: teardown ===\n");
	isc_loopmgr_shutdown(loopmgr);
}

/* ------------------------------------------------------------------ */
/* main                                                                */
/* ------------------------------------------------------------------ */

int
main(void) {
	isc_mem_create(&mctx);

	printf("=== PHASE 1: netmgr lifecycle ===\n");
	printf("main: isc_mem_create ok\n");

	isc_loopmgr_create(mctx, 3, &loopmgr);
	printf("main: isc_loopmgr_create(3) ok\n");

	isc_netmgr_create(mctx, loopmgr, &netmgr);
	printf("main: isc_netmgr_create ok\n");

	mainloop = isc_loop_main(loopmgr);

	isc_loop_setup(mainloop, phase1_setup, NULL);
	isc_loop_teardown(mainloop, loop0_teardown, NULL);

	isc_loopmgr_run(loopmgr);
	printf("main: isc_loopmgr_run returned\n");

	isc_loopmgr_destroy(&loopmgr);
	printf("main: isc_loopmgr_destroy ok\n");

	isc_netmgr_destroy(&netmgr);
	printf("main: isc_netmgr_destroy ok\n");

	isc_mem_destroy(&mctx);
	printf("main: isc_mem_destroy ok\n");

	return 0;
}
