#include <config.h>
#include <time.h>
#include <unistd.h>
#include <errno.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <sys/poll.h>
#include <netinet/in.h>
#include <string.h>
#include <assert.h>
#include <errno.h>

#include "common/sockaddr.h"
#include "knot/common.h"
#include "knot/other/error.h"
#include "knot/server/udp-handler.h"
#include "libknot/nameserver/name-server.h"
#include "knot/stat/stat.h"
#include "knot/server/server.h"
#include "libknot/util/wire.h"
#include "libknot/consts.h"
#include "libknot/packet/packet.h"
#include "knot/server/zones.h"
#include "knot/server/notify.h"


static inline int udp_handle(int fd, uint8_t *qbuf, size_t qbuflen,
			     sockaddr_t* addr, knot_nameserver_t *ns,
			     stat_t* thread_stat)
{
	/* faddr has to be read immediately. */
	stat_get_first(thread_stat, addr->ptr);

	debug_net("udp: received %zd bytes.\n", qbuflen);

	knot_packet_type_t qtype = KNOT_QUERY_NORMAL;
	size_t resp_len = SOCKET_MTU_SZ;

	//knot_response_t *resp = knot_response_new(4 * 1024); // 4K
	knot_packet_t *packet =
		knot_packet_new(KNOT_PACKET_PREALLOC_QUERY);
	if (packet == NULL) {
		uint16_t pkt_id = knot_wire_get_id(qbuf);
		knot_ns_error_response(ns, pkt_id, KNOT_RCODE_SERVFAIL,
				  qbuf, &resp_len);
		return KNOTD_ENOMEM;
	}

	/* Parse query. */
	int res = knot_ns_parse_packet(qbuf, qbuflen, packet, &qtype);
	if (unlikely(res != KNOTD_EOK)) {
		debug_net("udp: sending back error response.\n");
		/* Send error response on dnslib RCODE. */
		if (res > 0) {
			uint16_t pkt_id = knot_wire_get_id(qbuf);
			knot_ns_error_response(ns, pkt_id, res,
					  qbuf, &resp_len);
		}

		knot_packet_free(&packet);
		return KNOTD_ERROR;
	}

	/* Handle query. */
	res = KNOTD_ERROR;
	switch(qtype) {

	/* Response types. */
	case KNOT_RESPONSE_NORMAL:
		res = zones_process_response(ns, addr, packet,
					     qbuf, &resp_len);
//			res = knot_ns_process_response();
		break;
	case KNOT_RESPONSE_AXFR:
	case KNOT_RESPONSE_IXFR:
	case KNOT_RESPONSE_NOTIFY:
		res = notify_process_response(ns, packet, addr,
					      qbuf, &resp_len);
		break;

	/* Query types. */
	case KNOT_QUERY_NORMAL:
		res = knot_ns_answer_normal(ns, packet, qbuf,
					      &resp_len);
		break;
	case KNOT_QUERY_AXFR:
	case KNOT_QUERY_IXFR:
		/*! \todo Send error, not available on UDP. */
		break;
	case KNOT_QUERY_NOTIFY:
//		rcu_read_lock();
//			const knot_zone_t *zone = NULL;
//			res = knot_ns_answer_notify(ns, packet, qbuf,
//			                              &resp_len, &zone);
		res = notify_process_request(ns, packet, addr,
					     qbuf, &resp_len);
//			if (res == KNOT_EOK) {
//				res = zones_notify_schedule(zone, &addr);
//			}
		break;
	case KNOT_QUERY_UPDATE:
		/*! \todo Implement query notify/update. */
		break;
	}

	knot_packet_free(&packet);

	/* Send answer. */
	if (res == KNOTD_EOK && resp_len > 0) {

		debug_net("udp: got answer of size %zd.\n", resp_len);

		//debug_net("udp: answer wire format (size %zd):\n",
		//	  resp_len);
		//debug_net_hex((const char *) outbuf, resp_len);

		// Send datagram
		res = sendto(fd, qbuf, resp_len,
			     0, addr->ptr, addr->len);

		// Check result
		if (res != (int)resp_len) {
			debug_net("udp: %s: failed: %d - %d.\n",
				  "socket_sendto()",
				  res, errno);
			return KNOTD_ERROR;
		}

		stat_get_second(thread_stat);
	}

	return KNOTD_EOK;
}

static inline int udp_master_recvfrom(dthread_t *thread, stat_t *thread_stat)
{
	iohandler_t *h = (iohandler_t *)thread->data;
	knot_nameserver_t *ns = h->server->nameserver;
	int sock = dup(h->fd);

	sockaddr_t addr;
	if (sockaddr_init(&addr, h->type) != KNOTD_EOK) {
		log_server_error("Socket type %d is not supported, "
				 "IPv6 support is probably disabled.\n",
				 h->type);
		return KNOTD_ENOTSUP;
	}


	/* Loop until all data is read. */
	ssize_t n = 0;
	uint8_t qbuf[SOCKET_MTU_SZ];
	while (n >= 0) {

		/* Receive packet. */
		n = recvfrom(sock, qbuf, sizeof(qbuf), 0,
			     addr.ptr, &addr.len);

		/* Cancellation point. */
		if (dt_is_cancelled(thread)) {
			break;
		}

		/* Error and interrupt handling. */
		if (unlikely(n <= 0)) {
			if (errno != EINTR && errno != 0) {
				debug_net("udp: recvfrom() failed: %d\n",
					  errno);
			}

			if (!(h->state & ServerRunning)) {
				debug_net("udp: stopping\n");
				break;
			} else {
				continue;
			}
		}

		/* Handle received pkt. */
		udp_handle(sock, qbuf, n, &addr, ns, thread_stat);
	}

	/* Free allocd resources. */
	close(sock);
}

static inline int udp_master_recvmmsg(dthread_t *thread, stat_t *thread_stat)
{
#ifdef MSG_WAITFORONE
	iohandler_t *h = (iohandler_t *)thread->data;
	knot_nameserver_t *ns = h->server->nameserver;
	int sock = dup(h->fd);

	/* Allocate batch for N packets. */
	char *iobuf = malloc(SOCKET_MTU_SZ * RECVMMSG_BATCHLEN);
	sockaddr_t *addrs = malloc(sizeof(sockaddr_t) * RECVMMSG_BATCHLEN);
	struct iovec *iov = malloc(sizeof(struct iovec) * RECVMMSG_BATCHLEN);
	struct mmsghdr *msgs = malloc(sizeof(struct mmsghdr) * RECVMMSG_BATCHLEN);

	/* Prepare batch. */
	memset(msgs, 0, sizeof(struct mmsghdr) * RECVMMSG_BATCHLEN);
	for (unsigned i = 0; i < RECVMMSG_BATCHLEN; ++i) {
		sockaddr_init(addrs + i, h->type);
		iov[i].iov_base = iobuf + i * SOCKET_MTU_SZ;
		iov[i].iov_len = SOCKET_MTU_SZ;
		msgs[i].msg_hdr.msg_iov = iov + i;
		msgs[i].msg_hdr.msg_iovlen = 1;
		msgs[i].msg_hdr.msg_name = addrs[i].ptr;
		msgs[i].msg_hdr.msg_namelen = addrs[i].len;
	}

	/* Loop until all data is read. */
	ssize_t n = 0;
	while (n >= 0) {

		/* Receive multiple messages. */
		n = recvmmsg(sock, msgs, RECVMMSG_BATCHLEN, MSG_WAITFORONE, 0);

		/* Cancellation point. */
		if (dt_is_cancelled(thread)) {
			break;
		}

		/* Error and interrupt handling. */
		if (unlikely(n <= 0)) {
			if (errno != EINTR && errno != 0) {
				debug_net("udp: recvmmsg() failed: %d\n",
					  errno);
			}

			if (!(h->state & ServerRunning)) {
				debug_net("udp: stopping\n");
				break;
			} else {
				continue;
			}
		}

		/* Handle each received msg. */
		for (unsigned i = 0; i < n; ++i) {
			struct iovec *cvec = msgs[i].msg_hdr.msg_iov;
			udp_handle(sock, cvec->iov_base, msgs[i].msg_len,
				   addrs + i, ns, thread_stat);
		}
	}

	/* Free allocd resources. */
	free(iobuf);
	free(addrs);
	free(iov);
	free(msgs);
	close(sock);

	return KNOTD_EOK;
#endif
}

int udp_master(dthread_t *thread)
{
	iohandler_t *handler = (iohandler_t *)thread->data;
	int sock = handler->fd;

	/* Check socket. */
	if (sock < 0) {
		debug_net("udp_master: null socket recevied, finishing.\n");
		return KNOTD_EINVAL;
	}

	/* Set socket options. */
	int flag = 1;
#ifndef DISABLE_IPV6
	if (handler->type == AF_INET6) {
		/* Disable dual-stack for performance reasons. */
		setsockopt(sock, IPPROTO_IPV6, IPV6_V6ONLY, &flag, sizeof(flag));

		/* UDP packets will not exceed a minimum MTU size. */
		/*flag = IPV6_MIN_MTU;
		setsockopt(fd, IPPROTO_IPV6, IPV6_MTU, &flag, sizeof(flag));
		flag = 1; */
	}
#endif
	if (handler->type == AF_INET) {

#ifdef IP_PMTUDISC_DONT
		/* Disable fragmentation. */
		flag = IP_PMTUDISC_DONT;
		setsockopt(sock, IPPROTO_IP, IP_MTU_DISCOVER, &flag, sizeof(flag));
		flag = 1;
#endif
	}

	/* in case of STAT_COMPILE the following code will declare thread_stat
	 * variable in following fashion: stat_t *thread_stat;
	 */

	stat_t *thread_stat = 0;
	STAT_INIT(thread_stat); //XXX new stat instance every time.
	stat_set_protocol(thread_stat, stat_UDP);

	/* Execute proper handler. */
	debug_net("udp: thread started (worker %p).\n", thread);
	int ret = KNOTD_EOK;

#ifdef MSG_WAITFORONE
	ret = udp_master_recvmmsg(thread, thread_stat);
#else
	ret = udp_master_recvfrom(thread, thread_stat);
#endif


	stat_free(thread_stat);
	debug_net("udp: worker %p finished.\n", thread);
	return KNOTD_EOK;
}

