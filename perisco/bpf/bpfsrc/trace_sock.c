#include "../libbpf/vmlinux.h"
#include "../libbpf/bpf_helpers.h"
#include "../libbpf/bpf_tracing.h"
#include "../libbpf/bpf_endian.h"

#include "trace_sock.h"


char LICENSE[] SEC("license") = "Dual BSD/GPL";


struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key, struct sock_key);
	__type(value, struct conn_info);
	__uint(max_entries, 1024);
} conn_info_map SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 256 * 1024);
} conn_events SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 256 * 1024);
} close_events SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 256 * 4096);
} data_events SEC(".maps");

// static __always_inline bool is_v4_loopback(__u32 addr)
// {
// 	/* Check for 127.0.0.0/8 range, RFC3330. */
// 	return (addr & bpf_htonl(0x7f000000)) == bpf_htonl(0x7f000000);
// }

// static __always_inline bool is_sk_v4_loopback(const struct sock *sk)
// {
// 	return is_v4_loopback(sk->__sk_common.skc_rcv_saddr) || is_v4_loopback(sk->__sk_common.skc_daddr);
// }

// static __always_inline void sk_extract4_key(const struct sock *sk,
// 					    struct sock_key *key)
// {
// 	key->sip.ip4.addr = sk->__sk_common.skc_rcv_saddr;
// 	key->dip.ip4.addr = sk->__sk_common.skc_daddr;

// 	key->sport = sk->__sk_common.skc_num;
// 	key->dport = bpf_ntohs(sk->__sk_common.skc_dport);

// 	key->family = AF_INET;
// }

static __always_inline void sk_extract_key(const struct sock *sk,
					    struct sock_key *key)
{
	key->sport = sk->__sk_common.skc_num;
	key->dport = bpf_ntohs(sk->__sk_common.skc_dport);
	key->family = sk->__sk_common.skc_family;
	
	if (key->family == AF_INET) {
		key->sip.ip4.addr = sk->__sk_common.skc_rcv_saddr;
		key->dip.ip4.addr = sk->__sk_common.skc_daddr;
	} else if (key->family == AF_INET6) {
		bpf_probe_read(key->sip.ip6.addr, sizeof(key->sip.ip6.addr), sk->__sk_common.skc_v6_rcv_saddr.in6_u.u6_addr8);
		bpf_probe_read(key->dip.ip6.addr, sizeof(key->dip.ip6.addr), sk->__sk_common.skc_v6_daddr.in6_u.u6_addr8);
	} 
}

SEC("fexit/inet_accept")
int BPF_PROG(inet_accept, struct socket *sock,
				      struct socket *newsock, int flags, bool kern, long ret) {
	if (ret < 0)
		return 0;
	
	u16 family = newsock->sk->__sk_common.skc_family;
	if (family != AF_INET && family != AF_INET6)
		return 0;
	// if (is_sk_v4_loopback(newsock->sk))
	// 	return 0;

	struct conn_event *conn_event = NULL;
	conn_event = bpf_ringbuf_reserve(&conn_events, sizeof(struct conn_event), 0);
	if (!conn_event)
		return 0;

	// sk_extract4_key(newsock->sk, &conn_event->sock_key);
	sk_extract_key(newsock->sk, &conn_event->sock_key);
	conn_event->endpoint_role = kRoleServer;

	struct conn_info conn_info = {};
	conn_info.sock_key = conn_event->sock_key;
	conn_info.endpoint_role = conn_event->endpoint_role;
	bpf_map_update_elem(&conn_info_map, &conn_info.sock_key, &conn_info, BPF_ANY);
	
	bpf_ringbuf_submit(conn_event, 0);

	return 0;
}

SEC("fexit/tcp_connect")
int BPF_PROG(tcp_connect, struct sock *sock, long ret) {
	if (ret < 0)
		return 0;

	u16 family = sock->__sk_common.skc_family;
	if (family != AF_INET && family != AF_INET6)
		return 0;
	// if (is_sk_v4_loopback(sock))
	// 	return 0;

	struct conn_event *conn_event = NULL;
	conn_event = bpf_ringbuf_reserve(&conn_events, sizeof(struct conn_event), 0);
	if (!conn_event)
		return 0;

	// sk_extract4_key(sock, &conn_event->sock_key);
	sk_extract_key(sock, &conn_event->sock_key);
	conn_event->endpoint_role = kRoleClient;

	struct conn_info conn_info = {};
	conn_info.sock_key = conn_event->sock_key;
	conn_info.endpoint_role = conn_event->endpoint_role;
	bpf_map_update_elem(&conn_info_map, &conn_info.sock_key, &conn_info, BPF_ANY);

	bpf_ringbuf_submit(conn_event, 0);

	return 0;
}

static __always_inline void copy_data_from_msghdr(struct iov_iter *iter, struct conn_info *conn_info, enum direction_type direction) {
	if (iter->iov_offset != 0 || iter->count == 0) {
		return;
	}

	size_t copyed = 0;

	struct data_event *event = bpf_ringbuf_reserve(&data_events, sizeof(struct data_event), 0);
	if (event != NULL) {
		event->sock_key = conn_info->sock_key;
		event->endpoint_role = conn_info->endpoint_role;

		// direction	role		msg
		// egress(0)	client(0)	request(0)
		// egress(0)	server(1)	response(1)
		// ingress(1)	client(0)	response(1)
		// ingress(1)	server(1)	request(0)
		event->msg_type = direction ^ conn_info->endpoint_role;
		if (conn_info->endpoint_role == kRoleUnknown)
			event->msg_type = kUnknown;

		#pragma unroll
		for(int i = 0; i < 10; i++) {
			if (i >= iter->nr_segs)
				break;

			struct kvec iov;
			bpf_probe_read(&iov, sizeof(iov), &(iter->kvec[i]));
			
			size_t remaining = MAX_MSG_SIZE - copyed;
			if (remaining <= 0)
				break;
			size_t to_copy = iov.iov_len;
			if (to_copy > remaining)
				to_copy = remaining;

			bpf_probe_read(event->msg+copyed, to_copy, iov.iov_base);
			event->msg_size += to_copy;
		}
		bpf_ringbuf_submit(event, 0);
	}
}

SEC("fentry/tcp_sendmsg")
int BPF_PROG(tcp_sendmsg, struct sock *sk, struct msghdr *msg, size_t size) {

	struct sock_key sk_key = {};
	// sk_extract4_key(sk, &sk_key);
	sk_extract_key(sk, &sk_key);

	struct conn_info *conn_info = bpf_map_lookup_elem(&conn_info_map, &sk_key);
	if (conn_info == NULL)
		return 0;

	copy_data_from_msghdr(&msg->msg_iter, conn_info, egress);
	
	conn_info->send_bytes += size;
	bpf_map_update_elem(&conn_info_map, &conn_info->sock_key, conn_info, BPF_ANY);

	return 0;
}

static __always_inline void submit_data_event(const char *msg, size_t size, struct conn_info *conn_info, enum direction_type direction, int ret,
		u64 nr_segs, u32 count, u32 iov_offset, u32 iov_idx) {
	
	struct data_event *event = bpf_ringbuf_reserve(&data_events, sizeof(struct data_event), 0);
	if (event != NULL) {
		event->sock_key = conn_info->sock_key;
		event->endpoint_role = conn_info->endpoint_role;

		// direction	role		msg
		// egress(0)	client(0)	request(0)
		// egress(0)	server(1)	response(1)
		// ingress(1)	client(0)	response(1)
		// ingress(1)	server(1)	request(0)
		event->msg_type = direction ^ conn_info->endpoint_role;
		if (conn_info->endpoint_role == kRoleUnknown)
			event->msg_type = kUnknown;
		event->ret = ret;
		event->msg_size = ret;

		size_t to_copy = size;
		if (to_copy > MAX_MSG_SIZE)
			to_copy = MAX_MSG_SIZE;
		bpf_probe_read(event->msg, to_copy, msg);

		event->iter_nr_segs = nr_segs;
		event->iter_count = count;
		event->iter_offset = iov_offset;
		event->iov_idx = iov_idx;

		bpf_ringbuf_submit(event, 0);
	}	
}

static __always_inline void copy_data_from_msghdr_recv(struct iov_iter *iter, struct conn_info *conn_info, enum direction_type direction, int ret) {
	if (iter->count == 0) {
		return;
	}

	#pragma unroll
	for(int i = 0; i < 10; i++) {
		if (i >= iter->nr_segs)
			break;

		struct kvec iov;
		bpf_probe_read(&iov, sizeof(iov), &(iter->kvec[i]));
		
		submit_data_event(iov.iov_base, 
					iov.iov_len, 
					conn_info,
					ingress, 
					ret,
					iter->nr_segs,
					iter->count,
					iter->iov_offset,
					i);
	}

}

// SEC("fentry/tcp_recvmsg")
// SEC("fexit/tcp_recvmsg")
// int BPF_PROG(tcp_recvmsg, struct sock *sk, struct msghdr *msg, size_t size, int nonblock, int flags, int *addr_len) {

SEC("fexit/sock_recvmsg")
int BPF_PROG(tcp_recvmsg, struct socket *sock, struct msghdr *msg, int flags, int ret) {
	
	if (ret <= 0)
		return 0;

	struct sock *sk = sock->sk;
	struct sock_key sk_key = {};
	sk_extract_key(sk, &sk_key);

	struct conn_info *conn_info = bpf_map_lookup_elem(&conn_info_map, &sk_key);
	if (conn_info == NULL)
		return 0;

	copy_data_from_msghdr_recv(&msg->msg_iter, conn_info, ingress, ret);

	conn_info->recv_bytes += msg->msg_iter.count;
	bpf_map_update_elem(&conn_info_map, &conn_info->sock_key, conn_info, BPF_ANY);

	return 0;
}

SEC("fexit/tcp_close")
int BPF_PROG(tcp_close, struct sock *sk, long ret) {
	if (ret < 0)
		return 0;

	struct sock_key sk_key = {};
	// sk_extract4_key(sk, &sk_key);
	sk_extract_key(sk, &sk_key);

	struct conn_info *conn_info = bpf_map_lookup_elem(&conn_info_map, &sk_key);
	if (conn_info == NULL)
		return 0;
	
	struct close_event *close_event = bpf_ringbuf_reserve(&close_events, sizeof(struct close_event), 0);
	if (close_event == NULL)
		return 0;
	
	close_event->sock_key = conn_info->sock_key;
	close_event->endpoint_role = conn_info->endpoint_role;
	close_event->send_bytes = conn_info->send_bytes;
	close_event->recv_bytes = conn_info->recv_bytes;
	bpf_ringbuf_submit(close_event, 0);

	bpf_map_delete_elem(&conn_info_map, &sk_key);

	return 0;
}