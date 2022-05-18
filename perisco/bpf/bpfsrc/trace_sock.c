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

static __always_inline void sk_extract4_key(const struct sock *sk,
					    struct sock_key *key)
{
	key->sip.ip4.addr = sk->__sk_common.skc_rcv_saddr;
	key->dip.ip4.addr = sk->__sk_common.skc_daddr;

	key->sport = sk->__sk_common.skc_num;
	key->dport = bpf_ntohs(sk->__sk_common.skc_dport);

	key->family = AF_INET;
}

SEC("fexit/inet_accept")
int BPF_PROG(inet_accept, struct socket *sock,
				      struct socket *newsock, int flags, bool kern, long ret) {
	if (ret < 0)
		return 0;
	
	if (newsock->sk->__sk_common.skc_family != AF_INET)
		return 0;

	struct conn_event *conn_event = NULL;
	conn_event = bpf_ringbuf_reserve(&conn_events, sizeof(struct conn_event), 0);
	if (!conn_event)
		return 0;

	sk_extract4_key(newsock->sk, &conn_event->sock_key);
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

	if (sock->__sk_common.skc_family != AF_INET)
		return 0;

	struct conn_event *conn_event = NULL;
	conn_event = bpf_ringbuf_reserve(&conn_events, sizeof(struct conn_event), 0);
	if (!conn_event)
		return 0;

	sk_extract4_key(sock, &conn_event->sock_key);
	conn_event->endpoint_role = kRoleClient;

	struct conn_info conn_info = {};
	conn_info.sock_key = conn_event->sock_key;
	conn_info.endpoint_role = conn_event->endpoint_role;
	bpf_map_update_elem(&conn_info_map, &conn_info.sock_key, &conn_info, BPF_ANY);

	bpf_ringbuf_submit(conn_event, 0);

	return 0;
}


// static __always_inline void copy_data_from_iter(struct iov_iter *iter, struct conn_info *conn_info) {
// 	// struct iov_iter *iter = &msg->msg_iter;

// 	if (iter->iov_offset != 0 || iter->count == 0) {
// 		return;
// 	}

// 	const struct kvec *iov = iter->kvec;

// 	size_t to_copy = iov->iov_len;
// 	size_t copyed = 0;
	
// 	#pragma unroll
// 	for (int i = 0; i < 10; i++) {
// 		size_t remaining = to_copy - copyed;
// 		if (remaining <= 0)
// 			break;

// 		size_t buf_size = remaining > MAX_MSG_SIZE ? MAX_MSG_SIZE : remaining;

// 		struct data_event *event = bpf_ringbuf_reserve(&data_events, sizeof(struct data_event), 0);
// 		if (event != NULL) {
// 			event->sock_key = conn_info->sock_key;
// 			event->endpoint_role = conn_info->endpoint_role;
// 			event->msg_type = conn_info->endpoint_role == kRoleServer ?  kRequest : kResponse;
// 			event->nr_segs = iter->nr_segs;
// 			event->count = iter->count;
// 			event->offset = i;
// 			event->msg_size = buf_size;
// 			bpf_probe_read(event->msg, buf_size, iov->iov_base + copyed);

// 			bpf_ringbuf_submit(event, 0);
// 		}

// 		copyed += buf_size;
// 	}
// }

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
		event->nr_segs = iter->nr_segs;
		event->count = iter->count;

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
	sk_extract4_key(sk, &sk_key);

	struct conn_info *conn_info = bpf_map_lookup_elem(&conn_info_map, &sk_key);
	if (conn_info == NULL)
		return 0;

	copy_data_from_msghdr(&msg->msg_iter, conn_info, egress);
	
	conn_info->send_bytes += size;
	bpf_map_update_elem(&conn_info_map, &conn_info->sock_key, conn_info, BPF_ANY);

	return 0;
}

SEC("fentry/tcp_recvmsg")
int BPF_PROG(tcp_recvmsg, struct sock *sk, struct msghdr *msg, 
				size_t len, int nonblock, int flags, int *addr_len) {

	struct sock_key sk_key = {};
	sk_extract4_key(sk, &sk_key);

	struct conn_info *conn_info = bpf_map_lookup_elem(&conn_info_map, &sk_key);
	if (conn_info == NULL)
		return 0;

	copy_data_from_msghdr(&msg->msg_iter, conn_info, ingress);

	conn_info->recv_bytes += len;
	bpf_map_update_elem(&conn_info_map, &conn_info->sock_key, conn_info, BPF_ANY);

	return 0;
}

SEC("fexit/tcp_close")
int BPF_PROG(tcp_close, struct sock *sk, long ret) {
	if (ret < 0)
		return 0;

	struct sock_key sk_key = {};
	sk_extract4_key(sk, &sk_key);

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