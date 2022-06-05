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
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key, struct sock_key);
	__type(value, struct recvmsg_arg);
	__uint(max_entries, 1024);
} recvmsg_arg_map SEC(".maps");

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

static __always_inline void sk_extract_key(const struct sock *sk,
					    struct sock_key *key)
{
	if (sk->__sk_common.skc_family == AF_INET) {
		bpf_probe_read(key->ip.source, 4, &sk->__sk_common.skc_rcv_saddr);
		bpf_probe_read(key->ip.destination, 4, &sk->__sk_common.skc_daddr);
		key->ip.ip_version = IPv4;
	} else if (sk->__sk_common.skc_family == AF_INET6) {
		bpf_probe_read(key->ip.source, 16, sk->__sk_common.skc_v6_rcv_saddr.in6_u.u6_addr8);
		bpf_probe_read(key->ip.destination, 16, sk->__sk_common.skc_v6_daddr.in6_u.u6_addr8);
		key->ip.ip_version = IPv6;
	} 

	key->l4.source_port = sk->__sk_common.skc_num;
	key->l4.destination_port = bpf_ntohs(sk->__sk_common.skc_dport);

	key->pid = bpf_get_current_pid_tgid() >> 32;
}

SEC("fexit/inet_accept")
int BPF_PROG(inet_accept, struct socket *sock,
				      struct socket *newsock, int flags, bool kern, long ret) {
	if (ret < 0)
		return 0;
	
	u16 family = newsock->sk->__sk_common.skc_family;
	if (family != AF_INET && family != AF_INET6)
		return 0;

	struct conn_event *conn_event = NULL;
	conn_event = bpf_ringbuf_reserve(&conn_events, sizeof(struct conn_event), 0);
	if (!conn_event)
		return 0;

	sk_extract_key(newsock->sk, &conn_event->sock_key);

	struct conn_info conn_info = {};
	conn_info.sock_key = conn_event->sock_key;
	bpf_map_update_elem(&conn_info_map, &conn_info.sock_key, &conn_info, BPF_ANY);
	
	bpf_ringbuf_submit(conn_event, 0);

	return 0;
}

SEC("fexit/inet_shutdown")
int BPF_PROG(inet_shutdown, struct socket *sock, int how, long ret) {
	if (ret < 0)
		return 0;

	struct sock *sk = sock->sk;
	struct sock_key sk_key = {};
	sk_extract_key(sk, &sk_key);

	struct conn_info *conn_info = bpf_map_lookup_elem(&conn_info_map, &sk_key);
	if (conn_info == NULL)
		return 0;
	
	struct close_event *close_event = bpf_ringbuf_reserve(&close_events, sizeof(struct close_event), 0);
	if (close_event == NULL)
		return 0;
	
	close_event->sock_key = conn_info->sock_key;
	close_event->send_bytes = conn_info->send_bytes;
	close_event->recv_bytes = conn_info->recv_bytes;
	bpf_ringbuf_submit(close_event, 0);

	bpf_map_delete_elem(&conn_info_map, &sk_key);

	return 0;
}

SEC("fentry/sock_recvmsg")
int BPF_PROG(fentry_sock_recvmsg, struct socket *sock, struct msghdr *msg, int flags) {

	struct sock *sk = sock->sk;
	struct sock_key sk_key = {};
	sk_extract_key(sk, &sk_key);

	struct conn_info *conn_info = bpf_map_lookup_elem(&conn_info_map, &sk_key);
	if (conn_info == NULL)
		return 0;
	
	struct recvmsg_arg recvmsg_arg = {};
	bpf_probe_read(&(recvmsg_arg.iter), sizeof(struct iov_iter), &(msg->msg_iter));

	bpf_map_update_elem(&recvmsg_arg_map, &sk_key, &recvmsg_arg, BPF_NOEXIST);

	return 0;
}

static __always_inline void submit_data_event(const char *msg, size_t size, struct conn_info *conn_info, enum direction direction, u64 timestamp) {
	
	struct data_event *event = bpf_ringbuf_reserve(&data_events, sizeof(struct data_event), 0);
	if (event != NULL) {
		event->sock_key = conn_info->sock_key;
		event->timestamp = timestamp;
		event->flow_type = direction == INGRESS ? REQUEST : RESPONSE;
		event->protocol = conn_info->protocol;

		size_t to_copy = size;
		if (to_copy > MAX_MSG_SIZE)
			to_copy = MAX_MSG_SIZE;
		bpf_probe_read(event->msg, to_copy, msg);
		event->msg_size = to_copy;

		bpf_ringbuf_submit(event, 0);
	}	
}

static __always_inline void copy_data_from_iov_iter(struct iov_iter *iter, size_t size, struct conn_info *conn_info, enum direction direction, u64 timestamp) {
	
	if (iter->count == 0) 
		return ;

	size_t remained = size;
	
	#pragma unroll
	for(int i = 0; i < MAX_NR_SEGS; i++) {
		if (i >= iter->nr_segs)
			break;

		struct kvec iov;
		bpf_probe_read(&iov, sizeof(iov), &(iter->kvec[i]));

		size_t to_copy = remained;
		if (to_copy > iov.iov_len)
			to_copy = iov.iov_len;
		
		submit_data_event(iov.iov_base, to_copy, conn_info, direction, timestamp);

		remained -= to_copy;
		if (remained <= 0)
			break;
	}
}

SEC("fexit/sock_recvmsg")
int BPF_PROG(fexit_sock_recvmsg, struct socket *sock, struct msghdr *msg, int flags, int ret) {
	
	if (ret <= 0)
		return 0;

	struct sock *sk = sock->sk;
	struct sock_key sk_key = {};
	sk_extract_key(sk, &sk_key);

	struct conn_info *conn_info = bpf_map_lookup_elem(&conn_info_map, &sk_key);
	if (conn_info == NULL)
		return 0;
	struct recvmsg_arg *recvmsg_arg = bpf_map_lookup_elem(&recvmsg_arg_map, &sk_key);
	if (recvmsg_arg == NULL)
		return 0;

	copy_data_from_iov_iter(&(recvmsg_arg->iter), ret, conn_info, INGRESS, bpf_ktime_get_ns());

	conn_info->recv_bytes += ret;
	bpf_map_update_elem(&conn_info_map, &conn_info->sock_key, conn_info, BPF_ANY);

	bpf_map_delete_elem(&recvmsg_arg_map, &sk_key);

	return 0;
}


SEC("fentry/sock_sendmsg")
int BPF_PROG(fentry_sock_sendmsg, struct socket *sock, struct msghdr *msg) {

	struct sock *sk = sock->sk;
	struct sock_key sk_key = {};
	sk_extract_key(sk, &sk_key);

	struct conn_info *conn_info = bpf_map_lookup_elem(&conn_info_map, &sk_key);
	if (conn_info == NULL)
		return 0;

	size_t size = msg->msg_iter.count;
	copy_data_from_iov_iter(&(msg->msg_iter), size, conn_info, EGRESS, bpf_ktime_get_ns());

	conn_info->send_bytes += size;
	bpf_map_update_elem(&conn_info_map, &conn_info->sock_key, conn_info, BPF_ANY);

	return 0;
}
