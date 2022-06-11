#include "../libbpf/vmlinux.h"
#include "../libbpf/bpf_helpers.h"
#include "../libbpf/bpf_tracing.h"
#include "../libbpf/bpf_endian.h"

#include "trace_sock.h"

char LICENSE[] SEC("license") = "Dual BSD/GPL";

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

static __always_inline bool is_inet_conn(const struct sock *sk) {
	u16 family = sk->__sk_common.skc_family;
	if (family != AF_INET && family != AF_INET6)
		return false;
	return true;
}

static __always_inline void extract_sock_key(const struct sock *sk,
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

SEC("fentry/sock_recvmsg")
int BPF_PROG(fentry_sock_recvmsg, struct socket *sock, struct msghdr *msg, int flags) {

	struct sock *sk = sock->sk;
	if (!is_inet_conn(sk))
		return 0;
	
	// check blacklist

	struct sock_key sk_key = {};
	extract_sock_key(sk, &sk_key);
	
	struct recvmsg_arg recvmsg_arg = {};
	bpf_probe_read(&(recvmsg_arg.iter), sizeof(struct iov_iter), &(msg->msg_iter));

	bpf_map_update_elem(&recvmsg_arg_map, &sk_key, &recvmsg_arg, BPF_NOEXIST);

	return 0;
}

static __always_inline 
void submit_data_event
(const char *msg, size_t size, struct sock_key *key, u64 timestamp, enum protocol_type protocol, enum direction direction) {
	
	struct data_event *event = bpf_ringbuf_reserve(&data_events, sizeof(struct data_event), 0);
	if (event != NULL) {
		event->sock_key = *key;
		event->timestamp = timestamp;
		event->protocol = protocol;
		event->flow_type = direction == INGRESS ? REQUEST : RESPONSE;

		size_t to_copy = size;
		if (to_copy > MAX_MSG_SIZE)
			to_copy = MAX_MSG_SIZE;
		bpf_probe_read(event->msg, to_copy, msg);
		event->msg_size = to_copy;

		bpf_ringbuf_submit(event, 0);
	}	
}

static __always_inline 
void copy_data_from_iov_iter
(struct iov_iter *iter, size_t size, struct sock_key *key, u64 timestamp, enum protocol_type protocol, enum direction direction) {
	
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
		
		submit_data_event(iov.iov_base, to_copy, key, timestamp, protocol, direction);

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
	extract_sock_key(sk, &sk_key);

	struct recvmsg_arg *recvmsg_arg = bpf_map_lookup_elem(&recvmsg_arg_map, &sk_key);
	if (recvmsg_arg == NULL)
		return 0;
	
	// check protocol table

	copy_data_from_iov_iter(&(recvmsg_arg->iter), ret, &sk_key, bpf_ktime_get_ns(), PROTO_UNKNOWN, INGRESS);

	bpf_map_delete_elem(&recvmsg_arg_map, &sk_key);

	return 0;
}


SEC("fentry/sock_sendmsg")
int BPF_PROG(fentry_sock_sendmsg, struct socket *sock, struct msghdr *msg) {

	struct sock *sk = sock->sk;
	if (!is_inet_conn(sk))
		return 0;
	
	// check blacklist

	struct sock_key sk_key = {};
	extract_sock_key(sk, &sk_key);

	size_t size = msg->msg_iter.count;
	copy_data_from_iov_iter(&(msg->msg_iter), size, &sk_key, bpf_ktime_get_ns(), PROTO_UNKNOWN, EGRESS);

	return 0;
}
