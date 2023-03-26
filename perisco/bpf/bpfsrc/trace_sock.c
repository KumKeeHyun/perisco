#include "kernel_struct.h"

#include "../libbpf/bpf_helpers.h"
#include "../libbpf/bpf_tracing.h"
#include "../libbpf/bpf_endian.h"

#include "trace_sock.h"

char LICENSE[] SEC("license") = "Dual BSD/GPL";

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__type(key, u32);
	__type(value, struct ip_networks);
	__uint(max_entries, 1);
} network_filter SEC(".maps");

const u32 net_filter_key = 0;

struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__type(key, struct endpoint_key);
	__type(value, enum protocol_type);
	__uint(max_entries, 1024);
} protocol_map SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__type(key, struct endpoint_key);
	__type(value, u32);
	__uint(max_entries, 1024);
} server_map SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key, u64);
	__type(value, struct msg_arg);
	__uint(max_entries, 1024);
} recvmsg_arg_map SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 256 * 4096);
} sendmsg_events SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 256 * 4096);
} recvmsg_events SEC(".maps");

static __always_inline bool is_inet_conn(const struct sock *sk) {
	u16 family = sk->__sk_common.skc_family;
	if (family != AF_INET && family != AF_INET6)
		return false;
	return true;
}

static __always_inline bool is_tcp_conn(const struct socket *sock) {
	if (sock->type == SOCK_STREAM) {
		return true;
	}
	return false;
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
	if (sk->sk_socket->type == SOCK_STREAM)
		key->l4.l4_type = TCP;
	else if (sk->sk_socket->type == SOCK_DGRAM)
		key->l4.l4_type = UDP;
	else
		key->l4.l4_type = LAYER4_UNKNOWN;

	key->pid = bpf_get_current_pid_tgid() >> 32;
}

static __always_inline 
bool is_in_net(const struct sock_key *key, const struct ip_network *ip_net) {
	#pragma unroll
	for (int i = 0; i < 16; i++) {
		if ((key->ip.source[i]&ip_net->ip_mask[i]) != ip_net->ip_addr[i])
			return false;
	}
	return true;
}

static __always_inline 
bool is_in_net_filter(const struct sock_key *key) {

	struct ip_networks *networks = bpf_map_lookup_elem(&network_filter, &net_filter_key);
	if (networks == NULL) 
		return true;

	#pragma unroll
	for (int i = 0; i < MAX_NET_FILTER_SIZE; i++) {
		if (i == networks->size) {
			// if network filter is empty, allow all IPs.
			if (networks->size == 0) return true;
			else return false;
		}
		if (is_in_net(key, networks->data + i)) 
			return true;
	}
	return false;
}

static __always_inline 
void sock_key_to_endpoint_key(const struct sock_key *sk_key, struct endpoint_key *ep_key) {
	bpf_probe_read(ep_key->ip_addr, 16, sk_key->ip.source);
	ep_key->ip_version = sk_key->ip.ip_version;
	ep_key->port = sk_key->l4.source_port;
	ep_key->pid = sk_key->pid;
}

static __always_inline bool is_server(const struct sock_key *key) {
	struct endpoint_key ep_key = {0, };
	sock_key_to_endpoint_key(key, &ep_key);

	u32 *exist = bpf_map_lookup_elem(&server_map, &ep_key);
	if (exist != NULL)
		return true;
	return false;
}

static __always_inline 
enum protocol_type lookup_protocol(struct sock_key *key) {
	struct endpoint_key ep_key;
	sock_key_to_endpoint_key(key, &ep_key);

	enum protocol_type *protocol = bpf_map_lookup_elem(&protocol_map, &ep_key);
	if (protocol == NULL)
		return PROTO_UNKNOWN;
	return *protocol;
}

SEC("fexit/inet_accept")
int BPF_PROG(fexit_inet_accept, struct socket *sock, struct socket *newsock, int flags, bool kern, int ret) {
	if (ret < 0) 
		return 0;

	struct sock_key sk_key = {0, };
	extract_sock_key(newsock->sk, &sk_key);
	
	if (!is_in_net_filter(&sk_key))
		return 0;
	
	struct endpoint_key ep_key = {0, };
	sock_key_to_endpoint_key(&sk_key, &ep_key);
	u32 value = 1;

	bpf_map_update_elem(&server_map, &ep_key, &value, BPF_ANY);

	return 0;
}

SEC("fentry/sock_recvmsg")
int BPF_PROG(fentry_sock_recvmsg, struct socket *sock, struct msghdr *msg, int flags) {

	struct sock *sk = sock->sk;
	if (!is_inet_conn(sk))
		return 0;

	struct sock_key sk_key = {0, };
	extract_sock_key(sk, &sk_key);

	if (is_tcp_conn(sock) && !is_server(&sk_key))
		return 0;

	if (!is_in_net_filter(&sk_key))
		return 0;
	
	enum protocol_type protocol = lookup_protocol(&sk_key);
	if (protocol == PROTO_SKIP)
		return 0;

	struct msg_arg recvmsg_arg = {};
	bpf_probe_read(&(recvmsg_arg.iter), sizeof(struct iov_iter), &(msg->msg_iter));
	recvmsg_arg.protocol = protocol;

	u64 id = bpf_get_current_pid_tgid();
	// bpf_printk("recv entry - id: %d, kvec: %p\n", id, (void *)recvmsg_arg.iter.kvec);
	bpf_map_update_elem(&recvmsg_arg_map, &id, &recvmsg_arg, BPF_ANY);
	
	return 0;
}

static __always_inline 
void submit_msg_event
(const char *msg, size_t size, struct sock_key *key, u64 timestamp, enum protocol_type protocol, enum direction direction) {
	
	struct msg_event *event;
	if (direction == INGRESS) event = bpf_ringbuf_reserve(&recvmsg_events, sizeof(struct msg_event), 0);
	else event = bpf_ringbuf_reserve(&sendmsg_events, sizeof(struct msg_event), 0);

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
void copy_msg_from_iov_iter
(struct iov_iter *iter, size_t size, struct sock_key *key, u64 timestamp, enum protocol_type protocol, enum direction direction) {
	
	// bpf_printk("srv_port: %d, cli_port: %d, dir:%d\n", key->l4.source_port, key->l4.destination_port, direction);
	// bpf_printk("nr_segs: %lu, count: %lu, size: %lu\n", iter->nr_segs, iter->count, size);

	struct kvec iov;
	bpf_probe_read(&iov, sizeof(iov), &(iter->kvec[0]));
	size_t to_copy = iter->count;
	if (size > 0 && size < to_copy) {
		to_copy = size;
	}
	// bpf_printk("iov iter: %ld, iov len: %lu, to copy: %lu\n", 0, iov.iov_len, to_copy);
	submit_msg_event(iov.iov_base, to_copy, key, timestamp, protocol, direction);
}

SEC("fexit/sock_recvmsg")
int BPF_PROG(fexit_sock_recvmsg, struct socket *sock, struct msghdr *msg, int flags, int ret) {
	u64 id = bpf_get_current_pid_tgid();
	
	if (ret < 0) {
		// bpf_printk("recv exit - id: %d, ret: %d\n", id, ret);
		return 0;
	}

	struct sock *sk = sock->sk;
	struct sock_key sk_key = {0, };
	extract_sock_key(sk, &sk_key);

	struct msg_arg *recvmsg_arg = bpf_map_lookup_elem(&recvmsg_arg_map, &id);
	if (recvmsg_arg == NULL)
		return 0;

	
	// bpf_printk("recv exit - id: %d, kvec: %p, ret:%d\n", id, (void *)recvmsg_arg->iter.kvec, ret);

	copy_msg_from_iov_iter(&(recvmsg_arg->iter), ret, &sk_key, bpf_ktime_get_ns(), recvmsg_arg->protocol, INGRESS);
	bpf_map_delete_elem(&recvmsg_arg_map, &id);

	return 0;
}


SEC("fentry/sock_sendmsg")
int BPF_PROG(fentry_sock_sendmsg, struct socket *sock, struct msghdr *msg) {

	struct sock *sk = sock->sk;
	if (!is_inet_conn(sk))
		return 0;
	
	struct sock_key sk_key = {0, };
	extract_sock_key(sk, &sk_key);

	if (is_tcp_conn(sock) && !is_server(&sk_key))
		return 0;

	if (!is_in_net_filter(&sk_key))
		return 0;
	
	enum protocol_type protocol = lookup_protocol(&sk_key);
	if (protocol == PROTO_SKIP)
		return 0;

	size_t size = msg->msg_iter.count;
	copy_msg_from_iov_iter(&(msg->msg_iter), size, &sk_key, bpf_ktime_get_ns(), protocol, EGRESS);

	return 0;
}
