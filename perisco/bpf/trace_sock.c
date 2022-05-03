#include "headers/vmlinux.h"
#include "headers/bpf_helpers.h"
#include "headers/bpf_tracing.h"
#include "headers/bpf_endian.h"

#define AF_INET 2
#define AF_INET6 10

char LICENSE[] SEC("license") = "Dual BSD/GPL";

struct __attribute__((__packed__)) v6addr {
	__u8 addr[16];
};

struct __attribute__((__packed__)) v4addr {
	__u32		addr;
	__u32		pad1;
	__u32		pad2;
	__u32		pad3;
};

struct __attribute__((__packed__)) ipaddr {
	__u32		pad1;
	__u32		pad2;
	__u32		pad3;
	__u32		pad4;
};

union __attribute__((__packed__)) ip {
	struct ipaddr addr;
	struct v4addr ip4;
	struct v6addr ip6;
};

struct __attribute__((__packed__)) sock_key {
	union ip sip;
	union ip dip;
	__u32 sport;
	__u32 dport;
	__u8 family;
	__u8 pad1;
	__u16 pad2;
};

static __always_inline void sk_extract4_key(const struct sock *sk,
					    struct sock_key *key)
{
	key->sip.ip4.addr = sk->__sk_common.skc_rcv_saddr;
	key->dip.ip4.addr = sk->__sk_common.skc_daddr;

	key->sport = sk->__sk_common.skc_num;
	key->dport = bpf_ntohs(sk->__sk_common.skc_dport);

	key->family = AF_INET;
}

enum endpoint_role {
  	kRoleClient = 1 << 0,
  	kRoleServer = 1 << 1,
  	kRoleUnknown = 1 << 2,
};

struct conn_info {
  	struct sock_key sock_key;
  	enum endpoint_role endpoint_role;
	u64 send_bytes;
	u64 recv_bytes;
};

struct conn_event {
  	struct sock_key sock_key;
  	enum endpoint_role endpoint_role;
};
struct conn_event *unused_conn_event __attribute__((unused));

struct close_event {
	struct sock_key sock_key;
  	enum endpoint_role endpoint_role;
	u64 send_bytes;
	u64 recv_bytes;
};
struct close_event *unused_close_event __attribute__((unused));

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

SEC("fexit/tcp_sendmsg")
int BPF_PROG(tcp_sendmsg, struct sock *sk, struct msghdr *msg, size_t size, long ret) {
	bpf_printk("BPF triggered from tcp_sendmsg. send size: %d.\n", size);

	struct sock_key sk_key = {};
	sk_extract4_key(sk, &sk_key);

	struct conn_info *conn_info = bpf_map_lookup_elem(&conn_info_map, &sk_key);
	if (conn_info == NULL)
		return 0;

	conn_info->send_bytes += size;
	bpf_map_update_elem(&conn_info_map, &conn_info->sock_key, conn_info, BPF_ANY);

	return 0;
}



SEC("fexit/tcp_recvmsg")
int BPF_PROG(tcp_recvmsg, struct sock *sk, struct msghdr *msg, 
				size_t len, int nonblock, int flags, int *addr_len, long ret) {

	bpf_printk("BPF triggered from tcp_recvmsg. recv size: %d.\n", len);

	struct sock_key sk_key = {};
	sk_extract4_key(sk, &sk_key);

	struct conn_info *conn_info = bpf_map_lookup_elem(&conn_info_map, &sk_key);
	if (conn_info == NULL)
		return 0;

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