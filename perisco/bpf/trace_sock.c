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

struct __attribute__((__packed__)) addr_pad {
	__u32		pad1;
	__u32		pad2;
	__u32		pad3;
	__u32		pad4;
};

union __attribute__((__packed__)) ip {
	struct addr_pad addr;
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

  // The protocol of traffic on the connection (HTTP, MySQL, etc.).
  enum endpoint_role endpoint_role;
};
struct conn_info *unused_event __attribute__((unused));

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
	
	struct sock_common *sk_common = &newsock->sk->__sk_common;
	u16 family = sk_common->skc_family;
	if (family != AF_INET)
		return 0;

	struct conn_info *conn_info = NULL;
	conn_info = bpf_ringbuf_reserve(&conn_events, sizeof(struct conn_info), 0);
	if (!conn_info)
		return 0;

	sk_extract4_key(newsock->sk, &conn_info->sock_key);

	conn_info->endpoint_role = kRoleServer;

	struct conn_info conn_info_c = *conn_info;
	bpf_map_update_elem(&conn_info_map, &conn_info_c.sock_key, &conn_info_c, BPF_ANY);
	
	bpf_ringbuf_submit(conn_info, 0);

	return 0;
}

SEC("fexit/tcp_connect")
int BPF_PROG(tcp_connect, struct sock *sock) {

	struct sock_common *sk_common = &sock->__sk_common;

	u16 family = sk_common->skc_family;
	if (family != AF_INET)
		return 0;

	struct conn_info *conn_info = NULL;
	conn_info = bpf_ringbuf_reserve(&conn_events, sizeof(struct conn_info), 0);
	if (!conn_info)
		return 0;

	sk_extract4_key(sock, &conn_info->sock_key);

	conn_info->endpoint_role = kRoleClient;

	struct conn_info conn_info_c = *conn_info;
	bpf_map_update_elem(&conn_info_map, &conn_info_c.sock_key, &conn_info_c, BPF_ANY);
	
	bpf_ringbuf_submit(conn_info, 0);

	return 0;
}

SEC("fexit/tcp_close")
int BPF_PROG(tcp_close, struct sock *sk, long ret) {
	if (ret < 0)
		return 0;

	struct sock_key sk_key = {};
	sk_extract4_key(sk, &sk_key);

	struct conn_info *value = bpf_map_lookup_elem(&conn_info_map, &sk_key);
	if (value == NULL)
		return 0;
	
	struct conn_info *conn_info = bpf_ringbuf_reserve(&close_events, sizeof(struct conn_info), 0);
	if (conn_info == NULL)
		return 0;
	
	*conn_info = *value;
	bpf_ringbuf_submit(conn_info, 0);

	bpf_map_delete_elem(&conn_info_map, &sk_key);

	return 0;
}