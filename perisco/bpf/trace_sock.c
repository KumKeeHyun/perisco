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

struct __attribute__((__packed__)) sock_key_t {
	union ip sip;
	union ip dip;
	__u32 sport;
	__u32 dport;
	__u8 family;
	__u8 pad1;
	__u16 pad2;
};

static __always_inline void sk_extract4_key(const struct sock *sk,
					    struct sock_key_t *key)
{
	key->sip.ip4.addr = sk->__sk_common.skc_rcv_saddr;
	key->dip.ip4.addr = sk->__sk_common.skc_daddr;

	key->sport = sk->__sk_common.skc_num;
	key->dport = bpf_ntohs(sk->__sk_common.skc_dport);

	key->family = AF_INET;
}

enum endpoint_role_t {
  kRoleClient = 1 << 0,
  kRoleServer = 1 << 1,
  kRoleUnknown = 1 << 2,
};

struct conn_id_t {
  // The unique identifier of the pid/tgid.
  u64 pid_tgid;
  // Unique id of the conn_id (timestamp).
  u64 tsid;
  // The file descriptor to the opened network connection.
  s32 fd;
};

struct sockaddr_t {
	u32 src_addr;
	u32 dst_addr;
	u16 src_port;
	u16 dst_port;
};

struct conn_info {
  struct sock_key_t sock_key;

  // The protocol of traffic on the connection (HTTP, MySQL, etc.).
  enum endpoint_role_t endpoint_role;
};
struct conn_info *unused_event __attribute__((unused));


struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 256 * 1024);
} conn_events SEC(".maps");

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

	// conn_info->conn_id.pid_tgid = bpf_get_current_pid_tgid();
	// conn_info->conn_id.fd = ret;
	// conn_info->conn_id.tsid = bpf_ktime_get_ns();

	// conn_info->addr.dst_addr = sk_common->skc_rcv_saddr;
	// conn_info->addr.dst_port = sk_common->skc_num;
	// conn_info->addr.src_addr = sk_common->skc_daddr;
	// conn_info->addr.src_port = bpf_ntohs(sk_common->skc_dport);

	conn_info->endpoint_role = kRoleServer;
	
	bpf_ringbuf_submit(conn_info, 0);

	// if (family == AF_INET) {
	// } else if (family == AF_INET6) {
	// }

	return 0;
}

SEC("fexit/tcp_connect")
int BPF_PROG(tcp_connect, struct sock *sock, long ret) {
	if (ret < 0)
		return 0;

	struct sock_common *sk_common = &sock->__sk_common;

	u16 family = sk_common->skc_family;
	if (family != AF_INET)
		return 0;

	struct conn_info *conn_info = NULL;
	conn_info = bpf_ringbuf_reserve(&conn_events, sizeof(struct conn_info), 0);
	if (!conn_info)
		return 0;

	sk_extract4_key(sock, &conn_info->sock_key);
	// conn_info->conn_id.pid_tgid = bpf_get_current_pid_tgid();
	// conn_info->conn_id.fd = ret;
	// conn_info->conn_id.tsid = bpf_ktime_get_ns();

	// conn_info->addr.src_addr = sk_common->skc_rcv_saddr;
	// conn_info->addr.src_port = sk_common->skc_num;
	// conn_info->addr.dst_addr = sk_common->skc_daddr;
	// conn_info->addr.dst_port = bpf_ntohs(sk_common->skc_dport);

	conn_info->endpoint_role = kRoleClient;
	
	bpf_ringbuf_submit(conn_info, 0);

	return 0;
}