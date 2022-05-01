#include "headers/vmlinux.h"
#include "headers/bpf_helpers.h"
#include "headers/bpf_tracing.h"
#include "headers/bpf_endian.h"

#define AF_INET 2
#define AF_INET6 10

char LICENSE[] SEC("license") = "Dual BSD/GPL";

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
  // Connection identifier (PID, FD, etc.).
  struct conn_id_t conn_id;

  // IP address of the remote endpoint.
  struct sockaddr_t addr;

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

	conn_info->conn_id.pid_tgid = bpf_get_current_pid_tgid();
	conn_info->conn_id.fd = ret;
	conn_info->conn_id.tsid = bpf_ktime_get_ns();

	conn_info->addr.src_addr = sk_common->skc_rcv_saddr;
	conn_info->addr.src_port = sk_common->skc_num;
	conn_info->addr.dst_addr = sk_common->skc_daddr;
	conn_info->addr.dst_port = bpf_ntohs(sk_common->skc_dport);

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

	conn_info->conn_id.pid_tgid = bpf_get_current_pid_tgid();
	conn_info->conn_id.fd = ret;
	conn_info->conn_id.tsid = bpf_ktime_get_ns();

	conn_info->addr.src_addr = sk_common->skc_rcv_saddr;
	conn_info->addr.src_port = sk_common->skc_num;
	conn_info->addr.dst_addr = sk_common->skc_daddr;
	conn_info->addr.dst_port = bpf_ntohs(sk_common->skc_dport);

	conn_info->endpoint_role = kRoleClient;
	
	bpf_ringbuf_submit(conn_info, 0);
	
	// if (family == AF_INET) {
	// } else if (family == AF_INET6) {
	// }

	return 0;
}