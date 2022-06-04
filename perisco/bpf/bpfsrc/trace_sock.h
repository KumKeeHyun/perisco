#pragma once 

#include "../libbpf/vmlinux.h"
#include "../libbpf/bpf_helpers.h"
#include "../libbpf/bpf_endian.h"

#define AF_INET 2
#define AF_INET6 10

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
	__u32 pid;
	__u8 family;
	__u8 pad1;
	__u16 pad2;
};

enum message_type { request, response, unknown };

enum direction_type { ingress, egress };

struct conn_info {
  	struct sock_key sock_key;
	u64 send_bytes;
	u64 recv_bytes;
};

struct conn_event {
  	struct sock_key sock_key;
};
struct conn_event *unused_conn_event __attribute__((unused));

struct close_event {
	struct sock_key sock_key;
	u64 send_bytes;
	u64 recv_bytes;
};
struct close_event *unused_close_event __attribute__((unused));


struct recvmsg_arg {
	struct iov_iter iter;
};
struct recvmsg_arg *unused_recvmsg_arg __attribute__((unused));

#define MAX_MSG_SIZE 4096
#define MAX_NR_SEGS 10

struct data_event {
	char msg[MAX_MSG_SIZE];
	struct sock_key sock_key;
	enum message_type msg_type;
	s32 proto_type;
	u32 msg_size;
};
struct data_event *unused_data_event __attribute__((unused));
