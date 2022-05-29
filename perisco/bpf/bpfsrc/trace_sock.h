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
	__u8 family;
	__u8 pad1;
	__u16 pad2;
	__u32 pad3;
};

enum endpoint_role {
  	kRoleClient = 0,
  	kRoleServer = 1,
  	kRoleUnknown = 2,
};

enum message_type { kRequest, kResponse, kUnknown };

enum direction_type { egress, ingress };

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

#define MAX_MSG_SIZE 4096

struct data_event {
	char msg[MAX_MSG_SIZE];
	struct sock_key sock_key;
	u64 msg_size;
	s32 ret;
  	enum endpoint_role endpoint_role;
	enum message_type msg_type;
	u64 iter_nr_segs;
	u32 iter_count;
	u32 iter_offset;
	u32 iov_idx;
};
struct data_event *unused_data_event __attribute__((unused));
