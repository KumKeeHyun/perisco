#pragma once 

#include "../libbpf/vmlinux.h"
#include "../libbpf/bpf_helpers.h"
#include "../libbpf/bpf_endian.h"

#define AF_INET 2
#define AF_INET6 10

enum ip_version { IP_UNKNOWN, IPv4, IPv6 };

struct ip {
	char source[16];
	char destination[16];
	enum ip_version ip_version;
};

struct layer4 {
	u32 source_port;
	u32 destination_port;
};

struct sock_key {
	struct ip ip;
	struct layer4 l4;
	u32 pid;
};

enum flow_type { FLOW_UNKNOWN, REQUEST, RESPONSE };

enum direction { DIR_UNKNOWN, INGRESS, EGRESS };

enum protocol_type {
	PROTO_UNKNOWN,

	HTTP1,
	HTTP2,

	RESERVED1,
	RESERVED2,
	RESERVED3,
	RESERVED4,
	RESERVED5
};

struct recvmsg_arg {
	struct iov_iter iter;
};
struct recvmsg_arg *unused_recvmsg_arg __attribute__((unused));

#define MAX_MSG_SIZE 4096

// 'unroll for loop'에서 스택 크기 제한으로 크기를 조절해야 함.
#define MAX_NR_SEGS 7

struct data_event {
	char msg[MAX_MSG_SIZE];
	struct sock_key sock_key;
	u64 timestamp;
	enum flow_type flow_type;
	enum protocol_type protocol;
	u32 msg_size;
};
struct data_event *unused_data_event __attribute__((unused));
