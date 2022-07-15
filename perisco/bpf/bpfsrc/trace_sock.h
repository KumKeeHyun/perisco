#pragma once 

#include "kernel_struct.h"

#include "../libbpf/bpf_helpers.h"
#include "../libbpf/bpf_endian.h"

#define MAX_NET_FILTER_SIZE 5

#define AF_INET 2
#define AF_INET6 10

// #define SOCK_STREAM 1
// #define SOCK_DGRAM 2

#define MAX_MSG_SIZE 4096

// 'unroll for loop'에서 스택 크기 제한으로 크기를 조절해야 함.
#define MAX_NR_SEGS 5

enum ip_version { IP_UNKNOWN, IPv4, IPv6 };

struct ip {
	char source[16];
	char destination[16];
	enum ip_version ip_version;
};

enum layer4_type { LAYER4_UNKNOWN, TCP, UDP };

struct layer4 {
	u32 source_port;
	u32 destination_port;
	enum layer4_type l4_type;
};

struct sock_key {
	struct ip ip;
	struct layer4 l4;
	u32 pid;
};

struct ip_network {
	char ip_addr[16];
	char ip_mask[16];
};

struct ip_networks {
	struct ip_network data[MAX_NET_FILTER_SIZE];
	u32 size;
};

struct endpoint_key {
	char ip_addr[16];
	enum ip_version ip_version;
	u32 port;
	u32 pid;
};

enum flow_type { FLOW_UNKNOWN, REQUEST, RESPONSE };

enum direction { DIR_UNKNOWN, INGRESS, EGRESS };

enum protocol_type {
	PROTO_UNKNOWN,
	PROTO_SKIP,

	HTTP1,
	HTTP2,

	RESERVED1,
	RESERVED2,
	RESERVED3,
	RESERVED4,
	RESERVED5
};

struct msg_arg {
	struct iov_iter iter;
	enum protocol_type protocol;
};
struct msg_arg *unused_msg_arg __attribute__((unused));

struct msg_event {
	char msg[MAX_MSG_SIZE];
	struct sock_key sock_key;
	u32 msg_size;
	u64 timestamp;
	enum flow_type flow_type;
	enum protocol_type protocol;
};
struct msg_event *unused_data_event __attribute__((unused));
