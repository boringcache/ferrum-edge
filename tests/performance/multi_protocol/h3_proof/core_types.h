/* Minimal CO-RE declarations: field offsets come from the running kernel BTF.
 * This is not a vmlinux layout. Only the named fields are read. */
#ifndef H3_CORE_TYPES_H
#define H3_CORE_TYPES_H
#include <linux/bpf.h>
#include <linux/types.h>
#pragma clang attribute push (__attribute__((preserve_access_index)), apply_to = record)
struct ns_common { unsigned int inum; };
struct net { struct ns_common ns; };
typedef struct { struct net *net; } possible_net_t;
typedef struct { long long counter; } atomic64_t;
struct sock_common { possible_net_t skc_net; atomic64_t skc_cookie;
    __u32 skc_daddr, skc_rcv_saddr; __u16 skc_dport, skc_num, skc_family; };
typedef struct { int counter; } atomic_t;
struct sock { struct sock_common __sk_common; int sk_rcvbuf, sk_sndbuf; atomic_t sk_drops; __u16 sk_protocol; struct sock_reuseport *sk_reuseport_cb; };
struct sock_filter { __u16 code; __u8 jt, jf; __u32 k; };
struct sock_fprog_kern { __u16 len; struct sock_filter *filter; };
struct bpf_prog { enum bpf_prog_type type; struct sock_fprog_kern *orig_prog; };
struct socket { struct sock *sk; };
struct sockaddr { __u16 sa_family; };
struct in_addr { __be32 s_addr; };
struct sockaddr_in { __u16 sin_family; __be16 sin_port; struct in_addr sin_addr; };
struct sock_reuseport { __u16 num_socks; struct sock *socks[]; };
struct nsproxy { struct net *net_ns; };
struct task_struct { struct nsproxy *nsproxy; struct task_struct *group_leader;
    __u64 start_boottime; int pid, tgid; };
struct sk_buff { struct sock *sk; };
struct inet_cork { __u16 gso_size; };
struct msghdr { unsigned int msg_flags; void *msg_name; int msg_namelen; };
struct pt_regs { unsigned long di, si, dx, r10, r8, r9, cs, orig_ax; };
#pragma clang attribute pop
#endif
