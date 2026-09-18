/* Minimal CO-RE declarations: field offsets come from the running kernel BTF.
 * This is not a vmlinux layout. Only the named fields are read. */
#ifndef H3_CORE_TYPES_H
#define H3_CORE_TYPES_H
#include <linux/types.h>
#pragma clang attribute push (__attribute__((preserve_access_index)), apply_to = record)
struct ns_common { unsigned int inum; };
struct net { struct ns_common ns; };
typedef struct { struct net *net; } possible_net_t;
typedef struct { long long counter; } atomic64_t;
struct sock_common { possible_net_t skc_net; atomic64_t skc_cookie; };
struct sock { struct sock_common __sk_common; };
struct sock_reuseport { __u16 num_socks; struct sock *socks[]; };
struct nsproxy { struct net *net_ns; };
struct task_struct { struct nsproxy *nsproxy; };
struct sk_buff { struct sock *sk; };
struct inet_cork { __u16 gso_size; };
struct msghdr { unsigned int msg_flags; };
#pragma clang attribute pop
#endif
