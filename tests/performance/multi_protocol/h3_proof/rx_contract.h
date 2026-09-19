#ifndef H3_RX_CONTRACT_H
#define H3_RX_CONTRACT_H
#include <linux/types.h>
/* Fixed native amd64 userspace ABI. These are deliberately not CO-RE types. */
struct user_msg {
    __u64 name; __u32 namelen, pad;
    __u64 iov, iovlen, control, controllen;
    __u32 flags, pad2;
};
struct user_cmsg { __u64 length; int level, type; };

static __inline int h3_native_call(int id, int batch, __u32 vlen)
{
    return id == (batch ? 299 : 47) && vlen > 0 && vlen <= 32;
}
static __inline int h3_control_bounds(__u64 original, __u64 capacity, __u64 returned, __u64 length)
{
    return original == returned && length <= capacity && length <= 256 && returned + length >= returned;
}
static __inline int h3_cmsg_shape(const struct user_cmsg *c, __u64 remaining, __u32 seen)
{
    return c->length >= 16 && c->length <= remaining &&
        !(c->level == 17 && c->type == 104 && (c->length != 20 || seen));
}
static __inline int h3_segment_valid(int segment)
{
    return segment > 0 && segment <= 65535;
}
static __inline int h3_delivered_gro(__u64 bytes, __u32 segment, __u32 output, __u32 input)
{
    return segment && bytes > segment && !(output & (8 | 32)) && !(input & (2 | 8192));
}
static __inline int h3_prefix_valid(long returned, __u32 requested, __u32 entries)
{
    return returned > 0 && requested > 0 && requested <= 32 && returned <= requested && returned <= entries;
}
#endif
