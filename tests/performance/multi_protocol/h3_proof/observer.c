// SPDX-License-Identifier: GPL-2.0
#define _GNU_SOURCE
#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <bpf/btf.h>
#include <errno.h>
#include <poll.h>
#include <signal.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>
#include "contract.h"

_Static_assert(sizeof(void *) == 8 && sizeof(struct msghdr) == 56, "native amd64 ABI");
_Static_assert(offsetof(struct msghdr, msg_flags) == 48, "native msg_flags");
static volatile sig_atomic_t stopping;
static char verifier[256 * 1024];
static size_t log_bytes;
static bool log_truncated;

static int logger(enum libbpf_print_level level, const char *fmt, va_list ap)
{
    (void)level;
    char buf[4096];
    int n = vsnprintf(buf, sizeof(buf), fmt, ap);
    if (n < 0) return n;
    size_t length = (size_t)n < sizeof(buf) ? (size_t)n : sizeof(buf) - 1;
    if ((size_t)n >= sizeof(buf)) log_truncated = true;
    if (log_bytes + length > 512 * 1024) { log_truncated = true; return n; }
    log_bytes += length;
    // libbpf diagnostics are metadata/verifier instructions, never packet bytes.
    fwrite(buf, 1, length, stderr);
    return n;
}
static unsigned long long now_ns(void)
{
    struct timespec t;
    if (clock_gettime(CLOCK_MONOTONIC, &t)) return 0;
    return (unsigned long long)t.tv_sec * 1000000000ULL + (unsigned long long)t.tv_nsec;
}
static void stop_signal(int sig) { (void)sig; stopping = 1; }

// The small JSON strings passed here are fixed tokens, never arbitrary diagnostics.
static int unavailable(const char *status, const char *stage, int error)
{
    printf("{\"phase\":\"ready\",\"status\":\"%s\",\"reason\":\"%s\","
           "\"errno\":%d,\"verifier_log_truncated\":%s}\n",
           status, stage, error, log_truncated ? "true" : "false");
    fflush(stdout);
    return strcmp(status, "error") == 0 ? 1 : 0;
}
static const struct btf_type *resolve(const struct btf *b, __u32 id)
{
    const struct btf_type *t = btf__type_by_id(b, id);
    for (int i = 0; t && i < 16; i++) {
        if (!btf_is_mod(t) && !btf_is_typedef(t) && !btf_is_type_tag(t)) return t;
        t = btf__type_by_id(b, t->type);
    }
    return NULL;
}
static bool pointer_to(const struct btf *b, __u32 id, const char *name)
{
    const struct btf_type *t = resolve(b, id);
    if (!t || !btf_is_ptr(t)) return false;
    t = resolve(b, t->type);
    return t && btf_is_struct(t) && strcmp(btf__name_by_offset(b, t->name_off), name) == 0;
}
static bool integer(const struct btf *b, __u32 id, unsigned int size)
{
    const struct btf_type *t = resolve(b, id);
    return t && btf_is_int(t) && t->size == size;
}
struct site { const char *name; int argc; const char *args[5]; const char *ret; };
static const struct site tx_sites[] = {
    {"udp_sendmsg", 3, {"sock", "msghdr", "8"}, "4"},
    {"udp_send_skb", 3, {"sk_buff", "flowi4", "inet_cork"}, "4"},
};
static const struct site rx_sites[] = {
    // Only the first argument is consumed; accept four/five-argument variants.
    {"udp_recvmsg", -1, {"sock", "msghdr", "8", "4"}, "4"},
};
static const struct site classic_sites[] = {
    {"reuseport_select_sock", 4, {"sock", "4", "sk_buff", "4"}, "sock"},
    {"run_bpf_filter", 5, {"sock_reuseport", "2", "bpf_prog", "sk_buff", "4"}, "sock"},
    {"reuseport_attach_prog", 2, {"sock", "bpf_prog"}, "4"},
};
static bool matches(const struct btf *btf, __u32 type, const char *spec)
{
    if (spec[0] >= '0' && spec[0] <= '9') return integer(btf, type, (unsigned int)atoi(spec));
    return pointer_to(btf, type, spec);
}
static int check_site(const struct btf *b, const struct site *s)
{
    int id = btf__find_by_name_kind(b, s->name, BTF_KIND_FUNC);
    if (id < 0) { fprintf(stderr, "missing BTF function: %s\n", s->name); return ENOENT; }
    const struct btf_type *f = btf__type_by_id(b, (__u32)id);
    const struct btf_type *p = btf__type_by_id(b, f->type);
    if (!p || !btf_is_func_proto(p)) return EPROTO;
    int count = btf_vlen(p), checked = s->argc;
    fprintf(stderr, "BTF function %s id=%d argc=%d\n", s->name, id, count);
    if (checked < 0) {
        if (count != 4 && count != 5) return EPROTO;
        checked = 4;
    } else if (count != checked) return EPROTO;
    if (!matches(b, p->type, s->ret)) return EPROTO;
    const struct btf_param *params = btf_params(p);
    for (int i = 0; i < checked; i++)
        if (!matches(b, params[i].type, s->args[i])) return EPROTO;
    return 0;
}
static int check_ftrace(const struct site *sites, size_t count)
{
    FILE *file = fopen("/sys/kernel/tracing/available_filter_functions", "r");
    if (!file) return errno;
    bool found[3] = {};
    char line[512], name[256];
    unsigned int lines = 0;
    while (lines++ < 200000 && fgets(line, sizeof(line), file)) {
        if (sscanf(line, "%255s", name) != 1) continue;
        for (size_t i = 0; i < count; i++) if (!strcmp(name, sites[i].name)) found[i] = true;
    }
    int err = ferror(file) ? EIO : 0;
    fclose(file);
    for (size_t i = 0; i < count; i++) if (!found[i]) {
        fprintf(stderr, "not available as exact ftrace function: %s (scan limit 200000 lines)\n", sites[i].name);
        return ENOENT;
    }
    return err;
}
static int check_format(const char *path, const char **fields, const int *offsets, int count)
{
    FILE *file = fopen(path, "r");
    if (!file) return errno;
    char line[512];
    unsigned int seen = 0;
    while (fgets(line, sizeof(line), file)) {
        for (int i = 0; i < count; i++) {
            char *position = strstr(line, "offset:");
            int offset = -1, size = -1;
            if (!strstr(line, fields[i]) || !position) continue;
            if (sscanf(position, "offset:%d; size:%d;", &offset, &size) != 2 ||
                offset != offsets[i] || size != (i == 0 ? 4 : 8)) { fclose(file); return EPROTO; }
            seen |= 1U << i;
        }
    }
    fclose(file);
    return seen == ((1U << count) - 1) ? 0 : EPROTO;
}
static int check_recvmsg_abi(void)
{
    const char *entry[] = {"__syscall_nr;", " fd;", " msg;", " flags;"};
    const int input_offsets[] = {8, 16, 24, 32};
    const char *leave[] = {"__syscall_nr;", " ret;"};
    const int output_offsets[] = {8, 16};
    int err = check_format("/sys/kernel/tracing/events/syscalls/sys_enter_recvmsg/format",
                           entry, input_offsets, 4);
    if (err) return err;
    return check_format("/sys/kernel/tracing/events/syscalls/sys_exit_recvmsg/format",
                         leave, output_offsets, 2);
}
static unsigned int pending_count(int fd, unsigned int *failures)
{
    __u64 key, next;
    unsigned int n = 0;
    int result = bpf_map_get_next_key(fd, NULL, &next);
    while (!result && n < 64) {
        n++; key = next;
        result = bpf_map_get_next_key(fd, &key, &next);
    }
    if (result && errno != ENOENT) (*failures)++;
    return n;
}
static unsigned int pending_selection(int fd, unsigned int *failures)
{
    int cpus = libbpf_num_possible_cpus();
    if (cpus < 1 || cpus > 4096) { (*failures)++; return 0; }
    struct selection *states = calloc((size_t)cpus, sizeof(*states));
    if (!states) { (*failures)++; return 0; }
    __u32 zero = 0;
    unsigned int active = 0;
    if (bpf_map_lookup_elem(fd, &zero, states)) (*failures)++;
    else for (int i = 0; i < cpus; i++) if (states[i].active) active++;
    free(states);
    return active;
}
static int snapshot(struct bpf_object *obj, const char *phase, unsigned long long start)
{
    int fd = bpf_object__find_map_fd_by_name(obj, "counts");
    int lfd = bpf_object__find_map_fd_by_name(obj, "losses");
    struct key key, next;
    struct value v;
    __u64 losses[LOSS_MAX] = {};
    unsigned int failures = 0, rows = 0;
    for (__u32 i = 0; i < LOSS_MAX; i++)
        if (bpf_map_lookup_elem(lfd, &i, &losses[i])) failures++;
    unsigned int tx = pending_count(bpf_object__find_map_fd_by_name(obj, "tx_pending"), &failures);
    unsigned int rx = pending_count(bpf_object__find_map_fd_by_name(obj, "rx_pending"), &failures);
    unsigned int selector = pending_selection(bpf_object__find_map_fd_by_name(obj, "selection"), &failures);
    printf("{\"phase\":\"%s\",\"start_ns\":%llu,\"end_ns\":%llu,\"rows\":[",
           phase, start, now_ns());
    int result = bpf_map_get_next_key(fd, NULL, &next);
    while (!result && rows < 512) {
        key = next;
        if (bpf_map_lookup_elem(fd, &key, &v)) { failures++; break; }
        if (rows++) printf(",");
        printf("{\"cookie\":%llu,\"peer_cookie\":%llu,\"kind\":%u,"
               "\"length\":%u,\"segment\":%u,\"result\":%lld,\"cpu\":%u,"
               "\"count\":%llu,\"first_ns\":%llu,\"last_ns\":%llu}",
               (unsigned long long)key.cookie, (unsigned long long)key.peer, key.kind,
               key.length, key.segment, (long long)key.result, key.cpu,
               (unsigned long long)v.count, (unsigned long long)v.first_ns,
               (unsigned long long)v.last_ns);
        result = bpf_map_get_next_key(fd, &key, &next);
    }
    if (result && errno != ENOENT) failures++;
    printf("],\"losses\":[");
    for (int i = 0; i < LOSS_MAX; i++) printf("%s%llu", i ? "," : "", (unsigned long long)losses[i]);
    printf("],\"map_read_failures\":%u,\"pending_tx\":%u,\"pending_rx\":%u,"
           "\"pending_selector\":%u,\"verifier_log_truncated\":%s,\"stream_sequence_gaps\":null,"
           "\"ring_drops\":null,\"stream_reason\":\"count_maps_no_event_stream\"}\n", failures, tx, rx, selector,
           log_truncated ? "true" : "false");
    fflush(stdout);
    return failures ? 1 : 0;
}
int main(int argc, char **argv)
{
    if (argc != 6) {
        fprintf(stderr, "usage: observer OBJECT {tx|rx|classic} NETNS {512|1} {normal|missing-btf|missing-symbol}\n");
        return 2;
    }
    const struct site *sites;
    size_t nsites;
    char prefix;
    if (!strcmp(argv[2], "tx")) { sites = tx_sites; nsites = 2; prefix = 't'; }
    else if (!strcmp(argv[2], "rx")) { sites = rx_sites; nsites = 1; prefix = 'r'; }
    else if (!strcmp(argv[2], "classic")) { sites = classic_sites; nsites = 3; prefix = 'c'; }
    else return 2;
    if (strcmp(argv[4], "512") && strcmp(argv[4], "1")) return 2;
    if (strcmp(argv[5], "normal") && strcmp(argv[5], "missing-btf") && strcmp(argv[5], "missing-symbol")) return 2;
    libbpf_set_print(logger);
    const char *btf_path = !strcmp(argv[5], "missing-btf") ? "/nonexistent/h3-proof-btf" : "/sys/kernel/btf/vmlinux";
    struct btf *btf = btf__parse(btf_path, NULL);
    long berr = libbpf_get_error(btf);
    if (!btf || berr) return unavailable("unsupported", "btf_read", berr ? (int)-berr : errno);
    for (size_t i = 0; i < nsites; i++) {
        int err = check_site(btf, &sites[i]);
        if (err) { btf__free(btf); return unavailable("unsupported", "btf_symbol_or_prototype", err); }
    }
    if (!strcmp(argv[5], "missing-symbol")) {
        struct site absent = {"h3_proof_deliberately_absent", 0, {NULL}, "4"};
        int err = check_site(btf, &absent);
        btf__free(btf);
        return unavailable(err ? "unsupported" : "error", "injected_missing_symbol", err);
    }
    btf__free(btf);
    int surface_error = check_ftrace(sites, nsites);
    if (surface_error) return unavailable("unsupported", "ftrace_function_visibility", surface_error);
    if (prefix == 'r' && (surface_error = check_recvmsg_abi()))
        return unavailable("unsupported", "native_recvmsg_tracepoint_abi", surface_error);
    LIBBPF_OPTS(bpf_object_open_opts, opts, .kernel_log_buf = verifier,
                .kernel_log_size = sizeof(verifier), .kernel_log_level = 1);
    struct bpf_object *obj = bpf_object__open_file(argv[1], &opts);
    if (!obj || libbpf_get_error(obj)) return unavailable("error", "object_open", errno);
    struct bpf_program *prog;
    bpf_object__for_each_program(prog, obj) {
        const char *name = bpf_program__name(prog);
        bpf_program__set_autoload(prog, name[0] == prefix && name[1] == '_');
    }
    struct bpf_map *map = bpf_object__find_map_by_name(obj, "counts");
    if (!map || bpf_map__set_max_entries(map, (__u32)atoi(argv[4]))) return unavailable("error", "map_config", errno);
    int err = bpf_object__load(obj);
    if (err) {
        fwrite(verifier, 1, strnlen(verifier, sizeof(verifier)), stderr);
        bpf_object__close(obj);
        return unavailable(err == -EPERM || err == -EACCES || err == -EOPNOTSUPP ? "unsupported" : "error", "load", -err);
    }
    __u32 zero = 0;
    char *end = NULL;
    struct config cfg = {.netns = strtoull(argv[3], &end, 10)};
    if (!end || *end || !cfg.netns) return unavailable("error", "netns_argument", EINVAL);
    if (bpf_map_update_elem(bpf_object__find_map_fd_by_name(obj, "config"), &zero, &cfg, BPF_ANY))
        return unavailable("error", "configure", errno);
    struct bpf_link *links[8] = {};
    int nlinks = 0;
    bpf_object__for_each_program(prog, obj) {
        if (!bpf_program__autoload(prog)) continue;
        fprintf(stderr, "attach %s\n", bpf_program__section_name(prog));
        struct bpf_link *link = bpf_program__attach(prog);
        err = (int)libbpf_get_error(link);
        if (!link || err) {
            if (!err) err = -errno;
            for (int i = 0; i < nlinks; i++) bpf_link__destroy(links[i]);
            bpf_object__close(obj);
            return unavailable(err == -EPERM || err == -EACCES || err == -ENOENT || err == -EOPNOTSUPP
                               ? "unsupported" : "error", "attach", -err);
        }
        links[nlinks++] = link;
    }
    signal(SIGTERM, stop_signal); signal(SIGINT, stop_signal);
    unsigned long long start = now_ns();
    printf("{\"phase\":\"ready\",\"status\":\"supported\",\"family\":\"%s\","
           "\"netns\":%llu,\"start_ns\":%llu,\"links\":%d,\"exercise_verified\":false}\n",
           argv[2], (unsigned long long)cfg.netns, start, nlinks);
    fflush(stdout);
    // Hard 30-second lifetime, bounded protocol (one-byte commands).
    int status = 0, snapshots = 0;
    while (!stopping && now_ns() - start < 30000000000ULL) {
        struct pollfd p = {.fd = STDIN_FILENO, .events = POLLIN};
        if (poll(&p, 1, 100) <= 0) continue;
        char c;
        if (read(STDIN_FILENO, &c, 1) != 1 || c == 'q') break;
        if (c == 's' && snapshots++ < 4) status |= snapshot(obj, "snapshot", start);
    }
    // Detach before final reads: final map iteration has no concurrent writers.
    for (int i = 0; i < nlinks; i++) bpf_link__destroy(links[i]);
    status |= snapshot(obj, "final", start);
    bpf_object__close(obj);
    return status;
}
