// Isolated H1 serialization/control. Loaded through the reviewed common loader.
#include "h1_contract.h"
static void h1_key_json(const struct h1_key *k)
{
    printf("\"pid\":%u,\"process_ns\":%llu,\"cgroup\":%llu,\"cookie\":%llu,"
           "\"netns\":%u,\"id\":%u,\"role\":%u,\"outcome\":%d,\"direction\":%u",
           k->pid, (unsigned long long)k->process_ns, (unsigned long long)k->cgroup,
           (unsigned long long)k->cookie, k->netns, k->id, k->role, k->outcome, k->direction);
}
static void h1_value_json(const struct h1_value *v)
{
#define H1_FIELD(f) printf(",\"" #f "\":%llu", (unsigned long long)v->f)
    H1_FIELD(attempts); H1_FIELD(exits); H1_FIELD(positive); H1_FIELD(zero);
    H1_FIELD(errors); H1_FIELD(restarts); H1_FIELD(eof); H1_FIELD(short_calls);
    H1_FIELD(offered); H1_FIELD(offered_known); H1_FIELD(accepted_bytes); H1_FIELD(accepted_known);
    H1_FIELD(return_sum); H1_FIELD(effective_bytes); H1_FIELD(inner_calls); H1_FIELD(inner_bytes);
    H1_FIELD(inner_errors); H1_FIELD(elapsed_ns); H1_FIELD(first_ns); H1_FIELD(last_ns);
#undef H1_FIELD
    printf(",\"min_return\":%lld,\"max_return\":%lld", (long long)v->min_return, (long long)v->max_return);
}
static int h1_event_json(void *ctx, void *data, size_t size)
{
    (void)ctx;
    if (size != sizeof(struct h1_event)) return -EPROTO;
    if (lifecycle_rows++ >= 8192) { lifecycle_omitted++; return 0; }
    const struct h1_event *e = data;
    printf("{\"phase\":\"h1_event\","); h1_key_json(&e->key);
#define H1_FIELD(f) printf(",\"" #f "\":%llu", (unsigned long long)e->f)
    H1_FIELD(thread_ns); H1_FIELD(sequence); H1_FIELD(entered_ns); H1_FIELD(exited_ns);
    H1_FIELD(offered); H1_FIELD(accepted); H1_FIELD(effective); H1_FIELD(inner_bytes);
    H1_FIELD(inner_calls); H1_FIELD(inner_errors); H1_FIELD(arg1); H1_FIELD(arg2);
    H1_FIELD(tid); H1_FIELD(kind); H1_FIELD(flags); H1_FIELD(kernel_flags); H1_FIELD(known); H1_FIELD(accepted_known);
    H1_FIELD(vlen); H1_FIELD(seen); H1_FIELD(metadata_error);
#undef H1_FIELD
    printf(",\"fd\":%d,\"result\":%lld}\n", e->fd, (long long)e->result);
    return 0;
}
static int h1_snapshot(struct bpf_object *obj, const char *phase)
{
    unsigned int failures = 0, rows = 0, pending = 0;
    unsigned long long before = now_ns();
    printf("{\"phase\":\"%s\",\"before_ns\":%llu,\"rows\":[", phase, before);
    int fd = bpf_object__find_map_fd_by_name(obj, "h_counts");
    struct h1_key key, next;
    int result = bpf_map_get_next_key(fd, NULL, &next);
    while (!result && rows < H1_CAPACITY) {
        key = next;
        struct h1_value v;
        if (bpf_map_lookup_elem(fd, &key, &v)) { failures++; break; }
        printf("%s{", rows++ ? "," : ""); h1_key_json(&key); h1_value_json(&v); printf("}");
        result = bpf_map_get_next_key(fd, &key, &next);
    }
    if ((result && errno != ENOENT) || (!result && rows == H1_CAPACITY)) failures++;
    printf("],\"totals\":[");
    rows = 0;
    fd = bpf_object__find_map_fd_by_name(obj, "h_totals");
    for (__u32 i = 0; i < 512; i++) {
        struct h1_value v;
        if (bpf_map_lookup_elem(fd, &i, &v)) { failures++; continue; }
        if (!v.attempts && !v.exits) continue;
        printf("%s{\"id\":%u", rows++ ? "," : "", i); h1_value_json(&v); printf("}");
    }
    printf("],\"census\":{");
    rows = 0;
    fd = bpf_object__find_map_fd_by_name(obj, "h_census");
    for (__u32 i = 0; i < 1024; i++) {
        __u64 v;
        if (bpf_map_lookup_elem(fd, &i, &v)) { failures++; continue; }
        if (v) printf("%s\"%u\":%llu", rows++ ? "," : "", i, (unsigned long long)v);
    }
    printf("},\"losses\":[");
    fd = bpf_object__find_map_fd_by_name(obj, "h_losses");
    for (__u32 i = 0; i < H_LOSS_MAX; i++) {
        __u64 v = 0;
        if (bpf_map_lookup_elem(fd, &i, &v)) failures++;
        printf("%s%llu", i ? "," : "", (unsigned long long)v);
    }
    fd = bpf_object__find_map_fd_by_name(obj, "h_pending");
    __u64 tid, next_tid;
    result = bpf_map_get_next_key(fd, NULL, &next_tid);
    while (!result && pending < H1_PENDING) {
        pending++; tid = next_tid; result = bpf_map_get_next_key(fd, &tid, &next_tid);
    }
    if (result && errno != ENOENT) failures++;
    printf("],\"pending\":%u,\"map_read_failures\":%u,\"after_ns\":%llu}\n", pending, failures, now_ns());
    fflush(stdout); return failures != 0;
}
static int h1_bind(struct bpf_object *obj, char *line)
{
    struct h1_config c = {};
    unsigned long long ticks, cgroup, netns;
    char extra;
    if (sscanf(line, "%u %llu %u %llu %llu %c", &c.pid, &ticks, &c.hz, &cgroup, &netns, &extra) != 5 ||
        !c.pid || !ticks || c.hz != 100 || !cgroup || !netns) return EINVAL;
    c.start_ticks = ticks; c.cgroup = cgroup; c.netns = netns;
    __u32 zero = 0;
    int error = bpf_map_update_elem(bpf_object__find_map_fd_by_name(obj, "h_config"), &zero, &c, BPF_ANY);
    if (error) return errno;
    printf("{\"phase\":\"bound\",\"pid\":%u,\"start_ticks\":%llu,\"cgroup\":%llu,\"netns\":%llu,\"at_ns\":%llu}\n",
           c.pid, ticks, cgroup, netns, now_ns());
    fflush(stdout); return 0;
}
static int h1_run(struct bpf_object *obj)
{
    struct ring_buffer *ring = ring_buffer__new(bpf_object__find_map_fd_by_name(obj, "h_events"), h1_event_json, NULL, NULL);
    if (!ring) { bpf_object__close(obj); return unavailable("error", "h1_ring_create", errno); }
    struct bpf_link *links[16] = {};
    int count = 0, status = 0;
    struct bpf_program *prog;
    bpf_object__for_each_program(prog, obj) {
        if (!bpf_program__autoload(prog)) continue;
        struct bpf_link *link = bpf_program__attach(prog);
        int error = (int)libbpf_get_error(link);
        if (!link || error || count == 16) {
            for (int i = 0; i < count; i++) bpf_link__destroy(links[i]);
            ring_buffer__free(ring); bpf_object__close(obj);
            return unavailable("unsupported", "h1_attach", error ? -error : errno);
        }
        links[count++] = link;
    }
    unsigned long long start = now_ns(), checkpoint = start;
    printf("{\"phase\":\"ready\",\"status\":\"supported\",\"family\":\"h1\",\"start_ns\":%llu,"
           "\"links\":%d,\"bound\":false,\"exercise_verified\":false,\"max_seconds\":300,\"max_snapshots\":64}\n", start, count);
    fflush(stdout);
    char binding[192] = {};
    unsigned int used = 0, snapshots = 0, omitted = 0;
    bool binding_line = false, bound = false, requested_stop = false;
    while (!stopping && now_ns() - start < 300000000000ULL) {
        if (ring_buffer__consume(ring) < 0) { status = 1; break; }
        if (bound && now_ns() - checkpoint >= 5000000000ULL && snapshots < 63) {
            status |= h1_snapshot(obj, "checkpoint"); snapshots++; checkpoint = now_ns();
        }
        struct pollfd input = {.fd = STDIN_FILENO, .events = POLLIN};
        if (poll(&input, 1, 100) <= 0) continue;
        char c;
        if (read(STDIN_FILENO, &c, 1) != 1) break;
        if (binding_line) {
            if (c == '\n') {
                binding[used] = 0;
                int error = h1_bind(obj, binding);
                if (error) { status = 1; break; }
                bound = true; binding_line = false;
            } else if (used < sizeof(binding) - 1) binding[used++] = c;
            else { status = 1; break; }
        } else if (c == 'b' && !bound) binding_line = true;
        else if (c == 'q') { requested_stop = true; break; }
        else if (c == 's') {
            if (snapshots++ < 63) status |= h1_snapshot(obj, "snapshot"); else omitted++;
        }
    }
    for (int i = 0; i < count; i++) bpf_link__destroy(links[i]);
    if (ring_buffer__consume(ring) < 0) status = 1;
    status |= h1_snapshot(obj, "final");
    printf("{\"phase\":\"termination\",\"requested_stop\":%s,\"bound\":%s,\"snapshot_failures\":%d,"
           "\"lifecycle_omitted\":%u,\"checkpoints_omitted\":%u,\"at_ns\":%llu}\n",
           requested_stop ? "true" : "false", bound ? "true" : "false", status, lifecycle_omitted, omitted, now_ns());
    ring_buffer__free(ring); bpf_object__close(obj); return status;
}
