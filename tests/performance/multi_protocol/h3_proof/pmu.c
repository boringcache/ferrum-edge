// SPDX-License-Identifier: GPL-2.0
#define _GNU_SOURCE
#include <errno.h>
#include <linux/perf_event.h>
#include <stdio.h>
#include <sys/ioctl.h>
#include <sys/syscall.h>
#include <unistd.h>

int main(void)
{
    const char *names[] = {"software_cpu_clock", "hardware_cycles"};
    printf("[");
    for (int i = 0; i < 2; i++) {
        struct perf_event_attr attr = {
            .size = sizeof(attr), .type = i ? PERF_TYPE_HARDWARE : PERF_TYPE_SOFTWARE,
            .config = i ? PERF_COUNT_HW_CPU_CYCLES : PERF_COUNT_SW_CPU_CLOCK,
            .disabled = 1, .exclude_kernel = 1, .exclude_hv = 1,
            .read_format = PERF_FORMAT_TOTAL_TIME_ENABLED | PERF_FORMAT_TOTAL_TIME_RUNNING,
        };
        int fd = (int)syscall(SYS_perf_event_open, &attr, 0, -1, -1, 0);
        if (i) printf(",");
        if (fd < 0) {
            printf("{\"event\":\"%s\",\"status\":\"unsupported\",\"stage\":\"open\",\"errno\":%d,\"value\":null}", names[i], errno);
            continue;
        }
        int err = ioctl(fd, PERF_EVENT_IOC_ENABLE, 0) ? errno : 0;
        for (volatile unsigned int j = 0; j < 1000000; j++) { }
        if (ioctl(fd, PERF_EVENT_IOC_DISABLE, 0) && !err) err = errno;
        struct { unsigned long long value, enabled, running; } result = {0};
        if (read(fd, &result, sizeof(result)) != (ssize_t)sizeof(result) && !err) err = errno ? errno : EIO;
        close(fd);
        if (err || !result.running) {
            printf("{\"event\":\"%s\",\"status\":\"unsupported\",\"stage\":\"read_or_not_running\",\"errno\":%d,\"value\":null}", names[i], err);
        } else {
            printf("{\"event\":\"%s\",\"status\":\"supported\",\"value\":%llu,\"enabled_ns\":%llu,\"running_ns\":%llu}",
                   names[i], result.value, result.enabled, result.running);
        }
    }
    puts("]");
    return 0;
}
