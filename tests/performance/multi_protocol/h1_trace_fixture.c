// SPDX-License-Identifier: GPL-2.0
#define _GNU_SOURCE
#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <signal.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/prctl.h>
#include <sys/socket.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <sys/uio.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

static char payload[1024 * 1024]; // synthetic bytes only
static _Thread_local volatile uint64_t sink;
static void receipt(const char *label, long id, int fd, long result, int error, size_t offered)
{
    printf("{\"phase\":\"call\",\"label\":\"%s\",\"pid\":%d,\"tid\":%ld,\"id\":%ld,\"fd\":%d,"
           "\"result\":%ld,\"errno\":%d,\"offered\":%zu}\n", label, getpid(), syscall(SYS_gettid), id, fd, result, error, offered);
    fflush(stdout);
}
#define CALL(label, id, fd, offered, ...) do { \
    errno = 0; long r = syscall(id, fd, __VA_ARGS__); int e = errno; \
    receipt(label, id, fd, r, e, offered); \
} while (0)
static void byte(void)
{
    char c;
    if (read(STDIN_FILENO, &c, 1) != 1) exit(3);
}
static int connected(int port, int *peer)
{
    int server = socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC, 0), one = 1;
    if (server < 0 || setsockopt(server, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one))) exit(4);
    struct sockaddr_in addr = {.sin_family = AF_INET, .sin_port = htons((uint16_t)port), .sin_addr.s_addr = htonl(INADDR_LOOPBACK)};
    if (bind(server, (void *)&addr, sizeof(addr)) || listen(server, 4)) exit(5);
    int client = socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC, 0);
    if (client < 0 || connect(client, (void *)&addr, sizeof(addr))) exit(6);
    *peer = accept4(server, NULL, NULL, SOCK_CLOEXEC);
    close(server);
    if (*peer < 0) exit(7);
    struct timeval timeout = {.tv_sec = 1};
    if (setsockopt(client, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout)) ||
        setsockopt(*peer, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout))) exit(8);
    return client;
}
static void transfers(int sender, int receiver)
{
    char output[64];
    struct iovec sendv[2] = {{payload, 5}, {payload + 5, 7}};
    struct iovec recvv[2] = {{output, 5}, {output + 5, 7}};
    struct msghdr sm = {.msg_iov = sendv, .msg_iovlen = 2};
    struct msghdr rm = {.msg_iov = recvv, .msg_iovlen = 2};
    CALL("scalar", SYS_write, sender, 12, payload, 12);
    CALL("scalar", SYS_read, receiver, 12, output, 12);
    CALL("vector", SYS_writev, sender, 12, sendv, 2);
    CALL("vector", SYS_readv, receiver, 12, recvv, 2);
    CALL("sendto", SYS_sendto, sender, 12, payload, 12, MSG_NOSIGNAL, NULL, 0);
    CALL("recvfrom", SYS_recvfrom, receiver, 12, output, 12, 0, NULL, NULL);
    CALL("sendmsg", SYS_sendmsg, sender, 12, &sm, MSG_NOSIGNAL);
    CALL("recvmsg", SYS_recvmsg, receiver, 12, &rm, 0);
    struct mmsghdr sendbatch[2] = {{.msg_hdr = sm}, {.msg_hdr = sm}};
    struct mmsghdr recvbatch[2] = {{.msg_hdr = rm}, {.msg_hdr = rm}};
    CALL("sendmmsg", SYS_sendmmsg, sender, 24, sendbatch, 2, MSG_NOSIGNAL);
    CALL("recvmmsg", SYS_recvmmsg, receiver, 24, recvbatch, 2, MSG_DONTWAIT, NULL);
    printf("{\"phase\":\"batch_lengths\",\"send\":[%u,%u],\"recv\":[%u,%u]}\n",
           sendbatch[0].msg_len, sendbatch[1].msg_len, recvbatch[0].msg_len, recvbatch[1].msg_len);
    CALL("zero_read", SYS_read, receiver, 0, output, 0);
    CALL("eagain", SYS_recvfrom, receiver, 12, output, 12, MSG_DONTWAIT, NULL, NULL);
    CALL("bad_fd", SYS_write, -1, 12, payload, 12);
    CALL("metadata_fault", SYS_writev, sender, 0, (void *)1, 2);
    struct iovec many[17] = {};
    CALL("vector_bound", SYS_writev, sender, 0, many, 17);
    // Positive batch prefix followed by malformed metadata; returned prefix only.
    sendbatch[1].msg_hdr.msg_iov = (void *)1;
    CALL("batch_partial", SYS_sendmmsg, sender, 0, sendbatch, 2, MSG_NOSIGNAL);
    CALL("batch_partial_drain", SYS_recvfrom, receiver, 64, output, 64, MSG_DONTWAIT, NULL, NULL);
    // The first send may transfer bytes before msg_len copyout faults.
    size_t page = (size_t)sysconf(_SC_PAGESIZE);
    struct mmsghdr *readonly = mmap(NULL, page, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (readonly == MAP_FAILED) exit(9);
    readonly[0].msg_hdr = sm;
    if (mprotect(readonly, page, PROT_READ)) exit(10);
    CALL("batch_copyout_fault", SYS_sendmmsg, sender, 12, readonly, 1, MSG_NOSIGNAL);
    CALL("copyout_drain", SYS_recvfrom, receiver, 64, output, 64, MSG_DONTWAIT, NULL, NULL);
    munmap(readonly, page);
    fflush(stdout);
}
static void *thread_transfer(void *argument)
{
    int *fds = argument;
    transfers(fds[0], fds[1]);
    return NULL;
}
static void noop(int sig) { (void)sig; }
static void *cancel_read(void *argument)
{
    int fd = *(int *)argument;
    CALL("interrupted", SYS_read, fd, 12, payload, 12);
    return NULL;
}
__attribute__((noinline)) static uint64_t fixture_leaf(uint64_t x)
{
    for (unsigned int i = 0; i < 200000; i++) x = (x ^ (x >> 7)) * 0x2545f4914f6cdd1dULL + i;
    __asm__ volatile("" : "+r"(x));
    return x;
}
__attribute__((noinline)) static uint64_t fixture_middle(uint64_t x)
{
    uint64_t y = fixture_leaf(x); __asm__ volatile("" : "+r"(y)); return y + 1;
}
__attribute__((noinline)) static void fixture_outer(void)
{
    struct timespec start, now;
    clock_gettime(CLOCK_MONOTONIC, &start);
    do {
        sink = fixture_middle(sink + 1);
        clock_gettime(CLOCK_MONOTONIC, &now);
    } while (now.tv_sec - start.tv_sec < 3);
}
static void *cpu_thread(void *unused) { (void)unused; fixture_outer(); return NULL; }
int main(int argc, char **argv)
{
    if (argc != 2 || getuid() == 0) return 2;
    if (prctl(PR_SET_PDEATHSIG, SIGTERM)) return 2;
    alarm(20); // all waits/work are owned and finite
    signal(SIGPIPE, SIG_IGN);
    setvbuf(stdout, NULL, _IOLBF, 0);
    printf("{\"phase\":\"ready\",\"pid\":%d,\"uid\":%d}\n", getpid(), getuid());
    byte(); // supervisor binds/attaches before any fixture work
    if (!strcmp(argv[1], "cpu") || !strcmp(argv[1], "cpu-teardown")) {
        pthread_t a, b;
        if (pthread_create(&a, NULL, cpu_thread, NULL) || pthread_create(&b, NULL, cpu_thread, NULL)) return 11;
        pid_t child = fork();
        if (child < 0) return 12;
        if (!child) { alarm(5); fixture_outer(); _exit(0); }
        printf("{\"phase\":\"child\",\"pid\":%d}\n", child);
        fixture_outer(); pthread_join(a, NULL); pthread_join(b, NULL);
        int status;
        if (waitpid(child, &status, 0) != child || !WIFEXITED(status) || WEXITSTATUS(status)) return 13;
        if (!strcmp(argv[1], "cpu-teardown")) {
            // All work/threads/child joined; remain alive until the supervisor
            // acknowledges teardown. The fixture never fabricates client RPS.
            puts("{\"phase\":\"workload_done\"}");
            byte();
        }
    } else if (!strcmp(argv[1], "syscalls")) {
        int accepted;
        int client = connected(8443, &accepted);
        transfers(client, accepted); // cookie may remain zero before INET_DIAG
        printf("{\"phase\":\"prime\"}\n"); byte();
        transfers(accepted, client);
        int fds[] = {client, accepted}; pthread_t thread;
        if (pthread_create(&thread, NULL, thread_transfer, fds)) return 14;
        pthread_join(thread, NULL);
        int alias = dup(accepted);
        CALL("alias", SYS_write, alias, 12, payload, 12);
        CALL("alias_recv", SYS_read, client, 12, payload, 12);
        close(alias);
        int upstream_peer, admin_peer;
        int upstream = connected(3447, &upstream_peer), admin = connected(9000, &admin_peer);
        printf("{\"phase\":\"prime\"}\n"); byte();
        transfers(upstream, upstream_peer); transfers(upstream_peer, upstream);
        transfers(admin, admin_peer);
        int reused = dup(upstream);
        int saved = reused; close(reused);
        if (dup2(admin, saved) < 0) return 15;
        CALL("fd_reused", SYS_write, saved, 12, payload, 12);
        CALL("fd_reused_recv", SYS_read, admin_peer, 12, payload, 12);
        close(saved);
        // Saturate without an active reader: bounded partial/EAGAIN observations.
        int size = 4096;
        if (setsockopt(accepted, SOL_SOCKET, SO_SNDBUF, &size, sizeof(size))) return 16;
        for (int i = 0; i < 16; i++) {
            errno = 0;
            long r = syscall(SYS_sendto, accepted, payload, sizeof(payload), MSG_DONTWAIT | MSG_NOSIGNAL, NULL, 0);
            receipt("partial_nonblocking", SYS_sendto, accepted, r, errno, sizeof(payload));
            if (r < 0) break;
        }
        struct sigaction act = {.sa_handler = noop}; sigemptyset(&act.sa_mask);
        if (sigaction(SIGUSR1, &act, NULL)) return 17;
        if (pthread_create(&thread, NULL, cancel_read, &upstream)) return 18;
        usleep(100000); pthread_kill(thread, SIGUSR1); pthread_join(thread, NULL);
        // Actual shutdown/EOF, followed by dup alias surviving original close.
        shutdown(upstream_peer, SHUT_WR);
        CALL("eof", SYS_read, upstream, 12, payload, 12);
        close(upstream); close(upstream_peer); close(admin); close(admin_peer);
        close(client); close(accepted);
        // Explicit unsupported census: no bytes claimed for sendfile/splice/io_uring.
        CALL("unsupported_sendfile", SYS_sendfile, -1, 0, -1, NULL, 1);
        CALL("unsupported_io_uring", SYS_io_uring_enter, -1, 0, 0, 0, 0, NULL, 0);
    } else return 2;
    puts("{\"phase\":\"done\"}");
    return 0;
}
