// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
/* Copyright (c) 2020 Facebook */
#include <stdio.h>
#include <unistd.h>
#include <sys/resource.h>
#include <bpf/bpf.h>
#include <bpf/btf.h>
#include <arpa/inet.h>

#include <bpf/libbpf.h>
#include "tcpconnection.skel.h"

#define TASK_COMM_LEN 16

typedef unsigned int u32;
typedef int pid_t;

struct event{
    union {
        __u32 saddr_v4; // IPv4 source address
        __u32 saddr_v6[16]; // IPv6 source address
    };
    union {
        __u32 daddr_v4; // IPv4 destination address
        __u32 daddr_v6[16]; // IPv6 destination address
    };
    char comm[TASK_COMM_LEN];

    __u64 delta_us; // 时间差，单位微秒
    __u64 ts_us; // 时间戳，单位微秒
    __u32 tgid; // 线程组 ID
    int af;
    __u16 lport; // 本地端口
    __u16 dport; // 远程端口
};

void tcpconnection_handle_event(void *ctx, int cpu, void *data, __u32 size){
    printf("tcpconnection_handle_event\n");
    const struct event *ev = data;
    char src[INET6_ADDRSTRLEN];
    char dst[INET6_ADDRSTRLEN];
    union {
        struct in_addr x4;
        struct in6_addr x6;
    } s, d;
    static __u64 start_ts;
    if (start_ts == 0) {
        start_ts = ev->ts_us;
    }

    printf("%-9.3f ", (ev->ts_us - start_ts) / 1000000.0);

    if (ev->af == AF_INET) {
        s.x4.s_addr = ev->saddr_v4;
        d.x4.s_addr = ev->daddr_v4;
    } else if (ev->af == AF_INET6) {
        memcpy(&s.x6.s6_addr, ev->saddr_v6, sizeof(s.x6.s6_addr));
        memcpy(&d.x6.s6_addr, ev->daddr_v6, sizeof(d.x6.s6_addr));
    } else {
        fprintf(stderr, "Unknown address family: %d\n", ev->af);
        return;
    }

    printf("%-6d %-12.12s %-2d %-16s %-6d %-16s %-5d %.2f\n", ev->tgid,
        ev->comm, ev->af == AF_INET ? 4 : 6,
        inet_ntop(ev->af, &s, src, sizeof(src)),ev->lport,
        inet_ntop(ev->af, &d, dst, sizeof(dst)), ev->dport,
        ev->delta_us / 1000.0);
}

void tcpconnection_lose_event(void *ctx, int cpu, __u64 cnt){
    printf("tcpconnection_lose_event\n");
}

bool verbose = false;

static int libbpf_print_fn(enum libbpf_print_level level, const char *format, va_list args)
{
    if (level == LIBBPF_DEBUG && !verbose) return 0;
        return 0; // Skip debug messages if verbose is not enabled
    return vfprintf(stderr, format, args);
}

int main(int argc, char **argv)
{
    struct tcpconnection_bpf *skel;
    int err;

    /* Set up libbpf errors and debug info callback */
    libbpf_set_strict_mode(LIBBPF_STRICT_ALL);
    libbpf_set_print(libbpf_print_fn);
    /* Open BPF application */
    skel = tcpconnection_bpf__open();
    if (!skel) {
        fprintf(stderr, "Failed to open BPF skeleton\n");
        return 1;
    }

    bpf_program__set_autoload(skel->progs.tcp_v4_connect, true);
    bpf_program__set_autoload(skel->progs.tcp_v6_connect, true);
    bpf_program__set_autoload(skel->progs.tcp_rcv_state_process, true);
    /* ensure BPF program only handles write() syscalls from our process */
    // skel->bss->my_pid = getpid();

    /* Load & verify BPF programs */
    err = tcpconnection_bpf__load(skel);
    if (err) {
        fprintf(stderr, "Failed to load and verify BPF skeleton\n");
        goto cleanup;
    }

    /* Attach tracepoint handler */
    err = tcpconnection_bpf__attach(skel);
    if (err) {
        fprintf(stderr, "Failed to attach BPF skeleton\n");
        goto cleanup;
    }
#if 0
    printf("Successfully started! Please run `sudo cat /sys/kernel/debug/tracing/trace_pipe` "
            "to see output of the BPF programs.\n");
    for (;;) {
        /* trigger our BPF program */
        fprintf(stderr, ".");
        sleep(1);
    }
#else
    struct perf_buffer *pb = perf_buffer__new(bpf_map__fd(skel->maps.events), 8,
                     tcpconnection_handle_event, tcpconnection_lose_event, NULL, NULL);
    if (!pb) {
        goto cleanup;
    }

    while (1) {
        /* poll for events */
        err = perf_buffer__poll(pb, 1000);
        if (err < 0) {
            fprintf(stderr, "Error polling perf buffer: %d\n", err);
            break;
        }
    }

    perf_buffer__free(pb);
#endif
cleanup:
    tcpconnection_bpf__destroy(skel);
    return -err;
}
