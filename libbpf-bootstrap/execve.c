// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
/* Copyright (c) 2020 Facebook */
#include <stdio.h>
#include <unistd.h>
#include <sys/resource.h>
#include <bpf/libbpf.h>
#include "execve.skel.h"

#define TASK_COMM_LEN 16

struct comm_info{
    char comm[TASK_COMM_LEN];
    int pid;
};

void execve_handle_event(void *ctx, int cpu, void *data, __u32 size){
    // printf("execve_handle_event: cpu %d, size %u, comm %s, pid %d\n", cpu, size, info->comm, info->pid);
    struct comm_info *info = (struct comm_info *)data;
    if(!info) return;
    printf("comm %s, pid %d\n", info->comm, info->pid);
}

void execve_lose_event(void *ctx, int cpu, __u64 cnt){
    printf("execve_lose_event: cpu %d, cnt %llu\n", cpu, cnt);
}

static int libbpf_print_fn(enum libbpf_print_level level, const char *format, va_list args)
{
        return vfprintf(stderr, format, args);
}

int main(int argc, char **argv)
{
    struct execve_bpf *skel;
    int err;

    /* Set up libbpf errors and debug info callback */
    libbpf_set_print(libbpf_print_fn);

    /* Open BPF application */
    skel = execve_bpf__open();
    if (!skel) {
            fprintf(stderr, "Failed to open BPF skeleton\n");
            return 1;
    }

    /* ensure BPF program only handles write() syscalls from our process */
    // skel->bss->my_pid = getpid();

    /* Load & verify BPF programs */
    err = execve_bpf__load(skel);
    if (err) {
        fprintf(stderr, "Failed to load and verify BPF skeleton\n");
        goto cleanup;
    }

    /* Attach tracepoint handler */
    err = execve_bpf__attach(skel);
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
    struct perf_buffer *pb = perf_buffer__new(bpf_map__fd(skel->maps.output), 8,
                     execve_handle_event, execve_lose_event, NULL, NULL);
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
    execve_bpf__destroy(skel);
    return -err;
}
