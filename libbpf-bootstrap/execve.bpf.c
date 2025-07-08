// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
/* Copyright (c) 2020 Facebook */
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

#define TASK_COMM_LEN 16

//int my_pid = 0;
struct comm_info{
    char comm[TASK_COMM_LEN];
    int pid;
};

struct {
    __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY); //类型是 perf event map，用于内核 → 用户态通信
    __uint(key_size, sizeof(u32));
    __uint(value_size, sizeof(u32));
} output SEC(".maps"); //放入 ELF 文件的 .maps section，供 libbpf 自动加载,用户态用 perf_buffer__new 监听它

struct {
    __uint(type, BPF_MAP_TYPE_HASH); //类型是 HASH，用于内核 → 用户态通信
    __uint(max_entries, 1024); //最大条目数
    __type(key, pid_t);
    __type(value, struct comm_info);
} execcomm SEC(".maps"); // perf event map for user space to read

SEC("tracepoint/syscalls/sys_enter_execve")
int handle_tp(void *ctx)
{
#if 0 
    char comm[TASK_COMM_LEN] = {0}; 
    bpf_get_current_comm(&comm, sizeof(comm)); 
    int pid = bpf_get_current_pid_tgid() >> 32; // Get the PID from the current task

    bpf_printk("name: [%s] %d -->\n", comm, pid);
#else

    struct comm_info info = {0};

    bpf_get_current_comm(&info.comm, sizeof(info.comm));

    info.pid = bpf_get_current_pid_tgid() >> 32; // Get the PID from the current task

    bpf_map_update_elem(&execcomm, &info.pid, &info, BPF_ANY); // 更新 execcomm map

    bpf_perf_event_output(ctx, &output, BPF_F_CURRENT_CPU, &info, sizeof(info)); // 发送到用户空间
#endif
    return 0;
}

char LICENSE[] SEC("license") = "Dual BSD/GPL";
