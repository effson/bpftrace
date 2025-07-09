// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
/* Copyright (c) 2020 Facebook */
#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>

typedef unsigned int u32;
typedef int pid_t;

#define AF_INET 2
#define AF_INET6 10
#define TASK_COMM_LEN 16

//int my_pid = 0;
struct piddata {
    char comm[TASK_COMM_LEN];
    __u64 ts; // 时间戳，单位纳秒
    __u32 tgid; // 线程组 ID
};

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

const volatile pid_t targ_tgid = 0; 

struct {
    __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY); //类型是 perf event map，用于内核 → 用户态通信
    __uint(key_size, sizeof(u32));
    __uint(value_size, sizeof(u32));
} events SEC(".maps"); //放入 ELF 文件的 .maps section，供 libbpf 自动加载,用户态用 perf_buffer__new 监听它

struct {
    __uint(type, BPF_MAP_TYPE_HASH); //类型是 HASH，用于内核 → 用户态通信
    __uint(max_entries, 4096); //最大条目数
    __type(key, struct sock *);
    __type(value, struct piddata);
} start SEC(".maps"); // perf event map for user space to read

#if 0
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
#else

static int trace_tcp_connect(struct sock *sk)
{
    __u64 id = bpf_get_current_pid_tgid(); // 获取当前进程的 PID 和 TGID
    pid_t tgid = id >> 32; // 获取 TGID

    struct piddata piddata = {0};
    if (targ_tgid && (tgid != targ_tgid)) {
        return 0; // 如果 TGID 不匹配，则直接返回
    }
    bpf_get_current_comm(&piddata.comm, sizeof(piddata.comm)); // 获取当前进程的命令名
    piddata.ts = bpf_ktime_get_ns(); // 获取当前时间戳
    piddata.tgid = tgid; // 设置 TGID

    bpf_map_update_elem(&start, &sk, &piddata, 0); 
    return 0; 
} 

static int handle_tcp_rcv_state_process(void *ctx, struct sock *sk)
{
    struct piddata *pdata;
    struct event event = {};
    u64 ts;
    s64 delta;
    bpf_printk("handle_tcp_rcv_state_process --> bpf_perf_event_output\n");

    if(TCP_SYN_SENT == BPF_CORE_READ(sk, __sk_common.skc_state)) {
        // 处理 TCP SYN_SENT 状态
        return 0;
    }  

    pdata = bpf_map_lookup_elem(&start, &sk); // 查找当前进程的条目
    if (!pdata) {
        return 0;
    }

    ts = bpf_ktime_get_ns();
    delta = (s64)(ts - pdata->ts);
    if (delta < 0) {
        goto cleanup; // 如果时间差为负，直接返回
    }

    event.delta_us = delta / 1000U; // 转换为微秒

    __builtin_memcpy(&event.comm, pdata->comm, sizeof(event.comm)); // 清空 event 结构体
    event.ts_us = ts / 1000;
    event.tgid = pdata->tgid;
    event.lport = BPF_CORE_READ(sk, __sk_common.skc_num);
    event.dport = BPF_CORE_READ(sk, __sk_common.skc_dport);
    event.af = BPF_CORE_READ(sk, __sk_common.skc_family);

    if (event.af == AF_INET) {
        event.saddr_v4 = BPF_CORE_READ(sk, __sk_common.skc_rcv_saddr);
        event.daddr_v4 = BPF_CORE_READ(sk, __sk_common.skc_daddr);
    } else {
        // 处理 IPv6 地址
        BPF_CORE_READ_INTO(&event.saddr_v6, sk, __sk_common.skc_v6_rcv_saddr.in6_u.u6_addr32);
        BPF_CORE_READ_INTO(&event.daddr_v6, sk, __sk_common.skc_v6_daddr.in6_u.u6_addr32);
    } 

    bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, &event, sizeof(event));
cleanup:
    bpf_map_delete_elem(&start, &sk); // 删除当前进程的条目
    return 0;
}

SEC("kprobe/tcp_v4_connect")
int BPF_KPROBE(tcp_v4_connect, struct sock *sk)
{
    return trace_tcp_connect(sk);
}

SEC("kprobe/tcp_v6_connect")
int BPF_KPROBE(tcp_v6_connect, struct sock *sk)
{
    return trace_tcp_connect(sk);
}

SEC("kprobe/tcp_rcv_state_process")
int BPF_KPROBE(tcp_rcv_state_process, struct sock *sk)
{
    return handle_tcp_rcv_state_process(ctx, sk);
}

#endif
char LICENSE[] SEC("license") = "Dual BSD/GPL";
