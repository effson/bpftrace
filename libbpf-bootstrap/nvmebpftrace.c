#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>

// BPF 宏，用于获取 struct request 结构体中与块设备操作相关的字节数
#define BLK_RQ_BYTES(rq) BPF_CORE_READ(rq, __data_len)
#define BLK_RQ_SECTOR(rq) BPF_CORE_READ(rq, sector)

typedef int pid_t;
#define TASK_COMM_LEN 16

const volatile pid_t targ_tgid = 0;

// 定义用于存储起始时间戳和进程信息的结构体
struct nvme_start_data {
    char comm[TASK_COMM_LEN];
    __u64 ts; // 纳秒时间戳
    __u32 tgid; // 线程组 ID
};

// 定义用于向用户空间输出的事件结构体
struct nvme_event {
    char comm[TASK_COMM_LEN];
    char disk_name[DISK_NAME_LEN];
    __u64 delta_us; // 时延，单位微秒
    __u64 ts_us; // 纳秒时间戳，单位微秒
    __u64 sector; // 起始扇区
    __u32 bytes; // 请求大小，单位字节
    __u32 tgid; // 线程组 ID
    __u8 op; // I/O 操作类型 (读/写/丢弃)
};

// --- BPF Maps ---
// perf event map，用于内核 → 用户态通信
struct {
    __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
    __uint(key_size, sizeof(__u32));
    __uint(value_size, sizeof(__u32));
} events_nvme SEC(".maps");

// 哈希映射，用于存储请求的起始时间。键是 struct request*，值是起始数据
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 4096);
    __type(key, struct request *);
    __type(value, struct nvme_start_data);
} start_nvme SEC(".maps");

// --- BPF 探针函数 ---

static int trace_nvme_request_submit(struct request *rq)
{
    __u64 id = bpf_get_current_pid_tgid();
    pid_t tgid = id >> 32;

    // 根据 tgid 过滤进程，如果 targ_tgid 不为0
    if (targ_tgid && (tgid != targ_tgid)) {
        return 0;
    }

    struct nvme_start_data data = {};
    bpf_get_current_comm(&data.comm, sizeof(data.comm));
    data.ts = bpf_ktime_get_ns();
    data.tgid = tgid;

    // 将请求指针作为键，起始数据作为值，存入哈希映射
    bpf_map_update_elem(&start_nvme, &rq, &data, BPF_ANY);

    return 0;
}

static int trace_nvme_request_complete(struct request *rq, __u32 result)
{
    struct nvme_start_data *pdata;
    struct nvme_event event = {};
    __u64 ts;
    __s64 delta;

    pdata = bpf_map_lookup_elem(&start_nvme, &rq);
    if (!pdata) {
        return 0;
    }

    ts = bpf_ktime_get_ns();
    delta = (__s64)(ts - pdata->ts);
    if (delta < 0) {
        goto cleanup;
    }

    // 填充事件结构体
    event.delta_us = delta / 1000U;
    __builtin_memcpy(&event.comm, pdata->comm, sizeof(event.comm));
    event.ts_us = ts / 1000;
    event.tgid = pdata->tgid;
    event.sector = BLK_RQ_SECTOR(rq);
    event.bytes = BLK_RQ_BYTES(rq);
    event.op = BPF_CORE_READ(rq, cmd_flags) & REQ_OP_MASK;

    // 可以在这里读取块设备名称
    struct gendisk *disk = BPF_CORE_READ(rq, q, disk);
    BPF_CORE_READ_INTO(&event.disk_name, disk, disk_name);

    // 将事件数据输出到用户空间
    bpf_perf_event_output(ctx, &events_nvme, BPF_F_CURRENT_CPU, &event, sizeof(event));

cleanup:
    // 清除哈希映射中的条目
    bpf_map_delete_elem(&start_nvme, &rq);
    return 0;
}

// --- kprobe 函数定义 ---

// 追踪 nvme_queue_rq，获取请求提交的起始时间
SEC("kprobe/nvme_queue_rq")
int BPF_KPROBE(nvme_queue_rq, struct blk_mq_hw_ctx *hctx, const struct blk_mq_queue_data *bd)
{
    return trace_nvme_request_submit(bd->rq);
}

// 追踪 nvme_complete_rq，获取请求完成的结束时间并计算时延
SEC("kprobe/nvme_complete_rq")
int BPF_KPROBE(nvme_complete_rq, struct request *rq, __u32 result)
{
    // 注意：nvme_complete_rq 的参数签名可能随内核版本变化
    return trace_nvme_request_complete(rq, result);
}

char LICENSE[] SEC("license") = "Dual BSD/GPL";
