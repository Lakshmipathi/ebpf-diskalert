#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

#define FNAME_LEN 64

typedef __u64 u64;
typedef char stringkey[64];
struct data_t {
    int pid;
    int uid;
    u64 path;
    u64 v;
    char command[FNAME_LEN];    
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 128);
	stringkey* key;
    __type(value, u64);
} monitor_disk SEC(".maps"); 

struct {
    __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
    __uint(key_size, sizeof(u32));
    __uint(value_size, sizeof(u32));
} output SEC(".maps");

SEC("tracepoint/block/block_bio_complete")
int bpf_traceblock(struct trace_event_raw_block_rq *ctx)
{
    struct data_t data = {};
    bpf_printk("Triggered bpf_traceblock\n");
    data.pid = bpf_get_current_pid_tgid() >> 32;
    data.uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;
    bpf_get_current_comm(&data.command, sizeof(data.command));

    
    int major = (ctx->dev >> 20) & 0xFFF;
    int minor = ctx->dev & 0xFFFFF; 
    char req_type = ctx->rwbs[0];
    data.path = ctx->dev;

    //trace only writes
    if (req_type != 'W') {
        return 0; 
    }
    // fetch value from userspace.
    stringkey key = "monitor_disk";
    u64 *v = NULL;
    v = bpf_map_lookup_elem(&monitor_disk, &key);
    if (v != NULL) {
    bpf_printk("diskid: %d\n", *v);
    }
    bpf_probe_read(&data.v, sizeof(data.v), v);
    if (data.path != data.v) {
      return 0;
    }

    bpf_printk("bpf_traceblock: devid: %d major:%d minor:%d type:%c dev:%d\n",data.v,major,minor,req_type,data.path);
    bpf_perf_event_output(ctx, &output, BPF_F_CURRENT_CPU, &data, sizeof(data));   
    return 0;
}
char LICENSE[] SEC("license") = "GPL";
