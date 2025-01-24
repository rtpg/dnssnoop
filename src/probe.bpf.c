#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <yeet/yeet.h>

#define GET_TID() bpf_get_current_pid_tgid() & 0xffffffff;
#define GET_PID() bpf_get_current_pid_tgid() >> 32;

#define EXIT_SUCCESS 0

#define MAX_NAME_LENGTH 255
#define MAX_LIB_FUNC_LENGTH 30

struct dns_output {
    int pid;
    // the DNS entry lookup
    char name[MAX_NAME_LENGTH];
    // the library used
    char lib_func[MAX_LIB_FUNC_LENGTH];
    // how long the call took (in ns)
    long duration_ns;
} __attribute__((packed));

RINGBUF_CHANNEL(dns_rb, 1024 * sizeof(struct dns_output), dns_output);

struct dns_call_data {
    u32 tid;
    char name[MAX_NAME_LENGTH];
    char lib_func[MAX_LIB_FUNC_LENGTH];
    u64 call_time_ns;
};


struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, u32); // thread id
    __type(value, struct dns_call_data);
    __uint(max_entries, 16);
} call_data_map SEC(".maps");

static void __always_inline capture_data(const char* name, const char* lib_func_name){
    // name is the DNS name being fetched
    // lib_func_name is the library that was used to attempt
    // the DNS lookup
    u32 tid = GET_TID();
    struct dns_call_data data = {
        .tid = tid,
    };

    bpf_probe_read(&data.name, MAX_NAME_LENGTH, name);
    bpf_probe_read(&data.lib_func, MAX_LIB_FUNC_LENGTH, lib_func_name);
    data.call_time_ns = bpf_ktime_get_ns();
    bpf_map_update_elem(&call_data_map, &tid, &data, BPF_ANY);
}

SEC("uprobe//lib/x86_64-linux-gnu/libc.so.6:getaddrinfo")
int trace_getaddrinfo(struct pt_regs* ctx) {
    const char* node = (const char*)PT_REGS_PARM1(ctx);
    capture_data(node, "getaddrinfo");
    return EXIT_SUCCESS;
}

SEC("uprobe//lib/x86_64-linux-gnu/libc.so.6:gethostbyname")
int trace_gethostbyname(struct pt_regs* ctx) {
    const char* name = (const char*)PT_REGS_PARM1(ctx);
    capture_data(name, "gethostbyname");
    return EXIT_SUCCESS;
}

SEC("uprobe//lib/x86_64-linux-gnu/libc.so.6:gethostbyname2")
int trace_gethostbyname2(struct pt_regs* ctx) {
    const char* name = (const char*)PT_REGS_PARM1(ctx);
    capture_data(name, "gethostbyname2");
    return EXIT_SUCCESS;
}

static void __always_inline submit_dns_data() {
    u32 tid = GET_TID();
    struct dns_call_data* data = bpf_map_lookup_elem(&call_data_map, &tid);
    if (data) {
        struct dns_output* out = bpf_ringbuf_reserve(&dns_rb, sizeof(struct dns_output), 0);
        if (!out) { // in case the ring buffer is full, drop.
            bpf_printk("bailed submission");
            return;
        }
        out->pid = GET_PID();
        bpf_probe_read(out->name, MAX_NAME_LENGTH, data->name);

        out->duration_ns = bpf_ktime_get_ns() - data->call_time_ns;
        bpf_dbg_printk("Submitted the following: pid: %s, name: %s, lib_func: %s", out->pid, out->name, out->lib_func);
        bpf_ringbuf_submit(out, 0);
    } else {
        bpf_dbg_printk("Found no data for the tid, bailing!");
    }
}
SEC("uretprobe//lib/x86_64-linux-gnu/libc.so.6:getaddrinfo")
int trace_getaddrinfo_return(struct pt_regs* ctx) {
    submit_dns_data();
    return EXIT_SUCCESS;
}


SEC("uretprobe//lib/x86_64-linux-gnu/libc.so.6:gethostbyname")
int trace_gethostbyname_return(struct pt_regs* ctx) {
    submit_dns_data();
    return EXIT_SUCCESS;
}


SEC("uretprobe//lib/x86_64-linux-gnu/libc.so.6:gethostbyname2")
int trace_gethostbyname2_return(struct pt_regs* ctx) {
    submit_dns_data();
    return EXIT_SUCCESS;
}

LICENSE("Dual BSD/GPL");
