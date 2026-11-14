//go:build ignore
// +build ignore

// SPDX-License-Identifier: GPL-2.0 OR MIT
//
// Hooks openat/openat2 entry. If the caller is a monitored process (pid / cgroup /
// inherited via fork) and the filename looks like code (.py .pyc .js .cjs .mjs
// .node .so .so.N), a record goes to a ring buffer for the user-space verifier.
// In enforce mode the probe additionally raises SIGSTOP on the caller; the daemon
// resumes it (SIGCONT) after the hash check passes or kills it (SIGKILL) if not.
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

#define PATH_MAX 4096
#define SIGSTOP 19

struct event {
    __u32 tgid;
    __u32 tid;
    __s32 dfd;
    __u32 reserved;
    char comm[16];
    char filename[PATH_MAX];
};

// Raw tracepoint layouts are a stable ABI (see /sys/kernel/tracing/events/.../format).
struct sys_enter_ctx {
    __u64 common; // common_type..common_pid (8 bytes)
    __s64 nr;     // __syscall_nr (+4 bytes padding)
    __u64 args[6]; // openat: dfd, filename, flags, mode | openat2: dfd, filename, how, usize
};

struct fork_ctx {
    __u64 common;
    char parent_comm[16];
    __s32 parent_pid;
    char child_comm[16];
    __s32 child_pid;
};

struct exit_ctx {
    __u64 common;
    char comm[16];
    __s32 pid;
    __s32 prio;
};

struct config {
    __u32 enforce;       // 0 = monitor, 1 = SIGSTOP caller on code open
    __u32 filter_cgroup; // 1 = match cgroup_ids map in addition to pids map
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 4096);
    __type(key, __u32);
    __type(value, __u8);
} pids SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 256);
    __type(key, __u64);
    __type(value, __u8);
} cgroup_ids SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct config);
} cfg SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 22); // 4 MiB
} events SEC(".maps");

// Scratch space per CPU so the 4 KiB event does not blow the 512-byte BPF stack.
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct event);
} scratch SEC(".maps");

static __always_inline bool has_suffix(const char *s, int len, const char *suf, int slen) {
    if (len < slen)
        return false;
    int off = len - slen;
    for (int i = 0; i < 8; i++) {
        if (i >= slen)
            break;
        if (s[(off + i) & (PATH_MAX - 1)] != suf[i])
            return false;
    }
    return true;
}

// Matches *.so and *.so.<digits>[.<digits>...]
static __always_inline bool is_versioned_so(const char *s, int len) {
    int i = len - 1;
    bool saw_digit = false;
    for (int step = 0; step < 24 && i >= 3; step++, i--) {
        char c = s[i & (PATH_MAX - 1)];
        if (c >= '0' && c <= '9') {
            saw_digit = true;
            continue;
        }
        if (c == '.' && saw_digit) {
            if (i >= 3 &&
                s[(i - 3) & (PATH_MAX - 1)] == '.' &&
                s[(i - 2) & (PATH_MAX - 1)] == 's' &&
                s[(i - 1) & (PATH_MAX - 1)] == 'o') {
                return true;
            }
            saw_digit = false;
            continue;
        }
        return false;
    }
    return false;
}

static __always_inline bool is_code(const char *s, int len) {
    if (has_suffix(s, len, ".py", 3))
        return true;
    if (has_suffix(s, len, ".js", 3))
        return true;
    if (has_suffix(s, len, ".so", 3))
        return true;
    if (has_suffix(s, len, ".pyc", 4))
        return true;
    if (has_suffix(s, len, ".cjs", 4))
        return true;
    if (has_suffix(s, len, ".mjs", 4))
        return true;
    if (has_suffix(s, len, ".node", 5))
        return true;
    return is_versioned_so(s, len);
}

static __always_inline int handle_open(__s32 dfd, const char *user_filename) {
    __u64 id = bpf_get_current_pid_tgid();
    __u32 tgid = id >> 32;

    __u32 zero = 0;
    struct config *c = bpf_map_lookup_elem(&cfg, &zero);

    bool tracked = bpf_map_lookup_elem(&pids, &tgid) != NULL;
    if (!tracked && c && c->filter_cgroup) {
        __u64 cg = bpf_get_current_cgroup_id();
        tracked = bpf_map_lookup_elem(&cgroup_ids, &cg) != NULL;
    }
    if (!tracked)
        return 0;

    struct event *ev = bpf_map_lookup_elem(&scratch, &zero);
    if (!ev)
        return 0;

    long n = bpf_probe_read_user_str(ev->filename, sizeof(ev->filename), user_filename);
    if (n <= 1)
        return 0;
    int len = (int)n - 1; // exclude NUL

    if (!is_code(ev->filename, len))
        return 0;

    ev->tgid = tgid;
    ev->tid = (__u32)id;
    ev->dfd = dfd;
    ev->reserved = 0;
    bpf_get_current_comm(ev->comm, sizeof(ev->comm));

    bpf_ringbuf_output(&events, ev, sizeof(*ev), 0);

    if (c && c->enforce)
        bpf_send_signal(SIGSTOP);

    return 0;
}

SEC("tracepoint/syscalls/sys_enter_openat")
int tp_openat(struct sys_enter_ctx *ctx) {
    return handle_open((__s32)ctx->args[0], (const char *)ctx->args[1]);
}

SEC("tracepoint/syscalls/sys_enter_openat2")
int tp_openat2(struct sys_enter_ctx *ctx) {
    return handle_open((__s32)ctx->args[0], (const char *)ctx->args[1]);
}

SEC("tracepoint/sched/sched_process_fork")
int tp_fork(struct fork_ctx *ctx) {
    __u32 parent = (__u32)ctx->parent_pid;
    if (!bpf_map_lookup_elem(&pids, &parent))
        return 0;
    __u32 child = (__u32)ctx->child_pid;
    __u8 one = 1;
    bpf_map_update_elem(&pids, &child, &one, BPF_ANY);
    return 0;
}

SEC("tracepoint/sched/sched_process_exit")
int tp_exit(struct exit_ctx *ctx) {
    __u32 pid = (__u32)ctx->pid;
    bpf_map_delete_elem(&pids, &pid);
    return 0;
}

char LICENSE[] SEC("license") = "GPL";
