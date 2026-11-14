//go:build ignore
// +build ignore

// SPDX-License-Identifier: GPL-2.0
// DepGuard Tier-B kernel probe. Build via `go generate` (bpf2go, clang, libbpf-dev).
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
	__u64 common;  // common_type..common_pid (8 bytes)
	__s64 nr;      // __syscall_nr (+4 bytes padding)
	__u64 args[6]; // openat: dfd, filename, flags, mode | openat2: dfd, filename, how, usize
};
struct fork_ctx {
	__u64 common;
	char parent_comm[16];
	__s32 parent_pid;
	char child_comm[16];
	__s32 child_pid;
};

const volatile __u8 watch_all = 0;
const volatile __u8 enforce = 0;
const volatile __u32 self_tgid = 0;

struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__uint(max_entries, 65536);
	__type(key, __u32);
	__type(value, __u8);
} target_pids SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 1024);
	__type(key, __u64);
	__type(value, __u8);
} target_cgroups SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, char[PATH_MAX]);
} scratch SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, __u64);
} dropped SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 1 << 24);
} events SEC(".maps");

static __always_inline int has_suffix(const char *b, long len, const char *suf, int n)
{
	// len includes the trailing NUL; require at least one char before the suffix.
	if (len < n + 2 || len > PATH_MAX)
		return 0;
	long base = len - 1 - n;
#pragma unroll
	for (int i = 0; i < n; i++) {
		if (b[(base + i) & (PATH_MAX - 1)] != suf[i])
			return 0;
	}
	return 1;
}

static __always_inline int is_versioned_so(const char *b, long len)
{
	// matches ".so.<digit>" within the last 12 bytes, e.g. libssl.so.3, libz.so.1.2.13
	if (len < 8 || len > PATH_MAX)
		return 0;
#pragma unroll
	for (int k = 4; k < 12; k++) {
		long p = len - 1 - k;
		if (p < 0)
			break;
		if (b[p & (PATH_MAX - 1)] == '.' && b[(p + 1) & (PATH_MAX - 1)] == 's' &&
		    b[(p + 2) & (PATH_MAX - 1)] == 'o' && b[(p + 3) & (PATH_MAX - 1)] == '.') {
			char d = b[(p + 4) & (PATH_MAX - 1)];
			if (d >= '0' && d <= '9')
				return 1;
		}
	}
	return 0;
}

static __always_inline int is_code(const char *b, long len)
{
	return has_suffix(b, len, ".py", 3) || has_suffix(b, len, ".pyc", 4) ||
	       has_suffix(b, len, ".js", 3) || has_suffix(b, len, ".cjs", 4) ||
	       has_suffix(b, len, ".mjs", 4) || has_suffix(b, len, ".so", 3) ||
	       has_suffix(b, len, ".node", 5) || is_versioned_so(b, len);
}

static __always_inline int handle_open(__s32 dfd, const char *fname)
{
	__u64 pt = bpf_get_current_pid_tgid();
	__u32 tgid = pt >> 32;

	if (tgid == self_tgid)
		return 0;
	if (!watch_all && !bpf_map_lookup_elem(&target_pids, &tgid)) {
		__u64 cg = bpf_get_current_cgroup_id();
		if (!bpf_map_lookup_elem(&target_cgroups, &cg))
			return 0;
	}

	__u32 zero = 0;
	char *buf = bpf_map_lookup_elem(&scratch, &zero);
	if (!buf)
		return 0;
	long len = bpf_probe_read_user_str(buf, PATH_MAX, fname);
	if (len <= 0 || !is_code(buf, len))
		return 0;

	struct event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
	if (!e) {
		__u64 *d = bpf_map_lookup_elem(&dropped, &zero);
		if (d)
			__sync_fetch_and_add(d, 1);
		return 0;
	}
	e->tgid = tgid;
	e->tid = (__u32)pt;
	e->dfd = dfd;
	e->reserved = 0;
	bpf_get_current_comm(e->comm, sizeof(e->comm));
	bpf_probe_read_user_str(e->filename, sizeof(e->filename), fname);

	// Queue the stop BEFORE publishing the event so a fast SIGCONT can never
	// overtake it. The signal is delivered on return to user mode: the process
	// halts before it can read()/mmap() the file it just opened.
	if (enforce)
		bpf_send_signal(SIGSTOP);
	bpf_ringbuf_submit(e, 0);
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_openat")
int tp_openat(struct sys_enter_ctx *ctx)
{
	return handle_open((__s32)ctx->args[0], (const char *)ctx->args[1]);
}

SEC("tracepoint/syscalls/sys_enter_openat2")
int tp_openat2(struct sys_enter_ctx *ctx)
{
	return handle_open((__s32)ctx->args[0], (const char *)ctx->args[1]);
}

// Follow children of monitored processes (cgroup targets are inherited natively).
SEC("tracepoint/sched/sched_process_fork")
int tp_fork(struct fork_ctx *ctx)
{
	__u32 parent = bpf_get_current_pid_tgid() >> 32;
	if (!bpf_map_lookup_elem(&target_pids, &parent))
		return 0;
	__u32 child = (__u32)ctx->child_pid;
	__u8 one = 1;
	bpf_map_update_elem(&target_pids, &child, &one, BPF_ANY);
	return 0;
}

char LICENSE[] SEC("license") = "GPL";
