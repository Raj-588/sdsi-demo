// SPDX-License-Identifier: GPL-2.0
/*
 * CheckPoint Zero kernel checkpoint (BPF LSM, Linux >= 5.7 with CONFIG_BPF_LSM and lsm=...,bpf).
 *
 * Design rule: the kernel never parses content. It enforces small policy maps that the user-space
 * daemon (checkpointd) fills, and reports what it saw through a ring buffer:
 *
 *   ai_pids          pids of AI agents and everything they spawn (inherited on fork, in-kernel)
 *   protected_inodes credential files (~/.ssh/id_*, ~/.aws/credentials, ...) by (dev, ino)
 *   egress_allow     IPv4 addresses AI-lineage processes may connect to
 *   config           [0] = enforce (1) / monitor (0)
 *
 * Hooks
 *   sched_process_fork  child of an AI pid becomes an AI pid (lineage tracked without user space)
 *   bprm_check_security every exec in AI lineage is reported (user space judges the command line)
 *   file_open           AI lineage opening a protected credential file -> -EPERM
 *   socket_connect      AI lineage connecting to a non-allow-listed IPv4 address -> -EPERM
 */
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

#define EPERM 1
#define AF_INET 2

char LICENSE[] SEC("license") = "GPL";

enum event_kind { EV_EXEC = 1, EV_FILE_DENY = 2, EV_NET_DENY = 3, EV_FILE_SEEN = 4, EV_NET_SEEN = 5 };

struct inode_key { __u64 dev; __u64 ino; };

struct event {
	__u32 kind;
	__u32 pid;
	__u32 ppid;
	__u32 root_pid;
	__u32 daddr;
	__u16 dport;
	__u16 denied;
	__u64 ino;
	char comm[16];
	char path[128];
};

struct { __uint(type, BPF_MAP_TYPE_HASH); __uint(max_entries, 65536); __type(key, __u32); __type(value, __u32); } ai_pids SEC(".maps");
struct { __uint(type, BPF_MAP_TYPE_HASH); __uint(max_entries, 4096); __type(key, struct inode_key); __type(value, __u8); } protected_inodes SEC(".maps");
struct { __uint(type, BPF_MAP_TYPE_HASH); __uint(max_entries, 4096); __type(key, __u32); __type(value, __u8); } egress_allow SEC(".maps");
struct { __uint(type, BPF_MAP_TYPE_ARRAY); __uint(max_entries, 4); __type(key, __u32); __type(value, __u32); } config SEC(".maps");
struct { __uint(type, BPF_MAP_TYPE_RINGBUF); __uint(max_entries, 1 << 20); } events SEC(".maps");

static __always_inline __u32 *ai_root(void)
{
	__u32 pid = bpf_get_current_pid_tgid() >> 32;
	return bpf_map_lookup_elem(&ai_pids, &pid);
}

static __always_inline int enforcing(void)
{
	__u32 k = 0, *v = bpf_map_lookup_elem(&config, &k);
	return v && *v == 1;
}

static __always_inline struct event *new_event(__u32 kind, __u32 root)
{
	struct event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
	if (!e)
		return 0;
	__builtin_memset(e, 0, sizeof(*e));
	struct task_struct *t = (struct task_struct *)bpf_get_current_task();
	e->kind = kind;
	e->pid = bpf_get_current_pid_tgid() >> 32;
	e->ppid = BPF_CORE_READ(t, real_parent, tgid);
	e->root_pid = root;
	bpf_get_current_comm(e->comm, sizeof(e->comm));
	return e;
}

SEC("tp_btf/sched_process_fork")
int BPF_PROG(on_fork, struct task_struct *parent, struct task_struct *child)
{
	__u32 ppid = BPF_CORE_READ(parent, tgid), cpid = BPF_CORE_READ(child, tgid);
	__u32 *root = bpf_map_lookup_elem(&ai_pids, &ppid);
	if (root && cpid != ppid)
		bpf_map_update_elem(&ai_pids, &cpid, root, BPF_ANY);
	return 0;
}

SEC("tp_btf/sched_process_exit")
int BPF_PROG(on_exit, struct task_struct *p)
{
	__u32 pid = BPF_CORE_READ(p, tgid);
	if (BPF_CORE_READ(p, pid) == pid)          /* thread-group leader exiting */
		bpf_map_delete_elem(&ai_pids, &pid);
	return 0;
}

SEC("lsm/bprm_check_security")
int BPF_PROG(on_exec, struct linux_binprm *bprm, int ret)
{
	__u32 *root = ai_root();
	if (ret || !root)
		return ret;
	struct event *e = new_event(EV_EXEC, *root);
	if (e) {
		bpf_probe_read_kernel_str(e->path, sizeof(e->path), BPF_CORE_READ(bprm, filename));
		bpf_ringbuf_submit(e, 0);
	}
	return 0;   /* the command line is judged in user space; bad commands are killed or added to policy */
}

SEC("lsm/file_open")
int BPF_PROG(on_file_open, struct file *file, int ret)
{
	__u32 *root = ai_root();
	if (ret || !root)
		return ret;
	struct inode_key k = {
		.dev = BPF_CORE_READ(file, f_inode, i_sb, s_dev),
		.ino = BPF_CORE_READ(file, f_inode, i_ino),
	};
	if (!bpf_map_lookup_elem(&protected_inodes, &k))
		return 0;
	int deny = enforcing();
	struct event *e = new_event(deny ? EV_FILE_DENY : EV_FILE_SEEN, *root);
	if (e) {
		e->ino = k.ino;
		e->denied = deny;
		bpf_d_path(&file->f_path, e->path, sizeof(e->path));
		bpf_ringbuf_submit(e, 0);
	}
	return deny ? -EPERM : 0;
}

SEC("lsm/socket_connect")
int BPF_PROG(on_connect, struct socket *sock, struct sockaddr *address, int addrlen, int ret)
{
	__u32 *root = ai_root();
	if (ret || !root || BPF_CORE_READ(address, sa_family) != AF_INET)
		return ret;
	struct sockaddr_in *sin = (struct sockaddr_in *)address;
	__u32 daddr = BPF_CORE_READ(sin, sin_addr.s_addr);
	__u8 first = daddr & 0xff;                  /* network byte order: first octet is the low byte */
	if (first == 127 || first == 10 || bpf_map_lookup_elem(&egress_allow, &daddr))
		return 0;
	int deny = enforcing();
	struct event *e = new_event(deny ? EV_NET_DENY : EV_NET_SEEN, *root);
	if (e) {
		e->daddr = daddr;
		e->dport = bpf_ntohs(BPF_CORE_READ(sin, sin_port));
		e->denied = deny;
		bpf_ringbuf_submit(e, 0);
	}
	return deny ? -EPERM : 0;
}
