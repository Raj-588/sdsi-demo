// SPDX-License-Identifier: GPL-2.0
/*
 * Loads checkpoint.bpf.o, pins its policy maps under /sys/fs/bpf/checkpointd/ so checkpointd can update
 * them (bpftool map update pinned ...), and streams ring-buffer events to stdout as JSON lines.
 *
 *   sudo ./checkpoint-loader [--enforce]
 */
#include <arpa/inet.h>
#include <errno.h>
#include <signal.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include "checkpoint.skel.h"

#define PIN_DIR "/sys/fs/bpf/checkpointd"

struct event {
	__u32 kind, pid, ppid, root_pid, daddr;
	__u16 dport, denied;
	__u64 ino;
	char comm[16];
	char path[128];
};

static volatile sig_atomic_t stop;
static void on_sig(int s) { (void)s; stop = 1; }

static const char *kind_name(__u32 k)
{
	switch (k) {
	case 1: return "EXEC";
	case 2: return "FILE_DENY";
	case 3: return "NET_DENY";
	case 4: return "FILE_SEEN";
	case 5: return "NET_SEEN";
	default: return "UNKNOWN";
	}
}

static void json_str(const char *s)
{
	putchar('"');
	for (; *s; s++) {
		if (*s == '"' || *s == '\\') putchar('\\');
		if ((unsigned char)*s < 0x20) continue;
		putchar(*s);
	}
	putchar('"');
}

static int handle(void *ctx, void *data, size_t len)
{
	(void)ctx; (void)len;
	const struct event *e = data;
	char ip[INET_ADDRSTRLEN] = "";
	if (e->daddr) inet_ntop(AF_INET, &e->daddr, ip, sizeof(ip));
	printf("{\"kind\":\"%s\",\"pid\":%u,\"ppid\":%u,\"root_pid\":%u,\"denied\":%u,\"comm\":",
	       kind_name(e->kind), e->pid, e->ppid, e->root_pid, e->denied);
	json_str(e->comm);
	printf(",\"path\":");
	json_str(e->path);
	printf(",\"ino\":%llu,\"daddr\":\"%s\",\"dport\":%u}\n", (unsigned long long)e->ino, ip, e->dport);
	fflush(stdout);
	return 0;
}

static int pin(struct bpf_map *m, const char *name)
{
	char p[256];
	snprintf(p, sizeof(p), PIN_DIR "/%s", name);
	unlink(p);
	return bpf_map__pin(m, p);
}

int main(int argc, char **argv)
{
	int enforce = argc > 1 && strcmp(argv[1], "--enforce") == 0;
	struct checkpoint_bpf *skel = checkpoint_bpf__open_and_load();
	if (!skel) {
		fprintf(stderr, "load failed: is CONFIG_BPF_LSM enabled and 'bpf' in the lsm= boot parameter?\n");
		return 1;
	}
	if (checkpoint_bpf__attach(skel)) {
		fprintf(stderr, "attach failed: %s\n", strerror(errno));
		checkpoint_bpf__destroy(skel);
		return 1;
	}
	mkdir(PIN_DIR, 0700);
	if (pin(skel->maps.ai_pids, "ai_pids") || pin(skel->maps.protected_inodes, "protected_inodes") ||
	    pin(skel->maps.egress_allow, "egress_allow") || pin(skel->maps.config, "config")) {
		fprintf(stderr, "pinning maps under " PIN_DIR " failed: %s\n", strerror(errno));
		checkpoint_bpf__destroy(skel);
		return 1;
	}
	__u32 k = 0, v = enforce;
	bpf_map__update_elem(skel->maps.config, &k, sizeof(k), &v, sizeof(v), BPF_ANY);
	struct ring_buffer *rb = ring_buffer__new(bpf_map__fd(skel->maps.events), handle, NULL, NULL);
	signal(SIGINT, on_sig);
	signal(SIGTERM, on_sig);
	fprintf(stderr, "checkpoint-loader: attached (%s); maps pinned in " PIN_DIR "\n", enforce ? "ENFORCE" : "MONITOR");
	while (!stop)
		ring_buffer__poll(rb, 200);
	ring_buffer__free(rb);
	checkpoint_bpf__destroy(skel);   /* programs detach; pinned maps are removed by checkpointd on shutdown */
	return 0;
}
