# Build Troubleshooting Guide

## Issue: Build Errors with `real_mount()` and Undeclared Functions

### Problem
You're seeing errors like:
```
error: call to undeclared function 'real_mount'
error: use of undeclared identifier 'MAX_PERCPU_BUFSIZE'
error: use of undeclared identifier 'buf_t'
```

### Root Cause
These errors indicate you have a **different/older version** of the code locally than what's in the repository.

The errors reference:
- Path: `/home/laks/ebpf-diskalert/` (your local machine)
- Code in: `/home/user/ebpf-diskalert/` (working repository)

### Solution

#### Step 1: Verify Your Location
```bash
pwd
# Should show: /home/laks/ebpf-diskalert (or your local path)
```

#### Step 2: Check Current Branch
```bash
git branch
# You should see: * claude/file-recovery-via-fd-01FnmymjWjCxaQEUVv7zyBxM
```

#### Step 3: Pull Latest Changes
```bash
# Fetch all branches
git fetch origin

# Switch to the recovery branch
git checkout claude/file-recovery-via-fd-01FnmymjWjCxaQEUVv7zyBxM

# Pull latest changes
git pull origin claude/file-recovery-via-fd-01FnmymjWjCxaQEUVv7zyBxM
```

#### Step 4: Clean Build Artifacts
```bash
# Clean old build files
make clean

# Restore go.mod (clean corrupts it)
git checkout go.mod

# OR manually restore it from git:
git show HEAD:go.mod > go.mod
```

#### Step 5: Verify Source Files
Check that you have the correct files:

```bash
# Check diskalert.bpf.c is the simple version (should be ~67 lines)
wc -l src/bpf/diskalert.bpf.c

# Check recovery files exist
ls -l src/bpf/recovery.bpf.c
ls -l src/recovery_*.go

# Verify the files
git status
```

Expected files from the recovery implementation:
```
Modified:
  - Makefile
  - src/disk_details.go
  - src/main.go

New:
  - QUICKSTART-RECOVERY.md
  - config/config-with-recovery.toml
  - docs/FILE-RECOVERY-README.md
  - src/bpf/recovery.bpf.c
  - src/recovery_handler.go
  - src/recovery_loader.go
  - src/recovery_main.go
  - tests/test_recovery.sh
```

#### Step 6: Build
```bash
make build
```

### What the Correct diskalert.bpf.c Looks Like

The working version is ~67 lines and should look like this:

```c
#include "vmlinux.h"
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

    bpf_printk("bpf_traceblock: devid: %d major:%d minor:%d type:%c dev:%d\n",
               data.v,major,minor,req_type,data.path);
    bpf_perf_event_output(ctx, &output, BPF_F_CURRENT_CPU, &data, sizeof(data));
    return 0;
}
char LICENSE[] SEC("license") = "GPL";
```

**It should NOT contain**:
- `real_mount()` function calls
- `buf_t` type definitions
- `MAX_PERCPU_BUFSIZE` constants
- `get_buf()` functions
- `MAX_PATH_COMPONENTS` constants
- Path traversal logic

If your file has those, you have old/broken code.

### Alternative: Fresh Clone

If the above doesn't work, do a fresh clone:

```bash
# Backup your current directory
mv /home/laks/ebpf-diskalert /home/laks/ebpf-diskalert.old

# Fresh clone
cd /home/laks
git clone <repository-url> ebpf-diskalert
cd ebpf-diskalert

# Checkout the recovery branch
git checkout claude/file-recovery-via-fd-01FnmymjWjCxaQEUVv7zyBxM

# Build
make build
```

### Prerequisites

Ensure you have the required tools:

```bash
# Check tools
which clang
which go
which bpftool

# Check kernel version (need 5.14+)
uname -r

# Check BTF support
ls /sys/kernel/btf/vmlinux

# Check kernel headers
ls /usr/src/linux-headers-$(uname -r) || ls /usr/include/linux
```

### If Build Still Fails

1. **Check go.mod** - Make sure it has proper version numbers, not "latest"
2. **Check Go version** - Should be 1.19 or later: `go version`
3. **Check clang version** - Should be 10 or later: `clang --version`
4. **Generate vmlinux.h manually**:
   ```bash
   bpftool btf dump file /sys/kernel/btf/vmlinux format c > src/bpf/vmlinux.h
   ```

### Build Order

The correct build order is:
1. `make clean` - Clean old artifacts
2. `git checkout go.mod` - Restore go.mod
3. `make gen` - Generate eBPF bindings
4. `make build` - Build application

Or simply: `make build` (it handles dependencies)

### Getting Help

If you still have issues:

1. Show the **exact error messages**
2. Show your **git status** output
3. Show **git log -1** to confirm which commit you're on
4. Run `ls -l src/bpf/*.c` to list eBPF source files
5. Run `head -50 src/bpf/diskalert.bpf.c` to show the file content

### Commits in This Branch

You should have these commits:
```
e6fea2d - Implement Strategy 2: Proactive file descriptor tracking for recovery
fbfcbd1 - Add file recovery via file descriptor design document
```

Check with: `git log --oneline -5`

---

## Summary

**The implementation is correct and complete.** The build errors you're seeing are from having old/different code locally. Pull the latest changes from the `claude/file-recovery-via-fd-01FnmymjWjCxaQEUVv7zyBxM` branch and it should build successfully.
