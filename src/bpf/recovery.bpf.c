#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

#define FNAME_LEN 256
#define COMM_LEN 16
#define PATH_MAX 4096

// Data structures for tracking file descriptors
struct fd_key_t {
    u64 inode;      // Inode number
    u32 dev;        // Device ID
};

struct fd_info_t {
    u32 pid;        // Process ID that has file open
    u32 fd;         // File descriptor number
    u64 opened_at;  // Timestamp when opened
};

// Event sent to userspace when file is deleted but has open fd
struct recovery_event_t {
    u32 pid;                    // Process that called unlink
    u32 pid_with_fd;            // Process that has file open
    u32 fd_number;              // File descriptor number
    u64 inode;                  // Inode number
    u32 dev;                    // Device ID
    u64 file_size;              // Size of file being deleted
    char filename[FNAME_LEN];   // Original filename
    char comm[COMM_LEN];        // Command that deleted the file
};

// Event for tracking open/close operations
struct fd_track_event_t {
    u32 pid;
    u32 fd;
    u64 inode;
    u32 dev;
    u64 size;
    u8 event_type;  // 0=open, 1=close
    char filename[FNAME_LEN];
    char comm[COMM_LEN];
};

// BPF Maps

// Map to track open file descriptors: (inode, dev) -> (pid, fd)
struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);  // LRU to auto-evict old entries
    __uint(max_entries, 100000);          // Track up to 100k open files
    __type(key, struct fd_key_t);
    __type(value, struct fd_info_t);
} open_fds_map SEC(".maps");

// Perf event array for recovery events
struct {
    __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
    __uint(key_size, sizeof(u32));
    __uint(value_size, sizeof(u32));
} recovery_events SEC(".maps");

// Perf event array for tracking events (optional, for debugging)
struct {
    __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
    __uint(key_size, sizeof(u32));
    __uint(value_size, sizeof(u32));
} tracking_events SEC(".maps");

// Configuration map: enable/disable tracking
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 16);
    __type(key, u32);   // Config key: 0=enabled, 1=min_file_size, etc.
    __type(value, u64); // Config value
} config_map SEC(".maps");

// Helper function to check if tracking is enabled
static __always_inline int is_tracking_enabled() {
    u32 key = 0;  // 0 = enabled flag
    u64 *enabled = bpf_map_lookup_elem(&config_map, &key);
    if (!enabled) {
        return 0;  // Default: disabled
    }
    return *enabled ? 1 : 0;
}

// Helper function to get minimum file size threshold
static __always_inline u64 get_min_file_size() {
    u32 key = 1;  // 1 = min_file_size
    u64 *min_size = bpf_map_lookup_elem(&config_map, &key);
    if (!min_size) {
        return 0;  // Default: track all sizes
    }
    return *min_size;
}

// Helper to read inode info from file structure
static __always_inline int get_file_inode_info(struct file *file,
                                                u64 *inode_num,
                                                u32 *dev,
                                                u64 *size) {
    if (!file) {
        return -1;
    }

    struct inode *inode = BPF_CORE_READ(file, f_inode);
    if (!inode) {
        return -1;
    }

    *inode_num = BPF_CORE_READ(inode, i_ino);

    struct super_block *sb = BPF_CORE_READ(inode, i_sb);
    if (!sb) {
        return -1;
    }
    *dev = BPF_CORE_READ(sb, s_dev);
    *size = BPF_CORE_READ(inode, i_size);

    return 0;
}

// Hook: Track file opens via openat syscall
SEC("tracepoint/syscalls/sys_exit_openat")
int trace_openat_exit(struct trace_event_raw_sys_exit *ctx)
{
    if (!is_tracking_enabled()) {
        return 0;
    }

    // Get file descriptor from return value
    int fd = ctx->ret;
    if (fd < 0) {
        return 0;  // Failed open, ignore
    }

    u64 pid_tgid = bpf_get_current_pid_tgid();
    u32 pid = pid_tgid >> 32;
    u32 tid = (u32)pid_tgid;

    // Get current task
    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    if (!task) {
        return 0;
    }

    // Get files structure
    struct files_struct *files = BPF_CORE_READ(task, files);
    if (!files) {
        return 0;
    }

    // Get fdtable
    struct fdtable *fdt = BPF_CORE_READ(files, fdt);
    if (!fdt) {
        return 0;
    }

    // Get fd array
    struct file **fd_array = BPF_CORE_READ(fdt, fd);
    if (!fd_array) {
        return 0;
    }

    // Get file structure for this fd
    struct file *file;
    bpf_probe_read_kernel(&file, sizeof(file), &fd_array[fd]);
    if (!file) {
        return 0;
    }

    // Get inode information
    u64 inode_num;
    u32 dev;
    u64 size;
    if (get_file_inode_info(file, &inode_num, &dev, &size) < 0) {
        return 0;
    }

    // Check minimum file size filter
    u64 min_size = get_min_file_size();
    if (size < min_size) {
        return 0;
    }

    // Create tracking entry
    struct fd_key_t key = {
        .inode = inode_num,
        .dev = dev,
    };

    struct fd_info_t info = {
        .pid = pid,
        .fd = fd,
        .opened_at = bpf_ktime_get_ns(),
    };

    // Store in tracking map
    bpf_map_update_elem(&open_fds_map, &key, &info, BPF_ANY);

    // Optional: Send tracking event for monitoring
    struct fd_track_event_t track_event = {
        .pid = pid,
        .fd = fd,
        .inode = inode_num,
        .dev = dev,
        .size = size,
        .event_type = 0,  // 0 = open
    };
    bpf_get_current_comm(&track_event.comm, sizeof(track_event.comm));

    bpf_perf_event_output(ctx, &tracking_events, BPF_F_CURRENT_CPU,
                          &track_event, sizeof(track_event));

    return 0;
}

// Hook: Track file closes
SEC("tracepoint/syscalls/sys_enter_close")
int trace_close_entry(struct trace_event_raw_sys_enter *ctx)
{
    if (!is_tracking_enabled()) {
        return 0;
    }

    int fd = ctx->args[0];
    u32 pid = bpf_get_current_pid_tgid() >> 32;

    // Get current task
    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    if (!task) {
        return 0;
    }

    // Get files structure
    struct files_struct *files = BPF_CORE_READ(task, files);
    if (!files) {
        return 0;
    }

    // Get fdtable
    struct fdtable *fdt = BPF_CORE_READ(files, fdt);
    if (!fdt) {
        return 0;
    }

    // Get fd array
    struct file **fd_array = BPF_CORE_READ(fdt, fd);
    if (!fd_array) {
        return 0;
    }

    // Get file structure for this fd
    struct file *file;
    bpf_probe_read_kernel(&file, sizeof(file), &fd_array[fd]);
    if (!file) {
        return 0;
    }

    // Get inode information
    u64 inode_num;
    u32 dev;
    u64 size;
    if (get_file_inode_info(file, &inode_num, &dev, &size) < 0) {
        return 0;
    }

    // Create key for lookup
    struct fd_key_t key = {
        .inode = inode_num,
        .dev = dev,
    };

    // Check if we're tracking this file
    struct fd_info_t *info = bpf_map_lookup_elem(&open_fds_map, &key);
    if (info && info->pid == pid && info->fd == fd) {
        // Remove from tracking map
        bpf_map_delete_elem(&open_fds_map, &key);

        // Optional: Send tracking event
        struct fd_track_event_t track_event = {
            .pid = pid,
            .fd = fd,
            .inode = inode_num,
            .dev = dev,
            .size = size,
            .event_type = 1,  // 1 = close
        };
        bpf_get_current_comm(&track_event.comm, sizeof(track_event.comm));

        bpf_perf_event_output(ctx, &tracking_events, BPF_F_CURRENT_CPU,
                              &track_event, sizeof(track_event));
    }

    return 0;
}

// Hook: Detect file deletion and check for open fds
SEC("tracepoint/syscalls/sys_enter_unlinkat")
int trace_unlinkat_entry(struct trace_event_raw_sys_enter *ctx)
{
    if (!is_tracking_enabled()) {
        return 0;
    }

    u64 pid_tgid = bpf_get_current_pid_tgid();
    u32 pid = pid_tgid >> 32;

    // Get pathname from syscall arguments
    // args[0] = dfd (directory fd)
    // args[1] = pathname (char __user *)
    // args[2] = flags
    char *pathname_ptr = (char *)ctx->args[1];
    if (!pathname_ptr) {
        return 0;
    }

    struct recovery_event_t event = {0};
    event.pid = pid;
    bpf_get_current_comm(&event.comm, sizeof(event.comm));

    // Read pathname from userspace
    bpf_probe_read_user_str(&event.filename, sizeof(event.filename), pathname_ptr);

    // TODO: We need to resolve pathname to inode
    // This is complex in eBPF - we'd need to walk the dentry cache
    // For now, we'll rely on userspace to do inode resolution
    // and check the open_fds_map from userspace

    // Alternative approach: Hook at a lower level where we have inode
    // For production, we should use kprobe on vfs_unlink or do_unlinkat

    // Send event to userspace for processing
    bpf_perf_event_output(ctx, &recovery_events, BPF_F_CURRENT_CPU,
                          &event, sizeof(event));

    return 0;
}

// Hook: More reliable deletion detection via vfs_unlink kprobe
// This gives us direct access to inode information
SEC("kprobe/vfs_unlink")
int kprobe_vfs_unlink(struct pt_regs *ctx)
{
    if (!is_tracking_enabled()) {
        return 0;
    }

    // vfs_unlink signature: int vfs_unlink(struct inode *dir, struct dentry *dentry, struct inode **delegated_inode)
    // Get dentry from second argument
    struct dentry *dentry = (struct dentry *)PT_REGS_PARM2(ctx);
    if (!dentry) {
        return 0;
    }

    // Get inode from dentry
    struct inode *inode = BPF_CORE_READ(dentry, d_inode);
    if (!inode) {
        return 0;
    }

    u64 inode_num = BPF_CORE_READ(inode, i_ino);
    u64 file_size = BPF_CORE_READ(inode, i_size);

    struct super_block *sb = BPF_CORE_READ(inode, i_sb);
    if (!sb) {
        return 0;
    }
    u32 dev = BPF_CORE_READ(sb, s_dev);

    // Check if we have this file open in our tracking map
    struct fd_key_t key = {
        .inode = inode_num,
        .dev = dev,
    };

    struct fd_info_t *info = bpf_map_lookup_elem(&open_fds_map, &key);
    if (info) {
        // File is being deleted and we have it tracked!
        // Send recovery event to userspace
        struct recovery_event_t event = {0};
        event.pid = bpf_get_current_pid_tgid() >> 32;
        event.pid_with_fd = info->pid;
        event.fd_number = info->fd;
        event.inode = inode_num;
        event.dev = dev;
        event.file_size = file_size;

        bpf_get_current_comm(&event.comm, sizeof(event.comm));

        // Try to get filename from dentry
        struct qstr d_name = BPF_CORE_READ(dentry, d_name);
        bpf_probe_read_kernel_str(&event.filename, sizeof(event.filename), d_name.name);

        bpf_perf_event_output(ctx, &recovery_events, BPF_F_CURRENT_CPU,
                              &event, sizeof(event));
    }

    return 0;
}

char LICENSE[] SEC("license") = "GPL";
