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
    u32 padding;    // Explicit padding for 16-byte alignment
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

// Temporary map to store pathname between sys_enter and sys_exit_openat
struct openat_args_t {
    char pathname[FNAME_LEN];
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 10240);
    __type(key, u64);  // pid_tgid
    __type(value, struct openat_args_t);
} openat_args_map SEC(".maps");

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

// Helper to read inode info from file structure - FIXED for proper kernel memory access
static __always_inline int get_file_inode_info(struct file *file,
                                                u64 *inode_num,
                                                u32 *dev,
                                                u64 *size) {
    if (!file) {
        bpf_printk("[recovery] get_file_inode_info: file is NULL\n");
        return -1;
    }

    // Read f_inode pointer
    struct inode *inode;
    int ret = bpf_probe_read_kernel(&inode, sizeof(inode), &file->f_inode);
    if (ret != 0 || !inode) {
        bpf_printk("[recovery] failed to read f_inode, ret=%d\n", ret);
        return -1;
    }

    // Read inode number
    ret = bpf_probe_read_kernel(inode_num, sizeof(*inode_num), &inode->i_ino);
    if (ret != 0) {
        bpf_printk("[recovery] failed to read i_ino, ret=%d\n", ret);
        return -1;
    }

    // Read superblock pointer
    struct super_block *sb;
    ret = bpf_probe_read_kernel(&sb, sizeof(sb), &inode->i_sb);
    if (ret != 0 || !sb) {
        bpf_printk("[recovery] failed to read i_sb, ret=%d\n", ret);
        return -1;
    }

    // Read device ID
    ret = bpf_probe_read_kernel(dev, sizeof(*dev), &sb->s_dev);
    if (ret != 0) {
        bpf_printk("[recovery] failed to read s_dev, ret=%d\n", ret);
        return -1;
    }

    // Read file size using BPF_CORE_READ for proper access
    *size = BPF_CORE_READ(inode, i_size);

    bpf_printk("[recovery] inode=%llu dev=%u size=%llu\n", *inode_num, *dev, *size);

    return 0;
}

// Hook: Capture pathname on openat entry
SEC("tracepoint/syscalls/sys_enter_openat")
int trace_openat_enter(struct trace_event_raw_sys_enter *ctx)
{
    if (!is_tracking_enabled()) {
        return 0;
    }

    u64 pid_tgid = bpf_get_current_pid_tgid();

    // Get pathname from syscall args
    // openat(dfd, pathname, flags, mode)
    // args[1] is the pathname pointer
    char *pathname_ptr = (char *)ctx->args[1];
    if (!pathname_ptr) {
        return 0;
    }

    struct openat_args_t args = {0};
    bpf_probe_read_user_str(&args.pathname, sizeof(args.pathname), pathname_ptr);

    // Store in temp map
    bpf_map_update_elem(&openat_args_map, &pid_tgid, &args, BPF_ANY);

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

    // Get current task
    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    if (!task) {
        return 0;
    }

    // Read files structure pointer
    struct files_struct *files;
    int ret = bpf_probe_read_kernel(&files, sizeof(files), &task->files);
    if (ret != 0 || !files) {
        return 0;
    }

    // Read fdtable pointer
    struct fdtable *fdt;
    ret = bpf_probe_read_kernel(&fdt, sizeof(fdt), &files->fdt);
    if (ret != 0 || !fdt) {
        return 0;
    }

    // Read fd array pointer
    struct file **fd_array;
    ret = bpf_probe_read_kernel(&fd_array, sizeof(fd_array), &fdt->fd);
    if (ret != 0 || !fd_array) {
        return 0;
    }

    // Read file structure pointer for this fd
    struct file *file;
    ret = bpf_probe_read_kernel(&file, sizeof(file), &fd_array[fd]);
    if (ret != 0 || !file) {
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
        bpf_printk("[recovery] file too small (%llu < %llu), skipping\n", size, min_size);
        return 0;
    }

    // Create tracking entry
    struct fd_key_t key = {
        .inode = inode_num,
        .dev = dev,
        .padding = 0,
    };

    struct fd_info_t info = {
        .pid = pid,
        .fd = fd,
        .opened_at = bpf_ktime_get_ns(),
    };

    // Store in tracking map
    int map_ret = bpf_map_update_elem(&open_fds_map, &key, &info, BPF_ANY);
    if (map_ret != 0) {
        bpf_printk("[recovery] map update failed, ret=%d\n", map_ret);
        return 0;
    }

    bpf_printk("[recovery] TRACKED: inode=%llu dev=%u pid=%d fd=%d size=%llu\n",
               inode_num, dev, pid, fd, size);

    // Send tracking event with path for shadow FD opening
    struct fd_track_event_t track_event = {
        .pid = pid,
        .fd = fd,
        .inode = inode_num,
        .dev = dev,
        .size = size,
        .event_type = 0,  // 0 = open
    };
    bpf_get_current_comm(&track_event.comm, sizeof(track_event.comm));

    // Retrieve pathname from temp map
    struct openat_args_t *args = bpf_map_lookup_elem(&openat_args_map, &pid_tgid);
    if (args) {
        __builtin_memcpy(&track_event.filename, args->pathname, sizeof(track_event.filename));
        bpf_map_delete_elem(&openat_args_map, &pid_tgid);  // Clean up temp entry
        bpf_printk("[recovery] Path: %s\n", track_event.filename);
    }

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

    // Read files structure
    struct files_struct *files;
    int ret = bpf_probe_read_kernel(&files, sizeof(files), &task->files);
    if (ret != 0 || !files) {
        return 0;
    }

    // Read fdtable
    struct fdtable *fdt;
    ret = bpf_probe_read_kernel(&fdt, sizeof(fdt), &files->fdt);
    if (ret != 0 || !fdt) {
        return 0;
    }

    // Read fd array
    struct file **fd_array;
    ret = bpf_probe_read_kernel(&fd_array, sizeof(fd_array), &fdt->fd);
    if (ret != 0 || !fd_array) {
        return 0;
    }

    // Read file structure
    struct file *file;
    ret = bpf_probe_read_kernel(&file, sizeof(file), &fd_array[fd]);
    if (ret != 0 || !file) {
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
        .padding = 0,
    };

    // Check if we're tracking this file
    struct fd_info_t *info = bpf_map_lookup_elem(&open_fds_map, &key);
    if (info && info->pid == pid && info->fd == fd) {
        // Remove from tracking map
        bpf_map_delete_elem(&open_fds_map, &key);

        bpf_printk("[recovery] UNTRACKED: inode=%llu dev=%u pid=%d fd=%d\n",
                   inode_num, dev, pid, fd);

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
// NOTE: vfs_unlink signature changed in kernel 6.3+
// Old: int vfs_unlink(struct inode *dir, struct dentry *dentry, struct inode **delegated_inode)
// New: int vfs_unlink(struct mnt_idmap *idmap, struct inode *dir, struct dentry *dentry, struct inode **delegated_inode)
SEC("kprobe/vfs_unlink")
int kprobe_vfs_unlink(struct pt_regs *ctx)
{
    if (!is_tracking_enabled()) {
        return 0;
    }

    bpf_printk("[recovery] vfs_unlink TRIGGERED\n");

    // Try to get dentry from different parameter positions
    // For kernel 6.3+: parameter 3 (after mnt_idmap and dir)
    // For older kernels: parameter 2 (after dir)
    struct dentry *dentry = (struct dentry *)PT_REGS_PARM3(ctx);
    if (!dentry) {
        dentry = (struct dentry *)PT_REGS_PARM2(ctx);
    }

    if (!dentry) {
        bpf_printk("[recovery] vfs_unlink: dentry is NULL\n");
        return 0;
    }

    // Read inode pointer from dentry
    struct inode *inode;
    int ret = bpf_probe_read_kernel(&inode, sizeof(inode), &dentry->d_inode);
    if (ret != 0 || !inode) {
        bpf_printk("[recovery] vfs_unlink: failed to read d_inode, ret=%d\n", ret);
        return 0;
    }

    // Read inode number
    u64 inode_num;
    ret = bpf_probe_read_kernel(&inode_num, sizeof(inode_num), &inode->i_ino);
    if (ret != 0) {
        bpf_printk("[recovery] vfs_unlink: failed to read i_ino, ret=%d\n", ret);
        return 0;
    }

    // Read file size
    loff_t file_size;
    ret = bpf_probe_read_kernel(&file_size, sizeof(file_size), &inode->i_size);
    if (ret != 0) {
        bpf_printk("[recovery] vfs_unlink: failed to read i_size, ret=%d\n", ret);
        return 0;
    }

    // Read superblock pointer
    struct super_block *sb;
    ret = bpf_probe_read_kernel(&sb, sizeof(sb), &inode->i_sb);
    if (ret != 0 || !sb) {
        bpf_printk("[recovery] vfs_unlink: failed to read i_sb, ret=%d\n", ret);
        return 0;
    }

    // Read device ID
    u32 dev;
    ret = bpf_probe_read_kernel(&dev, sizeof(dev), &sb->s_dev);
    if (ret != 0) {
        bpf_printk("[recovery] vfs_unlink: failed to read s_dev, ret=%d\n", ret);
        return 0;
    }

    bpf_printk("[recovery] vfs_unlink: inode=%llu dev=%u size=%lld\n",
               inode_num, dev, (u64)file_size);

    // Check if we have this file open in our tracking map
    struct fd_key_t key = {
        .inode = inode_num,
        .dev = dev,
        .padding = 0,
    };

    bpf_printk("[recovery] vfs_unlink: looking up inode=%llu dev=%u in map\n",
               inode_num, dev);

    struct fd_info_t *info = bpf_map_lookup_elem(&open_fds_map, &key);
    if (info) {
        bpf_printk("[recovery] vfs_unlink: FOUND in map! pid=%d fd=%d - RECOVERING\n",
                   info->pid, info->fd);

        // File is being deleted and we have it tracked!
        // Send recovery event to userspace
        struct recovery_event_t event = {0};
        event.pid = bpf_get_current_pid_tgid() >> 32;
        event.pid_with_fd = info->pid;
        event.fd_number = info->fd;
        event.inode = inode_num;
        event.dev = dev;
        event.file_size = (u64)file_size;

        bpf_get_current_comm(&event.comm, sizeof(event.comm));

        // Try to get filename from dentry
        struct qstr d_name;
        ret = bpf_probe_read_kernel(&d_name, sizeof(d_name), &dentry->d_name);
        if (ret == 0 && d_name.name) {
            bpf_probe_read_kernel_str(&event.filename, sizeof(event.filename), d_name.name);
        }

        bpf_printk("[recovery] vfs_unlink: sending recovery event for '%s'\n", event.filename);
        bpf_perf_event_output(ctx, &recovery_events, BPF_F_CURRENT_CPU,
                              &event, sizeof(event));
    } else {
        bpf_printk("[recovery] vfs_unlink: NOT in map (file not tracked or already closed)\n");
    }

    return 0;
}

// Fallback: Hook unlinkat syscall (less reliable but more portable)
SEC("tracepoint/syscalls/sys_enter_unlinkat")
int trace_unlinkat_entry(struct trace_event_raw_sys_enter *ctx)
{
    if (!is_tracking_enabled()) {
        return 0;
    }

    u32 pid = bpf_get_current_pid_tgid() >> 32;
    char *pathname_ptr = (char *)ctx->args[1];

    if (!pathname_ptr) {
        return 0;
    }

    struct recovery_event_t event = {0};
    event.pid = pid;
    bpf_get_current_comm(&event.comm, sizeof(event.comm));
    bpf_probe_read_user_str(&event.filename, sizeof(event.filename), pathname_ptr);

    bpf_printk("[recovery] unlinkat: file='%s' by pid=%d (using syscall fallback)\n",
               event.filename, pid);

    // NOTE: We don't have inode info here, so this is just informational
    // The kprobe/vfs_unlink should handle the actual recovery

    return 0;
}

char LICENSE[] SEC("license") = "GPL";
