# eBPF File Recovery System

## Overview

The eBPF File Recovery System is a proactive file recovery feature that can restore deleted files by leveraging open file descriptors. When a file is deleted via `rm` or `unlink()` but still has open file descriptors, the file's data remains accessible on disk. This system uses eBPF to detect such deletions and automatically recover the file contents.

## How It Works

### The Core Concept

In Linux, when you delete a file:
1. The directory entry is removed (file disappears from `ls`)
2. The inode's link count is decremented
3. **Critical behavior**: If the file has open file descriptors, the inode and data blocks remain on disk until all fds are closed
4. The file can be accessed via `/proc/<pid>/fd/<fd>` even after deletion

### Architecture

```
┌─────────────────────────────────────────────────────────────┐
│ 1. FILE OPERATIONS                                          │
│    - User opens file: openat() syscall                      │
│    - User deletes file: unlinkat() or rm command            │
│    - User closes file: close() syscall                      │
└────────────────────┬────────────────────────────────────────┘
                     │
┌────────────────────▼────────────────────────────────────────┐
│ 2. eBPF HOOKS (Kernel Space)                               │
│    - sys_exit_openat: Track file opens                      │
│    - sys_enter_close: Track file closes                     │
│    - vfs_unlink: Detect file deletions                      │
│    - BPF Map: (inode, dev) -> (pid, fd)                    │
└────────────────────┬────────────────────────────────────────┘
                     │ Perf Event Ring Buffer
                     │
┌────────────────────▼────────────────────────────────────────┐
│ 3. USERSPACE RECOVERY DAEMON                                │
│    - Receives deletion events                                │
│    - Checks if file has open fd in tracking map             │
│    - Reads file via /proc/<pid>/fd/<fd>                     │
│    - Saves to recovery directory                            │
└─────────────────────────────────────────────────────────────┘
```

### eBPF Programs

The system uses three main eBPF hooks:

1. **`trace_openat_exit`** (tracepoint/syscalls/sys_exit_openat)
   - Intercepts successful file opens
   - Extracts inode and device numbers
   - Stores (inode, dev) -> (pid, fd) mapping in BPF map
   - Applies minimum file size filter

2. **`trace_close_entry`** (tracepoint/syscalls/sys_enter_close)
   - Intercepts file closes
   - Removes entry from tracking map

3. **`kprobe_vfs_unlink`** (kprobe/vfs_unlink)
   - Intercepts file deletions at VFS layer
   - Checks if file is in tracking map
   - Sends recovery event to userspace if fd is open

### BPF Maps

- **`open_fds_map`**: LRU hash map (max 100k entries)
  - Key: `{inode, dev}`
  - Value: `{pid, fd, opened_at}`
  - Tracks all open files system-wide

- **`config_map`**: Configuration map
  - Key 0: Enabled flag (0/1)
  - Key 1: Minimum file size threshold

- **`recovery_events`**: Perf event array
  - Sends deletion events to userspace

- **`tracking_events`**: Perf event array (optional)
  - Sends open/close events for debugging

## Installation

### Prerequisites

1. **Linux Kernel**: 5.14+ (BTF support required)
2. **Kernel Headers**: For eBPF compilation
3. **Go**: 1.19 or later
4. **clang/LLVM**: For compiling eBPF programs
5. **Root privileges**: eBPF requires CAP_BPF or root

### Build

```bash
cd /home/user/ebpf-diskalert/src

# Generate eBPF Go bindings
go generate ./...

# Build the application
go build -o ../bin/ebpf-diskalert .
```

### Configuration

Create or update your configuration file:

```toml
# config.toml

# Disk monitoring (existing feature)
devicename = "/dev/mapper/debian--vg-root"
diskusage_threshold = 90
action = "/usr/bin/date"
repeat_action = 1

# File Recovery Configuration
recovery_enabled = true
recovery_min_size = 1024          # Only track files >= 1KB
recovery_dir = "/var/lib/diskalert/recovered"
recovery_max_files = 1000
```

### Running

```bash
# As root
sudo ./bin/ebpf-diskalert -c config/config-with-recovery.toml
```

## Configuration Options

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `recovery_enabled` | bool | false | Enable/disable file recovery |
| `recovery_min_size` | uint64 | 0 | Minimum file size in bytes to track |
| `recovery_dir` | string | `/var/lib/diskalert/recovered` | Directory for recovered files |
| `recovery_max_files` | uint64 | 1000 | Maximum recovered files to keep |

## Usage

### Automatic Recovery

Once running, the system automatically:

1. **Tracks** all file open operations (for files > min_size)
2. **Detects** when tracked files are deleted
3. **Recovers** files that have open file descriptors
4. **Saves** recovered files to `recovery_dir`

### Recovered File Naming

Recovered files are named:
```
<timestamp>_<original_basename>_inode<inode_number>
```

Example:
```
1700000000_important_data.txt_inode12345678
```

### Metadata Files

Each recovered file has an accompanying `.meta` file with recovery information:

```
Recovery Metadata
================
Original Path: /home/user/important_data.txt
Recovered At: 2024-11-22T10:30:45Z
Inode: 12345678
Process ID: 5432
File Descriptor: 3
File Size: 2048 bytes
Recovery Path: /var/lib/diskalert/recovered/1700000000_important_data.txt_inode12345678
```

## Testing

### Manual Test

```bash
# Terminal 1: Start the recovery system
sudo ./bin/ebpf-diskalert -c config/config-with-recovery.toml

# Terminal 2: Test file recovery
cd /tmp
echo "Important data" > testfile.txt

# Open file and keep it open
exec 3< testfile.txt

# Delete the file
rm testfile.txt

# File is deleted from directory but still readable
cat <&3  # Still works!

# Wait a few seconds for recovery
sleep 3

# Check recovery directory
ls -lh /var/lib/diskalert/recovered/

# Close the fd
exec 3<&-
```

### Automated Test Script

```bash
sudo ./tests/test_recovery.sh
```

## Monitoring

### Logs

Recovery events are logged to:
```
/var/log/diskalert-recovery.log
```

Example log entries:
```
[TRACK] OPEN: pid=1234 fd=3 inode=567890 size=2048 comm=vim
[DELETION DETECTED] file=/tmp/testfile.txt inode=567890 size=2048 deleted_by=rm (pid=1235)
  → File is open: pid=1234 fd=3 - attempting recovery
    Recovered 2048 bytes to: /var/lib/diskalert/recovered/1700000000_testfile.txt_inode567890
  ✓ Recovery successful
```

### Statistics

The system tracks:
- Files tracked
- Files deleted
- Files recovered
- Recovery failures
- Total bytes recovered

Stats are logged every 60 seconds.

### eBPF Tools

Check loaded eBPF programs:
```bash
sudo bpftool prog list | grep recovery
```

Check BPF maps:
```bash
sudo bpftool map list
sudo bpftool map dump name open_fds_map
```

## Performance Considerations

### Memory Usage

- **BPF Map**: ~100k entries × 32 bytes ≈ 3.2 MB
- **LRU eviction**: Automatically removes oldest entries when full
- **Userspace**: Minimal overhead

### CPU Overhead

- **Tracepoints**: Low overhead (< 1% for typical workloads)
- **File size filtering**: Reduces tracking of small files
- **Path filtering**: Can be added to track specific directories only

### Tuning

To reduce overhead:

1. **Increase minimum file size**:
   ```toml
   recovery_min_size = 1048576  # Only track files >= 1MB
   ```

2. **Limit map size** (edit `recovery.bpf.c`):
   ```c
   __uint(max_entries, 10000);  // Track fewer files
   ```

3. **Add path filters** (future enhancement)

## Limitations

### What Can Be Recovered

✅ **Can recover**:
- Files deleted while open by any process
- Files held open by text editors (vim, nano, etc.)
- Log files being actively written
- Database files with open connections
- Files opened by long-running processes

❌ **Cannot recover**:
- Files that were never opened
- Files opened and immediately closed before deletion
- Files deleted before eBPF program loaded
- Very small files (below `recovery_min_size`)

### Race Conditions

There's a small timing window where a file could be:
1. Opened
2. Closed
3. Deleted

...all before eBPF tracking updates. This is inherent to the approach.

**Mitigation**: Use `recovery_min_size` to focus on important files that are typically open longer.

### Filesystem Compatibility

- ✅ Works with: ext4, xfs, btrfs, zfs (most filesystems)
- ❌ May not work with: network filesystems (NFS, CIFS), FUSE filesystems
- ⚠️ Special cases: Requires testing with specific filesystem features

## Use Cases

### 1. Development Environments

Recover accidentally deleted source code files still open in editors:

```toml
recovery_enabled = true
recovery_min_size = 100  # Track even small source files
recovery_dir = "/var/backups/dev-recovery"
```

### 2. Log File Protection

Recover deleted log files still being written by applications:

```toml
recovery_enabled = true
recovery_min_size = 10240  # Track logs >= 10KB
recovery_dir = "/var/backups/log-recovery"
```

### 3. Database Safety Net

Recover database files accidentally removed while database is running:

```toml
recovery_enabled = true
recovery_min_size = 1048576  # Track files >= 1MB
recovery_dir = "/var/backups/db-recovery"
```

## Troubleshooting

### Recovery Not Working

1. **Check if eBPF program is loaded**:
   ```bash
   sudo bpftool prog list | grep recovery
   ```

2. **Check logs**:
   ```bash
   tail -f /var/log/diskalert-recovery.log
   ```

3. **Verify file size threshold**:
   - Files smaller than `recovery_min_size` won't be tracked

4. **Check recovery directory permissions**:
   ```bash
   ls -ld /var/lib/diskalert/recovered
   ```

### Permission Errors

The program must run as root or with these capabilities:
```bash
sudo setcap cap_bpf,cap_sys_admin,cap_sys_ptrace+ep ./ebpf-diskalert
```

### Memory Errors

If you see "failed to set rlimit" errors:
```bash
# Increase memlock limit
ulimit -l unlimited
```

Or edit `/etc/security/limits.conf`:
```
* soft memlock unlimited
* hard memlock unlimited
```

## Security Considerations

### Recovered File Permissions

- Recovered files are created with mode `0644`
- Owned by the user running the recovery daemon (usually root)
- **Important**: Secure the recovery directory appropriately

### Sensitive Data

Be aware that:
- Deleted files containing secrets may be recovered
- Recovery directory should have restricted permissions
- Consider encryption for the recovery directory

### Recommended Security

```bash
# Restrict recovery directory
sudo chmod 700 /var/lib/diskalert/recovered
sudo chown root:root /var/lib/diskalert/recovered

# Regular cleanup
# (automatically done every 7 days by the daemon)
```

## Advanced Topics

### Adding Path Filters

To only track files in specific directories, edit `recovery.bpf.c`:

```c
// Add path filtering in trace_openat_exit
char path[256];
bpf_probe_read_user_str(&path, sizeof(path), pathname);

// Only track /home and /var/log
if (!starts_with(path, "/home/") && !starts_with(path, "/var/log/")) {
    return 0;
}
```

### Integration with Backup Systems

Recovered files can trigger backup scripts:

```bash
# config.toml
recovery_dir = "/var/lib/diskalert/recovered"

# Create inotify watcher
inotifywait -m /var/lib/diskalert/recovered -e create |
while read path action file; do
    echo "New recovery: $file"
    # Trigger backup
    rsync -av "$path/$file" /backup/recovered/
done
```

### Custom Recovery Actions

Hook into the recovery process by monitoring the log:

```bash
tail -f /var/log/diskalert-recovery.log | grep "Recovery successful" | while read line; do
    # Send notification
    notify-send "File recovered" "$line"
done
```

## Future Enhancements

Planned features:

- [ ] Path-based filtering (only track specific directories)
- [ ] Per-user recovery directories
- [ ] Recovery rate limiting (prevent resource exhaustion)
- [ ] Integration with inotify for real-time recovery
- [ ] REST API for recovery management
- [ ] Web UI for browsing recovered files
- [ ] Automatic file validation (checksums)
- [ ] Compression of recovered files
- [ ] Cloud backup integration

## FAQ

**Q: Does this work on kernel version X.Y?**
A: Requires kernel 5.14+ with BTF support. Check with: `ls /sys/kernel/btf/vmlinux`

**Q: What's the performance impact?**
A: Typically < 1% CPU overhead. Can be tuned with `recovery_min_size`.

**Q: Can it recover files deleted weeks ago?**
A: No. Files must have an open fd at the time of deletion. This is not a "undelete" tool.

**Q: Why use eBPF instead of inotify?**
A: eBPF hooks at the VFS layer, providing access to inode information and file descriptors that inotify doesn't expose.

**Q: Does it work with `shred` or `srm`?**
A: No. These tools overwrite data before deletion, making recovery impossible.

**Q: How much disk space do I need?**
A: Depends on your `recovery_max_files` setting and typical file sizes. Budget ~100MB per 100 files.

## Contributing

See the main design document at `docs/file-recovery-via-fd-design.md` for implementation details and strategies.

## License

Same as ebpf-diskalert main project.

## References

- [Design Document](file-recovery-via-fd-design.md)
- [eBPF Documentation](https://ebpf.io/)
- [Linux File Deletion Internals](https://www.kernel.org/doc/html/latest/filesystems/index.html)
- [BPF Type Format (BTF)](https://www.kernel.org/doc/html/latest/bpf/btf.html)
