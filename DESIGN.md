# ebpf-diskalert Design Document

## Table of Contents
1. [Project Overview](#project-overview)
2. [Architecture Overview](#architecture-overview)
3. [System Architecture Diagram](#system-architecture-diagram)
4. [Component Details](#component-details)
5. [Data Flow](#data-flow)
6. [Key Technologies](#key-technologies)
7. [Configuration](#configuration)
8. [Design Decisions](#design-decisions)
9. [System Requirements](#system-requirements)
10. [Known Limitations](#known-limitations)
11. [Future Enhancements](#future-enhancements)

## Project Overview

**ebpf-diskalert** is a high-performance disk monitoring tool that leverages eBPF (Extended Berkeley Packet Filter) technology to monitor disk usage in real-time and trigger automated actions when usage thresholds are exceeded.

### Key Features
- **Real-time monitoring**: Uses eBPF to intercept block I/O operations at the kernel level
- **Low overhead**: Minimal performance impact due to in-kernel event filtering
- **Threshold-based actions**: Automatically executes user-defined scripts when disk usage exceeds configured thresholds
- **Write operation tracking**: Specifically monitors write operations to track disk usage changes
- **Configurable notifications**: Supports repeated action execution with configurable limits

### Use Cases
- Automated disk expansion when usage reaches critical levels
- Alert notifications for disk space warnings
- Log rotation or cleanup triggers
- Integration with monitoring systems
- Proactive storage management in production environments

## Architecture Overview

ebpf-diskalert follows a hybrid kernel-userspace architecture where:
- **Kernel Space**: eBPF program intercepts and filters block I/O events
- **User Space**: Go application manages configuration, monitors events, and executes actions

```
┌─────────────────────────────────────────────────────────────────────┐
│                         User Space                                  │
│  ┌───────────────────────────────────────────────────────────────┐  │
│  │                    ebpf-diskalert (Go)                        │  │
│  │  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐        │  │
│  │  │   Config     │  │    Disk      │  │   Action     │        │  │
│  │  │   Parser     │  │   Monitor    │  │   Executor   │        │  │
│  │  │  (Viper)     │  │              │  │              │        │  │
│  │  └──────┬───────┘  └──────┬───────┘  └──────▲───────┘        │  │
│  │         │                 │                 │                 │  │
│  │         └─────────────────┼─────────────────┘                 │  │
│  │                           │                                   │  │
│  │  ┌────────────────────────▼────────────────────────┐          │  │
│  │  │        eBPF Loader & Event Handler              │          │  │
│  │  │  - Load BPF Program                             │          │  │
│  │  │  - Attach to Tracepoints                        │          │  │
│  │  │  - Read Perf Events                             │          │  │
│  │  │  - Process Event Data                           │          │  │
│  │  └────────────────────┬────────────────────────────┘          │  │
│  └───────────────────────┼───────────────────────────────────────┘  │
└────────────────────────────┼──────────────────────────────────────────┘
                             │ Perf Event Buffer
                             │ (Ring Buffer)
┌────────────────────────────┼──────────────────────────────────────────┐
│                  Kernel Space                                         │
│  ┌──────────────────────────▼───────────────────────────────┐        │
│  │            eBPF Maps (Shared Memory)                     │        │
│  │  ┌─────────────────┐  ┌────────────────────────┐        │        │
│  │  │  monitor_disk   │  │  output (perf events)  │        │        │
│  │  │  (Hash Map)     │  │  (Ring Buffer)         │        │        │
│  │  │  - Device ID    │  │  - Event Data          │        │        │
│  │  └────────▲────────┘  └────────▲───────────────┘        │        │
│  │           │                    │                         │        │
│  │  ┌────────┴────────────────────┴───────────────────┐    │        │
│  │  │      eBPF Program (diskalert.bpf.c)             │    │        │
│  │  │  - Filter write operations                      │    │        │
│  │  │  - Match device ID                              │    │        │
│  │  │  - Extract process info                         │    │        │
│  │  │  - Send events to userspace                     │    │        │
│  │  └─────────────────────┬───────────────────────────┘    │        │
│  └────────────────────────┼──────────────────────────────────┘        │
│                           │                                           │
│  ┌────────────────────────▼──────────────────────────────┐            │
│  │        Linux Kernel Tracepoints                       │            │
│  │  - block/block_bio_complete                           │            │
│  │  - block/block_rq_complete                            │            │
│  └────────────────────────┬──────────────────────────────┘            │
│                           │                                           │
│  ┌────────────────────────▼──────────────────────────────┐            │
│  │           Block I/O Layer                             │            │
│  │  - Intercepts all block device operations             │            │
│  └────────────────────────┬──────────────────────────────┘            │
└────────────────────────────┼──────────────────────────────────────────┘
                             │
                    ┌────────▼────────┐
                    │  Block Devices  │
                    │  (/dev/sda1,    │
                    │   /dev/dm-0,    │
                    │   etc.)         │
                    └─────────────────┘
```

## System Architecture Diagram

### Component Interaction Flow

```
┌─────────────┐
│   config.   │
│    toml     │
└──────┬──────┘
       │
       │ Read Configuration
       ▼
┌─────────────────────────────────────────────────────────────┐
│                      main.go (Entry Point)                  │
│  - Parse CLI arguments                                      │
│  - Initialize cobra command framework                       │
└────────────────────────────┬────────────────────────────────┘
                             │
                             ▼
┌─────────────────────────────────────────────────────────────┐
│                   disk_details.go                           │
│  ┌─────────────────────────────────────────────────────┐    │
│  │  handle_io()                                        │    │
│  │  - Parse config with Viper                          │    │
│  │  - Resolve device symlinks                          │    │
│  │  - Get major/minor numbers from /proc/diskstats     │    │
│  │  - Find mount point from /proc/mounts               │    │
│  │  - Calculate device ID: (major << 20) | minor       │    │
│  └─────────────────────────────────────────────────────┘    │
└────────────────────────────┬────────────────────────────────┘
                             │
                             │ ConfigData + Devinfo
                             ▼
┌─────────────────────────────────────────────────────────────┐
│                   ebpf_loader.go                            │
│  ┌─────────────────────────────────────────────────────┐    │
│  │  ebpf_loader()                                      │    │
│  │  1. Set RLIMIT_MEMLOCK to allow BPF map creation   │    │
│  │  2. Load compiled BPF object into kernel            │    │
│  │  3. Initialize "monitor_disk" map with device ID   │    │
│  │  4. Attach to tracepoints:                          │    │
│  │     - block/block_bio_complete                      │    │
│  │     - block/block_rq_complete                       │    │
│  │  5. Create perf event reader                        │    │
│  │  6. Event loop:                                     │    │
│  │     - Read events from ring buffer                  │    │
│  │     - Parse event data                              │    │
│  │     - Call checkDiskUsage()                         │    │
│  └─────────────────────────────────────────────────────┘    │
└────────────────────────────┬────────────────────────────────┘
                             │
                             │ Perf Events
                             ▼
┌─────────────────────────────────────────────────────────────┐
│                      notify.go                              │
│  ┌─────────────────────────────────────────────────────┐    │
│  │  checkDiskUsage()                                   │    │
│  │  1. Call syscall.Statfs() on mount point            │    │
│  │  2. Calculate:                                       │    │
│  │     - Total blocks                                   │    │
│  │     - Used blocks = Total - Free                     │    │
│  │     - Threshold = Total * (threshold% / 100)         │    │
│  │  3. Compare: if Used > Threshold                     │    │
│  │  4. Check repeat_action counter                      │    │
│  │  5. Execute action script in background              │    │
│  └─────────────────────────────────────────────────────┘    │
└────────────────────────────┬────────────────────────────────┘
                             │
                             │ Execute if threshold exceeded
                             ▼
                      ┌─────────────┐
                      │   Action    │
                      │   Script    │
                      │ (notify.sh, │
                      │ lvm_extend  │
                      │   .sh, etc.)│
                      └─────────────┘
```

## Component Details

### 1. eBPF Kernel Program (`diskalert.bpf.c`)

**Purpose**: Runs in kernel space to filter and capture block I/O events

**Key Components**:
- **BPF Maps**:
  - `monitor_disk`: Hash map storing the target device ID to monitor
  - `output`: Perf event array for sending data to userspace

- **Tracepoint Handler** (`bpf_traceblock`):
  - Attached to: `block/block_bio_complete` and `block/block_rq_complete`
  - Filters: Only write operations (`rwbs[0] == 'W'`)
  - Extracts:
    - Process ID (PID)
    - User ID (UID)
    - Command name
    - Device ID (major/minor encoded)
  - Sends filtered events to userspace via perf buffer

**Location**: `src/bpf/diskalert.bpf.c`

### 2. Configuration Parser (`disk_details.go`)

**Purpose**: Parse configuration and gather device information

**Key Functions**:
- `getConfig()`: Reads TOML configuration using Viper library
- `isSymlink()`: Resolves device symlinks (e.g., `/dev/mapper/*` → `/dev/dm-X`)
- `getDeviceNumbers()`: Parses `/proc/diskstats` for major/minor numbers
- `findMountPoint()`: Parses `/proc/mounts` to find device mount point
- `handle_io()`: Orchestrates all I/O initialization

**Data Structures**:
```go
type ConfigData struct {
    DeviceName         string  // Device to monitor
    DiskUsageThreshold uint64  // Usage threshold (percentage)
    Action             string  // Script to execute
    RepeatAction       uint64  // Max number of action executions
}

type Devinfo struct {
    Devid      uint64  // Encoded device ID
    MountPoint string  // Filesystem mount point
}
```

**Location**: `src/disk_details.go`

### 3. eBPF Loader (`ebpf_loader.go`)

**Purpose**: Load eBPF program and handle kernel events

**Key Functions**:
- `setlimit()`: Sets RLIMIT_MEMLOCK to allow BPF operations
- `ebpf_loader()`: Main event processing loop
  - Loads BPF objects generated by bpf2go
  - Populates BPF maps with device ID
  - Attaches to kernel tracepoints
  - Reads perf events in infinite loop
  - Calls disk usage checker for each write event

**Event Processing**:
1. Read raw sample from perf ring buffer
2. Parse binary data into `data_t` structure
3. Log process information
4. Invoke disk usage check with mutex protection

**Location**: `src/ebpf_loader.go`

### 4. Action Executor (`notify.go`)

**Purpose**: Monitor disk usage and execute actions

**Key Functions**:
- `DiskUsage()`: Uses `syscall.Statfs()` to get filesystem statistics
- `checkDiskUsage()`: Compares usage against threshold
- `runInBackground()`: Executes action script asynchronously

**Disk Usage Calculation**:
```
Threshold = Total_Blocks × (Threshold_Percentage / 100)
Used_Blocks = Total_Blocks - Free_Blocks

if Used_Blocks > Threshold:
    Execute Action (if counter < repeat_action)
```

**Action Limiting**:
- Global counter `disknofity_counter` tracks executions
- Reset to 0 when usage drops below threshold
- Prevents action spam during sustained high usage

**Location**: `src/notify.go`

### 5. Main Entry Point (`main.go`)

**Purpose**: CLI interface and application bootstrap

**Features**:
- Uses Cobra framework for CLI
- Flags:
  - `-c, --config`: Path to configuration file (required)
  - `--version`: Display version information
- Orchestrates initialization sequence

**Location**: `src/main.go`

## Data Flow

### Complete Event Flow

```
1. User initiates write operation
   └─> Application writes to file
       └─> VFS layer
           └─> Filesystem (ext4, xfs, etc.)
               └─> Block I/O layer

2. Kernel block layer processes I/O
   └─> Triggers tracepoint: block/block_bio_complete
       └─> eBPF program attached to tracepoint executes
           ├─> Filter: Is this a write? (Check rwbs[0] == 'W')
           ├─> Filter: Is this our target device? (Check dev ID)
           └─> If matches:
               ├─> Extract: PID, UID, Command, Device ID
               └─> Send event via perf buffer

3. Userspace application (ebpf-diskalert)
   └─> Perf reader receives event
       ├─> Parse binary event data
       ├─> Log: "Command X wrote to mountpoint Y"
       └─> Call checkDiskUsage() with mutex lock
           ├─> syscall.Statfs() on mount point
           ├─> Calculate: Used_Blocks, Threshold
           └─> If Used > Threshold:
               ├─> Check: counter < repeat_action?
               ├─> Execute action script in background
               └─> Increment counter

4. Action script executes
   └─> Example actions:
       ├─> Send alert notification
       ├─> Expand LVM volume
       ├─> Clean up old logs
       └─> Trigger external monitoring system
```

### Configuration Flow

```
config.toml
    │
    ├─> devicename: "/dev/sda1"
    │   └─> Resolved to real device (handle symlinks)
    │       └─> Parse /proc/diskstats for major/minor
    │           └─> Calculate device ID: (major << 20) | minor
    │               └─> Store in BPF map "monitor_disk"
    │
    ├─> diskusage_threshold: 90
    │   └─> Used in checkDiskUsage()
    │       └─> Threshold = Total_Blocks * 0.90
    │
    ├─> action: "/path/to/script.sh"
    │   └─> Executed when threshold exceeded
    │
    └─> repeat_action: 10
        └─> Action executes max 10 times
            └─> Counter resets when usage drops
```

## Key Technologies

### eBPF (Extended Berkeley Packet Filter)
- **Purpose**: In-kernel event filtering and data collection
- **Advantages**:
  - Low overhead (runs in kernel space)
  - Safe execution (verified by kernel)
  - No kernel module required
  - Dynamic attachment/detachment

### Cilium eBPF Library
- **Package**: `github.com/cilium/ebpf`
- **Features**:
  - Pure Go eBPF implementation
  - bpf2go code generation
  - Map management
  - Program loading and verification
  - Perf event handling

### Linux Tracepoints
- **Used Tracepoints**:
  - `block/block_bio_complete`: Fired when block I/O completes
  - `block/block_rq_complete`: Alternative completion point
- **Why both?**: Different kernel versions may use different tracepoints

### Go Libraries
- **Cobra**: CLI framework
- **Viper**: Configuration management (TOML parsing)
- **golang.org/x/sys/unix**: System call wrappers

### Build Tools
- **bpf2go**: Generates Go code from C BPF programs
- **clang**: Compiles BPF C code to BPF bytecode
- **bpftool**: Dumps kernel BTF information (vmlinux.h)

## Configuration

### Configuration File Format (TOML)

```toml
devicename = "/dev/sda1"           # Device to monitor
diskusage_threshold = 90           # Threshold percentage (0-100)
action = "/usr/bin/notify.sh"      # Action to execute
repeat_action = 1                  # Max action repetitions
```

### Configuration Parameters

| Parameter | Type | Description | Example |
|-----------|------|-------------|---------|
| `devicename` | string | Block device path to monitor | `/dev/sda1`, `/dev/mapper/vg-lv` |
| `diskusage_threshold` | integer | Usage percentage threshold (0-100) | `90` |
| `action` | string | Script or binary to execute | `/usr/bin/notify.sh` |
| `repeat_action` | integer | Maximum number of action executions | `1` (once), `10` (10 times) |

### Important Notes
- **Ext4 Reserved Blocks**: By default, ext4 reserves 5% of blocks for root. Use `tune2fs -m0 /dev/device` to remove reserved blocks if needed.
- **Threshold Adjustment**: If triggering based on `df` output, set threshold 5% lower (e.g., threshold=65 for df=70%)

## Design Decisions

### 1. Why eBPF?
**Decision**: Use eBPF for monitoring instead of polling

**Rationale**:
- **Event-driven**: No polling overhead
- **Real-time**: Immediate detection of writes
- **Efficient**: Filtering in kernel space
- **Accurate**: Captures all I/O operations

**Alternative Considered**: Periodic polling with `df`
- **Rejected because**: High overhead, delayed detection, less accurate

### 2. Tracepoint Selection
**Decision**: Attach to `block_bio_complete` and `block_rq_complete`

**Rationale**:
- Captures completed I/O operations
- Works across different kernel versions
- Provides device information

**Alternative Considered**: Filesystem-level tracing
- **Rejected because**: Filesystem-specific, more complex

### 3. Write-Only Filtering
**Decision**: Only monitor write operations

**Rationale**:
- Disk usage only increases with writes
- Reduces event volume
- Lower overhead

### 4. Userspace Disk Check
**Decision**: Disk usage calculation in userspace, not kernel

**Rationale**:
- Simpler implementation
- Easier to debug
- More flexible (can use standard syscalls)
- BPF program remains simple and efficient

**Trade-off**: Slight latency between write event and usage check

### 5. Action Execution
**Decision**: Run actions in background with output logging

**Rationale**:
- Non-blocking event processing
- Captures action output for debugging
- Prevents action failures from blocking monitoring

### 6. Repeat Action Counter
**Decision**: Global counter with threshold-based reset

**Rationale**:
- Prevents action spam
- Automatic recovery when usage decreases
- Configurable repetition limit

### 7. Mutex Protection
**Decision**: Mutex around `checkDiskUsage()`

**Rationale**:
- Prevents concurrent action execution
- Protects shared counter variable
- Ensures serial disk checks

## System Requirements

### Kernel Requirements
- **Minimum Version**: 5.14.21 (tested)
- **Recommended**: 6.2.0 or later
- **Required Features**:
  - eBPF support (`CONFIG_BPF=y`)
  - BTF support (`CONFIG_DEBUG_INFO_BTF=y`)
  - Tracepoint support (`CONFIG_TRACEPOINTS=y`)

### Build Dependencies
- **Go**: 1.20 or later
- **clang**: For compiling BPF programs
- **bpftool**: For generating vmlinux.h
- **Kernel headers**: For BPF development

### Runtime Requirements
- **Privileges**: Must run as root (required for BPF operations)
- **Kernel BTF**: `/sys/kernel/btf/vmlinux` must exist
- **Memory**: RLIMIT_MEMLOCK must allow BPF map creation

### Tested Kernel Versions

| Kernel Version | Status | Notes |
|----------------|--------|-------|
| 5.4.0 | ❌ Fail | Needs investigation |
| 5.15.0 | ❌ Fail | Needs investigation |
| 5.14.21 | ✅ Pass | Minimum working version |
| 6.2.0 | ✅ Pass | Recommended |
| 6.3.5 | ✅ Pass | |
| 6.5.0 | ✅ Pass | |

## Known Limitations

### 1. Ext4 Reserved Blocks
- Default 5% reserved blocks counted as used
- Affects threshold calculations
- Mitigation: Use `tune2fs -m0` or adjust threshold

### 2. Single Device Monitoring
- Current implementation monitors one device per instance
- Multi-device monitoring requires multiple instances
- Future enhancement: Support multiple devices in single instance

### 3. Action Execution
- No action timeout mechanism
- No action failure handling beyond logging
- Long-running actions could accumulate

### 4. Kernel Version Compatibility
- Fails on kernels < 5.14.21
- May need BPF program adjustments for older kernels

### 5. Perf Buffer Size
- Fixed at one page size
- May lose events under extreme I/O load
- Logged but not recoverable

## Future Enhancements

### 1. Multi-Device Support
- Monitor multiple devices in single instance
- Separate thresholds per device
- Consolidated event processing

### 2. Advanced Action Management
- Action timeouts
- Action dependency chains
- Conditional action execution
- Action priority queues

### 3. Metrics and Monitoring
- Prometheus exporter
- Grafana dashboard templates
- Historical usage tracking
- Event rate statistics

### 4. Enhanced Configuration
- Hot reload of configuration
- Multiple threshold levels
- Time-based thresholds
- Rate limiting for actions

### 5. Improved Reliability
- Action retry logic
- Dead letter queue for failed actions
- Health check endpoint
- Graceful shutdown handling

### 6. Broader Kernel Support
- Backward compatibility for older kernels
- Fallback to polling mode
- Auto-detection of kernel features

### 7. Additional Monitoring
- Read operation tracking
- I/O latency monitoring
- Per-process disk usage attribution
- Inode usage monitoring

### 8. Security Enhancements
- Non-root operation (with capabilities)
- Action sandboxing
- Configuration validation
- Audit logging

---

## Appendix A: Building from Source

```bash
# Clone repository
git clone https://github.com/Lakshmipathi/ebpf-diskalert.git
cd ebpf-diskalert

# Build
make build

# Install
sudo cp ebpf-diskalert /usr/sbin/
sudo chmod 500 /usr/sbin/ebpf-diskalert
```

## Appendix B: Example Action Scripts

### Notification Script
```bash
#!/bin/bash
# notify.sh - Send email alert
echo "Disk usage threshold exceeded on $(hostname)" | \
    mail -s "ALERT: Disk Full" admin@example.com
```

### LVM Extension Script
```bash
#!/bin/bash
# lvm_extend.sh - Automatically extend logical volume
LV_PATH="/dev/vg01/lv_data"
lvextend -L +10G $LV_PATH
resize2fs $LV_PATH
```

## Appendix C: Troubleshooting

### Issue: eBPF program fails to load
- **Check**: Kernel version (requires >= 5.14.21)
- **Check**: BTF support: `ls /sys/kernel/btf/vmlinux`
- **Check**: Run as root

### Issue: No events received
- **Check**: Device name is correct
- **Check**: Device is mounted
- **Check**: Write operations are occurring
- **Check**: Kernel logs: `sudo dmesg | grep bpf`

### Issue: Actions not executing
- **Check**: Script has execute permissions
- **Check**: Script path is absolute
- **Check**: Check logs: `/var/log/diskalert.log`
- **Check**: Threshold is actually exceeded

---

**Document Version**: 1.0
**Last Updated**: 2025-11-18
**Author**: Lakshmipathi Ganapathi
**License**: See LICENSE file
