# ebpf-diskalert Architecture Diagrams

This document contains detailed architecture diagrams for the ebpf-diskalert project.

## High-Level System Architecture

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                              USER SPACE                                     │
│                                                                             │
│  ┌───────────────────────────────────────────────────────────────────────┐  │
│  │                        ebpf-diskalert                                 │  │
│  │                         (Go Application)                              │  │
│  │                                                                       │  │
│  │  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐  ┌──────────┐ │  │
│  │  │    Config    │  │     Disk     │  │     eBPF     │  │  Action  │ │  │
│  │  │    Parser    │─▶│   Details    │─▶│    Loader    │─▶│ Executor │ │  │
│  │  │  (Viper)     │  │   Resolver   │  │   Manager    │  │          │ │  │
│  │  └──────────────┘  └──────────────┘  └──────┬───────┘  └──────────┘ │  │
│  │                                              │                        │  │
│  │                                              │                        │  │
│  │                                     ┌────────▼────────┐               │  │
│  │                                     │  Perf Event     │               │  │
│  │                                     │    Reader       │               │  │
│  │                                     │  (Ring Buffer)  │               │  │
│  │                                     └────────┬────────┘               │  │
│  └──────────────────────────────────────────────┼────────────────────────┘  │
└─────────────────────────────────────────────────┼──────────────────────────┘
                                                  │
                                    ═══════════════════════════
                                      Perf Event Buffer
                                      (Kernel ↔ User)
                                    ═══════════════════════════
                                                  │
┌─────────────────────────────────────────────────┼──────────────────────────┐
│                            KERNEL SPACE         │                          │
│                                                 │                          │
│  ┌──────────────────────────────────────────────▼────────────────────────┐ │
│  │                          eBPF Maps                                    │ │
│  │  ┌────────────────────┐              ┌─────────────────────────────┐  │ │
│  │  │  monitor_disk      │              │   output                    │  │ │
│  │  │  (BPF_HASH_MAP)    │              │   (BPF_PERF_EVENT_ARRAY)    │  │ │
│  │  │                    │              │                             │  │ │
│  │  │  Key: "monitor_    │              │  Sends events to userspace  │  │ │
│  │  │       disk"        │              │  via perf ring buffer       │  │ │
│  │  │  Value: Device ID  │              │                             │  │ │
│  │  │  (major<<20|minor) │              │                             │  │ │
│  │  └─────────▲──────────┘              └──────────▲──────────────────┘  │ │
│  │            │                                    │                     │ │
│  │            │                                    │                     │ │
│  │  ┌─────────┴────────────────────────────────────┴──────────────────┐  │ │
│  │  │            eBPF Program (diskalert.bpf.c)                       │  │ │
│  │  │                                                                 │  │ │
│  │  │  SEC("tracepoint/block/block_bio_complete")                    │  │ │
│  │  │  int bpf_traceblock(ctx) {                                     │  │ │
│  │  │    1. Extract device ID from ctx->dev                          │  │ │
│  │  │    2. Check if rwbs[0] == 'W' (write operation)                │  │ │
│  │  │    3. Lookup device ID in monitor_disk map                     │  │ │
│  │  │    4. If match:                                                │  │ │
│  │  │       - Get PID, UID, command name                             │  │ │
│  │  │       - Send event to output perf buffer                       │  │ │
│  │  │  }                                                              │  │ │
│  │  └─────────────────────────────┬───────────────────────────────────┘  │ │
│  └────────────────────────────────┼──────────────────────────────────────┘ │
│                                   │                                        │
│  ┌────────────────────────────────▼──────────────────────────────────────┐ │
│  │                    Kernel Tracepoints                                 │ │
│  │                                                                       │ │
│  │    ┌────────────────────────┐      ┌─────────────────────────┐       │ │
│  │    │  block_bio_complete    │      │  block_rq_complete      │       │ │
│  │    │                        │      │                         │       │ │
│  │    │  Triggered when a bio  │      │  Triggered when a       │       │ │
│  │    │  I/O operation         │      │  request completes      │       │ │
│  │    │  completes             │      │                         │       │ │
│  │    └───────────┬────────────┘      └────────────┬────────────┘       │ │
│  └────────────────┼─────────────────────────────────┼────────────────────┘ │
│                   └─────────────────┬───────────────┘                      │
│                                     │                                      │
│  ┌──────────────────────────────────▼──────────────────────────────────┐   │
│  │                     Block I/O Subsystem                             │   │
│  │                                                                     │   │
│  │  - Handles all block device I/O operations                         │   │
│  │  - Manages I/O scheduling                                          │   │
│  │  - Triggers tracepoints at various stages                          │   │
│  └──────────────────────────────────┬──────────────────────────────────┘   │
└─────────────────────────────────────┼────────────────────────────────────┘
                                      │
                ┌─────────────────────┼─────────────────────┐
                │                     │                     │
         ┌──────▼──────┐      ┌──────▼──────┐      ┌──────▼──────┐
         │  /dev/sda1  │      │ /dev/dm-0   │      │ /dev/nvme0  │
         │             │      │   (LVM)     │      │             │
         │  Physical   │      │  Logical    │      │   NVMe      │
         │    Disk     │      │  Volume     │      │   Device    │
         └─────────────┘      └─────────────┘      └─────────────┘
```

## Detailed Event Flow Diagram

```
┌─────────────┐
│    User     │
│ Application │
└──────┬──────┘
       │ write()
       ▼
┌─────────────────────────────────────────────────────────────────────────┐
│                           KERNEL SPACE                                  │
│                                                                         │
│  ┌──────────┐                                                           │
│  │   VFS    │ Virtual File System                                      │
│  └────┬─────┘                                                           │
│       │                                                                 │
│       ▼                                                                 │
│  ┌──────────┐                                                           │
│  │   ext4   │ File System Layer                                        │
│  │   xfs    │                                                           │
│  │   btrfs  │                                                           │
│  └────┬─────┘                                                           │
│       │                                                                 │
│       ▼                                                                 │
│  ┌───────────────────────────────────────────────────────────┐          │
│  │             Block I/O Layer                               │          │
│  │                                                           │          │
│  │  ┌─────────────────────────────────────────────────────┐  │          │
│  │  │ 1. bio created (block I/O request)                  │  │          │
│  │  └─────────────────────────────────────────────────────┘  │          │
│  │                         │                                 │          │
│  │                         ▼                                 │          │
│  │  ┌─────────────────────────────────────────────────────┐  │          │
│  │  │ 2. I/O scheduler processes request                  │  │          │
│  │  └─────────────────────────────────────────────────────┘  │          │
│  │                         │                                 │          │
│  │                         ▼                                 │          │
│  │  ┌─────────────────────────────────────────────────────┐  │          │
│  │  │ 3. Request submitted to device driver               │  │          │
│  │  └─────────────────────────────────────────────────────┘  │          │
│  │                         │                                 │          │
│  │                         ▼                                 │          │
│  │  ┌─────────────────────────────────────────────────────┐  │          │
│  │  │ 4. I/O completes                                    │  │          │
│  │  └─────────────────────────────────────────────────────┘  │          │
│  │                         │                                 │          │
│  └─────────────────────────┼─────────────────────────────────┘          │
│                            │                                            │
│                            ▼                                            │
│  ┌──────────────────────────────────────────────────────────┐           │
│  │  TRACEPOINT: block/block_bio_complete                    │           │
│  │  TRACEPOINT: block/block_rq_complete                     │           │
│  │                                                           │           │
│  │  Context Data Available:                                 │           │
│  │  - ctx->dev       (device major:minor)                   │           │
│  │  - ctx->rwbs[0]   (operation type: R/W/F/etc)            │           │
│  │  - ctx->sector    (disk sector)                          │           │
│  │  - ctx->nr_sector (number of sectors)                    │           │
│  └────────────────────────┬─────────────────────────────────┘           │
│                           │                                             │
│                           ▼                                             │
│  ┌─────────────────────────────────────────────────────────────────┐    │
│  │           eBPF Program: bpf_traceblock()                        │    │
│  │                                                                 │    │
│  │  ┌───────────────────────────────────────────────────────────┐  │    │
│  │  │ Step 1: Extract device ID                                │  │    │
│  │  │   major = (ctx->dev >> 20) & 0xFFF                        │  │    │
│  │  │   minor = ctx->dev & 0xFFFFF                              │  │    │
│  │  └───────────────────────────────────────────────────────────┘  │    │
│  │                           │                                     │    │
│  │                           ▼                                     │    │
│  │  ┌───────────────────────────────────────────────────────────┐  │    │
│  │  │ Step 2: Filter by operation type                         │  │    │
│  │  │   if (ctx->rwbs[0] != 'W')                                │  │    │
│  │  │       return 0;  // Ignore reads                          │  │    │
│  │  └───────────────────────────────────────────────────────────┘  │    │
│  │                           │                                     │    │
│  │                           ▼                                     │    │
│  │  ┌───────────────────────────────────────────────────────────┐  │    │
│  │  │ Step 3: Check if this is our monitored device            │  │    │
│  │  │   target_dev = map_lookup(monitor_disk, "monitor_disk")   │  │    │
│  │  │   if (ctx->dev != target_dev)                             │  │    │
│  │  │       return 0;  // Not our device                        │  │    │
│  │  └───────────────────────────────────────────────────────────┘  │    │
│  │                           │                                     │    │
│  │                           ▼                                     │    │
│  │  ┌───────────────────────────────────────────────────────────┐  │    │
│  │  │ Step 4: Collect process information                      │  │    │
│  │  │   data.pid = bpf_get_current_pid_tgid() >> 32             │  │    │
│  │  │   data.uid = bpf_get_current_uid_gid() & 0xFFFFFFFF       │  │    │
│  │  │   bpf_get_current_comm(&data.command, 64)                 │  │    │
│  │  └───────────────────────────────────────────────────────────┘  │    │
│  │                           │                                     │    │
│  │                           ▼                                     │    │
│  │  ┌───────────────────────────────────────────────────────────┐  │    │
│  │  │ Step 5: Send event to userspace                          │  │    │
│  │  │   bpf_perf_event_output(ctx, &output,                     │  │    │
│  │  │                         BPF_F_CURRENT_CPU,                │  │    │
│  │  │                         &data, sizeof(data))              │  │    │
│  │  └───────────────────────────────────────────────────────────┘  │    │
│  └─────────────────────────────┬───────────────────────────────────┘    │
└────────────────────────────────┼──────────────────────────────────────┘
                                 │
                    ═════════════▼═════════════
                     Perf Ring Buffer (4KB)
                    ═══════════════════════════
                                 │
┌────────────────────────────────┼──────────────────────────────────────┐
│                       USER SPACE                                      │
│                                │                                      │
│  ┌─────────────────────────────▼──────────────────────────────────┐   │
│  │           Perf Event Reader (Go)                               │   │
│  │                                                                │   │
│  │  for {                                                         │   │
│  │      event = perf_reader.Read()                                │   │
│  │      if event.LostSamples > 0 {                                │   │
│  │          log("Lost samples!")                                  │   │
│  │          continue                                              │   │
│  │      }                                                         │   │
│  │                                                                │   │
│  │      // Parse binary event data                               │   │
│  │      data = binary.Read(event.RawSample)                       │   │
│  │                                                                │   │
│  │      log("Command:", data.Command, "wrote to", mountpoint)     │   │
│  │                                                                │   │
│  │      checkDiskUsage()                                          │   │
│  │  }                                                             │   │
│  └────────────────────────────┬───────────────────────────────────┘   │
│                               │                                       │
│                               ▼                                       │
│  ┌────────────────────────────────────────────────────────────────┐   │
│  │            checkDiskUsage() Function                           │   │
│  │                                                                │   │
│  │  1. syscall.Statfs(mountpoint, &stat)                         │   │
│  │                                                                │   │
│  │  2. Calculate usage:                                           │   │
│  │     total_blocks = stat.Blocks                                 │   │
│  │     free_blocks  = stat.Bfree                                  │   │
│  │     used_blocks  = total_blocks - free_blocks                  │   │
│  │     threshold    = total_blocks * (threshold_pct / 100)        │   │
│  │                                                                │   │
│  │  3. Check threshold:                                           │   │
│  │     if used_blocks > threshold {                               │   │
│  │         if counter < repeat_action {                           │   │
│  │             executeAction()                                    │   │
│  │             counter++                                          │   │
│  │         }                                                      │   │
│  │     } else {                                                   │   │
│  │         counter = 0  // Reset                                  │   │
│  │     }                                                          │   │
│  └────────────────────────────┬───────────────────────────────────┘   │
│                               │                                       │
│                               ▼                                       │
│                     ┌──────────────────┐                              │
│                     │  Execute Action  │                              │
│                     │   (Background)   │                              │
│                     └──────────────────┘                              │
└───────────────────────────────────────────────────────────────────────┘
```

## Component Interaction Sequence Diagram

```
User          main.go      disk_details.go    ebpf_loader.go    BPF Program    Kernel      notify.go    Action Script
 │                │                │                  │              │             │            │              │
 │  Run with      │                │                  │              │             │            │              │
 │  config file   │                │                  │              │             │            │              │
 │───────────────>│                │                  │              │             │            │              │
 │                │                │                  │              │             │            │              │
 │                │  Read config   │                  │              │             │            │              │
 │                │───────────────>│                  │              │             │            │              │
 │                │                │                  │              │             │            │              │
 │                │                │ Parse TOML       │              │             │            │              │
 │                │                │ Resolve symlinks │              │             │            │              │
 │                │                │ Get major/minor  │              │             │            │              │
 │                │                │ Find mountpoint  │              │             │            │              │
 │                │                │                  │              │             │            │              │
 │                │  Config + Dev  │                  │              │             │            │              │
 │                │<───────────────│                  │              │             │            │              │
 │                │                │                  │              │             │            │              │
 │                │  Load eBPF     │                  │              │             │            │              │
 │                │────────────────────────────────────>              │             │            │              │
 │                │                │                  │              │             │            │              │
 │                │                │                  │ Load BPF obj │             │            │              │
 │                │                │                  │─────────────────────────────>            │              │
 │                │                │                  │              │             │            │              │
 │                │                │                  │ Set map key  │             │            │              │
 │                │                │                  │ "monitor_disk" = dev_id    │            │              │
 │                │                │                  │─────────────>│             │            │              │
 │                │                │                  │              │             │            │              │
 │                │                │                  │ Attach tracepoints         │            │              │
 │                │                │                  │────────────────────────────>            │              │
 │                │                │                  │              │             │            │              │
 │                │                │                  │ Start perf reader          │            │              │
 │                │                │                  │                            │            │              │
 │                │                │                  │ ┌──────────────────────────┐            │              │
 │                │                │                  │ │ Event Loop (infinite)    │            │              │
 │                │                │                  │ └──────────────────────────┘            │              │
 │                │                │                  │              │             │            │              │
 │ User App       │                │                  │              │             │            │              │
 │ writes data    │                │                  │              │             │            │              │
 │────────────────────────────────────────────────────────────────────────────────>            │              │
 │                │                │                  │              │             │            │              │
 │                │                │                  │              │ Tracepoint  │            │              │
 │                │                │                  │              │  triggered  │            │              │
 │                │                │                  │              │<────────────│            │              │
 │                │                │                  │              │             │            │              │
 │                │                │                  │              │ Filter & process         │              │
 │                │                │                  │              │ Check device ID          │              │
 │                │                │                  │              │ Check if write           │              │
 │                │                │                  │              │ Extract process info     │              │
 │                │                │                  │              │             │            │              │
 │                │                │                  │ Event via    │             │            │              │
 │                │                │                  │ perf buffer  │             │            │              │
 │                │                │                  │<─────────────│             │            │              │
 │                │                │                  │              │             │            │              │
 │                │                │                  │ Parse event  │             │            │              │
 │                │                │                  │ Log details  │             │            │              │
 │                │                │                  │              │             │            │              │
 │                │                │                  │ Check disk usage           │            │              │
 │                │                │                  │────────────────────────────────────────>│              │
 │                │                │                  │              │             │            │              │
 │                │                │                  │              │             │  Statfs()  │              │
 │                │                │                  │              │             │<───────────│              │
 │                │                │                  │              │             │            │              │
 │                │                │                  │              │             │            │ Calculate    │
 │                │                │                  │              │             │            │ usage vs     │
 │                │                │                  │              │             │            │ threshold    │
 │                │                │                  │              │             │            │              │
 │                │                │                  │              │             │            │ If exceeded  │
 │                │                │                  │              │             │            │ & counter OK │
 │                │                │                  │              │             │            │              │
 │                │                │                  │              │             │            │ Run action   │
 │                │                │                  │              │             │            │─────────────>│
 │                │                │                  │              │             │            │              │
 │                │                │                  │              │             │            │              │ Execute
 │                │                │                  │              │             │            │              │ (notify,
 │                │                │                  │              │             │            │              │  extend,
 │                │                │                  │              │             │            │              │  cleanup)
 │                │                │                  │              │             │            │              │
 │                │                │                  │ (loop continues...)        │            │              │
 │                │                │                  │              │             │            │              │
```

## Data Structure Diagram

```
┌────────────────────────────────────────────────────────────────┐
│                    Configuration (TOML)                        │
│                                                                │
│  devicename          = "/dev/sda1"                             │
│  diskusage_threshold = 90                                      │
│  action              = "/usr/bin/notify.sh"                    │
│  repeat_action       = 1                                       │
└────────────────┬───────────────────────────────────────────────┘
                 │
                 │ Parsed by Viper
                 ▼
┌────────────────────────────────────────────────────────────────┐
│              ConfigData (Go Struct)                            │
│                                                                │
│  type ConfigData struct {                                      │
│      DeviceName         string  // "/dev/sda1"                 │
│      DiskUsageThreshold uint64  // 90                          │
│      Action             string  // "/usr/bin/notify.sh"        │
│      RepeatAction       uint64  // 1                           │
│  }                                                             │
└────────────────┬───────────────────────────────────────────────┘
                 │
                 │ Combined with device info
                 ▼
┌────────────────────────────────────────────────────────────────┐
│               Devinfo (Go Struct)                              │
│                                                                │
│  type Devinfo struct {                                         │
│      Devid      uint64  // (major << 20) | minor               │
│      MountPoint string  // "/mnt/data"                         │
│  }                                                             │
│                                                                │
│  Example:                                                      │
│    Device: /dev/sda1                                           │
│    Major: 8, Minor: 1                                          │
│    Devid: (8 << 20) | 1 = 8388609                             │
└────────────────┬───────────────────────────────────────────────┘
                 │
                 │ Stored in BPF map
                 ▼
┌────────────────────────────────────────────────────────────────┐
│          BPF Map: monitor_disk (Kernel Space)                  │
│                                                                │
│  Type: BPF_MAP_TYPE_HASH                                       │
│  Max Entries: 128                                              │
│                                                                │
│  ┌──────────────────┬──────────────────┐                       │
│  │      Key         │      Value       │                       │
│  ├──────────────────┼──────────────────┤                       │
│  │ "monitor_disk"   │   8388609        │                       │
│  │  (char[64])      │   (uint64)       │                       │
│  └──────────────────┴──────────────────┘                       │
└────────────────────────────────────────────────────────────────┘


┌────────────────────────────────────────────────────────────────┐
│            Event Data Structure (BPF → User)                   │
│                                                                │
│  BPF Side (C struct):                                          │
│  ┌──────────────────────────────────────────────────────────┐  │
│  │ struct data_t {                                          │  │
│  │     int   pid;           // Process ID                   │  │
│  │     int   uid;           // User ID                      │  │
│  │     u64   path;          // Device ID from event         │  │
│  │     u64   v;             // Target device ID from map    │  │
│  │     char  command[64];   // Process command name         │  │
│  │ };                                                       │  │
│  └──────────────────────────────────────────────────────────┘  │
│                             │                                  │
│                             │ Sent via perf buffer             │
│                             │ (binary serialized)              │
│                             ▼                                  │
│  User Side (Go struct):                                        │
│  ┌──────────────────────────────────────────────────────────┐  │
│  │ type data_t struct {                                     │  │
│  │     Pid     uint32       // Process ID                   │  │
│  │     Uid     uint32       // User ID                      │  │
│  │     Path    uint32       // Device ID from event         │  │
│  │     V       uint32       // Target device ID             │  │
│  │     Command [32]byte     // Process command name         │  │
│  │ }                                                        │  │
│  └──────────────────────────────────────────────────────────┘  │
│                                                                │
│  Example Event:                                                │
│    Pid:     1234                                               │
│    Uid:     1000                                               │
│    Path:    8388609                                            │
│    V:       8388609                                            │
│    Command: "dd"                                               │
└────────────────────────────────────────────────────────────────┘


┌────────────────────────────────────────────────────────────────┐
│             Disk Status Structure                              │
│                                                                │
│  type DiskStatus struct {                                      │
│      Blocks    uint64  // Total blocks                         │
│      Bavail    uint64  // Available blocks                     │
│      Bfree     uint64  // Free blocks                          │
│      Bused     uint64  // Used blocks (Blocks - Bfree)         │
│      Threshold uint64  // Threshold in blocks                  │
│  }                                                             │
│                                                                │
│  Example (4K block size):                                      │
│    Blocks:    25000000  (100GB total)                          │
│    Bfree:     2500000   (10GB free)                            │
│    Bused:     22500000  (90GB used)                            │
│    Bavail:    2375000   (9.5GB available to non-root)          │
│    Threshold: 22500000  (90% of 25000000)                      │
│                                                                │
│  Decision: Bused (22500000) >= Threshold (22500000)            │
│            → Execute action!                                   │
└────────────────────────────────────────────────────────────────┘
```

## File Organization

```
ebpf-diskalert/
│
├── src/
│   ├── main.go              ─┐
│   │                          │  Go Application
│   ├── ebpf_loader.go        │  (User Space)
│   ├── disk_details.go       │
│   ├── notify.go             │
│   ├── diskalert_bpfel.go   ─┘  (Generated by bpf2go)
│   │
│   └── bpf/
│       ├── diskalert.bpf.c  ──  eBPF C Program (Kernel Space)
│       └── vmlinux.h         ──  Kernel types (Generated)
│
├── config/
│   └── config.toml          ──  Configuration file
│
├── Makefile                 ──  Build system
├── go.mod                   ──  Go dependencies
├── go.sum                   ──  Dependency checksums
└── README.md                ──  Documentation
```

## Build Process Flow

```
┌─────────────┐
│  make build │
└──────┬──────┘
       │
       ▼
┌────────────────────────────────────────────────────────────┐
│  Step 1: Generate vmlinux.h                                │
│                                                            │
│  $ bpftool btf dump file /sys/kernel/btf/vmlinux           │
│             format c > src/bpf/vmlinux.h                   │
│                                                            │
│  Output: vmlinux.h (kernel type definitions)               │
└──────────────────────┬─────────────────────────────────────┘
                       │
                       ▼
┌────────────────────────────────────────────────────────────┐
│  Step 2: Generate Go code from BPF C code                  │
│                                                            │
│  $ go generate src/*.go                                    │
│                                                            │
│  This runs: go run github.com/cilium/ebpf/cmd/bpf2go       │
│             -target bpfel                                  │
│             -cc clang                                      │
│             diskalert                                      │
│             ./bpf/diskalert.bpf.c                          │
│             -- -I/usr/include/bpf -I.                      │
│                                                            │
│  Process:                                                  │
│  ┌──────────────────┐         ┌──────────────────┐         │
│  │ diskalert.bpf.c  │         │   vmlinux.h      │         │
│  └────────┬─────────┘         └────────┬─────────┘         │
│           │                            │                   │
│           └──────────┬─────────────────┘                   │
│                      │                                     │
│                      ▼                                     │
│            ┌─────────────────┐                             │
│            │  clang compiler │                             │
│            └────────┬────────┘                             │
│                     │                                      │
│                     ▼                                      │
│            ┌──────────────────┐                            │
│            │  BPF bytecode    │                            │
│            │  (embedded in    │                            │
│            │   Go code)       │                            │
│            └────────┬─────────┘                            │
│                     │                                      │
│                     ▼                                      │
│  Output:                                                   │
│  - diskalert_bpfel.go (generated Go code)                  │
│  - diskalert_bpfel.o  (compiled BPF object - embedded)     │
│                                                            │
└──────────────────────┬─────────────────────────────────────┘
                       │
                       ▼
┌────────────────────────────────────────────────────────────┐
│  Step 3: Compile Go application                            │
│                                                            │
│  $ CGO_ENABLED=0 go build -o ebpf-diskalert src/*.go      │
│                                                            │
│  Input files:                                              │
│  - main.go                                                 │
│  - ebpf_loader.go                                          │
│  - disk_details.go                                         │
│  - notify.go                                               │
│  - diskalert_bpfel.go (generated)                          │
│                                                            │
│  Output: ebpf-diskalert (static binary)                    │
└──────────────────────┬─────────────────────────────────────┘
                       │
                       ▼
              ┌────────────────┐
              │  ebpf-diskalert│
              │  (executable)  │
              └────────────────┘
```

---

**Document Version**: 1.0
**Last Updated**: 2025-11-18
