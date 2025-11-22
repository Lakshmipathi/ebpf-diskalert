package main

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -target bpfel -cc clang recovery ./bpf/recovery.bpf.c -- -I/usr/include/bpf -I.

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"log"
	"os"
	"sync"
	"time"

	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/perf"
	"golang.org/x/sys/unix"
)

const (
	CONFIG_ENABLED       = 0
	CONFIG_MIN_FILE_SIZE = 1
)

// RecoveryEvent - corresponds to recovery_event_t in eBPF
type RecoveryEvent struct {
	Pid        uint32
	PidWithFd  uint32
	FdNumber   uint32
	Inode      uint64
	Dev        uint32
	FileSize   uint64
	Filename   [256]byte
	Comm       [16]byte
}

// FdTrackEvent - corresponds to fd_track_event_t in eBPF
type FdTrackEvent struct {
	Pid       uint32
	Fd        uint32
	Inode     uint64
	Dev       uint32
	Size      uint64
	EventType uint8
	Filename  [256]byte
	Comm      [16]byte
}

// RecoveryConfig holds configuration for file recovery
type RecoveryConfig struct {
	Enabled       bool
	MinFileSize   uint64
	RecoveryDir   string
	MaxRecoveries uint64
	Logger        *log.Logger
}

// RecoveryStats holds statistics
type RecoveryStats struct {
	FilesTracked    uint64
	FilesDeleted    uint64
	FilesRecovered  uint64
	RecoveryFailed  uint64
	TotalBytesRecovered uint64
	mu              sync.RWMutex
}

func (rs *RecoveryStats) IncrementTracked() {
	rs.mu.Lock()
	defer rs.mu.Unlock()
	rs.FilesTracked++
}

func (rs *RecoveryStats) IncrementDeleted() {
	rs.mu.Lock()
	defer rs.mu.Unlock()
	rs.FilesDeleted++
}

func (rs *RecoveryStats) IncrementRecovered(bytes uint64) {
	rs.mu.Lock()
	defer rs.mu.Unlock()
	rs.FilesRecovered++
	rs.TotalBytesRecovered += bytes
}

func (rs *RecoveryStats) IncrementFailed() {
	rs.mu.Lock()
	defer rs.mu.Unlock()
	rs.RecoveryFailed++
}

func (rs *RecoveryStats) GetStats() (uint64, uint64, uint64, uint64, uint64) {
	rs.mu.RLock()
	defer rs.mu.RUnlock()
	return rs.FilesTracked, rs.FilesDeleted, rs.FilesRecovered,
	       rs.RecoveryFailed, rs.TotalBytesRecovered
}

// Global recovery stats
var recoveryStats RecoveryStats

// setRecoveryRlimit sets the memory limit for eBPF operations
func setRecoveryRlimit() error {
	return unix.Setrlimit(unix.RLIMIT_MEMLOCK,
		&unix.Rlimit{
			Cur: unix.RLIM_INFINITY,
			Max: unix.RLIM_INFINITY,
		})
}

// RecoveryLoader manages the recovery eBPF program lifecycle
func RecoveryLoader(config *RecoveryConfig) error {
	if !config.Enabled {
		config.Logger.Println("File recovery is disabled")
		return nil
	}

	// Set memory limits
	if err := setRecoveryRlimit(); err != nil {
		return fmt.Errorf("failed to set rlimit: %w", err)
	}

	// Ensure recovery directory exists
	if err := os.MkdirAll(config.RecoveryDir, 0755); err != nil {
		return fmt.Errorf("failed to create recovery directory: %w", err)
	}

	config.Logger.Printf("Loading recovery eBPF program...")

	// Load eBPF objects
	objs := recoveryObjects{}
	if err := loadRecoveryObjects(&objs, nil); err != nil {
		return fmt.Errorf("failed to load recovery eBPF objects: %w", err)
	}
	defer objs.Close()

	config.Logger.Printf("Recovery eBPF objects loaded successfully")

	// Configure eBPF program via config map
	enabledKey := uint32(CONFIG_ENABLED)
	enabledVal := uint64(1) // 1 = enabled
	if err := objs.ConfigMap.Put(enabledKey, enabledVal); err != nil {
		return fmt.Errorf("failed to set enabled config: %w", err)
	}

	minSizeKey := uint32(CONFIG_MIN_FILE_SIZE)
	minSizeVal := config.MinFileSize
	if err := objs.ConfigMap.Put(minSizeKey, minSizeVal); err != nil {
		return fmt.Errorf("failed to set min file size config: %w", err)
	}

	config.Logger.Printf("Recovery config: enabled=%v, min_file_size=%d bytes",
		config.Enabled, config.MinFileSize)

	// Attach tracepoints for openat
	tpOpenat, err := link.Tracepoint("syscalls", "sys_exit_openat",
	                                  objs.TraceOpenatExit, nil)
	if err != nil {
		return fmt.Errorf("failed to attach openat tracepoint: %w", err)
	}
	defer tpOpenat.Close()
	config.Logger.Printf("Attached to sys_exit_openat tracepoint")

	// Attach tracepoints for close
	tpClose, err := link.Tracepoint("syscalls", "sys_enter_close",
	                                 objs.TraceCloseEntry, nil)
	if err != nil {
		return fmt.Errorf("failed to attach close tracepoint: %w", err)
	}
	defer tpClose.Close()
	config.Logger.Printf("Attached to sys_enter_close tracepoint")

	// Attach kprobe for vfs_unlink (more reliable than unlinkat syscall)
	kpUnlink, err := link.Kprobe("vfs_unlink", objs.KprobeVfsUnlink, nil)
	if err != nil {
		// Try fallback to unlinkat tracepoint if kprobe fails
		config.Logger.Printf("Warning: failed to attach vfs_unlink kprobe: %v", err)
		config.Logger.Printf("Falling back to sys_enter_unlinkat tracepoint")

		tpUnlinkat, err := link.Tracepoint("syscalls", "sys_enter_unlinkat",
		                                    objs.TraceUnlinkatEntry, nil)
		if err != nil {
			return fmt.Errorf("failed to attach unlinkat tracepoint: %w", err)
		}
		defer tpUnlinkat.Close()
		config.Logger.Printf("Attached to sys_enter_unlinkat tracepoint")
	} else {
		defer kpUnlink.Close()
		config.Logger.Printf("Attached to vfs_unlink kprobe")
	}

	// Create perf readers for events
	recoveryReader, err := perf.NewReader(objs.RecoveryEvents, os.Getpagesize()*4)
	if err != nil {
		return fmt.Errorf("failed to create recovery event reader: %w", err)
	}
	defer recoveryReader.Close()

	trackingReader, err := perf.NewReader(objs.TrackingEvents, os.Getpagesize()*4)
	if err != nil {
		return fmt.Errorf("failed to create tracking event reader: %w", err)
	}
	defer trackingReader.Close()

	config.Logger.Printf("✓ Recovery system active - monitoring file operations")
	config.Logger.Printf("  Recovery directory: %s", config.RecoveryDir)
	config.Logger.Printf("  Minimum file size: %d bytes", config.MinFileSize)

	// Start goroutine to handle tracking events (optional, for debugging)
	var wg sync.WaitGroup
	wg.Add(2)

	// Handle tracking events
	go func() {
		defer wg.Done()
		handleTrackingEvents(trackingReader, config)
	}()

	// Handle recovery events (main event loop)
	go func() {
		defer wg.Done()
		handleRecoveryEvents(recoveryReader, config)
	}()

	// Print stats periodically
	go func() {
		ticker := time.NewTicker(60 * time.Second)
		defer ticker.Stop()
		for range ticker.C {
			tracked, deleted, recovered, failed, totalBytes := recoveryStats.GetStats()
			config.Logger.Printf("Recovery Stats: tracked=%d, deleted=%d, recovered=%d, failed=%d, bytes=%d",
				tracked, deleted, recovered, failed, totalBytes)
		}
	}()

	wg.Wait()
	return nil
}

// handleTrackingEvents processes file open/close tracking events
func handleTrackingEvents(reader *perf.Reader, config *RecoveryConfig) {
	for {
		record, err := reader.Read()
		if err != nil {
			if perf.IsClosed(err) {
				return
			}
			config.Logger.Printf("Error reading tracking event: %v", err)
			continue
		}

		if record.LostSamples != 0 {
			config.Logger.Printf("Warning: lost %d tracking events", record.LostSamples)
			continue
		}

		var event FdTrackEvent
		if err := binary.Read(bytes.NewBuffer(record.RawSample),
		                      binary.LittleEndian, &event); err != nil {
			config.Logger.Printf("Error parsing tracking event: %v", err)
			continue
		}

		// Process tracking event (optional logging)
		eventType := "OPEN"
		if event.EventType == 1 {
			eventType = "CLOSE"
		} else {
			recoveryStats.IncrementTracked()
		}

		// Only log if size is significant (reduce noise)
		if event.Size > config.MinFileSize {
			config.Logger.Printf("[TRACK] %s: pid=%d fd=%d inode=%d size=%d comm=%s",
				eventType, event.Pid, event.Fd, event.Inode, event.Size,
				nullTerminatedString(event.Comm[:]))
		}
	}
}

// handleRecoveryEvents processes file deletion events and performs recovery
func handleRecoveryEvents(reader *perf.Reader, config *RecoveryConfig) {
	for {
		record, err := reader.Read()
		if err != nil {
			if perf.IsClosed(err) {
				return
			}
			config.Logger.Printf("Error reading recovery event: %v", err)
			continue
		}

		if record.LostSamples != 0 {
			config.Logger.Printf("Warning: lost %d recovery events", record.LostSamples)
			continue
		}

		var event RecoveryEvent
		if err := binary.Read(bytes.NewBuffer(record.RawSample),
		                      binary.LittleEndian, &event); err != nil {
			config.Logger.Printf("Error parsing recovery event: %v", err)
			continue
		}

		// Process recovery event
		recoveryStats.IncrementDeleted()

		filename := nullTerminatedString(event.Filename[:])
		comm := nullTerminatedString(event.Comm[:])

		config.Logger.Printf("[DELETION DETECTED] file=%s inode=%d size=%d deleted_by=%s (pid=%d)",
			filename, event.Inode, event.FileSize, comm, event.Pid)

		// If we have an open fd, attempt recovery
		if event.PidWithFd > 0 && event.FdNumber > 0 {
			config.Logger.Printf("  → File is open: pid=%d fd=%d - attempting recovery",
				event.PidWithFd, event.FdNumber)

			if err := recoverFileFromFd(event.PidWithFd, event.FdNumber,
			                            event.Inode, filename, event.FileSize,
			                            config); err != nil {
				config.Logger.Printf("  ✗ Recovery failed: %v", err)
				recoveryStats.IncrementFailed()
			} else {
				config.Logger.Printf("  ✓ Recovery successful")
				recoveryStats.IncrementRecovered(event.FileSize)
			}
		} else {
			config.Logger.Printf("  → No open file descriptor found - cannot recover")
			recoveryStats.IncrementFailed()
		}
	}
}

// Helper function to convert null-terminated byte array to string
func nullTerminatedString(b []byte) string {
	n := bytes.IndexByte(b, 0)
	if n == -1 {
		n = len(b)
	}
	return string(b[:n])
}
