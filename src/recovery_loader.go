package main

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -target amd64 -cc clang recovery ./bpf/recovery.bpf.c -- -I/usr/include/bpf -I.

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"log"
	"os"
	"path/filepath"
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
	_          [4]byte // Padding for alignment before Inode
	Inode      uint64
	Dev        uint32
	_          [4]byte // Padding for alignment before FileSize
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
	_         [4]byte // Padding for alignment before Size
	Size      uint64
	EventType uint8
	_         [3]byte // Padding after EventType
	Filename  [256]byte
	Comm      [16]byte
}

// ShadowFD holds information about a shadow file descriptor we're keeping open
type ShadowFD struct {
	Fd        int
	Path      string
	Inode     uint64
	Dev       uint32
	Size      uint64
	OpenedAt  time.Time
}

// RecoveryConfig holds configuration for file recovery
type RecoveryConfig struct {
	Enabled          bool
	MinFileSize      uint64
	RecoveryDir      string
	MaxRecoveries    uint64
	Logger           *log.Logger
	// Shadow FD configuration
	ShadowFDEnabled  bool
	MaxShadowFDs     int
	MaxShadowSize    uint64
	ShadowFDTimeout  time.Duration
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

// Global shadow FD tracking
var (
	shadowFDs   = make(map[string]*ShadowFD) // key: "inode:dev"
	shadowFDsMu sync.RWMutex
)

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

	// Attach tracepoint for openat entry (to capture pathname)
	tpOpenatEnter, err := link.Tracepoint("syscalls", "sys_enter_openat",
	                                       objs.TraceOpenatEnter, nil)
	if err != nil {
		return fmt.Errorf("failed to attach sys_enter_openat tracepoint: %w", err)
	}
	defer tpOpenatEnter.Close()
	config.Logger.Printf("Attached to sys_enter_openat tracepoint")

	// Attach tracepoint for openat exit (to track fd)
	tpOpenatExit, err := link.Tracepoint("syscalls", "sys_exit_openat",
	                                      objs.TraceOpenatExit, nil)
	if err != nil {
		return fmt.Errorf("failed to attach sys_exit_openat tracepoint: %w", err)
	}
	defer tpOpenatExit.Close()
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

	// Cleanup old shadow FDs periodically
	if config.ShadowFDEnabled && config.ShadowFDTimeout > 0 {
		go func() {
			ticker := time.NewTicker(30 * time.Second)
			defer ticker.Stop()
			for range ticker.C {
				cleanupTimedOutShadowFDs(config)
			}
		}()
	}

	wg.Wait()
	return nil
}

// handleShadowFDOpen opens a shadow FD for the file
func handleShadowFDOpen(event *FdTrackEvent, config *RecoveryConfig) {
	// Apply filters
	if event.Size < config.MinFileSize {
		return
	}
	if config.MaxShadowSize > 0 && event.Size > config.MaxShadowSize {
		return // File too large for shadow FD
	}

	// Get pathname
	path := nullTerminatedString(event.Filename[:])
	if path == "" {
		config.Logger.Printf("[SHADOW] DEBUG: path empty for inode=%d, size=%d", event.Inode, event.Size)
		return // No path available
	}

	// Handle relative paths by resolving via /proc/pid/cwd
	fullPath := path
	if path[0] != '/' {
		// Relative path - resolve by reading process's cwd and joining with filename
		cwdLinkPath := fmt.Sprintf("/proc/%d/cwd", event.Pid)
		if cwd, err := os.Readlink(cwdLinkPath); err == nil {
			fullPath = filepath.Join(cwd, path)
			config.Logger.Printf("[SHADOW] DEBUG: Resolved relative path %s (cwd=%s) -> %s", path, cwd, fullPath)
		} else {
			config.Logger.Printf("[SHADOW] DEBUG: Failed to read cwd for pid %d: %v", event.Pid, err)
			return // Can't resolve path
		}
	} else {
		config.Logger.Printf("[SHADOW] DEBUG: Attempting to shadow: %s (inode=%d, size=%d)", path, event.Inode, event.Size)
	}

	// Check if we're at the limit
	shadowFDsMu.Lock()
	if len(shadowFDs) >= config.MaxShadowFDs {
		// At limit - remove oldest shadow FD
		cleanupOldestShadowFD()
	}

	// Create key
	key := fmt.Sprintf("%d:%d", event.Inode, event.Dev)

	// Check if we already have this file
	if _, exists := shadowFDs[key]; exists {
		shadowFDsMu.Unlock()
		return // Already tracking
	}
	shadowFDsMu.Unlock()

	// Try to open the file using the resolved path
	fd, err := unix.Open(fullPath, unix.O_RDONLY|unix.O_NOFOLLOW, 0)
	if err != nil {
		// File might already be deleted or we don't have permission
		config.Logger.Printf("[SHADOW] DEBUG: Failed to open %s: %v", fullPath, err)
		return
	}

	// Store shadow FD
	shadow := &ShadowFD{
		Fd:       fd,
		Path:     fullPath,
		Inode:    event.Inode,
		Dev:      event.Dev,
		Size:     event.Size,
		OpenedAt: time.Now(),
	}

	shadowFDsMu.Lock()
	shadowFDs[key] = shadow
	shadowFDsMu.Unlock()

	config.Logger.Printf("[SHADOW] Opened: %s (inode=%d, fd=%d, size=%d bytes)",
		path, event.Inode, fd, event.Size)
}

// cleanupOldestShadowFD removes the oldest shadow FD (must be called with lock held)
func cleanupOldestShadowFD() {
	var oldestKey string
	var oldestTime time.Time

	for key, shadow := range shadowFDs {
		if oldestKey == "" || shadow.OpenedAt.Before(oldestTime) {
			oldestKey = key
			oldestTime = shadow.OpenedAt
		}
	}

	if oldestKey != "" {
		if shadow, exists := shadowFDs[oldestKey]; exists {
			unix.Close(shadow.Fd)
			delete(shadowFDs, oldestKey)
		}
	}
}

// cleanupTimedOutShadowFDs removes shadow FDs that have exceeded the timeout
func cleanupTimedOutShadowFDs(config *RecoveryConfig) {
	now := time.Now()
	var toRemove []string

	shadowFDsMu.RLock()
	for key, shadow := range shadowFDs {
		if now.Sub(shadow.OpenedAt) > config.ShadowFDTimeout {
			toRemove = append(toRemove, key)
		}
	}
	shadowFDsMu.RUnlock()

	if len(toRemove) > 0 {
		shadowFDsMu.Lock()
		for _, key := range toRemove {
			if shadow, exists := shadowFDs[key]; exists {
				unix.Close(shadow.Fd)
				delete(shadowFDs, key)
				config.Logger.Printf("[SHADOW] Timeout closed: %s (held for %v)",
					shadow.Path, now.Sub(shadow.OpenedAt))
			}
		}
		shadowFDsMu.Unlock()
	}
}

// handleTrackingEvents processes file open/close tracking events
func handleTrackingEvents(reader *perf.Reader, config *RecoveryConfig) {
	for {
		record, err := reader.Read()
		if err != nil {
			if errors.Is(err, perf.ErrClosed) {
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

		// Process tracking event
		if event.EventType == 0 {
			// File OPEN event
			recoveryStats.IncrementTracked()

			// Try to open shadow FD if enabled
			if config.ShadowFDEnabled {
				handleShadowFDOpen(&event, config)
			}

			// Only log if size is significant (reduce noise)
			if event.Size > config.MinFileSize {
				config.Logger.Printf("[TRACK] OPEN: pid=%d fd=%d inode=%d size=%d comm=%s",
					event.Pid, event.Fd, event.Inode, event.Size,
					nullTerminatedString(event.Comm[:]))
			}
		} else {
			// File CLOSE event - could remove shadow FD here if desired
			if event.Size > config.MinFileSize {
				config.Logger.Printf("[TRACK] CLOSE: pid=%d fd=%d inode=%d size=%d comm=%s",
					event.Pid, event.Fd, event.Inode, event.Size,
					nullTerminatedString(event.Comm[:]))
			}
		}
	}
}

// handleRecoveryEvents processes file deletion events and performs recovery
func handleRecoveryEvents(reader *perf.Reader, config *RecoveryConfig) {
	for {
		record, err := reader.Read()
		if err != nil {
			if errors.Is(err, perf.ErrClosed) {
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

		// First, check if we have a shadow FD for this file
		key := fmt.Sprintf("%d:%d", event.Inode, event.Dev)
		shadowFDsMu.RLock()
		shadow, hasShadow := shadowFDs[key]
		shadowFDsMu.RUnlock()

		if hasShadow {
			// We have a shadow FD! Use it for recovery
			config.Logger.Printf("  → Using shadow FD: fd=%d - attempting recovery", shadow.Fd)

			if err := recoverFileFromFdDirect(shadow.Fd, shadow.Path,
			                                   event.Inode, event.FileSize,
			                                   config); err != nil {
				config.Logger.Printf("  ✗ Recovery from shadow FD failed: %v", err)
				recoveryStats.IncrementFailed()
			} else {
				config.Logger.Printf("  ✓ Recovery successful (via shadow FD)")
				recoveryStats.IncrementRecovered(event.FileSize)
			}

			// Close and remove the shadow FD after recovery attempt
			shadowFDsMu.Lock()
			unix.Close(shadow.Fd)
			delete(shadowFDs, key)
			shadowFDsMu.Unlock()
		} else if event.PidWithFd > 0 && event.FdNumber > 0 {
			// Fallback: check if another process has it open
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
