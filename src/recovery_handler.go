package main

import (
	"fmt"
	"io"
	"io/ioutil"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"
)

// FdInfo holds information about an open file descriptor
type FdInfo struct {
	Pid      uint32
	Fd       uint32
	FilePath string
	Inode    uint64
	Dev      uint32
}

// recoverFileFromFd recovers a deleted file using an open file descriptor
func recoverFileFromFd(pid, fd uint32, inode uint64, originalPath string,
                       size uint64, config *RecoveryConfig) error {
	// Construct /proc path to the file descriptor
	procFdPath := fmt.Sprintf("/proc/%d/fd/%d", pid, fd)

	// Verify the fd still exists
	if _, err := os.Lstat(procFdPath); err != nil {
		return fmt.Errorf("fd no longer exists: %w", err)
	}

	// Generate recovery filename
	timestamp := time.Now().Unix()
	basename := filepath.Base(originalPath)
	if basename == "" || basename == "." {
		basename = fmt.Sprintf("unnamed_%d", inode)
	}

	recoveryFilename := fmt.Sprintf("%d_%s_inode%d", timestamp, basename, inode)
	recoveryPath := filepath.Join(config.RecoveryDir, recoveryFilename)

	// Open source file via /proc
	srcFile, err := os.Open(procFdPath)
	if err != nil {
		return fmt.Errorf("failed to open proc fd: %w", err)
	}
	defer srcFile.Close()

	// Create destination file
	dstFile, err := os.Create(recoveryPath)
	if err != nil {
		return fmt.Errorf("failed to create recovery file: %w", err)
	}
	defer dstFile.Close()

	// Copy file contents
	bytesWritten, err := io.Copy(dstFile, srcFile)
	if err != nil {
		// Clean up partial file
		os.Remove(recoveryPath)
		return fmt.Errorf("failed to copy file: %w", err)
	}

	// Sync to disk
	if err := dstFile.Sync(); err != nil {
		return fmt.Errorf("failed to sync file: %w", err)
	}

	config.Logger.Printf("    Recovered %d bytes to: %s", bytesWritten, recoveryPath)

	// Create metadata file with recovery information
	if err := writeRecoveryMetadata(recoveryPath, originalPath, pid, fd,
	                                 inode, bytesWritten); err != nil {
		config.Logger.Printf("    Warning: failed to write metadata: %v", err)
	}

	return nil
}

// writeRecoveryMetadata creates a .meta file with recovery information
func writeRecoveryMetadata(recoveryPath, originalPath string,
                           pid, fd uint32, inode uint64, size int64) error {
	metaPath := recoveryPath + ".meta"
	metaContent := fmt.Sprintf(`Recovery Metadata
================
Original Path: %s
Recovered At: %s
Inode: %d
Process ID: %d
File Descriptor: %d
File Size: %d bytes
Recovery Path: %s
`,
		originalPath,
		time.Now().Format(time.RFC3339),
		inode,
		pid,
		fd,
		size,
		recoveryPath,
	)

	return ioutil.WriteFile(metaPath, []byte(metaContent), 0644)
}

// findOpenFds scans /proc to find all open file descriptors for a given file
// This is useful when we don't have fd tracking data from eBPF
func findOpenFds(targetPath string) ([]FdInfo, error) {
	var result []FdInfo

	// Get all process directories
	procDirs, err := filepath.Glob("/proc/[0-9]*")
	if err != nil {
		return nil, fmt.Errorf("failed to glob /proc: %w", err)
	}

	for _, procDir := range procDirs {
		// Extract PID
		pidStr := filepath.Base(procDir)
		pid, err := strconv.ParseUint(pidStr, 10, 32)
		if err != nil {
			continue
		}

		// Check fd directory
		fdDir := filepath.Join(procDir, "fd")
		fds, err := ioutil.ReadDir(fdDir)
		if err != nil {
			// Process might have exited or we don't have permission
			continue
		}

		for _, fdEntry := range fds {
			fdPath := filepath.Join(fdDir, fdEntry.Name())

			// Read symlink
			linkTarget, err := os.Readlink(fdPath)
			if err != nil {
				continue
			}

			// Check if it matches our target
			// Handle both regular paths and "path (deleted)" format
			if linkTarget == targetPath ||
			   strings.HasPrefix(linkTarget, targetPath+" (deleted)") {
				fdNum, err := strconv.ParseUint(fdEntry.Name(), 10, 32)
				if err != nil {
					continue
				}

				// Get inode info
				var stat syscall.Stat_t
				if err := syscall.Fstat(int(fdNum), &stat); err == nil {
					result = append(result, FdInfo{
						Pid:      uint32(pid),
						Fd:       uint32(fdNum),
						FilePath: linkTarget,
						Inode:    stat.Ino,
						Dev:      uint32(stat.Dev),
					})
				}
			}
		}
	}

	return result, nil
}

// findOpenFdsByInode finds open file descriptors by inode number
func findOpenFdsByInode(targetInode uint64, targetDev uint32) ([]FdInfo, error) {
	var result []FdInfo

	// Get all process directories
	procDirs, err := filepath.Glob("/proc/[0-9]*")
	if err != nil {
		return nil, fmt.Errorf("failed to glob /proc: %w", err)
	}

	for _, procDir := range procDirs {
		// Extract PID
		pidStr := filepath.Base(procDir)
		pid, err := strconv.ParseUint(pidStr, 10, 32)
		if err != nil {
			continue
		}

		// Check fd directory
		fdDir := filepath.Join(procDir, "fd")
		fds, err := ioutil.ReadDir(fdDir)
		if err != nil {
			continue
		}

		for _, fdEntry := range fds {
			fdPath := filepath.Join(fdDir, fdEntry.Name())
			fdNum, err := strconv.ParseUint(fdEntry.Name(), 10, 32)
			if err != nil {
				continue
			}

			// Get file info via stat
			var stat syscall.Stat_t
			if err := syscall.Stat(fdPath, &stat); err != nil {
				continue
			}

			// Check if inode matches
			if stat.Ino == targetInode && uint32(stat.Dev) == targetDev {
				linkTarget, _ := os.Readlink(fdPath)
				result = append(result, FdInfo{
					Pid:      uint32(pid),
					Fd:       uint32(fdNum),
					FilePath: linkTarget,
					Inode:    stat.Ino,
					Dev:      uint32(stat.Dev),
				})
			}
		}
	}

	return result, nil
}

// recoverFileByPath attempts to recover a file by path using /proc fd scanning
// This is a fallback when eBPF tracking doesn't have the info
func recoverFileByPath(filePath string, config *RecoveryConfig) error {
	config.Logger.Printf("[RECOVERY] Attempting to recover: %s", filePath)

	// Find open fds for this file
	fds, err := findOpenFds(filePath)
	if err != nil {
		return fmt.Errorf("failed to scan for open fds: %w", err)
	}

	if len(fds) == 0 {
		return fmt.Errorf("no open file descriptors found for %s", filePath)
	}

	config.Logger.Printf("  Found %d open file descriptor(s)", len(fds))

	// Use the first available fd to recover
	fd := fds[0]
	procFdPath := fmt.Sprintf("/proc/%d/fd/%d", fd.Pid, fd.Fd)

	// Get file size
	info, err := os.Stat(procFdPath)
	if err != nil {
		return fmt.Errorf("failed to stat fd: %w", err)
	}

	return recoverFileFromFd(fd.Pid, fd.Fd, fd.Inode, filePath,
	                         uint64(info.Size()), config)
}

// cleanupOldRecoveries removes recovery files older than specified duration
func cleanupOldRecoveries(config *RecoveryConfig, maxAge time.Duration) error {
	entries, err := ioutil.ReadDir(config.RecoveryDir)
	if err != nil {
		return fmt.Errorf("failed to read recovery dir: %w", err)
	}

	now := time.Now()
	cleaned := 0

	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}

		// Check file age
		if now.Sub(entry.ModTime()) > maxAge {
			filePath := filepath.Join(config.RecoveryDir, entry.Name())
			if err := os.Remove(filePath); err != nil {
				config.Logger.Printf("Failed to remove old recovery file %s: %v",
					filePath, err)
			} else {
				cleaned++
			}
		}
	}

	if cleaned > 0 {
		config.Logger.Printf("Cleaned up %d old recovery files", cleaned)
	}

	return nil
}

// RecoveryManagerDaemon runs periodic cleanup tasks
func RecoveryManagerDaemon(config *RecoveryConfig, cleanupInterval time.Duration) {
	ticker := time.NewTicker(cleanupInterval)
	defer ticker.Stop()

	for range ticker.C {
		// Clean up files older than 7 days
		if err := cleanupOldRecoveries(config, 7*24*time.Hour); err != nil {
			config.Logger.Printf("Cleanup error: %v", err)
		}
	}
}
