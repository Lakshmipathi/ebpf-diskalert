package main

import (
	"math"
	"os"
	"os/exec"
	"strings"
	"syscall"
)

// Run action binary in background and log the results
func runInBackground(action string, logFile string) error {
	parts := strings.Fields(action)
	cmd := exec.Command(parts[0], parts[1:]...)

	outFile, err := os.Create(logFile)
	if err != nil {
		return err
	}
	defer outFile.Close()

	cmd.Stdout = outFile
	err = cmd.Start()
	if err != nil {
		return err
	}
	return nil
}

type DiskStatus struct {
	Blocks    uint64 `json:"blocks"`
	Bavail    uint64 `json:"avail"`
	Bfree     uint64 `json:"free"`
	Bused     uint64 `json:"used"`
	Threshold uint64 `json:"threshold"`
}

func DiskUsage(path string, DiskUsageThreshold uint64) (disk DiskStatus) {
	fs := syscall.Statfs_t{}
	err := syscall.Statfs(path, &fs)
	if err != nil {
		return
	}
	// df --block-size=4K /mnt_pt
	//fmt.println(fs.Blocks, fs.Bavail, fs.Bfree, fs.Bsize)
	max_threshold := float64(DiskUsageThreshold) / 100.0
	var threshold uint64 = uint64(math.Round(float64(fs.Blocks) * max_threshold))
	disk.Blocks = fs.Blocks
	disk.Bavail = fs.Bavail
	disk.Bfree = fs.Bfree
	disk.Bused = fs.Blocks - fs.Bfree
	disk.Threshold = threshold
	return
}

func checkDiskUSage(ci *ConfigData, di *Devinfo) {
	var err error

	disk := DiskUsage(di.MountPoint, cf.DiskUsageThreshold)
	//fmt.Println("TotalBlocks:", disk.Blocks, "FreeBlocks:", disk.Bfree, "UsedBlocks:", disk.Bused, "Threshold:", disk.Threshold)

	if disk.Bused > disk.Threshold {
		logger.Println("Threshold breached Perform action:", cf.Action)
		if cf.RepeatAction > disknofity_counter {
			err = runInBackground(cf.Action, APPLOG_PATH)
			if err != nil {
				logger.Printf("Error runInBackground: %v\n", err)
				return
			} else {
				logger.Printf("Started background process: %s\n", cf.Action)
			}
			disknofity_counter += 1
		} else {
			logger.Println("Already nofitication completed for ", cf.RepeatAction, "times. Stopped further nofitication.")
		}
	} else {
		disknofity_counter = 0 // reset the counter
	}
}
