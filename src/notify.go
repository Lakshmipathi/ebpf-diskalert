package main

import (
	"bytes"
	"fmt"
	"math"
	"net/http"
	"os"
	"os/exec"
	"strings"
	"syscall"
	"time"
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

// Send alert to Slack via webhook
func sendSlackAlert(webhookURL string, device string, usedPct float64) error {
	hostname, _ := os.Hostname()
	payload := fmt.Sprintf(`{"text":"🚨 *Disk Alert* on %s\nDevice: %s\nUsage: %.1f%% (threshold breached)\nTime: %s"}`,
		hostname, device, usedPct, time.Now().Format("2006-01-02 15:04:05"))

	resp, err := http.Post(webhookURL, "application/json", bytes.NewBufferString(payload))
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	return nil
}

// Send alert to a generic webhook (POST with JSON)
func sendWebhookAlert(webhookURL string, device string, usedPct float64) error {
	hostname, _ := os.Hostname()
	payload := fmt.Sprintf(`{"hostname":"%s","device":"%s","usage_pct":%.1f,"threshold":%d,"timestamp":"%s"}`,
		hostname, device, usedPct, cf.DiskUsageThreshold, time.Now().Format(time.RFC3339))

	resp, err := http.Post(webhookURL, "application/json", bytes.NewBufferString(payload))
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	return nil
}

func checkDiskUSage(ci *ConfigData, di *Devinfo) {
	var err error

	disk := DiskUsage(di.MountPoint, cf.DiskUsageThreshold)
	//fmt.Println("TotalBlocks:", disk.Blocks, "FreeBlocks:", disk.Bfree, "UsedBlocks:", disk.Bused, "Threshold:", disk.Threshold)

	if disk.Bused > disk.Threshold {
		usedPct := float64(disk.Bused) / float64(disk.Blocks) * 100.0
		logger.Println("Threshold breached Perform action:", cf.Action)
		if cf.RepeatAction > disknofity_counter {
			// Run action script (existing behavior)
			if cf.Action != "" {
				err = runInBackground(cf.Action, APPLOG_PATH)
				if err != nil {
					logger.Printf("Error runInBackground: %v\n", err)
				} else {
					logger.Printf("Started background process: %s\n", cf.Action)
				}
			}

			// Send Slack notification
			if cf.SlackWebhook != "" {
				err = sendSlackAlert(cf.SlackWebhook, cf.DeviceName, usedPct)
				if err != nil {
					logger.Printf("Error sending Slack alert: %v\n", err)
				} else {
					logger.Println("Slack alert sent successfully")
				}
			}

			// Send generic webhook notification
			if cf.Webhook != "" {
				err = sendWebhookAlert(cf.Webhook, cf.DeviceName, usedPct)
				if err != nil {
					logger.Printf("Error sending webhook alert: %v\n", err)
				} else {
					logger.Println("Webhook alert sent successfully")
				}
			}

			disknofity_counter += 1
		} else {
			logger.Println("Already nofitication completed for ", cf.RepeatAction, "times. Stopped further nofitication.")
		}
	} else {
		disknofity_counter = 0 // reset the counter
	}
}
