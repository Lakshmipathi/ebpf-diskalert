package main

import (
	"bufio"
	"fmt"
	"io"
	"log"
	"os"
	"strings"

	"github.com/spf13/viper"
)

func setupLog(logFilePath string) (*log.Logger, *os.File, error) {
	logFile, err := os.OpenFile(logFilePath, os.O_WRONLY|os.O_CREATE|os.O_APPEND, 0666)
	if err != nil {
		return nil, nil, err
	}

	logMulti := io.MultiWriter(os.Stdout, logFile)
	logger := log.New(logMulti, "", log.LstdFlags)
	return logger, logFile, nil
}

func isSymlink(path string) (bool, string, error) {
	// Stat the file to get information about it
	fileInfo, err := os.Lstat(path)
	if err != nil {
		log.Fatal("Lstat Error:", err)
	}
	// Check if it's a symbolic link
	if fileInfo.Mode()&os.ModeSymlink != 0 {
		// It's a symbolic link, get its target
		target, err := os.Readlink(path)
		if err != nil {
			log.Fatal("Error reading symlink:", err)
		}
		fmt.Printf("Path '%s' is a symbolic link pointing to '%s'\n", path, target)
		return true, target, nil
	} else {
		fmt.Printf("Path '%s' is not a symbolic link\n", path)
		return false, "", nil
	}
}

// Get major,minor numbers from /proc/diskstats
func getDeviceNumbers(deviceName string) (uint64, uint64, error) {
	deviceName = strings.TrimPrefix(deviceName, "/dev/")

	file, err := os.Open("/proc/diskstats")
	if err != nil {
		return 0, 0, err
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := scanner.Text()
		fields := strings.Fields(line)

		if len(fields) >= 3 && fields[2] == deviceName {
			major, minor := fields[0], fields[1]
			var majorNum, minorNum uint64
			_, err := fmt.Sscanf(major, "%d", &majorNum)
			if err != nil {
				return 0, 0, err
			}
			_, err = fmt.Sscanf(minor, "%d", &minorNum)
			if err != nil {
				return 0, 0, err
			}
			return majorNum, minorNum, nil
		}
	}

	if err := scanner.Err(); err != nil {
		return 0, 0, err
	}
	return 0, 0, fmt.Errorf("device not found in /proc/diskstats")
}

type ConfigData struct {
	DeviceName         string
	DiskUsageThreshold uint64
	Action             string
	RepeatAction       uint64
	// File recovery configuration
	RecoveryEnabled    bool
	RecoveryMinSize    uint64
	RecoveryDir        string
	RecoveryMaxFiles   uint64
}

type Devinfo struct {
	Devid      uint64
	MountPoint string
}

func getConfig(configFile string) ConfigData {
	var cf ConfigData
	if configFile == "" {
		log.Fatal("Please specify a config file using the --config flag")
	}
	viper.SetConfigFile(configFile)
	err := viper.ReadInConfig()
	if err != nil {
		log.Fatalf("Error reading config file: %v", err)
	}
	// Read config
	cf.DeviceName = viper.GetString("devicename")
	cf.DiskUsageThreshold = viper.GetUint64("diskusage_threshold")
	cf.Action = viper.GetString("action")
	cf.RepeatAction = viper.GetUint64("repeat_action")

	// Read recovery configuration
	cf.RecoveryEnabled = viper.GetBool("recovery_enabled")
	cf.RecoveryMinSize = viper.GetUint64("recovery_min_size")
	cf.RecoveryDir = viper.GetString("recovery_dir")
	if cf.RecoveryDir == "" {
		cf.RecoveryDir = "/var/lib/diskalert/recovered"
	}
	cf.RecoveryMaxFiles = viper.GetUint64("recovery_max_files")
	if cf.RecoveryMaxFiles == 0 {
		cf.RecoveryMaxFiles = 1000
	}

	return cf
}

var cf ConfigData
var di Devinfo
var logFile *os.File
var logger *log.Logger

func handle_io() (ConfigData, Devinfo) {
	var err error
	logger, logFile, err = setupLog(LOGFILE_PATH)
	if err != nil {
		log.Fatalf("Failed to set up log: %v", err)
	}
	defer logFile.Close()

	logger.Println("Reading configuration from path:", configFile)
	cf = getConfig(configFile)
	// get mountpoint
	di.MountPoint, err = findMountPoint(cf.DeviceName)
	if err != nil {
		logger.Fatalf("Error getting mount point: %v", err)
	}
	// Get device numbers
	islink, target, _ := isSymlink(cf.DeviceName)
	logger.Printf("Is this symlink? %t %s\n", islink, target)

	if islink {
		cf.DeviceName = target
		// If target has ../dm-2 then change it as /dev/dm-2. We are dealing with LVM.
		if strings.HasPrefix(cf.DeviceName, "../") {
			cf.DeviceName = "/dev/" + strings.TrimPrefix(cf.DeviceName, "../")
		}
	}

	major, minor, err := getDeviceNumbers(cf.DeviceName)
	if err != nil {
		logger.Fatalf("Error while getting Device number: %v\n", err)
	}
	logger.Printf("Major: %d Minor: %d\n", major, minor)

	var dev uint64 = (major << 20) | minor
	di.Devid = dev

	logger.Printf("Device Name: %s\n", cf.DeviceName)
	logger.Printf("Max Usage Threshold: %d\n", cf.DiskUsageThreshold)
	logger.Printf("Action: %s\n", cf.Action)
	logger.Printf("Device Number: %v\n", di.Devid)
	logger.Printf("MountPoint: %s\n", di.MountPoint)
	return cf, di
}

func findMountPoint(deviceName string) (string, error) {
	file, err := os.Open("/proc/mounts")
	if err != nil {
		return "", err
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := scanner.Text()
		fields := strings.Fields(line)
		if len(fields) >= 2 && fields[0] == deviceName {
			return fields[1], nil
		}
	}

	if err := scanner.Err(); err != nil {
		return "", err
	}
	return "", fmt.Errorf("device '%s' not found in /proc/mounts", deviceName)
}
