package main

import (
	"log"
	"os"
	"time"
)

// startRecoverySystem initializes and starts the file recovery system
func startRecoverySystem(cf *ConfigData) {
	// Create logger for recovery
	recoveryLogPath := "/var/log/diskalert-recovery.log"
	logger, logFile, err := setupLog(recoveryLogPath)
	if err != nil {
		log.Fatalf("Failed to set up recovery log: %v", err)
	}
	defer logFile.Close()

	logger.Println("===============================================")
	logger.Println("Starting eBPF File Recovery System")
	logger.Println("===============================================")

	// Create recovery configuration
	recoveryConfig := &RecoveryConfig{
		Enabled:          cf.RecoveryEnabled,
		MinFileSize:      cf.RecoveryMinSize,
		RecoveryDir:      cf.RecoveryDir,
		MaxRecoveries:    cf.RecoveryMaxFiles,
		Logger:           logger,
		ShadowFDEnabled:  cf.ShadowFDEnabled,
		MaxShadowFDs:     int(cf.MaxShadowFDs),
		MaxShadowSize:    cf.MaxShadowSize,
		ShadowFDTimeout:  time.Duration(cf.ShadowFDTimeoutSecs) * time.Second,
	}

	// Ensure recovery directory exists
	if err := os.MkdirAll(recoveryConfig.RecoveryDir, 0755); err != nil {
		logger.Fatalf("Failed to create recovery directory: %v", err)
	}

	logger.Printf("Recovery Configuration:")
	logger.Printf("  Enabled: %v", recoveryConfig.Enabled)
	logger.Printf("  Min File Size: %d bytes", recoveryConfig.MinFileSize)
	logger.Printf("  Recovery Directory: %s", recoveryConfig.RecoveryDir)
	logger.Printf("  Max Recoveries: %d", recoveryConfig.MaxRecoveries)
	logger.Printf("  Shadow FD Enabled: %v", recoveryConfig.ShadowFDEnabled)
	if recoveryConfig.ShadowFDEnabled {
		logger.Printf("  Max Shadow FDs: %d", recoveryConfig.MaxShadowFDs)
		logger.Printf("  Max Shadow Size: %d bytes", recoveryConfig.MaxShadowSize)
		logger.Printf("  Shadow FD Timeout: %v", recoveryConfig.ShadowFDTimeout)
	}

	// Start cleanup daemon in background
	go RecoveryManagerDaemon(recoveryConfig, 1*time.Hour)

	// Start the recovery loader (blocks)
	if err := RecoveryLoader(recoveryConfig); err != nil {
		logger.Fatalf("Recovery loader failed: %v", err)
	}
}
