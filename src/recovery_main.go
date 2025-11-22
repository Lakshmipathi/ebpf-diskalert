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
		Enabled:       cf.RecoveryEnabled,
		MinFileSize:   cf.RecoveryMinSize,
		RecoveryDir:   cf.RecoveryDir,
		MaxRecoveries: cf.RecoveryMaxFiles,
		Logger:        logger,
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

	// Start cleanup daemon in background
	go RecoveryManagerDaemon(recoveryConfig, 1*time.Hour)

	// Start the recovery loader (blocks)
	if err := RecoveryLoader(recoveryConfig); err != nil {
		logger.Fatalf("Recovery loader failed: %v", err)
	}
}
