package main

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
)

var configFile string
var versionFlag bool

var LOGFILE_PATH string = "/var/log/diskusage.log"
var APPLOG_PATH string = "/var/log/diskalert.log"

func main() {
	var rootCmd = &cobra.Command{
		Use:     "ebpf-diskalert",
		Short:   "monitor disk usage and take action",
		Long:    "ebpf-diskalert is a tool to monitor disk usage and perform actions.\n\n(C) 2023: Lakshmipathi Ganapathi <lakshmipathi.g@gmail.com>",
		Version: "0.1",
		Run: func(cmd *cobra.Command, args []string) {
			if versionFlag {
				fmt.Println("Version 1.0")
			} else {
				if configFile == "" {
					fmt.Println("Please provide a config file using '-c' flag.")
				} else {
					cf, di := handle_io()
					ebpf_loader(&cf, &di)
				}
			}
		},
	}

	rootCmd.Flags().StringVarP(&configFile, "config", "c", "", "Config file path")
	rootCmd.Flags().BoolVar(&versionFlag, "version", false, "Print the app version")

	rootCmd.MarkFlagRequired("config") // Make the config flag required

	if err := rootCmd.Execute(); err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
}
