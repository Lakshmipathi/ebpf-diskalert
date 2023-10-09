package main

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -target bpfel -cc clang diskalert ./bpf/diskalert.bpf.c -- -I/usr/include/bpf -I.

import (
	"bytes"
	"encoding/binary"
	"log"
	"os"
	"sync"

	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/perf"
	"golang.org/x/sys/unix"
)

type data_t struct {
	Pid     uint32
	Uid     uint32
	Path    uint32
	V       uint32
	Command [32]byte
}

func setlimit() {
	if err := unix.Setrlimit(unix.RLIMIT_MEMLOCK,
		&unix.Rlimit{
			Cur: unix.RLIM_INFINITY,
			Max: unix.RLIM_INFINITY,
		}); err != nil {
		log.Fatalf("failed to set temporary rlimit: %v", err)
	}
}

var disknofity_counter uint64 = 0

func ebpf_loader(ci *ConfigData, di *Devinfo) {
	setlimit()
	logger, logFile, err := setupLog(LOGFILE_PATH)
	if err != nil {
		log.Fatalf("Failed to set up log: %v", err)
	}
	defer logFile.Close()

	objs := diskalertObjects{}
	loadDiskalertObjects(&objs, nil)
	defer objs.Close()

	var key [64]byte
	copy(key[:], []byte("monitor_disk"))
	var val uint64 = di.Devid
	if err := objs.diskalertMaps.MonitorDisk.Put(key, val); err != nil {
		logger.Fatalf("init map key error: %s", err)
	}
	link.Tracepoint("block", "block_bio_complete", objs.BpfTraceblock, nil)
	link.Tracepoint("block", "block_rq_complete", objs.BpfTraceblock, nil)

	rd, err := perf.NewReader(objs.Output, os.Getpagesize())
	if err != nil {
		logger.Fatalf("ebpf_loader: reader error")
	}
	var m sync.Mutex
	for {
		ev, err := rd.Read()
		if err != nil {
			logger.Fatalf("ebpf_loader: Read fail")
		}

		if ev.LostSamples != 0 {
			logger.Printf("perf event ring buffer full, dropped %d samples", ev.LostSamples)
			continue
		}

		b_arr := bytes.NewBuffer(ev.RawSample)

		var data data_t
		if err := binary.Read(b_arr, binary.LittleEndian, &data); err != nil {
			logger.Printf("parsing perf event: %s", err)
			continue
		}

		logger.Printf("Command:%s User: %d  wrote to the mountpoint:%s\n", data.Command, data.Pid, di.MountPoint)

		m.Lock()
		checkDiskUSage(ci, di)
		m.Unlock()
	}
}
