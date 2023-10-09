// Code generated by bpf2go; DO NOT EDIT.
//go:build 386 || amd64 || amd64p32 || arm || arm64 || loong64 || mips64le || mips64p32le || mipsle || ppc64le || riscv64

package main

import (
	"bytes"
	_ "embed"
	"fmt"
	"io"

	"github.com/cilium/ebpf"
)

type diskalertStringkey [64]int8

// loadDiskalert returns the embedded CollectionSpec for diskalert.
func loadDiskalert() (*ebpf.CollectionSpec, error) {
	reader := bytes.NewReader(_DiskalertBytes)
	spec, err := ebpf.LoadCollectionSpecFromReader(reader)
	if err != nil {
		return nil, fmt.Errorf("can't load diskalert: %w", err)
	}

	return spec, err
}

// loadDiskalertObjects loads diskalert and converts it into a struct.
//
// The following types are suitable as obj argument:
//
//	*diskalertObjects
//	*diskalertPrograms
//	*diskalertMaps
//
// See ebpf.CollectionSpec.LoadAndAssign documentation for details.
func loadDiskalertObjects(obj interface{}, opts *ebpf.CollectionOptions) error {
	spec, err := loadDiskalert()
	if err != nil {
		return err
	}

	return spec.LoadAndAssign(obj, opts)
}

// diskalertSpecs contains maps and programs before they are loaded into the kernel.
//
// It can be passed ebpf.CollectionSpec.Assign.
type diskalertSpecs struct {
	diskalertProgramSpecs
	diskalertMapSpecs
}

// diskalertSpecs contains programs before they are loaded into the kernel.
//
// It can be passed ebpf.CollectionSpec.Assign.
type diskalertProgramSpecs struct {
	BpfTraceblock *ebpf.ProgramSpec `ebpf:"bpf_traceblock"`
}

// diskalertMapSpecs contains maps before they are loaded into the kernel.
//
// It can be passed ebpf.CollectionSpec.Assign.
type diskalertMapSpecs struct {
	MonitorDisk *ebpf.MapSpec `ebpf:"monitor_disk"`
	Output      *ebpf.MapSpec `ebpf:"output"`
}

// diskalertObjects contains all objects after they have been loaded into the kernel.
//
// It can be passed to loadDiskalertObjects or ebpf.CollectionSpec.LoadAndAssign.
type diskalertObjects struct {
	diskalertPrograms
	diskalertMaps
}

func (o *diskalertObjects) Close() error {
	return _DiskalertClose(
		&o.diskalertPrograms,
		&o.diskalertMaps,
	)
}

// diskalertMaps contains all maps after they have been loaded into the kernel.
//
// It can be passed to loadDiskalertObjects or ebpf.CollectionSpec.LoadAndAssign.
type diskalertMaps struct {
	MonitorDisk *ebpf.Map `ebpf:"monitor_disk"`
	Output      *ebpf.Map `ebpf:"output"`
}

func (m *diskalertMaps) Close() error {
	return _DiskalertClose(
		m.MonitorDisk,
		m.Output,
	)
}

// diskalertPrograms contains all programs after they have been loaded into the kernel.
//
// It can be passed to loadDiskalertObjects or ebpf.CollectionSpec.LoadAndAssign.
type diskalertPrograms struct {
	BpfTraceblock *ebpf.Program `ebpf:"bpf_traceblock"`
}

func (p *diskalertPrograms) Close() error {
	return _DiskalertClose(
		p.BpfTraceblock,
	)
}

func _DiskalertClose(closers ...io.Closer) error {
	for _, closer := range closers {
		if err := closer.Close(); err != nil {
			return err
		}
	}
	return nil
}

// Do not access this directly.
//
//go:embed diskalert_bpfel.o
var _DiskalertBytes []byte