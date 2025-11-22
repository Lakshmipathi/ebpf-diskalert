APP=ebpf-diskalert

.PHONY: all build run gen vmlinux sum fmt clean help
.PHONY: build-recovery test-recovery install uninstall

# Default target
all: build

# Build main application
build: gen $(APP)

# Build with recovery support
build-recovery: gen $(APP)
	@echo "✓ Built with recovery support"

# Run with default config (requires root)
run: build
	sudo ./$(APP) -c config/config.toml

# Run with recovery enabled (requires root)
run-recovery: build
	sudo ./$(APP) -c config/config-with-recovery.toml

# Generate eBPF bindings for both diskalert and recovery
gen: sum vmlinux src/diskalert_bpfel.go src/recovery_bpfel.go

# Generate vmlinux.h from kernel BTF
vmlinux: src/bpf/vmlinux.h

# Download dependencies
sum: go.sum

# Format Go code
fmt: sum
	go fmt src/*.go

# Clean build artifacts
clean:
	-rm $(APP)
	-rm src/*_bpfel.go src/*_bpfel.o
	-rm src/gen*
	-rm src/bpf/vmlinux.h
	-rm go.sum
	sed 's/v.*/latest/g' -i go.mod
	@echo "✓ Cleaned"

# Test recovery feature (requires root)
test-recovery:
	@echo "Testing file recovery feature..."
	@if [ -x tests/test_recovery.sh ]; then \
		sudo tests/test_recovery.sh; \
	else \
		echo "Test script not found or not executable"; \
		exit 1; \
	fi

# Install to system (requires root)
install: build
	@echo "Installing ebpf-diskalert..."
	@if [ "$$(id -u)" -ne 0 ]; then \
		echo "Error: Installation requires root privileges"; \
		echo "Run: sudo make install"; \
		exit 1; \
	fi
	install -m 755 $(APP) /usr/local/bin/
	mkdir -p /etc/ebpf-diskalert
	mkdir -p /var/lib/diskalert/recovered
	install -m 644 config/config-with-recovery.toml /etc/ebpf-diskalert/config.toml.example
	@echo "✓ Installed to /usr/local/bin/$(APP)"

# Uninstall from system (requires root)
uninstall:
	@echo "Uninstalling ebpf-diskalert..."
	@if [ "$$(id -u)" -ne 0 ]; then \
		echo "Error: Uninstallation requires root privileges"; \
		exit 1; \
	fi
	rm -f /usr/local/bin/$(APP)
	@echo "✓ Uninstalled"

# Show help
help:
	@echo "eBPF Disk Alert - Makefile targets"
	@echo ""
	@echo "  make build           - Build the application"
	@echo "  make build-recovery  - Build with recovery support"
	@echo "  make run             - Build and run with default config"
	@echo "  make run-recovery    - Build and run with recovery enabled"
	@echo "  make test-recovery   - Test file recovery feature"
	@echo "  make install         - Install to /usr/local/bin (requires root)"
	@echo "  make uninstall       - Uninstall from system (requires root)"
	@echo "  make clean           - Clean build artifacts"
	@echo "  make help            - Show this help"

# Build application
$(APP): src/main.go src/diskalert_bpfel.go src/recovery_bpfel.go
	CGO_ENABLED=0 go build -o $(APP) src/*.go

# Generate vmlinux.h from kernel BTF
src/bpf/vmlinux.h:
	bpftool btf dump file /sys/kernel/btf/vmlinux format c > src/bpf/vmlinux.h

# Generate diskalert eBPF bindings
src/diskalert_bpfel.go: src/bpf/diskalert.bpf.c
	cd src && go generate -x ./...

# Generate recovery eBPF bindings
src/recovery_bpfel.go: src/bpf/recovery.bpf.c
	cd src && go generate -x ./...

# Download Go dependencies
go.sum:
	go mod download github.com/cilium/ebpf
	go get github.com/cilium/ebpf/internal/unix
