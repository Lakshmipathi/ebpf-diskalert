#!/bin/bash
# Test script for eBPF file recovery feature
# This script demonstrates the file recovery capability

set -e

echo "=========================================="
echo "eBPF File Recovery Test Script"
echo "=========================================="
echo ""

# Configuration
TEST_DIR="/tmp/ebpf-recovery-test"
TEST_FILE="$TEST_DIR/important_data.txt"
RECOVERY_DIR="/var/lib/diskalert/recovered"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

log_info() {
    echo -e "${GREEN}[INFO]${NC} $1"
}

log_warn() {
    echo -e "${YELLOW}[WARN]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Check if running as root
if [ "$EUID" -ne 0 ]; then
    log_error "This test script must be run as root (eBPF requires elevated privileges)"
    exit 1
fi

# Create test directory
log_info "Creating test directory: $TEST_DIR"
mkdir -p "$TEST_DIR"

# Create test file with content
log_info "Creating test file with data..."
cat > "$TEST_FILE" <<EOF
This is a test file for eBPF file recovery.
Created at: $(date)
PID: $$

This file will be deleted while a process has it open.
The eBPF recovery system should detect this and recover the file.

Lorem ipsum dolor sit amet, consectetur adipiscing elit.
Sed do eiusmod tempor incididunt ut labore et dolore magna aliqua.
EOF

log_info "Test file created: $TEST_FILE"
log_info "File size: $(stat -f%z "$TEST_FILE" 2>/dev/null || stat -c%s "$TEST_FILE") bytes"
echo ""

# Test Case 1: File open while being deleted
log_info "==== Test Case 1: Delete file while process has it open ===="
log_info "Starting a background process that keeps the file open..."

# Start a process that keeps the file open
{
    exec 3< "$TEST_FILE"  # Open file for reading with fd 3
    log_info "Process $$ has opened the file (fd 3)"
    log_info "Sleeping for 2 seconds to allow eBPF tracking..."
    sleep 2

    log_info "Now deleting the file with 'rm'..."
    rm -f "$TEST_FILE"
    log_info "File deleted! But fd 3 is still open in this process."

    log_info "Sleeping for 3 seconds to allow recovery to complete..."
    sleep 3

    log_info "Verifying we can still read from fd 3..."
    if cat <&3 > /dev/null 2>&1; then
        log_info "✓ Successfully read from fd 3 even after deletion"
    else
        log_warn "× Could not read from fd 3"
    fi

    exec 3<&-  # Close fd 3
    log_info "Closed fd 3"
} &

PROC_PID=$!
log_info "Background process PID: $PROC_PID"
echo ""

# Wait for the background process
log_info "Waiting for background process to complete..."
wait $PROC_PID

echo ""
log_info "==== Checking Recovery Results ===="
log_info "Looking for recovered files in: $RECOVERY_DIR"

if [ -d "$RECOVERY_DIR" ]; then
    RECOVERED_FILES=$(find "$RECOVERY_DIR" -name "*important_data*" -type f 2>/dev/null | head -5)
    if [ -n "$RECOVERED_FILES" ]; then
        log_info "✓ Found recovered file(s):"
        echo "$RECOVERED_FILES" | while read -r file; do
            echo "  - $file"
            echo "    Size: $(stat -f%z "$file" 2>/dev/null || stat -c%s "$file") bytes"
            echo "    Modified: $(stat -f%Sm "$file" 2>/dev/null || stat -c%y "$file")"
        done
        echo ""
        log_info "Content of recovered file:"
        echo "----------------------------------------"
        cat $(echo "$RECOVERED_FILES" | head -1)
        echo "----------------------------------------"
    else
        log_warn "× No recovered files found"
        log_warn "This could mean:"
        log_warn "  1. Recovery system is not running"
        log_warn "  2. File size was below minimum threshold"
        log_warn "  3. eBPF program is not loaded"
    fi
else
    log_warn "Recovery directory does not exist: $RECOVERY_DIR"
fi

echo ""
log_info "==== Test Case 2: Simulate text editor scenario ===="
log_info "This simulates an editor that keeps a backup file open..."

# Create a new test file
TEST_FILE2="$TEST_DIR/editor_backup.txt"
cat > "$TEST_FILE2" <<EOF
This file simulates an editor backup file.
Editors often keep files open while working.
EOF

# Open, modify, delete, close pattern
{
    exec 4< "$TEST_FILE2"
    sleep 1
    rm -f "$TEST_FILE2"
    log_info "Deleted: $TEST_FILE2"
    sleep 2
    exec 4<&-
} &

wait $!

echo ""
log_info "==== Cleanup ===="
log_info "Test directory will be left for inspection: $TEST_DIR"
log_info "To clean up manually, run: rm -rf $TEST_DIR"

echo ""
log_info "=========================================="
log_info "Test Complete!"
log_info "=========================================="
log_info ""
log_info "Check the recovery system logs at:"
log_info "  - /var/log/diskalert-recovery.log"
log_info ""
log_info "To verify the recovery system is running:"
log_info "  - Check eBPF programs: bpftool prog list | grep recovery"
log_info "  - Check BPF maps: bpftool map list"
log_info "  - Monitor events: cat /var/log/diskalert-recovery.log"
