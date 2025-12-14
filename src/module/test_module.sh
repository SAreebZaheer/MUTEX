#!/bin/bash
#
# KPROXY Module Testing Script
# Part of the MUTEX Project
# Authors: Syed Areeb Zaheer, Azeem, Hamza Bin Aamir
#
# This script automates the testing of the KPROXY kernel module

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Module name
MODULE_NAME="kproxy"

echo -e "${YELLOW}=== KPROXY Kernel Module Test Script ===${NC}"
echo -e "Testing: Branch 2 - Syscall Registration"

# Check if we're running as root
if [ "$EUID" -ne 0 ]; then 
    echo -e "${RED}Please run as root (sudo)${NC}"
    exit 1
fi

# Step 1: Build the module
echo -e "\n${YELLOW}[1/5] Building module...${NC}"
make clean > /dev/null 2>&1
if make > /dev/null 2>&1; then
    echo -e "${GREEN}✓ Build successful${NC}"
else
    echo -e "${RED}✗ Build failed${NC}"
    exit 1
fi

# Step 2: Check if module exists
echo -e "\n${YELLOW}[2/5] Checking if module file exists...${NC}"
if [ -f "${MODULE_NAME}.ko" ]; then
    echo -e "${GREEN}✓ Module file found: ${MODULE_NAME}.ko${NC}"
else
    echo -e "${RED}✗ Module file not found${NC}"
    exit 1
fi

# Step 3: Load the module
echo -e "\n${YELLOW}[3/5] Loading module...${NC}"
if insmod "${MODULE_NAME}.ko"; then
    echo -e "${GREEN}✓ Module loaded successfully${NC}"
else
    echo -e "${RED}✗ Failed to load module${NC}"
    exit 1
fi

# Step 4: Verify module is loaded
echo -e "\n${YELLOW}[4/5] Verifying module is loaded...${NC}"
if lsmod | grep -q "^${MODULE_NAME}"; then
    echo -e "${GREEN}✓ Module is loaded${NC}"
    lsmod | grep "^${MODULE_NAME}"
else
    echo -e "${RED}✗ Module not found in lsmod${NC}"
    exit 1
fi

# Show kernel messages
echo -e "\n${YELLOW}Kernel messages (loading):${NC}"
dmesg | grep KPROXY | tail -10

# Wait a bit
sleep 1

# Step 5: Build and run syscall test program
echo -e "\n${YELLOW}[5/7] Building syscall test program...${NC}"
if gcc -o test_syscall test_syscall.c -Wall; then
    echo -e "${GREEN}✓ Test program compiled successfully${NC}"
else
    echo -e "${RED}✗ Failed to compile test program${NC}"
    rmmod "${MODULE_NAME}"
    exit 1
fi

# Step 6: Test syscall - enable proxy
echo -e "\n${YELLOW}[6/7] Testing syscall (enable proxy)...${NC}"
if ./test_syscall enable 192.168.1.100 8080; then
    echo -e "${GREEN}✓ Syscall test (enable) passed${NC}"
else
    echo -e "${RED}✗ Syscall test (enable) failed${NC}"
    rmmod "${MODULE_NAME}"
    exit 1
fi

echo -e "\n${YELLOW}Kernel messages (syscall enable):${NC}"
dmesg | grep KPROXY | tail -5

sleep 1

# Test syscall - disable proxy
echo -e "\n${YELLOW}Testing syscall (disable proxy)...${NC}"
if ./test_syscall disable 192.168.1.100 8080; then
    echo -e "${GREEN}✓ Syscall test (disable) passed${NC}"
else
    echo -e "${RED}✗ Syscall test (disable) failed${NC}"
    rmmod "${MODULE_NAME}"
    exit 1
fi

echo -e "\n${YELLOW}Kernel messages (syscall disable):${NC}"
dmesg | grep KPROXY | tail -5

# Step 7: Unload the module
echo -e "\n${YELLOW}[7/7] Unloading module...${NC}"
if rmmod "${MODULE_NAME}"; then
    echo -e "${GREEN}✓ Module unloaded successfully${NC}"
else
    echo -e "${RED}✗ Failed to unload module${NC}"
    exit 1
fi

# Verify module is unloaded
if ! lsmod | grep -q "^${MODULE_NAME}"; then
    echo -e "${GREEN}✓ Module successfully removed${NC}"
else
    echo -e "${RED}✗ Module still loaded${NC}"
    exit 1
fi

# Show kernel messages
echo -e "\n${YELLOW}Kernel messages (unloading):${NC}"
dmesg | grep KPROXY | tail -2

# Summary
echo -e "\n${GREEN}=== All tests passed! ===${NC}"
echo -e "The module loads and unloads cleanly without kernel panics."
echo -e "System call registration and invocation works correctly."
echo -e "\nModule details:"
ls -lh "${MODULE_NAME}.ko"
echo -e "\nTest artifacts:"
ls -lh test_syscall

# Cleanup test program
rm -f test_syscall

exit 0
