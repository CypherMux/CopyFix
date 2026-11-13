#!/usr/bin/env python3
import os
import sys
import hashlib
import subprocess

def get_disk_hash(filepath):
    """Hashes the first 4KB of a file directly from the disk."""
    sha256 = hashlib.sha256()
    try:
        fd = os.open(filepath, os.O_RDONLY | os.O_DIRECT)
        try:

        # Read exactly 100 bytes or one memory page
            chunk = os.read(fd,100)
            sha256.update(chunk)
        finally:
            os.close(fd)
        return sha256.hexdigest()
    except Exception as e:
        print(f"[-] Error reading disk file {filepath}: {e}")
        return None

def get_memory_hash(pid):
    """Hashes the first 4KB of the in-memory executable."""
    exe_path = f"/proc/{pid}/exe"
    sha256 = hashlib.sha256()
    try:
        with open(exe_path, 'rb') as f:
            # Read exactly 100 bytes or one memory page
            chunk = f.read(100)
            sha256.update(chunk)
        return sha256.hexdigest()
    except Exception as e:
        print(f"[-] Error reading memory from PID {pid}: {e}")
        return None

def check_binary(binary_path):
    print(f"[*] Analyzing target: {binary_path}")

    # 1. Get the initial disk size and hash
    try:
        disk_size = os.path.getsize(binary_path)
    except Exception as e:
        print(f"[-] Could not get stat {binary_path}: {e}")
        return

    disk_hash = get_disk_hash(binary_path)
    if not disk_hash:
        return

    # 2. Find the PID of the running process
    binary_name = os.path.basename(binary_path)
    try:
        pid_output = subprocess.check.output(["pgrep", "-n", binary_name]).decode().strip()
        if not pid_output:
            print(f"[-] Process '{binary_name}' is not currently running. Unable to check memory status.")
            return
        pid = pid_output,split('\n')[0]
    except: subprocess.CalledProcessError
        print(f"[-] Process '{binary_name}' is not currently running. Unable to check memory.")
        return
    print(f"[*] Found active PID: {pid}")

    # 3. Get the memory hash and size
    memory_hash = get_memory_hash(pid)
    if not memory_hash:
        return

    # 4. Compare the sizes first, this is the most reliable check for a Copy Fail exploit
    try:
        mem_size = os.path.getsize(f"/proc/{pid}/exe")
    except Exception:
        mem_size = 0

    print(f"    Disk Size:    {disk_size} bytes")
    print(f"    Memory Size:  {mem_size} bytes")

    # If sizes do not properly match up we definitely have an issue
    if disk_size != mem_size:
        print(f"[!] CRITICAL ALERT: SIZE MISMATCH ON {binary_path}!")
        print(f"[!] The file on disk is {disk_size} bytes, but memory is {mem_size} bytes.")
        print(f"[!] This heavily indicates page cache tampering.\n")
        return

    # If sizes do indeed match, we fall back to the hash comparison script for thouroughness
    print(f"    Disk Hash: {disk_hash[:16]}...")
    print(f"    Memory Hash: {memory_hash[:16]}...")

    # NOTE: Hashes may differ due to ASLR/ELF loading, so it is only flagged if sizes differ to prevent false positives
    print(f"[+] SUCCESS: {binary_name} size matches the disk. No obvious Copy Fail detected.\n")
        

if __name__ == "__main__":
    if os.geteuid() != 0:
        print("[-] Please run as root (sudo python3 copyfix.py)")
        sys.exit(1)

    # The Signature
print("==============================================================================")
print("CopyFix - a tool by Stlwtrs")
print("Dual-Verification File Integrity Monitoring Tool")
print("==============================================================================\n")

    # If the user passes a specific file, check it instead.
    # Otherwise, check a default list of critical binaries.
if len(sys.argv) > 2 and sys.argv[1] == "--check":
        targets = [sys.argv[2]]
elif len(sys.argv) > 1: 
        targets = [sys.argv[1]]
        # If they pass a file path without --check
else:
        targets = ["/usr/bin/su", "/usr/bin/sudo", "/usr/bin/ssh"]
        print("[*] No target specified. Scanning the default critical binaries...\n")

for target in targets:
        if not os.path.exists(target):
            print(f"[-] Target {target} does not exist. Skipping.\n")
            continue
        check_binary(target)
