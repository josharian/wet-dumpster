package main

import (
	"syscall"
	"unsafe"

	"golang.org/x/sys/unix"
)

// listProcs returns the running processes whose executables are visible.
// Without root, that is typically only the current user's processes.
func listProcs() ([]proc, error) {
	kps, err := unix.SysctlKinfoProcSlice("kern.proc.all")
	if err != nil {
		return nil, err
	}
	var procs []proc
	for _, kp := range kps {
		pid := int(kp.Proc.P_pid)
		if pid == 0 {
			continue
		}
		exe := exePath(pid)
		if exe == "" {
			continue
		}
		procs = append(procs, proc{pid: pid, exe: exe, path: exe})
	}
	return procs, nil
}

// exePath returns the absolute executable path of pid, or "" if unavailable.
func exePath(pid int) string {
	// Query PROC_PIDPATHINFO, as proc_pidpath does. kern.procargs2 can
	// contain a relative path, and the process may have changed directories.
	const (
		procInfoCallPIDInfo    = 2
		procPIDPathInfo        = 11
		procPIDPathInfoMaxSize = 4096
	)
	var buf [procPIDPathInfoMaxSize]byte
	_, _, errno := syscall.Syscall6(unix.SYS_PROC_INFO,
		procInfoCallPIDInfo, uintptr(pid), procPIDPathInfo, 0,
		uintptr(unsafe.Pointer(&buf[0])), uintptr(len(buf)))
	if errno != 0 {
		return ""
	}
	return unix.ByteSliceToString(buf[:])
}
