package main

import (
	"os"
	"path/filepath"
	"strconv"
)

// listProcs returns the running processes whose executables are visible.
// Opening /proc/PID/exe reads the executable the process is actually running,
// even if the file on disk has since been replaced or deleted.
func listProcs() ([]proc, error) {
	ents, err := os.ReadDir("/proc")
	if err != nil {
		return nil, err
	}
	var procs []proc
	for _, e := range ents {
		pid, err := strconv.Atoi(e.Name())
		if err != nil {
			continue
		}
		exe := filepath.Join("/proc", e.Name(), "exe")
		path, err := os.Readlink(exe)
		if err != nil {
			continue
		}
		procs = append(procs, proc{pid: pid, exe: exe, path: path})
	}
	return procs, nil
}
