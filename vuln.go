package main

import (
	"bytes"
	"context"
	"debug/macho"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"runtime"
	"strings"
	"time"

	"golang.org/x/vuln/scan"
)

// A vuln is a vulnerability in a running executable.
type vuln struct {
	Time      time.Time `json:"time"`
	Exe       string    `json:"exe"`
	PID       int       `json:"pid"` // a process running Exe
	GoVersion string    `json:"go_version"`
	OSV       string    `json:"osv"`
	Module    string    `json:"module"` // "stdlib" for the standard library
	Version   string    `json:"version"`
	Fixed     string    `json:"fixed,omitempty"`
	Summary   string    `json:"summary"`
}

// ignored lists vulnerabilities not worth reporting.
var ignored = map[string]bool{
	"GO-2026-5932": true, // golang.org/x/crypto/openpgp is unmaintained; no fix exists
}

// vulns runs govulncheck in binary mode on the executable at path.
// It reports only vulnerabilities whose vulnerable symbols are present in the
// executable, not ones that merely affect a module it contains.
func vulns(ctx context.Context, dbDir, path string) ([]vuln, error) {
	path, cleanup, err := thin(path)
	if err != nil {
		return nil, err
	}
	defer cleanup()

	var stdout, stderr bytes.Buffer
	cmd := scan.Command(ctx, "-db=file://"+dbDir, "-mode=binary", "-format=json", path)
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	if err := cmd.Start(); err != nil {
		return nil, err
	}
	if err := cmd.Wait(); err != nil {
		return nil, fmt.Errorf("%v: %s", err, strings.TrimSpace(stderr.String()))
	}

	var vulns []vuln
	seen := make(map[string]bool)
	summaries := make(map[string]string)
	dec := json.NewDecoder(&stdout)
	for {
		var msg struct {
			OSV *struct {
				ID      string `json:"id"`
				Summary string `json:"summary"`
			} `json:"osv"`
			Finding *struct {
				OSV          string `json:"osv"`
				FixedVersion string `json:"fixed_version"`
				Trace        []struct{ Module, Version, Function string }
			} `json:"finding"`
		}
		err := dec.Decode(&msg)
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, err
		}
		if o := msg.OSV; o != nil {
			summaries[o.ID] = o.Summary
		}
		// Govulncheck emits module-, package-, and symbol-level findings.
		// Keep the first symbol-level finding for each vulnerability.
		f := msg.Finding
		if f == nil || len(f.Trace) == 0 || f.Trace[0].Function == "" || seen[f.OSV] || ignored[f.OSV] {
			continue
		}
		seen[f.OSV] = true
		vulns = append(vulns, vuln{
			OSV:     f.OSV,
			Module:  f.Trace[0].Module,
			Version: f.Trace[0].Version,
			Fixed:   f.FixedVersion,
		})
	}
	for i := range vulns {
		vulns[i].Summary = summaries[vulns[i].OSV]
	}
	return vulns, nil
}

// thin returns path, or, if path is a universal Mach-O binary, which
// govulncheck cannot read, a temporary file holding the slice for the
// current architecture. The caller must call cleanup when done.
func thin(path string) (thinPath string, cleanup func(), err error) {
	nop := func() {}
	f, err := os.Open(path)
	if err != nil {
		return "", nop, err
	}
	defer f.Close()
	ff, err := macho.NewFatFile(f)
	if err != nil {
		return path, nop, nil // not universal; let govulncheck have a go
	}
	cpu := macho.CpuArm64
	if runtime.GOARCH == "amd64" {
		cpu = macho.CpuAmd64
	}
	arch := ff.Arches[0]
	for _, a := range ff.Arches {
		if a.Cpu == cpu {
			arch = a
		}
	}
	tmp, err := os.CreateTemp("", "wet-dumpster-*")
	if err != nil {
		return "", nop, err
	}
	cleanup = func() { os.Remove(tmp.Name()) }
	_, err = io.Copy(tmp, io.NewSectionReader(f, int64(arch.Offset), int64(arch.Size)))
	if cerr := tmp.Close(); err == nil {
		err = cerr
	}
	if err != nil {
		cleanup()
		return "", nop, err
	}
	return tmp.Name(), cleanup, nil
}
