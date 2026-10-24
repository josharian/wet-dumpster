// Command wet-dumpster reports known vulnerabilities in running Go programs.
//
// It periodically lists running processes and checks each Go executable
// with govulncheck's binary mode against a local mirror of the Go
// vulnerability database. It writes one line of JSON to stdout for each
// vulnerability whose vulnerable code is present in an executable.
//
// Each executable is reported when it is first seen running, and again
// whenever the database changes.
package main

import (
	"context"
	"debug/buildinfo"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"os"
	"syscall"
	"time"
)

var (
	flagPoll    = flag.Duration("poll", 10*time.Second, "how often to look for new processes")
	flagRefresh = flag.Duration("refresh", 15*time.Minute, "how often to check for vulnerability database updates")
	flagOnce    = flag.Bool("once", false, "check once and exit")
)

func main() {
	flag.Parse()
	db, err := newVulnDB()
	if err != nil {
		log.Fatal(err)
	}
	w := &watcher{
		db:      db,
		out:     json.NewEncoder(os.Stdout),
		checked: make(map[string]bool),
	}
	ctx := context.Background()
	for {
		err := w.check(ctx)
		if *flagOnce {
			if err != nil {
				log.Fatal(err)
			}
			return
		}
		if err != nil {
			log.Print(err)
		}
		time.Sleep(*flagPoll)
	}
}

type proc struct {
	pid  int
	exe  string // path to open
	path string // path to show
}

type watcher struct {
	db      *vulnDB
	out     *json.Encoder
	checked map[string]bool // keyed by fileID
}

// check reports vulnerabilities in running executables that it has not
// already checked. It returns an error if the check was incomplete.
func (w *watcher) check(ctx context.Context) error {
	changed, err := w.db.update(ctx)
	if err != nil {
		log.Printf("updating vulnerability database: %v", err)
	}
	if changed {
		clear(w.checked)
	}
	if _, err := w.db.etag(); err != nil {
		return fmt.Errorf("no vulnerability database")
	}
	procs, err := listProcs()
	if err != nil {
		return fmt.Errorf("listing processes: %v", err)
	}
	failed := 0
	for _, p := range procs {
		if err := w.checkProc(ctx, p); err != nil {
			log.Printf("checking %s: %v", p.path, err)
			failed++
		}
	}
	if failed > 0 {
		return fmt.Errorf("could not check %d processes", failed)
	}
	return nil
}

func (w *watcher) checkProc(ctx context.Context, p proc) error {
	f, err := os.Open(p.exe)
	if err != nil {
		return nil // exited, or not readable
	}
	defer f.Close()
	id, err := fileID(f)
	if err != nil || w.checked[id] {
		return err
	}
	bi, err := buildinfo.Read(f)
	if err != nil {
		w.checked[id] = true // not a Go executable
		return nil
	}
	vulns, err := vulns(ctx, w.db.dir, p.exe)
	if err != nil {
		return err
	}
	now := time.Now()
	for _, v := range vulns {
		v.Time, v.Exe, v.PID, v.GoVersion = now, p.path, p.pid, bi.GoVersion
		if err := w.out.Encode(v); err != nil {
			log.Fatal(err)
		}
	}
	w.checked[id] = true
	return nil
}

// fileID returns a string identifying the current contents of f,
// so that a rebuilt executable gets rechecked.
func fileID(f *os.File) (string, error) {
	fi, err := f.Stat()
	if err != nil {
		return "", err
	}
	st := fi.Sys().(*syscall.Stat_t)
	return fmt.Sprintf("%d:%d:%d:%d", st.Dev, st.Ino, fi.Size(), fi.ModTime().UnixNano()), nil
}
