package main

import (
	"archive/zip"
	"bytes"
	"context"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"time"
)

const vulnDBURL = "https://vuln.go.dev"

// A vulnDB is a local mirror of the Go vulnerability database,
// in the layout govulncheck accepts as -db file:///dir.
type vulnDB struct {
	dir         string
	lastAttempt time.Time
}

func newVulnDB() (*vulnDB, error) {
	cache, err := os.UserCacheDir()
	if err != nil {
		return nil, err
	}
	dir := filepath.Join(cache, "wet-dumpster", "vulndb")
	if err := os.MkdirAll(filepath.Dir(dir), 0o755); err != nil {
		return nil, err
	}
	return &vulnDB{dir: dir}, nil
}

// update refreshes the mirror if it is missing, or if it is due for a check
// and the upstream database has changed. It reports whether the mirror changed.
func (db *vulnDB) update(ctx context.Context) (bool, error) {
	etag, err := db.etag()
	if err == nil && time.Since(db.lastAttempt) < *flagRefresh {
		return false, nil
	}
	db.lastAttempt = time.Now()

	data, newETag, err := fetch(ctx, vulnDBURL+"/vulndb.zip", etag)
	if err != nil || data == nil {
		return false, err
	}
	tmp, err := os.MkdirTemp(filepath.Dir(db.dir), "vulndb-*")
	if err != nil {
		return false, err
	}
	defer os.RemoveAll(tmp)
	zr, err := zip.NewReader(bytes.NewReader(data), int64(len(data)))
	if err != nil {
		return false, err
	}
	if err := os.CopyFS(tmp, zr); err != nil {
		return false, err
	}
	if err := os.WriteFile(filepath.Join(tmp, "etag"), []byte(newETag), 0o644); err != nil {
		return false, err
	}
	if err := os.RemoveAll(db.dir); err != nil {
		return false, err
	}
	if err := os.Rename(tmp, db.dir); err != nil {
		return false, err
	}
	log.Printf("vulnerability database updated")
	return true, nil
}

// etag returns the ETag of the mirrored vulndb.zip.
// It returns an error if there is no mirror.
func (db *vulnDB) etag() (string, error) {
	b, err := os.ReadFile(filepath.Join(db.dir, "etag"))
	return string(b), err
}

// fetch fetches url, returning its body and ETag.
// If etag is non-empty and still matches, fetch returns a nil body.
func fetch(ctx context.Context, url, etag string) ([]byte, string, error) {
	ctx, cancel := context.WithTimeout(ctx, time.Minute)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return nil, "", err
	}
	if etag != "" {
		req.Header.Set("If-None-Match", etag)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, "", err
	}
	defer resp.Body.Close()
	switch resp.StatusCode {
	case http.StatusNotModified:
		return nil, etag, nil
	case http.StatusOK:
		data, err := io.ReadAll(resp.Body)
		return data, resp.Header.Get("ETag"), err
	}
	return nil, "", fmt.Errorf("%s: %s", url, resp.Status)
}
