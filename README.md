(vibe coded)

wet-dumpster watches the running Go programs and tells you which ones contain known vulns, so you know what to upgrade or rebuild.

```
go install github.com/josharian/wet-dumpster@latest
```

## Usage

```
sudo wet-dumpster        # watch forever
wet-dumpster -once       # check once and exit
```

Without root, it sees only your own processes. `-poll` (default 10s) sets how often it looks for new processes, and `-refresh` (default 15m) controls how often it checks for database updates.

It prints one JSON object per line, one per vulnerability per executable:

```
{"time":"2026-10-24T10:25:26-07:00","exe":"/usr/bin/dockerd","pid":1234,"go_version":"go1.24.4","osv":"GO-2026-6612","module":"golang.org/x/net","version":"v0.57.0","fixed":"v0.60.0","summary":"Double flow control refund on HTTP/2 server streams in net/http"}
```

To count vulnerabilities per executable:

```
wet-dumpster -once | jq -r .exe | sort | uniq -c
```

## How it works

Go executables record the module versions they were built with. wet-dumpster finds the running ones and checks each with [govulncheck](https://go.dev/doc/tutorial/govulncheck) against a local copy of the [Go vulnerability database](https://vuln.go.dev), reporting only vulnerabilities whose vulnerable code is actually in the binary. It checks new executables as they start and rechecks everything when the database changes.
