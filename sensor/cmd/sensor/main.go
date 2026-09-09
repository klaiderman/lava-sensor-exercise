// Command sensor is a read-only, bounded, unprivileged Linux posture sensor.
//
// It describes the machine it runs on and reports one finding per registered
// check as pass, fail or unknown, into a single JSON file.
//
// Usage:
//
//	sensor scan --out findings.json
//	sensor --version
//
// Exit codes:
//
//	0  the scan completed and the output file was written (findings may be
//	   fail or unknown; a finding's verdict never changes the exit code)
//	1  the output file was written but failed the structural self-check
//	2  the output file could not be written, or the invocation was invalid
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"os"
	"time"

	"lava-sensor-exercise/sensor/internal/checks"
	"lava-sensor-exercise/sensor/internal/probe"
	"lava-sensor-exercise/sensor/internal/scan"
)

// version is overridable at build time with -ldflags "-X main.version=...".
var version = "0.1.0-dev"

const (
	exitOK        = 0
	exitSelfCheck = 1
	exitFatal     = 2
)

func main() { os.Exit(run(os.Args[1:], os.Stdout, os.Stderr)) }

func run(args []string, stdout, stderr *os.File) int {
	fs := flag.NewFlagSet("sensor", flag.ContinueOnError)
	fs.SetOutput(stderr)
	var (
		out         = fs.String("out", "", "path of the findings JSON file to write (required)")
		showVersion = fs.Bool("version", false, "print the sensor version and exit")
	)
	fs.Usage = func() {
		fmt.Fprint(stderr, "usage: sensor scan --out findings.json\n       sensor --version\n\n")
		fs.PrintDefaults()
	}

	// The subcommand may come before or after the flags.
	var rest []string
	cmd := ""
	for _, a := range args {
		if cmd == "" && len(a) > 0 && a[0] != '-' {
			cmd = a
			continue
		}
		rest = append(rest, a)
	}
	if err := fs.Parse(rest); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return exitOK
		}
		return exitFatal
	}
	if *showVersion {
		fmt.Fprintf(stdout, "sensor %s\n", version)
		return exitOK
	}
	if cmd != "scan" {
		fs.Usage()
		return exitFatal
	}
	if *out == "" {
		fmt.Fprintln(stderr, "sensor: --out is required")
		return exitFatal
	}
	if fs.NArg() > 0 {
		fmt.Fprintf(stderr, "sensor: unexpected argument %q\n", fs.Arg(0))
		return exitFatal
	}

	roster := checks.All()
	// Fail fast: a duplicate check_id would silently drop a finding, which is
	// exactly the failure mode the whole design exists to prevent.
	if err := scan.ValidateRoster(roster); err != nil {
		fmt.Fprintf(stderr, "sensor: invalid check registry: %v\n", err)
		return exitFatal
	}

	files := probe.NewReader()
	defer files.Close()

	started := time.Now()
	// The whole-scan deadline is a constant: a bound an operator can raise
	// from the command line is not a bound.
	deadline := started.Add(scan.DefaultScanDeadline)
	ctx, cancel := context.WithDeadline(context.Background(), deadline)
	defer cancel()

	env := scan.NewEnv(files, probe.NewRunner(), time.Now, deadline, int64(os.Geteuid()))
	if _, _, detail := files.RootStatus(); detail != "" {
		env.Degradations = append(env.Degradations, detail)
	}

	machine := checks.CollectMachine(ctx, env)
	findings, cut := scan.Run(ctx, roster, env)

	doc := &scan.Document{
		SchemaVersion: scan.SchemaVersion,
		CollectedAt:   started.UTC().Format(time.RFC3339),
		SensorVersion: version,
		Machine:       machine,
		Findings:      findings,
		Scan: scan.ScanMeta{
			StartedAt:      started.UTC().Format(time.RFC3339),
			DurationMS:     time.Since(started).Milliseconds(),
			DeadlineMS:     scan.DefaultScanDeadline.Milliseconds(),
			ChecksRun:      int64(len(roster)),
			BudgetCut:      cut > 0,
			BudgetCutCount: cut,
			EUID:           int64(os.Geteuid()),
			Degradations:   env.Degradations,
			SelfCheck:      "pass",
		},
	}
	if doc.Scan.Degradations == nil {
		doc.Scan.Degradations = []string{}
	}

	// The self-check runs on the encoded bytes, then the result is recorded in
	// the document and the document re-encoded, so the artifact always says
	// whether it validated. Output is never suppressed (D3, LD-6).
	firstPass, err := scan.Encode(doc)
	if err != nil {
		fmt.Fprintf(stderr, "sensor: could not encode findings: %v\n", err)
		return exitFatal
	}
	fails := scan.SelfCheck(firstPass)
	if len(fails) > 0 {
		doc.Scan.SelfCheck = "fail"
		doc.Scan.SelfCheckFails = fails
	}
	body, err := scan.Encode(doc)
	if err != nil {
		fmt.Fprintf(stderr, "sensor: could not encode findings: %v\n", err)
		return exitFatal
	}
	if err := scan.Write(*out, body); err != nil {
		fmt.Fprintf(stderr, "sensor: could not write %s: %v\n", *out, err)
		return exitFatal
	}

	if len(fails) > 0 {
		fmt.Fprintf(stderr, "sensor: %s written, but it failed the structural self-check:\n", *out)
		for _, f := range fails {
			fmt.Fprintf(stderr, "  %s\n", f)
		}
		return exitSelfCheck
	}

	var pass, fail, unknown int
	for _, f := range findings {
		switch f.Status {
		case scan.StatusPass:
			pass++
		case scan.StatusFail:
			fail++
		default:
			unknown++
		}
	}
	fmt.Fprintf(stderr, "sensor %s: %d checks in %dms — %d pass, %d fail, %d unknown — wrote %s\n",
		version, len(findings), time.Since(started).Milliseconds(), pass, fail, unknown, *out)
	return exitOK
}
