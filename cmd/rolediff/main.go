package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/dc9-dev/rolediff"
)

const banner = `
     [ alice ] --+        R O L E D I F F
     [  bob  ] --+--> ?   Test who can access what.
     [ admin ] --+
     [ guest ] --+        Authorization regression tests

`

const usage = `Usage: rolediff [flags] [suite.json|-]

Read an explicit authorization test suite from a file or stdin.
Exit codes: 0 = pass; 1 = assertion failure; 2 = configuration or runtime error.
`

func terminal(f *os.File) bool {
	info, err := f.Stat()
	return err == nil && info.Mode()&os.ModeCharDevice != 0
}

func main() {
	args := os.Args[1:]
	if len(args) == 0 && terminal(os.Stdin) {
		args = []string{"-h"}
	}
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt)
	defer cancel()
	os.Exit(run(ctx, args, os.Stdin, os.Stdout, os.Stderr, os.LookupEnv))
}

func run(ctx context.Context, args []string, stdin io.Reader, stdout, stderr io.Writer, lookupEnv func(string) (string, bool)) int {
	fs := flag.NewFlagSet("github.com/dc9-dev/rolediff", flag.ContinueOnError)
	fs.SetOutput(stderr)
	asJSON := fs.Bool("json", false, "emit JSON")
	validate := fs.Bool("validate", false, "validate suite and credentials without sending requests")
	timeoutMS := fs.Int64("timeout-ms", 5000, "timeout per request, 1–300000 milliseconds")
	delayMS := fs.Int64("delay-ms", 100, "delay between requests, 0–60000 milliseconds")
	maxRequests := fs.Int("max-requests", 256, "maximum planned requests, 1–10000")
	maxBytes := fs.Int64("max-response-bytes", 1<<20, "maximum bytes per response, up to 64 MiB")
	fs.Usage = func() { fmt.Fprint(stderr, usage); fs.PrintDefaults() }
	if len(args) > 0 && (args[0] == "-h" || args[0] == "--help" || args[0] == "help") {
		fmt.Fprint(stdout, banner, usage)
		fs.SetOutput(stdout)
		fs.PrintDefaults()
		return 0
	}
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return 0
		}
		return 2
	}
	fail := func(message string) int { fmt.Fprintln(stderr, "rolediff:", message); return 2 }
	if fs.NArg() > 1 {
		return fail("expected one suite file; flags must precede it")
	}
	if *timeoutMS < 1 || *timeoutMS > 300000 || *delayMS < 0 || *delayMS > 60000 || *maxRequests < 1 || *maxRequests > 10000 || *maxBytes < 1 || *maxBytes > 64<<20 {
		return fail("invalid runner limits")
	}
	r := stdin
	if path := fs.Arg(0); path != "" && path != "-" {
		file, err := os.Open(path)
		if err != nil {
			return fail("cannot open suite file")
		}
		defer file.Close()
		r = file
	}
	suite, err := rolediff.ReadSuite(r)
	if err != nil {
		return fail(err.Error())
	}
	runner, err := rolediff.NewRunner(suite, rolediff.Options{Timeout: time.Duration(*timeoutMS) * time.Millisecond, Delay: time.Duration(*delayMS) * time.Millisecond, MaxRequests: *maxRequests, MaxResponseBytes: *maxBytes, LookupEnv: lookupEnv})
	if err != nil {
		return fail(err.Error())
	}
	if *validate {
		_, err := fmt.Fprintf(stdout, "{\"valid\":true,\"planned_requests\":%d}\n", runner.PlannedRequests())
		if err != nil {
			return fail("cannot write output")
		}
		return 0
	}
	report := runner.Run(ctx)
	if *asJSON {
		encoder := json.NewEncoder(stdout)
		encoder.SetIndent("", "  ")
		err = encoder.Encode(report)
	} else {
		err = render(stdout, report)
	}
	if err != nil {
		return fail("cannot write output")
	}
	return report.ExitCode()
}

func render(out io.Writer, report rolediff.Report) error {
	table := tabwriter.NewWriter(out, 0, 4, 2, ' ', 0)
	fmt.Fprintln(table, "CASE\tIDENTITY\tEXPECTED\tRESULT\tHTTP\tDETAIL")
	for _, result := range report.Results {
		detail := result.Error
		for _, failure := range result.Failures {
			if detail != "" {
				detail += ", "
			}
			detail += failure.Code
			if failure.Assertion > 0 {
				detail += " #" + strconv.Itoa(failure.Assertion)
			}
		}
		status := "-"
		if result.HTTPStatus != 0 {
			status = strconv.Itoa(result.HTTPStatus)
		}
		fmt.Fprintf(table, "%s\t%s\t%s\t%s\t%s\t%s\n", result.Case, result.Identity, result.Expected, result.Outcome, status, strings.TrimSpace(detail))
	}
	if err := table.Flush(); err != nil {
		return err
	}
	_, err := fmt.Fprintf(out, "\n%d passed, %d failed, %d errors, %d skipped\n", report.Passed, report.Failed, report.Errors, report.Skipped)
	return err
}
