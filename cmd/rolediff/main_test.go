package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func suiteInput(base string) string {
	return `{"base_url":"` + base + `","identities":[{"name":"alice","bearer_env":"TOKEN"}],"cases":[{"name":"profile","path":"/","expect":{"alice":{"access":"allow","status":[200],"json":[{"pointer":"/id","op":"equals","value":1}]}}}]}`
}

func TestCLIRunAndValidation(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.Write([]byte(`{"id":1,"secret":"DO_NOT_ECHO"}`)) }))
	defer server.Close()
	lookup := func(string) (string, bool) { return "fixture-secret", true }
	for _, args := range [][]string{{"-json", "-delay-ms", "0"}, {"-delay-ms", "0"}, {"-validate"}} {
		var out, errout bytes.Buffer
		code := run(context.Background(), args, strings.NewReader(suiteInput(server.URL)), &out, &errout, lookup)
		if code != 0 || errout.Len() != 0 || strings.Contains(out.String(), "DO_NOT_ECHO") || strings.Contains(out.String(), "fixture-secret") {
			t.Fatalf("unsafe CLI output: %d %s %s", code, &out, &errout)
		}
		if args[0] != "-delay-ms" && !json.Valid(out.Bytes()) {
			t.Fatal("JSON output corrupted")
		}
	}
}

func TestCLIInvalidInputAndHelp(t *testing.T) {
	for _, args := range [][]string{{"-timeout-ms", "0"}, {"-max-requests", "0"}, {"-unknown"}, {"a", "b"}, {"/no/such/suite"}, nil} {
		var out, errout bytes.Buffer
		code := run(context.Background(), args, strings.NewReader("DO_NOT_ECHO"), &out, &errout, func(string) (string, bool) { return "", false })
		if code != 2 || out.Len() != 0 || strings.Contains(errout.String(), "DO_NOT_ECHO") {
			t.Fatalf("invalid input output: %d %s %s", code, &out, &errout)
		}
	}
	var out, errout bytes.Buffer
	if code := run(context.Background(), []string{"-h"}, strings.NewReader(""), &out, &errout, nil); code != 0 || !strings.Contains(out.String(), "R O L E D I F F") {
		t.Fatal("banner/help missing")
	}
}

type brokenWriter struct{}

func (brokenWriter) Write([]byte) (int, error) { return 0, errors.New("broken output") }

func TestCLIWriteFailure(t *testing.T) {
	code := run(context.Background(), []string{"-validate"}, strings.NewReader(suiteInput("http://127.0.0.1:1")), brokenWriter{}, io.Discard, func(string) (string, bool) { return "fixture", true })
	if code != 2 {
		t.Fatal("write error ignored")
	}
}
