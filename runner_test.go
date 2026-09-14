package rolediff

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func testSuite(base string) Suite {
	return Suite{BaseURL: base, Identities: []Identity{{Name: "alice", BearerEnv: "ALICE"}, {Name: "bob", BearerEnv: "BOB"}, {Name: "anonymous"}}, Cases: []Case{{Name: "alice-order", Path: "/orders/1", Expect: map[string]Expectation{
		"alice":     {Access: Allow, Status: []int{200}, JSON: []Assertion{{Pointer: "/owner", Op: "equals", Value: json.RawMessage(`"alice"`)}}},
		"bob":       {Access: Deny, Status: []int{403}, JSON: []Assertion{{Pointer: "/owner", Op: "absent"}}},
		"anonymous": {Access: Deny, Status: []int{401}},
	}}}}
}

func testOptions() Options {
	return Options{LookupEnv: func(key string) (string, bool) { return "fixture-" + key, true }}
}

func TestRunnerAuthorizationAndIsolation(t *testing.T) {
	for _, vulnerable := range []bool{false, true} {
		t.Run(map[bool]string{true: "vulnerable", false: "fixed"}[vulnerable], func(t *testing.T) {
			var seen atomic.Int64
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				seen.Add(1)
				if r.Header.Get("Cookie") != "" {
					t.Error("cookie leaked between identities")
				}
				w.Header().Set("Set-Cookie", "session=DO_NOT_ECHO")
				switch r.Header.Get("Authorization") {
				case "Bearer fixture-ALICE":
					w.Write([]byte(`{"owner":"alice","secret":"DO_NOT_ECHO"}`))
				case "Bearer fixture-BOB":
					if vulnerable {
						w.Write([]byte(`{"owner":"alice"}`))
					} else {
						w.WriteHeader(403)
						w.Write([]byte(`{"error":"forbidden"}`))
					}
				default:
					w.WriteHeader(401)
				}
			}))
			defer server.Close()
			suite := testSuite(server.URL)
			runner, err := NewRunner(suite, testOptions())
			if err != nil {
				t.Fatal(err)
			}
			// Snapshot survives caller mutation after construction.
			suite.Cases[0].Path = "/mutated"
			report := runner.Run(context.Background())
			if seen.Load() != 3 {
				t.Fatal("wrong request count")
			}
			if vulnerable {
				if report.Failed != 1 || report.ExitCode() != 1 {
					t.Fatalf("missed authorization regression: %#v", report)
				}
			} else if report.ExitCode() != 0 || report.Passed != 3 {
				t.Fatalf("fixed service failed: %#v", report)
			}
			data, _ := json.Marshal(report)
			for _, secret := range []string{"DO_NOT_ECHO", "fixture-ALICE", "fixture-BOB", server.URL} {
				if bytes.Contains(data, []byte(secret)) {
					t.Fatal("report leaked response/credential/URL")
				}
			}
		})
	}
}

func TestRequestErrorsAndJSONAssertions(t *testing.T) {
	for _, tt := range []struct {
		name, body  string
		status      int
		wantOutcome Outcome
		wantCode    string
		limit       int64
	}{
		{"login page", "<html>login</html>", 200, Fail, "invalid_json", 0},
		{"duplicate JSON", `{"owner":"bob","owner":"alice"}`, 200, Fail, "invalid_json", 0},
		{"missing field", `{}`, 200, Fail, "json_equals_failed", 0},
		{"wrong value", `{"owner":"bob"}`, 200, Fail, "json_equals_failed", 0},
		{"wrong status", `{"owner":"alice"}`, 500, Fail, "status_mismatch", 0},
		{"too large", strings.Repeat("a", 33), 200, Error, "response_too_large", 32},
	} {
		t.Run(tt.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(tt.status); w.Write([]byte(tt.body)) }))
			defer server.Close()
			suite := testSuite(server.URL)
			suite.Identities = suite.Identities[:1]
			delete(suite.Cases[0].Expect, "bob")
			delete(suite.Cases[0].Expect, "anonymous")
			opts := testOptions()
			opts.MaxResponseBytes = tt.limit
			runner, err := NewRunner(suite, opts)
			if err != nil {
				t.Fatal(err)
			}
			row := runner.Run(context.Background()).Results[0]
			if row.Outcome != tt.wantOutcome {
				t.Fatalf("wrong outcome: %#v", row)
			}
			if tt.wantOutcome == Error {
				if row.Error != tt.wantCode {
					t.Fatalf("wrong error: %#v", row)
				}
			} else if len(row.Failures) == 0 || row.Failures[0].Code != tt.wantCode {
				t.Fatalf("wrong failures: %#v", row)
			}
		})
	}
}

func TestPreflightRedirectsTimeoutAndCancellation(t *testing.T) {
	var calls atomic.Int64
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { calls.Add(1) }))
	defer target.Close()
	redirect := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { http.Redirect(w, r, target.URL, 302) }))
	defer redirect.Close()
	runner, err := NewRunner(testSuite(redirect.URL), testOptions())
	if err != nil {
		t.Fatal(err)
	}
	report := runner.Run(context.Background())
	if report.Errors != 3 || calls.Load() != 0 || report.Results[0].Error != "redirect_blocked" {
		t.Fatalf("redirect followed: %#v", report)
	}
	opts := testOptions()
	opts.MaxRequests = 2
	if _, err := NewRunner(testSuite(target.URL), opts); err == nil {
		t.Fatal("request budget not enforced")
	}
	opts = testOptions()
	opts.LookupEnv = func(string) (string, bool) { return "", false }
	if _, err := NewRunner(testSuite(target.URL), opts); err == nil {
		t.Fatal("missing env not detected")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	report = runner.Run(ctx)
	if report.Skipped != 3 || report.ExitCode() != 2 {
		t.Fatal("cancellation not reported")
	}
	slow := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { time.Sleep(40 * time.Millisecond) }))
	defer slow.Close()
	opts = testOptions()
	opts.Timeout = 5 * time.Millisecond
	runner, _ = NewRunner(testSuite(slow.URL), opts)
	if row := runner.Run(context.Background()).Results[0]; row.Error != "timeout" {
		t.Fatalf("timeout not handled: %#v", row)
	}
}
