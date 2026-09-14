package rolediff

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"
)

type Options struct {
	Timeout          time.Duration
	Delay            time.Duration
	MaxRequests      int
	MaxResponseBytes int64
	LookupEnv        func(string) (string, bool)
}

type Outcome string

const (
	Pass  Outcome = "PASS"
	Fail  Outcome = "FAIL"
	Error Outcome = "ERROR"
	Skip  Outcome = "SKIP"
)

type Failure struct {
	Code string `json:"code"`
	// Assertion is one-based; zero is reserved for the HTTP status assertion.
	Assertion int `json:"assertion"`
}

// Result contains suite labels and metadata, never response bodies, URLs,
// expected JSON values, credentials or underlying transport error messages.
type Result struct {
	Case       string    `json:"case"`
	Identity   string    `json:"identity"`
	Expected   Access    `json:"expected"`
	Outcome    Outcome   `json:"outcome"`
	HTTPStatus int       `json:"http_status,omitempty"`
	Failures   []Failure `json:"failures"`
	Error      string    `json:"error,omitempty"`
}

type Report struct {
	Results []Result `json:"results"`
	Passed  int      `json:"passed"`
	Failed  int      `json:"failed"`
	Errors  int      `json:"errors"`
	Skipped int      `json:"skipped"`
}

func (r Report) ExitCode() int {
	if r.Errors > 0 || r.Skipped > 0 {
		return 2
	}
	if r.Failed > 0 {
		return 1
	}
	return 0
}

type Runner struct {
	suite   Suite
	headers []http.Header
	client  *http.Client
	options Options
}

// NewRunner validates and snapshots the suite and resolves every credential
// before the first request. It owns its HTTP client: no cookie jar, proxies,
// retries, redirect following or insecure-TLS override are enabled.
func NewRunner(suite Suite, options Options) (*Runner, error) {
	data, err := json.Marshal(suite)
	if err != nil {
		return nil, errors.New("invalid suite")
	}
	suite, err = ReadSuite(bytes.NewReader(data))
	if err != nil {
		return nil, err
	}
	if options.Timeout == 0 {
		options.Timeout = 5 * time.Second
	}
	if options.MaxRequests == 0 {
		options.MaxRequests = 256
	}
	if options.MaxResponseBytes == 0 {
		options.MaxResponseBytes = 1 << 20
	}
	if options.Timeout < 0 || options.Timeout > 5*time.Minute || options.Delay < 0 || options.Delay > time.Minute || options.MaxRequests < 1 || options.MaxRequests > 10000 || options.MaxResponseBytes < 1 || options.MaxResponseBytes > 64<<20 {
		return nil, errors.New("invalid runner limits")
	}
	if len(suite.Cases)*len(suite.Identities) > options.MaxRequests {
		return nil, errors.New("planned requests exceed max-requests; nothing sent")
	}
	if options.LookupEnv == nil {
		options.LookupEnv = os.LookupEnv
	}
	headers := make([]http.Header, len(suite.Identities))
	for i, identity := range suite.Identities {
		headers[i] = make(http.Header)
		resolve := func(variable string) (string, error) {
			value, exists := options.LookupEnv(variable)
			if !exists || strings.TrimSpace(value) == "" || strings.IndexFunc(value, func(r rune) bool { return r < 32 || r == 127 }) >= 0 {
				return "", fmt.Errorf("identity %d: credential environment variable is missing, empty or invalid", i+1)
			}
			return value, nil
		}
		for name, variable := range identity.HeaderEnv {
			value, err := resolve(variable)
			if err != nil {
				return nil, err
			}
			headers[i].Set(name, value)
		}
		if identity.BearerEnv != "" {
			value, err := resolve(identity.BearerEnv)
			if err != nil {
				return nil, err
			}
			headers[i].Set("Authorization", "Bearer "+value)
		}
	}
	transport := &http.Transport{Proxy: nil, DisableKeepAlives: true, TLSHandshakeTimeout: options.Timeout, ResponseHeaderTimeout: options.Timeout}
	client := &http.Client{Transport: transport, Timeout: options.Timeout, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	return &Runner{suite: suite, headers: headers, client: client, options: options}, nil
}

func (r *Runner) PlannedRequests() int { return len(r.suite.Cases) * len(r.suite.Identities) }

// Run is sequential. Cancellation skips unstarted requests and makes the report
// unsuccessful. Each Run starts with fresh connections and no session cookies.
func (r *Runner) Run(ctx context.Context) Report {
	report := Report{Results: make([]Result, 0, r.PlannedRequests())}
	base, _ := parseBase(r.suite.BaseURL)
	first := true
	for _, c := range r.suite.Cases {
		path, _ := parsePath(c.Path)
		target := *base
		target.Path, target.RawPath, target.RawQuery, target.ForceQuery = path.Path, path.RawPath, path.RawQuery, path.ForceQuery
		for i, identity := range r.suite.Identities {
			if !first && ctx.Err() == nil && r.options.Delay > 0 {
				timer := time.NewTimer(r.options.Delay)
				select {
				case <-timer.C:
				case <-ctx.Done():
				}
				timer.Stop()
			}
			first = false
			expect := c.Expect[identity.Name]
			result := Result{Case: c.Name, Identity: identity.Name, Expected: expect.Access, Outcome: Pass, Failures: make([]Failure, 0)}
			if ctx.Err() != nil {
				result.Outcome, result.Error = Skip, "cancelled"
			} else {
				r.request(ctx, c, target.String(), r.headers[i], expect, &result)
			}
			report.Results = append(report.Results, result)
			switch result.Outcome {
			case Pass:
				report.Passed++
			case Fail:
				report.Failed++
			case Error:
				report.Errors++
			case Skip:
				report.Skipped++
			}
		}
	}
	return report
}

func (r *Runner) request(ctx context.Context, c Case, target string, headers http.Header, expect Expectation, result *Result) {
	errorResult := func(code string) { result.Outcome, result.Error = Error, code }
	method := c.Method
	if method == "" {
		method = "GET"
	}
	req, err := http.NewRequestWithContext(ctx, method, target, nil)
	if err != nil {
		errorResult("request_invalid")
		return
	}
	req.Header = headers.Clone()
	if req.Header.Get("Accept") == "" {
		req.Header.Set("Accept", "application/json")
	}
	req.Header.Set("Accept-Encoding", "identity")
	req.Header.Set("User-Agent", "RoleDiff/0.1")
	response, err := r.client.Do(req)
	if err != nil {
		code := "request_failed"
		if ctx.Err() != nil {
			code = "cancelled"
		} else {
			var timeout interface{ Timeout() bool }
			if errors.As(err, &timeout) && timeout.Timeout() {
				code = "timeout"
			}
		}
		errorResult(code)
		return
	}
	defer response.Body.Close()
	result.HTTPStatus = response.StatusCode
	if response.StatusCode >= 300 && response.StatusCode < 400 {
		errorResult("redirect_blocked")
		return
	}
	body, err := io.ReadAll(io.LimitReader(response.Body, r.options.MaxResponseBytes+1))
	if err != nil {
		errorResult("body_read_failed")
		return
	}
	if int64(len(body)) > r.options.MaxResponseBytes {
		errorResult("response_too_large")
		return
	}
	matched := false
	for _, status := range expect.Status {
		if status == response.StatusCode {
			matched = true
		}
	}
	if !matched {
		result.Failures = append(result.Failures, Failure{Code: "status_mismatch"})
	}
	if len(expect.JSON) > 0 {
		value, err := decodeJSON(body)
		if err != nil {
			result.Failures = append(result.Failures, Failure{Code: "invalid_json"})
		} else {
			for i, assertion := range expect.JSON {
				parts, _ := pointerParts(assertion.Pointer)
				actual, exists := lookup(value, parts)
				expected, _ := decodeJSON(assertion.Value)
				passed := false
				switch assertion.Op {
				case "exists":
					passed = exists
				case "absent":
					passed = !exists
				case "equals":
					passed = exists && jsonEqual(actual, expected)
				case "not_equals":
					passed = exists && !jsonEqual(actual, expected)
				}
				if !passed {
					result.Failures = append(result.Failures, Failure{Code: "json_" + assertion.Op + "_failed", Assertion: i + 1})
				}
			}
		}
	}
	if len(result.Failures) > 0 {
		result.Outcome = Fail
	}
}
