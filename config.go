package rolediff

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strings"
)

const MaxSuiteBytes = 1 << 20

type Suite struct {
	BaseURL    string     `json:"base_url"`
	Identities []Identity `json:"identities"`
	Cases      []Case     `json:"cases"`
}

type Identity struct {
	Name string `json:"name"`
	// BearerEnv names an environment variable containing a token without the
	// "Bearer " prefix. HeaderEnv supports full Cookie and API-key values.
	BearerEnv string            `json:"bearer_env,omitempty"`
	HeaderEnv map[string]string `json:"header_env,omitempty"`
}

type Case struct {
	Name   string `json:"name"`
	Method string `json:"method,omitempty"`
	Path   string `json:"path"`
	// Every case explicitly covers every declared identity.
	Expect map[string]Expectation `json:"expect"`
}

type Access string

const (
	Allow Access = "allow"
	Deny  Access = "deny"
)

type Expectation struct {
	Access Access      `json:"access"`
	Status []int       `json:"status"`
	JSON   []Assertion `json:"json,omitempty"`
}

type Assertion struct {
	Pointer string          `json:"pointer"`
	Op      string          `json:"op"` // equals, not_equals, exists, absent
	Value   json.RawMessage `json:"value,omitempty"`
}

var (
	labelPattern  = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.-]{0,63}$`)
	envPattern    = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*$`)
	headerPattern = regexp.MustCompile("^[!#$%&'*+.^_`|~0-9A-Za-z-]+$")
)

// ReadSuite rejects oversized input, duplicate JSON keys, unknown fields and
// incomplete identity matrices. Errors do not include source JSON or values.
func ReadSuite(r io.Reader) (Suite, error) {
	data, err := io.ReadAll(io.LimitReader(r, MaxSuiteBytes+1))
	if err != nil {
		return Suite{}, errors.New("cannot read suite")
	}
	if len(data) > MaxSuiteBytes {
		return Suite{}, errors.New("suite exceeds 1 MiB limit")
	}
	if _, err := decodeJSON(data); err != nil {
		return Suite{}, errors.New("invalid suite JSON (including duplicate keys or excessive nesting)")
	}
	var suite Suite
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&suite); err != nil {
		return Suite{}, errors.New("invalid suite structure or unknown field")
	}
	if err := suite.Validate(); err != nil {
		return Suite{}, err
	}
	return suite, nil
}

func (s Suite) Validate() error {
	if _, err := parseBase(s.BaseURL); err != nil {
		return err
	}
	if len(s.Identities) == 0 || len(s.Identities) > 64 {
		return errors.New("declare between 1 and 64 identities")
	}
	if len(s.Cases) == 0 || len(s.Cases) > 1000 {
		return errors.New("declare between 1 and 1000 cases")
	}
	names := make(map[string]bool)
	for i, identity := range s.Identities {
		if !labelPattern.MatchString(identity.Name) || names[identity.Name] {
			return fmt.Errorf("identity %d: name must be a unique ASCII identifier of 1–64 characters", i+1)
		}
		names[identity.Name] = true
		if identity.BearerEnv != "" && !envPattern.MatchString(identity.BearerEnv) {
			return fmt.Errorf("identity %d: invalid bearer_env name", i+1)
		}
		seen := make(map[string]bool)
		for header, variable := range identity.HeaderEnv {
			name := http.CanonicalHeaderKey(header)
			if !allowedHeader(header) || !envPattern.MatchString(variable) || seen[name] || (name == "Authorization" && identity.BearerEnv != "") {
				return fmt.Errorf("identity %d: invalid, reserved or duplicate credential header", i+1)
			}
			seen[name] = true
		}
	}
	caseNames := make(map[string]bool)
	for i, c := range s.Cases {
		fail := func(message string) error { return fmt.Errorf("case %d: %s", i+1, message) }
		if !labelPattern.MatchString(c.Name) || caseNames[c.Name] {
			return fail("name must be a unique ASCII identifier of 1–64 characters")
		}
		caseNames[c.Name] = true
		if c.Method != "" && c.Method != "GET" && c.Method != "HEAD" {
			return fail("only GET and HEAD are supported")
		}
		if _, err := parsePath(c.Path); err != nil {
			return fail("path must be a rooted path on the configured origin, without a fragment")
		}
		if len(c.Expect) != len(names) {
			return fail("expect must cover every declared identity exactly once")
		}
		for name, expectation := range c.Expect {
			if !names[name] {
				return fail("expect contains an unknown identity")
			}
			if expectation.Access != Allow && expectation.Access != Deny {
				return fail("access must be allow or deny")
			}
			if len(expectation.Status) == 0 {
				return fail("each expectation must declare status codes")
			}
			successStatus := false
			for _, status := range expectation.Status {
				if status < 200 || status > 599 || (status >= 300 && status < 400) {
					return fail("expected statuses must be final 2xx, 4xx or 5xx responses; redirects are not followed")
				}
				if status < 300 {
					successStatus = true
				}
			}
			if c.Method == "HEAD" && len(expectation.JSON) > 0 {
				return fail("HEAD cannot have response-body assertions")
			}
			if len(expectation.JSON) > 64 {
				return fail("at most 64 JSON assertions per expectation")
			}
			positive := false
			for _, assertion := range expectation.JSON {
				if _, err := pointerParts(assertion.Pointer); err != nil {
					return fail("invalid JSON Pointer")
				}
				switch assertion.Op {
				case "equals", "not_equals":
					if len(assertion.Value) == 0 {
						return fail("equals and not_equals require a value, including explicit null")
					}
					if _, err := decodeJSON(assertion.Value); err != nil {
						return fail("invalid assertion value")
					}
				case "exists", "absent":
					if len(assertion.Value) > 0 {
						return fail("exists and absent do not accept a value")
					}
				default:
					return fail("unknown JSON assertion operator")
				}
				if assertion.Op == "equals" || assertion.Op == "exists" {
					positive = true
				}
			}
			if c.Method != "HEAD" && (expectation.Access == Allow || successStatus) && !positive {
				return fail("GET allow or 2xx expectations need a positive equals/exists body assertion")
			}
		}
	}
	return nil
}

func parseBase(raw string) (*url.URL, error) {
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" || u.Hostname() == "" || (u.Scheme != "http" && u.Scheme != "https") || !strings.HasPrefix(raw, u.Scheme+"://") || u.User != nil || (u.Path != "" && u.Path != "/") || u.RawQuery != "" || u.ForceQuery || u.Fragment != "" || strings.Contains(raw, "#") || strings.ContainsAny(raw, "\\\r\n\t ") {
		return nil, errors.New("base_url must be an HTTP(S) origin without credentials, path, query or fragment")
	}
	return u, nil
}

func parsePath(raw string) (*url.URL, error) {
	u, err := url.Parse(raw)
	if err != nil || !strings.HasPrefix(raw, "/") || strings.HasPrefix(raw, "//") || strings.HasPrefix(u.Path, "//") || u.IsAbs() || u.Host != "" || u.User != nil || u.Fragment != "" || strings.Contains(raw, "#") || strings.ContainsAny(raw, "\\\r\n\t ") || strings.Contains(u.Path, "\\") {
		return nil, errors.New("invalid request path")
	}
	for _, part := range strings.Split(u.Path, "/") {
		if part == "." || part == ".." {
			return nil, errors.New("dot path segments are not supported")
		}
	}
	return u, nil
}

func allowedHeader(name string) bool {
	if !headerPattern.MatchString(name) {
		return false
	}
	switch http.CanonicalHeaderKey(name) {
	case "Host", "Content-Length", "Transfer-Encoding", "Connection", "Upgrade", "Trailer", "Te", "Accept-Encoding", "Proxy-Authorization", "Proxy-Connection", "User-Agent":
		return false
	}
	return true
}
