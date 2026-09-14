package rolediff

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
)

func TestSuiteValidation(t *testing.T) {
	for _, mutate := range []func(*Suite){
		func(s *Suite) { s.BaseURL = "https://secret@example.test" },
		func(s *Suite) { s.BaseURL = "https://example.test/path" },
		func(s *Suite) { s.Cases[0].Path = "//elsewhere.test/" },
		func(s *Suite) { s.Cases[0].Path = "/%2felsewhere.test/" },
		func(s *Suite) { s.Cases[0].Method = "POST" },
		func(s *Suite) { delete(s.Cases[0].Expect, "bob") },
		func(s *Suite) { s.Identities[0].HeaderEnv = map[string]string{"Host": "HOST"} },
		func(s *Suite) { s.Identities[0].HeaderEnv = map[string]string{"Authorization": "OTHER"} },
		func(s *Suite) { e := s.Cases[0].Expect["alice"]; e.JSON = nil; s.Cases[0].Expect["alice"] = e },
		func(s *Suite) {
			e := s.Cases[0].Expect["alice"]
			e.JSON[0].Pointer = "/bad~2"
			s.Cases[0].Expect["alice"] = e
		},
		func(s *Suite) { s.Cases[0].Method = "HEAD" },
	} {
		suite := testSuite("https://example.test")
		mutate(&suite)
		if err := suite.Validate(); err == nil {
			t.Fatal("invalid suite accepted")
		}
	}
	data, _ := json.Marshal(testSuite("https://example.test"))
	for _, input := range []string{string(data) + " {}", strings.Replace(string(data), `"base_url":`, `"unknown":true,"base_url":`, 1), strings.Replace(string(data), `"base_url":`, `"base_url":"https://bad.test","base_url":`, 1), strings.Repeat("x", MaxSuiteBytes+1)} {
		if _, err := ReadSuite(strings.NewReader(input)); err == nil {
			t.Fatal("invalid JSON suite accepted")
		}
	}
	if _, err := ReadSuite(bytes.NewReader(data)); err != nil {
		t.Fatal(err)
	}
}

func TestJSONPrecisionPointersAndMissing(t *testing.T) {
	for _, pair := range [][2]string{{"1", "1.0"}, {"-0", "0.0"}, {"1e100000", "10e99999"}, {`{"x":[1,null]}`, `{"x":[1.0,null]}`}} {
		a, _ := decodeJSON([]byte(pair[0]))
		b, _ := decodeJSON([]byte(pair[1]))
		if !jsonEqual(a, b) {
			t.Fatalf("not equal: %v", pair)
		}
	}
	a, _ := decodeJSON([]byte("9007199254740993"))
	b, _ := decodeJSON([]byte("9007199254740992"))
	if jsonEqual(a, b) {
		t.Fatal("precision lost")
	}
	value, _ := decodeJSON([]byte(`{"a/b":{"~key":[null,2]}}`))
	parts, _ := pointerParts("/a~1b/~0key/0")
	if v, ok := lookup(value, parts); !ok || v != nil {
		t.Fatal("null confused with absence")
	}
	parts, _ = pointerParts("/a~1b/~0key/01")
	if _, ok := lookup(value, parts); ok {
		t.Fatal("leading-zero array index accepted")
	}
	for _, input := range []string{`{"x":1,"x":2}`, strings.Repeat("[", 66) + "0" + strings.Repeat("]", 66), "true false"} {
		if _, err := decodeJSON([]byte(input)); err == nil {
			t.Fatal("invalid JSON accepted")
		}
	}
}

func FuzzReadSuite(f *testing.F) {
	data, _ := json.Marshal(testSuite("https://example.test"))
	f.Add(data)
	f.Fuzz(func(t *testing.T, data []byte) {
		if len(data) > 65536 {
			t.Skip()
		}
		ReadSuite(bytes.NewReader(data))
	})
}
