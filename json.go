package rolediff

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"math/big"
	"strconv"
	"strings"
	"unicode/utf8"
)

// Strict decoding prevents duplicate-key ambiguity and float64 precision loss.
func decodeJSON(data []byte) (any, error) {
	if !utf8.Valid(data) {
		return nil, errors.New("invalid UTF-8")
	}
	d := json.NewDecoder(bytes.NewReader(data))
	d.UseNumber()
	value, err := jsonValue(d, 0)
	if err != nil {
		return nil, err
	}
	if _, err := d.Token(); err != io.EOF {
		return nil, errors.New("trailing JSON data")
	}
	return value, nil
}

func jsonValue(d *json.Decoder, depth int) (any, error) {
	if depth > 64 {
		return nil, errors.New("JSON nesting exceeds limit")
	}
	token, err := d.Token()
	if err != nil {
		return nil, errors.New("invalid JSON")
	}
	switch value := token.(type) {
	case json.Delim:
		switch value {
		case '{':
			object := make(map[string]any)
			for d.More() {
				keyToken, err := d.Token()
				if err != nil {
					return nil, errors.New("invalid object key")
				}
				key, ok := keyToken.(string)
				if !ok {
					return nil, errors.New("invalid object key")
				}
				if _, duplicate := object[key]; duplicate {
					return nil, errors.New("duplicate JSON key")
				}
				object[key], err = jsonValue(d, depth+1)
				if err != nil {
					return nil, err
				}
			}
			if end, err := d.Token(); err != nil || end != json.Delim('}') {
				return nil, errors.New("invalid object")
			}
			return object, nil
		case '[':
			array := make([]any, 0)
			for d.More() {
				item, err := jsonValue(d, depth+1)
				if err != nil {
					return nil, err
				}
				array = append(array, item)
			}
			if end, err := d.Token(); err != nil || end != json.Delim(']') {
				return nil, errors.New("invalid array")
			}
			return array, nil
		default:
			return nil, errors.New("unexpected JSON delimiter")
		}
	case json.Number:
		if len(value) > 1024 {
			return nil, errors.New("JSON number exceeds limit")
		}
	}
	return token, nil
}

func pointerParts(pointer string) ([]string, error) {
	if pointer == "" {
		return nil, nil
	}
	if !utf8.ValidString(pointer) || !strings.HasPrefix(pointer, "/") {
		return nil, errors.New("invalid JSON Pointer")
	}
	parts := strings.Split(pointer[1:], "/")
	for i, part := range parts {
		for j := 0; j < len(part); j++ {
			if part[j] == '~' {
				if j+1 >= len(part) || (part[j+1] != '0' && part[j+1] != '1') {
					return nil, errors.New("invalid JSON Pointer escape")
				}
				j++
			}
		}
		parts[i] = strings.ReplaceAll(strings.ReplaceAll(part, "~1", "/"), "~0", "~")
	}
	return parts, nil
}

func lookup(value any, parts []string) (any, bool) {
	for _, part := range parts {
		switch node := value.(type) {
		case map[string]any:
			var found bool
			value, found = node[part]
			if !found {
				return nil, false
			}
		case []any:
			if part == "" || (len(part) > 1 && part[0] == '0') || strings.IndexFunc(part, func(r rune) bool { return r < '0' || r > '9' }) >= 0 {
				return nil, false
			}
			index, err := strconv.ParseUint(part, 10, 64)
			if err != nil || index >= uint64(len(node)) {
				return nil, false
			}
			value = node[index]
		default:
			return nil, false
		}
	}
	return value, true
}

func jsonEqual(a, b any) bool {
	switch a := a.(type) {
	case json.Number:
		b, ok := b.(json.Number)
		return ok && decimal(a) == decimal(b)
	case []any:
		b, ok := b.([]any)
		if !ok || len(a) != len(b) {
			return false
		}
		for i := range a {
			if !jsonEqual(a[i], b[i]) {
				return false
			}
		}
		return true
	case map[string]any:
		b, ok := b.(map[string]any)
		if !ok || len(a) != len(b) {
			return false
		}
		for key, value := range a {
			other, ok := b[key]
			if !ok || !jsonEqual(value, other) {
				return false
			}
		}
		return true
	default:
		// Primitive JSON values are comparable, but b may be an object or array.
		switch b.(type) {
		case []any, map[string]any:
			return false
		}
		return a == b
	}
}

// Canonical decimal coefficient + exponent, without expanding large exponents.
func decimal(number json.Number) string {
	s := strings.ToLower(string(number))
	sign := ""
	if strings.HasPrefix(s, "-") {
		sign, s = "-", s[1:]
	}
	mantissa, power, _ := strings.Cut(s, "e")
	exponent := new(big.Int)
	if power != "" {
		exponent.SetString(power, 10)
	}
	whole, fraction, _ := strings.Cut(mantissa, ".")
	digits := strings.TrimLeft(whole+fraction, "0")
	if digits == "" {
		return "0"
	}
	trimmed := strings.TrimRight(digits, "0")
	exponent.Add(exponent, big.NewInt(int64(len(digits)-len(trimmed)-len(fraction))))
	return sign + trimmed + "e" + exponent.String()
}
