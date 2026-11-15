package generate

import (
	"encoding/base64"
	"encoding/hex"
	"regexp"
	"testing"
)

func TestValue(t *testing.T) {
	tests := []struct {
		format string
		length int
		want   string
	}{
		{"alnum", 0, `^[A-Za-z0-9]{32}$`},
		{"alnum", 5, `^[A-Za-z0-9]{5}$`},
		{"symbols", 40, `^[A-Za-z0-9!#$%&*+\-.:=?@^_~]{40}$`},
		{"digits", 0, `^[0-9]{6}$`},
		{"hex", 0, `^[0-9a-f]{64}$`},
		{"base64", 0, `^[A-Za-z0-9+/]{43}=$`},
		{"uuid", 0, `^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$`},
	}
	for _, tt := range tests {
		got, err := Value(tt.format, tt.length)
		if err != nil {
			t.Fatalf("Value(%q, %d): %v", tt.format, tt.length, err)
		}
		if !regexp.MustCompile(tt.want).MatchString(got) {
			t.Errorf("Value(%q, %d) = %q, want match %s", tt.format, tt.length, got, tt.want)
		}
	}

	h, _ := Value("hex", 16)
	if b, _ := hex.DecodeString(h); len(b) != 16 {
		t.Errorf("hex 16 decodes to %d bytes", len(b))
	}
	s, _ := Value("base64", 16)
	if b, _ := base64.StdEncoding.DecodeString(s); len(b) != 16 {
		t.Errorf("base64 16 decodes to %d bytes", len(b))
	}
}

func TestValueErrors(t *testing.T) {
	for _, tt := range []struct {
		format string
		length int
	}{
		{"nope", 0},
		{"uuid", 8},
		{"alnum", -1},
		{"alnum", MaxLength + 1},
	} {
		if _, err := Value(tt.format, tt.length); err == nil {
			t.Errorf("Value(%q, %d): want error", tt.format, tt.length)
		}
	}
}
