// Package generate makes random secret values.
package generate

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"slices"
	"strings"
)

const (
	// DefaultFormat is used when no format is given.
	DefaultFormat = "alnum"
	// MaxLength is the largest length any format accepts.
	MaxLength = 4096
	// MaxCount is the most values one request generates.
	MaxCount = 100
)

const (
	alnum   = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"
	symbols = alnum + "!#$%&*+-.:=?@^_~"
	digits  = "0123456789"
)

// Formats lists the supported formats, in the order shown to users.
var Formats = []string{"alnum", "symbols", "digits", "hex", "base64", "uuid"}

// DefaultLength returns the length used for format when none is given: a
// number of characters for alnum, symbols and digits, of random bytes for hex
// and base64, and 0 for uuid, which takes no length.
func DefaultLength(format string) int {
	switch format {
	case "digits":
		return 6
	case "uuid":
		return 0
	default:
		return 32
	}
}

// Value returns a random value in format. A length of 0 uses DefaultLength.
func Value(format string, length int) (string, error) {
	if err := Check(format, length); err != nil {
		return "", err
	}
	if length == 0 {
		length = DefaultLength(format)
	}
	switch format {
	case "alnum":
		return fromAlphabet(alnum, length), nil
	case "symbols":
		return fromAlphabet(symbols, length), nil
	case "digits":
		return fromAlphabet(digits, length), nil
	case "hex":
		return hex.EncodeToString(randomBytes(length)), nil
	case "base64":
		return base64.StdEncoding.EncodeToString(randomBytes(length)), nil
	default:
		return uuidV4(), nil
	}
}

// Check reports whether format exists and accepts length, 0 meaning the
// default.
func Check(format string, length int) error {
	if !slices.Contains(Formats, format) {
		return fmt.Errorf("format %q must be one of %s", format, strings.Join(Formats, ", "))
	}
	if format == "uuid" && length != 0 {
		return fmt.Errorf("format uuid takes no length")
	}
	if length < 0 || length > MaxLength {
		return fmt.Errorf("length %d must be between 1 and %d", length, MaxLength)
	}
	return nil
}

func randomBytes(n int) []byte {
	b := make([]byte, n)
	_, _ = rand.Read(b)
	return b
}

// fromAlphabet returns n characters drawn uniformly from alphabet, rejecting
// bytes at or above the largest multiple of len(alphabet) below 256.
func fromAlphabet(alphabet string, n int) string {
	limit := 256 - 256%len(alphabet)
	out := make([]byte, 0, n)
	for len(out) < n {
		for _, b := range randomBytes(n) {
			if int(b) < limit && len(out) < n {
				out = append(out, alphabet[int(b)%len(alphabet)])
			}
		}
	}
	return string(out)
}

func uuidV4() string {
	b := randomBytes(16)
	b[6] = b[6]&0x0f | 0x40
	b[8] = b[8]&0x3f | 0x80
	return fmt.Sprintf("%x-%x-%x-%x-%x", b[0:4], b[4:6], b[6:8], b[8:10], b[10:])
}
