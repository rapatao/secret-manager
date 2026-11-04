package cli

import (
	"bytes"
	"cmp"
	"io"
	"maps"
	"slices"
)

const maskText = "***"

// maskWriter replaces every secret value written to w with maskText. Bytes
// that may be the start of a secret split across writes are held until the
// next Write or Flush.
type maskWriter struct {
	w       io.Writer
	secrets [][]byte
	buf     []byte
}

func newMaskWriter(w io.Writer, secrets map[string]string) *maskWriter {
	m := &maskWriter{w: w}
	for _, v := range slices.Sorted(maps.Values(secrets)) {
		if v != "" {
			m.secrets = append(m.secrets, []byte(v))
		}
	}
	slices.SortStableFunc(m.secrets, func(a, b []byte) int { return cmp.Compare(len(b), len(a)) })
	m.secrets = slices.CompactFunc(m.secrets, bytes.Equal)
	return m
}

func (m *maskWriter) Write(p []byte) (int, error) {
	m.buf = append(m.buf, p...)
	if err := m.emit(false); err != nil {
		return 0, err
	}
	return len(p), nil
}

// Flush writes the held bytes, masking any complete secret among them.
func (m *maskWriter) Flush() error {
	return m.emit(true)
}

func (m *maskWriter) emit(final bool) error {
	var out []byte
	i := 0
scan:
	for i < len(m.buf) {
		rest := m.buf[i:]
		if !final && m.partial(rest) {
			break
		}
		for _, s := range m.secrets {
			if bytes.HasPrefix(rest, s) {
				out = append(out, maskText...)
				i += len(s)
				continue scan
			}
		}
		out = append(out, m.buf[i])
		i++
	}
	m.buf = append(m.buf[:0], m.buf[i:]...)
	if len(out) == 0 {
		return nil
	}
	_, err := m.w.Write(out)
	return err
}

// partial reports whether rest is a proper prefix of a secret, so more
// input could complete it.
func (m *maskWriter) partial(rest []byte) bool {
	for _, s := range m.secrets {
		if len(rest) < len(s) && bytes.HasPrefix(s, rest) {
			return true
		}
	}
	return false
}
