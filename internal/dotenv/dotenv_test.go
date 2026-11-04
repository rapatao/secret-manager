package dotenv

import (
	"bytes"
	"maps"
	"strings"
	"testing"
)

func TestDotenvRoundTrip(t *testing.T) {
	in := map[string]string{"A": `quote " back \ dollar $HOME`, "B": "line1\nline2\r\n", "C": ""}
	var buf bytes.Buffer
	if err := Format(&buf, in); err != nil {
		t.Fatal(err)
	}
	out, err := Parse(&buf)
	if err != nil {
		t.Fatal(err)
	}
	if !maps.Equal(in, out) {
		t.Fatalf("round trip: got %q, want %q", out, in)
	}
}

func TestParseDotenvErrors(t *testing.T) {
	for _, in := range []string{"NOEQUALS", `A="trailing\"`} {
		if _, err := Parse(strings.NewReader(in)); err == nil {
			t.Errorf("%q: want error", in)
		}
	}
}
