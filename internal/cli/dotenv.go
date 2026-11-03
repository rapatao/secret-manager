package cli

import (
	"bufio"
	"fmt"
	"io"
	"maps"
	"slices"
	"strings"
)

// parseDotenv reads KEY=VALUE lines. Blank lines, # comments and an optional
// "export " prefix are accepted. Values may be bare, 'single quoted' (literal)
// or "double quoted" with \\ \" \n \r \t \$ escapes.
func parseDotenv(r io.Reader) (map[string]string, error) {
	out := map[string]string{}
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 0, 64<<10), 1<<20)
	for n := 1; sc.Scan(); n++ {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		line = strings.TrimPrefix(line, "export ")
		key, raw, ok := strings.Cut(line, "=")
		if !ok {
			return nil, fmt.Errorf("line %d: missing '='", n)
		}
		val, err := unquote(strings.TrimSpace(raw))
		if err != nil {
			return nil, fmt.Errorf("line %d: %w", n, err)
		}
		out[strings.TrimSpace(key)] = val
	}
	return out, sc.Err()
}

func unquote(s string) (string, error) {
	if len(s) < 2 {
		return s, nil
	}
	switch q := s[0]; {
	case q == '\'' && s[len(s)-1] == '\'':
		return s[1 : len(s)-1], nil
	case q == '"' && s[len(s)-1] == '"':
		var b strings.Builder
		in := s[1 : len(s)-1]
		for i := 0; i < len(in); i++ {
			if in[i] != '\\' {
				b.WriteByte(in[i])
				continue
			}
			i++
			if i == len(in) {
				return "", fmt.Errorf("trailing backslash in %s", s)
			}
			switch in[i] {
			case 'n':
				b.WriteByte('\n')
			case 'r':
				b.WriteByte('\r')
			case 't':
				b.WriteByte('\t')
			default:
				b.WriteByte(in[i])
			}
		}
		return b.String(), nil
	}
	return s, nil
}

var dotenvEscaper = strings.NewReplacer(`\`, `\\`, `"`, `\"`, "\n", `\n`, "\r", `\r`, "$", `\$`)

// formatDotenv writes sorted KEY="VALUE" lines that parseDotenv reads back.
func formatDotenv(w io.Writer, data map[string]string) error {
	for _, k := range slices.Sorted(maps.Keys(data)) {
		if _, err := fmt.Fprintf(w, "%s=\"%s\"\n", k, dotenvEscaper.Replace(data[k])); err != nil {
			return err
		}
	}
	return nil
}
