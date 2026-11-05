package cli

import (
	"bufio"
	"bytes"
	"cmp"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"maps"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"unicode/utf8"

	"github.com/rapatao/secret-manager/internal/client"
	"github.com/rapatao/secret-manager/internal/secrets"
)

// scanMinLength is the default shortest value scan looks for; shorter
// values, like "1" or "true", would match almost every file.
const scanMinLength = 8

type leak struct {
	Commit string `json:"commit,omitempty"`
	File   string `json:"file"`
	Line   int    `json:"line"`
	Path   string `json:"path"`
	Key    string `json:"key"`
}

func (l leak) String() string {
	if l.Commit != "" {
		return fmt.Sprintf("%s:%s:%d: %s %s", l.Commit[:min(12, len(l.Commit))], l.File, l.Line, l.Path, l.Key)
	}
	return fmt.Sprintf("%s:%d: %s %s", l.File, l.Line, l.Path, l.Key)
}

type secretValue struct {
	path  string
	key   string
	value []byte
}

func (c *CLI) scan(ctx context.Context, args []string) error {
	f := c.flags("scan", true, true)
	history := f.fs.Bool("history", false, "also scan lines added in every commit of the git repository")
	asJSON := f.fs.Bool("json", false, "print findings as a JSON array")
	minLength := f.fs.Int("min-length", scanMinLength, "skip values shorter than this many characters")
	api, err := f.parse(args)
	if err != nil {
		return err
	}
	if *minLength < 1 {
		return fmt.Errorf("%w: --min-length must be at least 1", errUsage)
	}
	secrets, err := c.scanSecrets(ctx, f, api, *minLength)
	if err != nil {
		return err
	}

	targets := f.fs.Args()
	if len(targets) == 0 {
		targets = []string{"."}
	}
	var leaks []leak
	for _, t := range targets {
		found, err := scanTree(c.resolve(t), t, secrets)
		if err != nil {
			return err
		}
		leaks = append(leaks, found...)
	}
	if *history {
		found, err := scanHistory(ctx, c.resolve("."), f.fs.Args(), secrets)
		if err != nil {
			return err
		}
		leaks = append(leaks, found...)
	}

	if *asJSON {
		enc := json.NewEncoder(c.Stdout)
		enc.SetIndent("", "  ")
		if leaks == nil {
			leaks = []leak{}
		}
		if err := enc.Encode(leaks); err != nil {
			return err
		}
	} else {
		for _, l := range leaks {
			fmt.Fprintln(c.Stdout, l)
		}
	}
	if len(leaks) > 0 {
		return &exitError{code: 1}
	}
	if !*asJSON {
		fmt.Fprintln(c.Stderr, "no secret values found")
	}
	return nil
}

// scanSecrets reads the values to look for: those of --path, or with
// --recursive of every path under it, each kept with its own path. Values
// shorter than minLength characters are skipped and listed on stderr.
func (c *CLI) scanSecrets(ctx context.Context, f *flags, api *client.Client, minLength int) ([]secretValue, error) {
	root, err := secrets.NormalizePath(f.path)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", errUsage, err)
	}
	var all []pathData
	if f.recursive {
		if all, err = pathsUnder(ctx, api, root); err != nil {
			return nil, err
		}
	} else {
		data, err := api.Get(ctx, root, false)
		if err != nil {
			return nil, err
		}
		all = []pathData{{root, data}}
	}
	var out []secretValue
	var short []string
	for _, p := range all {
		for _, k := range slices.Sorted(maps.Keys(p.data)) {
			switch v := p.data[k]; {
			case v == "":
			case utf8.RuneCountInString(v) < minLength:
				short = append(short, p.path+" "+k)
			default:
				out = append(out, secretValue{p.path, k, []byte(v)})
			}
		}
	}
	if len(short) > 0 {
		fmt.Fprintf(c.Stderr, "not scanning values shorter than %d characters (--min-length):\n", minLength)
		for _, s := range short {
			fmt.Fprintln(c.Stderr, "  "+s)
		}
	}
	return out, nil
}

func (c *CLI) resolve(name string) string {
	if filepath.IsAbs(name) {
		return name
	}
	return filepath.Join(c.Dir, name)
}

// scanTree scans root, a file or a directory walked without following
// symlinks, skipping .git directories and binary files. Findings name files
// under shown, the root as the user gave it.
func scanTree(root, shown string, secrets []secretValue) ([]leak, error) {
	var leaks []leak
	err := filepath.WalkDir(root, func(name string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			if d.Name() == ".git" {
				return filepath.SkipDir
			}
			return nil
		}
		if !d.Type().IsRegular() {
			return nil
		}
		content, err := os.ReadFile(name) //nolint:gosec // read-only; a swapped symlink only reads another file the user can read
		if err != nil {
			return err
		}
		if isBinary(content) {
			return nil
		}
		rel, err := filepath.Rel(root, name)
		if err != nil {
			return err
		}
		file := filepath.Join(shown, rel)
		for _, m := range findSecrets(content, secrets) {
			leaks = append(leaks, leak{File: file, Line: m.line, Path: m.secret.path, Key: m.secret.key})
		}
		return nil
	})
	return leaks, err
}

// isBinary uses git's heuristic: a NUL byte in the first 8000 bytes.
func isBinary(content []byte) bool {
	return bytes.IndexByte(content[:min(len(content), 8000)], 0) >= 0
}

type match struct {
	line   int
	secret secretValue
}

// findSecrets returns the 1-based line and secret of every secret value in
// content, once per line and secret, in line order.
func findSecrets(content []byte, secrets []secretValue) []match {
	var out []match
	for _, s := range secrets {
		last := 0
		for off := 0; ; {
			i := bytes.Index(content[off:], s.value)
			if i < 0 {
				break
			}
			off += i
			line := bytes.Count(content[:off], []byte{'\n'}) + 1
			if line != last {
				out = append(out, match{line, s})
				last = line
			}
			off += len(s.value)
		}
	}
	slices.SortStableFunc(out, func(a, b match) int { return cmp.Compare(a.line, b.line) })
	return out
}

// scanHistory scans the lines added by every commit reachable from any ref of
// the git repository at dir, limited to paths when given.
func scanHistory(ctx context.Context, dir string, paths []string, secrets []secretValue) ([]leak, error) {
	args := []string{"-C", dir, "-c", "core.quotePath=false", "log", "--all", "-p", "--no-color", "--no-ext-diff", "--no-textconv", "--format=commit %H", "--"}
	cmd := exec.CommandContext(ctx, "git", append(args, paths...)...) //nolint:gosec // fixed git arguments; user paths only follow --
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	out, err := cmd.StdoutPipe()
	if err != nil {
		return nil, err
	}
	if err := cmd.Start(); err != nil {
		return nil, err
	}
	leaks, perr := parseHistory(out, secrets)
	if err := cmd.Wait(); err != nil {
		return nil, fmt.Errorf("git log: %w: %s", err, strings.TrimSpace(stderr.String()))
	}
	return leaks, perr
}

// parseHistory reads `git log -p --format="commit %H"` output and scans the
// added lines of each file of each commit.
func parseHistory(r io.Reader, secrets []secretValue) ([]leak, error) {
	var (
		leaks        []leak
		commit, file string
		added        []byte
		lines        []int
		inHunk       bool
		next         int
	)
	flush := func() {
		for _, m := range findSecrets(added, secrets) {
			leaks = append(leaks, leak{Commit: commit, File: file, Line: lines[m.line-1], Path: m.secret.path, Key: m.secret.key})
		}
		added, lines = added[:0], lines[:0]
	}
	br := bufio.NewReader(r)
	for {
		raw, err := br.ReadBytes('\n')
		if len(raw) > 0 {
			line := bytes.TrimSuffix(raw, []byte{'\n'})
			switch {
			case bytes.HasPrefix(line, []byte("commit ")):
				flush()
				commit, file, inHunk = string(line[len("commit "):]), "", false
			case bytes.HasPrefix(line, []byte("diff ")):
				flush()
				file, inHunk = "", false
			case !inHunk && bytes.HasPrefix(line, []byte("+++ ")):
				file = strings.TrimPrefix(string(line[len("+++ "):]), "b/")
			case bytes.HasPrefix(line, []byte("@@ ")):
				inHunk = true
				next = hunkStart(line)
			case inHunk && len(line) > 0 && line[0] == '+':
				added = append(append(added, line[1:]...), '\n')
				lines = append(lines, next)
				next++
			case inHunk && len(line) > 0 && line[0] == ' ':
				next++
			}
		}
		if errors.Is(err, io.EOF) {
			flush()
			return leaks, nil
		}
		if err != nil {
			return nil, err
		}
	}
}

// hunkStart returns the first new-file line of a "@@ -a,b +c,d @@" header.
func hunkStart(header []byte) int {
	_, rest, _ := strings.Cut(string(header), " +")
	n, _, _ := strings.Cut(rest, ",")
	n, _, _ = strings.Cut(n, " ")
	start, _ := strconv.Atoi(n)
	return start
}
