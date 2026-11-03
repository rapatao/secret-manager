// Package cli implements the secret-manager client commands.
package cli

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/exec"
	"os/signal"
	"strings"
	"syscall"

	"github.com/rapatao/secret-manager/internal/client"
)

const (
	// EnvURL holds the server URL.
	EnvURL = "SECRET_MANAGER_URL"
	// EnvToken holds the admin token.
	EnvToken = "SECRET_MANAGER_TOKEN"
)

// Usage lists the client commands.
const Usage = `Client commands (configure with ` + EnvURL + ` and ` + EnvToken + `):
  list                                         list paths
  get     --path P [--recursive] [KEY]         print one value, or all as dotenv
  set     --path P [--env-file F|-] [K=V...]   merge keys into a path
  delete  --path P (KEY... | --all)            delete keys, or the whole path
  export  --path P [--recursive] [--format dotenv|json]
  run     --path P [--recursive] -- CMD [ARGS...]
                                               run CMD with secrets as env vars
`

var errUsage = errors.New("usage")

// CLI runs client commands.
type CLI struct {
	Stdin   io.Reader
	Stdout  io.Writer
	Stderr  io.Writer
	Getenv  func(string) string
	Environ func() []string
}

// Default returns a CLI bound to the process stdio and environment.
func Default() *CLI {
	return &CLI{Stdin: os.Stdin, Stdout: os.Stdout, Stderr: os.Stderr, Getenv: os.Getenv, Environ: os.Environ}
}

// Run executes args[0] with the remaining args and returns the exit code.
func (c *CLI) Run(ctx context.Context, args []string) int {
	cmds := map[string]func(context.Context, *client.Client, []string) error{
		"list":   c.list,
		"get":    c.get,
		"set":    c.set,
		"delete": c.delete,
		"export": c.export,
		"run":    c.run,
	}
	if len(args) == 0 {
		fmt.Fprint(c.Stderr, Usage)
		return 2
	}
	cmd, ok := cmds[args[0]]
	if !ok {
		fmt.Fprintf(c.Stderr, "unknown command %q\n\n%s", args[0], Usage)
		return 2
	}

	url, token := c.Getenv(EnvURL), c.Getenv(EnvToken)
	if url == "" || token == "" {
		fmt.Fprintf(c.Stderr, "%s and %s must be set\n", EnvURL, EnvToken)
		return 2
	}

	err := cmd(ctx, client.New(url, token), args[1:])
	var exit *exitError
	switch {
	case err == nil:
		return 0
	case errors.As(err, &exit):
		return exit.code
	case errors.Is(err, errUsage), errors.Is(err, flag.ErrHelp):
		fmt.Fprint(c.Stderr, Usage)
		return 2
	default:
		fmt.Fprintln(c.Stderr, "error:", err)
		return 1
	}
}

type exitError struct{ code int }

func (e *exitError) Error() string { return fmt.Sprintf("exit status %d", e.code) }

type pathFlags struct {
	fs        *flag.FlagSet
	path      string
	recursive bool
}

func (c *CLI) flags(name string, recursive bool) *pathFlags {
	p := &pathFlags{fs: flag.NewFlagSet(name, flag.ContinueOnError)}
	p.fs.SetOutput(c.Stderr)
	p.fs.StringVar(&p.path, "path", "", "secret path, like /kubernetes/app")
	if recursive {
		p.fs.BoolVar(&p.recursive, "recursive", false, "include nested paths; deeper paths win on duplicate keys")
	}
	return p
}

func (p *pathFlags) parse(args []string) error {
	if err := p.fs.Parse(args); err != nil {
		return err
	}
	if p.path == "" {
		return fmt.Errorf("%w: --path is required", errUsage)
	}
	return nil
}

func (c *CLI) list(ctx context.Context, api *client.Client, args []string) error {
	if len(args) > 0 {
		return errUsage
	}
	paths, err := api.Paths(ctx)
	if err != nil {
		return err
	}
	for _, p := range paths {
		fmt.Fprintln(c.Stdout, p)
	}
	return nil
}

func (c *CLI) get(ctx context.Context, api *client.Client, args []string) error {
	f := c.flags("get", true)
	if err := f.parse(args); err != nil {
		return err
	}
	if f.fs.NArg() > 1 {
		return errUsage
	}
	data, err := api.Get(ctx, f.path, f.recursive)
	if err != nil {
		return err
	}
	if f.fs.NArg() == 0 {
		return formatDotenv(c.Stdout, data)
	}
	key := f.fs.Arg(0)
	v, ok := data[key]
	if !ok {
		return fmt.Errorf("key %s not found in %s", key, f.path)
	}
	_, err = fmt.Fprintln(c.Stdout, v)
	return err
}

func (c *CLI) set(ctx context.Context, api *client.Client, args []string) error {
	f := c.flags("set", false)
	envFile := f.fs.String("env-file", "", "dotenv file to import, - for stdin")
	if err := f.parse(args); err != nil {
		return err
	}

	values := map[string]string{}
	if *envFile != "" {
		r := c.Stdin
		if *envFile != "-" {
			file, err := os.Open(*envFile)
			if err != nil {
				return err
			}
			defer file.Close()
			r = file
		}
		parsed, err := parseDotenv(r)
		if err != nil {
			return fmt.Errorf("%s: %w", *envFile, err)
		}
		values = parsed
	}
	for _, kv := range f.fs.Args() {
		k, v, ok := strings.Cut(kv, "=")
		if !ok {
			return fmt.Errorf("%w: %q is not KEY=VALUE", errUsage, kv)
		}
		values[k] = v
	}
	if len(values) == 0 {
		return fmt.Errorf("%w: nothing to set", errUsage)
	}
	return api.Set(ctx, f.path, values)
}

func (c *CLI) delete(ctx context.Context, api *client.Client, args []string) error {
	f := c.flags("delete", false)
	all := f.fs.Bool("all", false, "delete the whole path")
	if err := f.parse(args); err != nil {
		return err
	}
	if *all {
		if f.fs.NArg() > 0 {
			return fmt.Errorf("%w: --all takes no keys", errUsage)
		}
		return api.DeletePath(ctx, f.path)
	}
	if f.fs.NArg() == 0 {
		return fmt.Errorf("%w: give keys or --all", errUsage)
	}
	for _, k := range f.fs.Args() {
		if err := api.DeleteKey(ctx, f.path, k); err != nil {
			return err
		}
	}
	return nil
}

func (c *CLI) export(ctx context.Context, api *client.Client, args []string) error {
	f := c.flags("export", true)
	format := f.fs.String("format", "dotenv", "dotenv or json")
	if err := f.parse(args); err != nil {
		return err
	}
	if *format != "dotenv" && *format != "json" {
		return fmt.Errorf("%w: unknown format %q", errUsage, *format)
	}
	data, err := api.Get(ctx, f.path, f.recursive)
	if err != nil {
		return err
	}
	if *format == "dotenv" {
		return formatDotenv(c.Stdout, data)
	}
	enc := json.NewEncoder(c.Stdout)
	enc.SetIndent("", "  ")
	return enc.Encode(data)
}

func (c *CLI) run(ctx context.Context, api *client.Client, args []string) error {
	f := c.flags("run", true)
	if err := f.parse(args); err != nil {
		return err
	}
	if f.fs.NArg() == 0 {
		return fmt.Errorf("%w: missing command", errUsage)
	}
	data, err := api.Get(ctx, f.path, f.recursive)
	if err != nil {
		return err
	}

	cmd := exec.Command(f.fs.Arg(0), f.fs.Args()[1:]...) //nolint:gosec // running the user-given command is the purpose of run
	cmd.Stdin, cmd.Stdout, cmd.Stderr = c.Stdin, c.Stdout, c.Stderr
	cmd.Env = mergeEnv(c.Environ(), data)
	if err := cmd.Start(); err != nil {
		return err
	}

	sigs := make(chan os.Signal, 1)
	signal.Notify(sigs, os.Interrupt, syscall.SIGTERM)
	defer func() {
		signal.Stop(sigs)
		close(sigs)
	}()
	go func() {
		for s := range sigs {
			_ = cmd.Process.Signal(s)
		}
	}()

	err = cmd.Wait()
	var exitErr *exec.ExitError
	if errors.As(err, &exitErr) {
		return &exitError{code: max(exitErr.ExitCode(), 1)}
	}
	return err
}

// mergeEnv returns environ with secrets added; secrets override variables
// already set.
func mergeEnv(environ []string, secrets map[string]string) []string {
	out := make([]string, 0, len(environ)+len(secrets))
	for _, kv := range environ {
		k, _, _ := strings.Cut(kv, "=")
		if _, ok := secrets[k]; !ok {
			out = append(out, kv)
		}
	}
	for k, v := range secrets {
		out = append(out, k+"="+v)
	}
	return out
}
