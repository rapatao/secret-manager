// Package cli implements the secret-manager client commands.
package cli

import (
	"bufio"
	"cmp"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"slices"
	"strings"
	"syscall"

	"golang.org/x/term"

	"github.com/rapatao/secret-manager/internal/client"
)

const (
	// EnvURL holds the server URL.
	EnvURL = "SECRET_MANAGER_URL"
	// EnvToken holds the admin token.
	EnvToken = "SECRET_MANAGER_TOKEN"
)

// Usage lists the client commands.
const Usage = `Client commands:
  servers [list]                               list logged-in servers, marking the default
  servers login --server URL [--token-stdin]   check and store a token, make URL the default
  servers logout [--server URL]                remove the stored token
  servers use URL                              make a logged-in server the default
  list                                         list paths
  get     --path P [--recursive] [KEY]         print one value, or all as dotenv
  set     --path P [--env-file F|-] [K=V...]   merge keys into a path
  delete  --path P (KEY... | --all)            delete keys, or the whole path
  export  --path P [--recursive] [--format dotenv|json]
  run     --path P [--recursive] -- CMD [ARGS...]
                                               run CMD with secrets as env vars

Every command accepts --server URL. Without it, $` + EnvURL + ` or the
default server is used. $` + EnvToken + ` is only sent to $` + EnvURL + `;
any other server uses the token stored by servers login.
`

var errUsage = errors.New("usage")

// CLI runs client commands.
type CLI struct {
	Stdin   io.Reader
	Stdout  io.Writer
	Stderr  io.Writer
	Getenv  func(string) string
	Environ func() []string
	// ConfigDir holds the default server and, without a usable OS keychain,
	// stored tokens.
	ConfigDir string
}

// Default returns a CLI bound to the process stdio and environment.
func Default() *CLI {
	return &CLI{
		Stdin:     os.Stdin,
		Stdout:    os.Stdout,
		Stderr:    os.Stderr,
		Getenv:    os.Getenv,
		Environ:   os.Environ,
		ConfigDir: DefaultConfigDir(),
	}
}

// Run executes args[0] with the remaining args and returns the exit code.
func (c *CLI) Run(ctx context.Context, args []string) int {
	cmds := map[string]func(context.Context, []string) error{
		"servers": c.servers,
		"list":    c.list,
		"get":     c.get,
		"set":     c.set,
		"delete":  c.delete,
		"export":  c.export,
		"run":     c.run,
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

	err := cmd(ctx, args[1:])
	var exit *exitError
	switch {
	case err == nil:
		return 0
	case errors.As(err, &exit):
		return exit.code
	case errors.Is(err, flag.ErrHelp):
		fmt.Fprint(c.Stderr, Usage)
		return 2
	case errors.Is(err, errUsage):
		fmt.Fprintf(c.Stderr, "error: %v\n\n%s", err, Usage)
		return 2
	default:
		fmt.Fprintln(c.Stderr, "error:", err)
		return 1
	}
}

type exitError struct{ code int }

func (e *exitError) Error() string { return fmt.Sprintf("exit status %d", e.code) }

type flags struct {
	fs        *flag.FlagSet
	store     store
	envURL    string
	envToken  string
	server    string
	path      string
	recursive bool
	needPath  bool
}

// flags returns a flag set with --server and, when withPath, --path and
// optionally --recursive.
func (c *CLI) flags(name string, withPath, recursive bool) *flags {
	f := &flags{
		fs:       flag.NewFlagSet(name, flag.ContinueOnError),
		store:    store{dir: c.ConfigDir},
		envURL:   normalizeServer(c.Getenv(EnvURL)),
		envToken: c.Getenv(EnvToken),
		needPath: withPath,
	}
	f.fs.SetOutput(io.Discard)
	f.fs.StringVar(&f.server, "server", "", "server URL")
	if withPath {
		f.fs.StringVar(&f.path, "path", "", "secret path, like /kubernetes/app")
	}
	if recursive {
		f.fs.BoolVar(&f.recursive, "recursive", false, "include nested paths; deeper paths win on duplicate keys")
	}
	return f
}

// parseFlags parses args and resolves the server: --server, then
// $SECRET_MANAGER_URL, then the default server.
func (f *flags) parseFlags(args []string) error {
	if err := f.fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return err
		}
		return fmt.Errorf("%w: %s: %w", errUsage, f.fs.Name(), err)
	}
	if f.needPath && f.path == "" {
		return fmt.Errorf("%w: --path is required", errUsage)
	}
	f.server = cmp.Or(normalizeServer(f.server), f.envURL)
	if f.server == "" {
		cfg, err := f.store.config()
		if err != nil {
			return err
		}
		f.server = cfg.Server
	}
	if f.server == "" {
		return fmt.Errorf("%w: give --server, set %s or run servers login", errUsage, EnvURL)
	}
	return nil
}

// parse parses args and returns a client for the resolved server.
// $SECRET_MANAGER_TOKEN belongs to $SECRET_MANAGER_URL and is only sent to
// that server; every other server uses the token stored by servers login.
func (f *flags) parse(args []string) (*client.Client, error) {
	if err := f.parseFlags(args); err != nil {
		return nil, err
	}
	if f.envToken != "" && f.envURL == "" {
		return nil, fmt.Errorf("%w: %s is set but %s is not; set both, or unset %s to use stored logins",
			errUsage, EnvToken, EnvURL, EnvToken)
	}
	if f.envToken != "" && f.server == f.envURL {
		return client.New(f.server, f.envToken), nil
	}
	token, err := f.store.token(f.server)
	if err != nil {
		return nil, err
	}
	if token == "" {
		return nil, fmt.Errorf("%w: no token for %s; run servers login --server %s", errUsage, f.server, f.server)
	}
	return client.New(f.server, token), nil
}

func (c *CLI) servers(ctx context.Context, args []string) error {
	sub, rest := "list", args
	if len(args) > 0 {
		sub, rest = args[0], args[1:]
	}
	switch sub {
	case "list":
		return c.serversList(rest)
	case "login":
		return c.serversLogin(ctx, rest)
	case "logout":
		return c.serversLogout(rest)
	case "use":
		return c.serversUse(rest)
	default:
		return fmt.Errorf("%w: unknown servers command %q", errUsage, sub)
	}
}

func (c *CLI) serversList(args []string) error {
	if len(args) > 0 {
		return fmt.Errorf("%w: servers list takes no arguments", errUsage)
	}
	cfg, err := (store{dir: c.ConfigDir}).config()
	if err != nil {
		return err
	}
	for _, server := range cfg.Servers {
		if server == cfg.Server {
			fmt.Fprintf(c.Stdout, "%s (default)\n", server)
		} else {
			fmt.Fprintln(c.Stdout, server)
		}
	}
	return nil
}

func (c *CLI) serversUse(args []string) error {
	if len(args) != 1 {
		return fmt.Errorf("%w: servers use takes one URL", errUsage)
	}
	st := store{dir: c.ConfigDir}
	cfg, err := st.config()
	if err != nil {
		return err
	}
	server := normalizeServer(args[0])
	if !slices.Contains(cfg.Servers, server) {
		return fmt.Errorf("not logged in to %s; run servers login --server %s", server, server)
	}
	cfg.Server = server
	if err := st.saveConfig(cfg); err != nil {
		return err
	}
	fmt.Fprintf(c.Stdout, "Default server is %s\n", server)
	return nil
}

func (c *CLI) serversLogin(ctx context.Context, args []string) error {
	f := c.flags("servers login", false, false)
	fromStdin := f.fs.Bool("token-stdin", false, "read the token from stdin")
	if err := f.parseFlags(args); err != nil {
		return err
	}
	if f.fs.NArg() > 0 {
		return fmt.Errorf("%w: servers login takes no arguments", errUsage)
	}

	token, err := c.readToken(*fromStdin)
	if err != nil {
		return err
	}
	if _, err := client.New(f.server, token).Paths(ctx); err != nil {
		var apiErr *client.Error
		if errors.As(err, &apiErr) && apiErr.Status == http.StatusUnauthorized {
			return fmt.Errorf("login to %s failed: invalid token", f.server)
		}
		return fmt.Errorf("login to %s failed: %w", f.server, err)
	}

	fallback, err := f.store.saveToken(f.server, token)
	if err != nil {
		return err
	}
	cfg, err := f.store.config()
	if err != nil {
		return err
	}
	cfg.add(f.server)
	cfg.Server = f.server
	if err := f.store.saveConfig(cfg); err != nil {
		return err
	}
	if fallback != nil {
		fmt.Fprintf(c.Stderr, "warning: OS keychain unavailable (%v); token stored in %s with 0600 permissions\n",
			fallback, filepath.Join(f.store.dir, "credentials.json"))
	}
	fmt.Fprintf(c.Stdout, "Logged in to %s\n", f.server)
	return nil
}

func (c *CLI) readToken(fromStdin bool) (string, error) {
	if fromStdin {
		line, err := bufio.NewReader(c.Stdin).ReadString('\n')
		if err != nil && !errors.Is(err, io.EOF) {
			return "", err
		}
		if token := strings.TrimSpace(line); token != "" {
			return token, nil
		}
		return "", fmt.Errorf("%w: empty token on stdin", errUsage)
	}
	in, ok := c.Stdin.(*os.File)
	if !ok || !term.IsTerminal(int(in.Fd())) {
		return "", fmt.Errorf("%w: stdin is not a terminal; use --token-stdin", errUsage)
	}
	fmt.Fprint(c.Stderr, "Token: ")
	b, err := term.ReadPassword(int(in.Fd()))
	fmt.Fprintln(c.Stderr)
	if err != nil {
		return "", err
	}
	if token := strings.TrimSpace(string(b)); token != "" {
		return token, nil
	}
	return "", fmt.Errorf("%w: empty token", errUsage)
}

func (c *CLI) serversLogout(args []string) error {
	f := c.flags("servers logout", false, false)
	if err := f.parseFlags(args); err != nil {
		return err
	}
	if f.fs.NArg() > 0 {
		return fmt.Errorf("%w: servers logout takes no arguments", errUsage)
	}
	if err := f.store.removeToken(f.server); err != nil {
		return err
	}
	cfg, err := f.store.config()
	if err != nil {
		return err
	}
	cfg.remove(f.server)
	if err := f.store.saveConfig(cfg); err != nil {
		return err
	}
	fmt.Fprintf(c.Stdout, "Logged out of %s\n", f.server)
	return nil
}

func (c *CLI) list(ctx context.Context, args []string) error {
	f := c.flags("list", false, false)
	api, err := f.parse(args)
	if err != nil {
		return err
	}
	if f.fs.NArg() > 0 {
		return fmt.Errorf("%w: list takes no arguments", errUsage)
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

func (c *CLI) get(ctx context.Context, args []string) error {
	f := c.flags("get", true, true)
	api, err := f.parse(args)
	if err != nil {
		return err
	}
	if f.fs.NArg() > 1 {
		return fmt.Errorf("%w: get takes at most one KEY", errUsage)
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

func (c *CLI) set(ctx context.Context, args []string) error {
	f := c.flags("set", true, false)
	envFile := f.fs.String("env-file", "", "dotenv file to import, - for stdin")
	api, err := f.parse(args)
	if err != nil {
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

func (c *CLI) delete(ctx context.Context, args []string) error {
	f := c.flags("delete", true, false)
	all := f.fs.Bool("all", false, "delete the whole path")
	api, err := f.parse(args)
	if err != nil {
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

func (c *CLI) export(ctx context.Context, args []string) error {
	f := c.flags("export", true, true)
	format := f.fs.String("format", "dotenv", "dotenv or json")
	api, err := f.parse(args)
	if err != nil {
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

func (c *CLI) run(ctx context.Context, args []string) error {
	f := c.flags("run", true, true)
	api, err := f.parse(args)
	if err != nil {
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
