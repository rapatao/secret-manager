// Package cli implements the secret-manager client commands.
package cli

import (
	"bufio"
	"cmp"
	"context"
	"crypto/rand"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"maps"
	"net/http"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"syscall"
	"text/tabwriter"
	"time"

	"github.com/rapatao/secret-manager/internal/client"
	"github.com/rapatao/secret-manager/internal/secrets"
	"github.com/rapatao/secret-manager/internal/storage"
	"github.com/rapatao/secret-manager/internal/storage/encrypted"
)

const (
	// EnvURL holds the server URL.
	EnvURL = "SECRET_MANAGER_URL"
	// EnvToken holds an integration token.
	EnvToken = "SECRET_MANAGER_TOKEN"
	// EnvBackupKey holds the base64 AES-256 key encrypting backups.
	EnvBackupKey = "SECRET_MANAGER_BACKUP_KEY"
)

// Usage lists the client commands.
const Usage = `Client commands:
  servers [list]                               list logged-in servers, marking the default
  servers login --server URL [--device | --token-stdin]
                                               approve a new integration in the browser,
                                               or read a token from stdin; store the
                                               token and make URL the default
  servers logout [--server URL]                remove the stored token
  servers use URL                              make a logged-in server the default
  list                                         list paths
  keys    --path P [--recursive]               list key names, without values; with
                                               --recursive, as PATH KEY for every
                                               nested path
  get     --path P [--recursive] [KEY]         print one value, or all as dotenv
  set     --path P [--env-file F|-] [--generate KEY[:LEN]...] [K=V...]
                                               merge keys into a path; --generate sets
                                               KEY to LEN (default 32) random letters
                                               and digits
  delete  --path P (KEY... | --all)            delete keys, or the whole path
  copy    --path P --to Q                      copy a path and its history to a new path
  move    --path P --to Q                      move a path and its history to a new path
  export  --path P [--recursive] [--format dotenv|json]
  history --path P [VERSION]                   list versions, or print one as dotenv
  history --path P --diff VERSION [VERSION2]   list keys added (+), removed (-) or
                                               changed (~) since VERSION, up to
                                               VERSION2 or the current data
  history --path P --delete VERSION...         delete versions, keeping the current data
  rollback --path P VERSION                    restore a version
  backup  [--history] [--output F]             print or write (0600) every path as JSON,
                                               encrypted when $` + EnvBackupKey + `
                                               is set
  restore FILE|-                               replace the paths held in a backup,
                                               decrypting it with $` + EnvBackupKey + `
  run     --path P [--recursive] -- CMD [ARGS...]
                                               run CMD with secrets as env vars
  version                                      print the client version and, when a
                                               server is set, its version and capabilities

get, export and run fall back to the last secrets read, kept encrypted for
as long as the server allows (default 168h), when the server is unreachable.
$` + EnvCacheMaxAge + ` can only lower that, 0 disables. servers logout
removes them.

Every command accepts --server URL. Without it, $` + EnvURL + ` or the
default server is used. $` + EnvToken + ` is only sent to $` + EnvURL + `;
any other server uses the token stored by servers login.
`

var errUsage = errors.New("usage")

var errNoServer = fmt.Errorf("%w: give --server, set %s or run servers login", errUsage, EnvURL)

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
	// Version is the client version printed by the version command.
	Version string
	// OpenBrowser opens a URL for servers login.
	OpenBrowser func(string) error
}

// Default returns a CLI bound to the process stdio and environment.
func Default() *CLI {
	return &CLI{
		Stdin:       os.Stdin,
		Stdout:      os.Stdout,
		Stderr:      os.Stderr,
		Getenv:      os.Getenv,
		Environ:     os.Environ,
		ConfigDir:   DefaultConfigDir(),
		OpenBrowser: openBrowser,
	}
}

// Run executes args[0] with the remaining args and returns the exit code.
func (c *CLI) Run(ctx context.Context, args []string) int {
	cmds := map[string]func(context.Context, []string) error{
		"servers":  c.servers,
		"list":     c.list,
		"keys":     c.keys,
		"get":      c.get,
		"set":      c.set,
		"delete":   c.delete,
		"copy":     c.copyPath(false),
		"move":     c.copyPath(true),
		"export":   c.export,
		"run":      c.run,
		"history":  c.history,
		"rollback": c.rollback,
		"version":  c.version,
		"backup":   c.backup,
		"restore":  c.restore,
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
		var apiErr *client.Error
		if errors.As(err, &apiErr) && apiErr.Status == http.StatusUnauthorized {
			fmt.Fprintln(c.Stderr, "Run servers login to get a new token.")
		}
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
		f.fs.BoolVar(&f.recursive, "recursive", false, "include nested paths, merged in path order; a nested path wins over its parents")
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
		return errNoServer
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
	device := f.fs.Bool("device", false, "approve the login from another device instead of a browser on this computer")
	if err := f.parseFlags(args); err != nil {
		return err
	}
	if f.fs.NArg() > 0 {
		return fmt.Errorf("%w: servers login takes no arguments", errUsage)
	}
	if *fromStdin && *device {
		return fmt.Errorf("%w: --token-stdin and --device cannot be combined", errUsage)
	}

	var token, granted string
	if *fromStdin {
		var err error
		if token, err = c.readToken(); err != nil {
			return err
		}
		if _, err := client.New(f.server, token).Paths(ctx); err != nil {
			var apiErr *client.Error
			if errors.As(err, &apiErr) && apiErr.Status == http.StatusUnauthorized {
				msg := "invalid token"
				if strings.HasPrefix(apiErr.Message, "token expired") {
					msg = apiErr.Message
				}
				return fmt.Errorf("login to %s failed: %s", f.server, msg)
			}
			return fmt.Errorf("login to %s failed: %w", f.server, err)
		}
	} else {
		login, err := c.browserLogin(ctx, f.server, *device)
		if err != nil {
			return fmt.Errorf("login to %s failed: %w", f.server, err)
		}
		token, granted = login.Token, describeLogin(login)
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
	fmt.Fprintf(c.Stdout, "Logged in to %s%s\n", f.server, granted)
	return nil
}

func describeLogin(l client.Login) string {
	access := "read-write"
	if l.ReadOnly {
		access = "read-only"
	}
	expires := "never expires"
	if !l.Expires.IsZero() {
		expires = "expires " + l.Expires.Format(time.RFC3339)
	}
	return fmt.Sprintf(" as integration %s (%s, %s, %s)", l.Name, l.Path, access, expires)
}

func (c *CLI) readToken() (string, error) {
	line, err := bufio.NewReader(c.Stdin).ReadString('\n')
	if err != nil && !errors.Is(err, io.EOF) {
		return "", err
	}
	if token := strings.TrimSpace(line); token != "" {
		return token, nil
	}
	return "", fmt.Errorf("%w: empty token on stdin", errUsage)
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
	ch, err := c.cache()
	if err != nil {
		return err
	}
	if err := ch.clear(f.server); err != nil {
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

func (c *CLI) keys(ctx context.Context, args []string) error {
	f := c.flags("keys", true, true)
	api, err := f.parse(args)
	if err != nil {
		return err
	}
	if f.fs.NArg() > 0 {
		return fmt.Errorf("%w: keys takes no arguments", errUsage)
	}
	root, err := secrets.NormalizePath(f.path)
	if err != nil {
		return fmt.Errorf("%w: %w", errUsage, err)
	}
	if !f.recursive {
		data, err := api.Get(ctx, root, false)
		if err != nil {
			return err
		}
		for _, k := range slices.Sorted(maps.Keys(data)) {
			fmt.Fprintln(c.Stdout, k)
		}
		return nil
	}
	paths, err := api.Paths(ctx)
	if err != nil {
		return err
	}
	w := tabwriter.NewWriter(c.Stdout, 0, 4, 2, ' ', 0)
	found := false
	for _, p := range paths {
		if !storage.Under(p, root) {
			continue
		}
		data, err := api.Get(ctx, p, false)
		var apiErr *client.Error
		if errors.As(err, &apiErr) && apiErr.Status == http.StatusNotFound {
			continue
		}
		if err != nil {
			return err
		}
		found = true
		for _, k := range slices.Sorted(maps.Keys(data)) {
			fmt.Fprintf(w, "%s\t%s\n", p, k)
		}
	}
	if !found {
		return fmt.Errorf("no paths under %s", root)
	}
	return w.Flush()
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
	data, err := c.getSecrets(ctx, f, api)
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
	generated := map[string]string{}
	f.fs.Func("generate", "set KEY[:LENGTH] to random letters and digits, LENGTH 32 by default", func(v string) error {
		key, length, err := parseGenerate(v)
		if err != nil {
			return err
		}
		generated[key] = randomValue(length)
		return nil
	})
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
	for k, v := range generated {
		if _, ok := values[k]; ok {
			return fmt.Errorf("%w: %s is both given and generated", errUsage, k)
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

func (c *CLI) copyPath(move bool) func(context.Context, []string) error {
	name := "copy"
	if move {
		name = "move"
	}
	return func(ctx context.Context, args []string) error {
		f := c.flags(name, true, false)
		to := f.fs.String("to", "", "new path")
		api, err := f.parse(args)
		if err != nil {
			return err
		}
		if *to == "" || f.fs.NArg() > 0 {
			return fmt.Errorf("%w: %s takes --path and --to only", errUsage, name)
		}
		if err := api.Require(ctx, "paths-copy"); err != nil {
			return err
		}
		return api.CopyPath(ctx, f.path, *to, move)
	}
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
	data, err := c.getSecrets(ctx, f, api)
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

func (c *CLI) history(ctx context.Context, args []string) error {
	f := c.flags("history", true, false)
	diff := f.fs.Bool("diff", false, "list the keys changed from VERSION to VERSION2 or the current data")
	del := f.fs.Bool("delete", false, "delete the given versions")
	api, err := f.parse(args)
	if err != nil {
		return err
	}
	if *diff && *del {
		return fmt.Errorf("%w: --diff and --delete cannot be combined", errUsage)
	}
	if *diff {
		return c.historyDiff(ctx, f, api)
	}
	if *del {
		return c.historyDelete(ctx, f, api)
	}
	switch f.fs.NArg() {
	case 0:
		versions, err := api.History(ctx, f.path)
		if err != nil {
			return err
		}
		w := tabwriter.NewWriter(c.Stdout, 0, 4, 2, ' ', 0)
		fmt.Fprintln(w, "VERSION\tWRITTEN\tKEYS")
		for _, v := range versions {
			fmt.Fprintf(w, "%d\t%s\t%s\n", v.Version, v.Time.Format(time.RFC3339), strings.Join(v.Keys, ","))
		}
		return w.Flush()
	case 1:
		n, err := parseVersion(f.fs.Arg(0))
		if err != nil {
			return err
		}
		v, err := api.Version(ctx, f.path, n)
		if err != nil {
			return err
		}
		return formatDotenv(c.Stdout, v.Data)
	default:
		return fmt.Errorf("%w: history takes at most one VERSION", errUsage)
	}
}

func (c *CLI) historyDiff(ctx context.Context, f *flags, api *client.Client) error {
	if n := f.fs.NArg(); n != 1 && n != 2 {
		return fmt.Errorf("%w: history --diff takes VERSION and an optional VERSION2", errUsage)
	}
	var snapshots []map[string]string
	for _, arg := range f.fs.Args() {
		n, err := parseVersion(arg)
		if err != nil {
			return err
		}
		v, err := api.Version(ctx, f.path, n)
		if err != nil {
			return err
		}
		snapshots = append(snapshots, v.Data)
	}
	if len(snapshots) == 1 {
		current, err := api.Get(ctx, f.path, false)
		var apiErr *client.Error
		if err != nil && (!errors.As(err, &apiErr) || apiErr.Status != http.StatusNotFound) {
			return err
		}
		snapshots = append(snapshots, current)
	}
	for _, ch := range secrets.Diff(snapshots[0], snapshots[1]) {
		fmt.Fprintf(c.Stdout, "%s %s\n", ch.Op, ch.Key)
	}
	return nil
}

func (c *CLI) historyDelete(ctx context.Context, f *flags, api *client.Client) error {
	if f.fs.NArg() == 0 {
		return fmt.Errorf("%w: history --delete takes at least one VERSION", errUsage)
	}
	var ns []int
	for _, arg := range f.fs.Args() {
		n, err := parseVersion(arg)
		if err != nil {
			return err
		}
		ns = append(ns, n)
	}
	if err := api.Require(ctx, "history-delete"); err != nil {
		return err
	}
	for _, n := range ns {
		if err := api.DeleteVersion(ctx, f.path, n); err != nil {
			return fmt.Errorf("version %d: %w", n, err)
		}
		fmt.Fprintf(c.Stdout, "Deleted version %d of %s\n", n, f.path)
	}
	return nil
}

func (c *CLI) rollback(ctx context.Context, args []string) error {
	f := c.flags("rollback", true, false)
	api, err := f.parse(args)
	if err != nil {
		return err
	}
	if f.fs.NArg() != 1 {
		return fmt.Errorf("%w: rollback takes one VERSION", errUsage)
	}
	n, err := parseVersion(f.fs.Arg(0))
	if err != nil {
		return err
	}
	return api.Rollback(ctx, f.path, n)
}

func (c *CLI) version(ctx context.Context, args []string) error {
	f := c.flags("version", false, false)
	api, err := f.parse(args)
	if errors.Is(err, errNoServer) && f.fs.NArg() == 0 {
		fmt.Fprintf(c.Stdout, "client: %s\n", c.Version)
		return nil
	}
	if err != nil {
		return err
	}
	if f.fs.NArg() > 0 {
		return fmt.Errorf("%w: version takes no arguments", errUsage)
	}
	fmt.Fprintf(c.Stdout, "client: %s\n", c.Version)
	info, err := api.Info(ctx)
	if err != nil {
		return fmt.Errorf("server %s: %w", f.server, err)
	}
	fmt.Fprintf(c.Stdout, "server: %s (%s)\n", cmp.Or(info.Version, "unknown, older than the client"), f.server)
	fmt.Fprintf(c.Stdout, "capabilities: %s\n", strings.Join(info.Capabilities, ", "))
	return nil
}

func (c *CLI) backup(ctx context.Context, args []string) error {
	f := c.flags("backup", false, false)
	withHistory := f.fs.Bool("history", false, "include the versions of every path")
	output := f.fs.String("output", "", "file to write with 0600 permissions, default stdout")
	api, err := f.parse(args)
	if err != nil {
		return err
	}
	if f.fs.NArg() > 0 {
		return fmt.Errorf("%w: backup takes no arguments", errUsage)
	}
	if err := api.Require(ctx, "backup"); err != nil {
		return err
	}
	key, err := c.backupKey()
	if err != nil {
		return err
	}
	data, err := api.Backup(ctx, *withHistory)
	if err != nil {
		return err
	}
	if key != nil {
		if data, err = encrypted.SealBackup(key, data); err != nil {
			return err
		}
	}
	data = append(data, '\n')
	if *output == "" {
		_, err = c.Stdout.Write(data)
		return err
	}
	file, err := os.OpenFile(*output, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o600)
	if err != nil {
		return err
	}
	_, err = file.Write(data)
	if chmodErr := file.Chmod(0o600); err == nil {
		err = chmodErr
	}
	if closeErr := file.Close(); err == nil {
		err = closeErr
	}
	return err
}

func (c *CLI) restore(ctx context.Context, args []string) error {
	f := c.flags("restore", false, false)
	api, err := f.parse(args)
	if err != nil {
		return err
	}
	if f.fs.NArg() != 1 {
		return fmt.Errorf("%w: restore takes one FILE, - for stdin", errUsage)
	}
	name := f.fs.Arg(0)
	var data []byte
	if name == "-" {
		data, err = io.ReadAll(c.Stdin)
	} else {
		data, err = os.ReadFile(name)
	}
	if err != nil {
		return err
	}
	if !json.Valid(data) {
		return fmt.Errorf("%s is not a JSON backup", name)
	}
	if encrypted.IsEncryptedBackup(data) {
		key, err := c.backupKey()
		if err != nil {
			return err
		}
		if key == nil {
			return fmt.Errorf("%s is encrypted; set %s to its backup key", name, EnvBackupKey)
		}
		if data, err = encrypted.OpenBackup(key, data); err != nil {
			return fmt.Errorf("%s: %w", name, err)
		}
	}
	if err := api.Require(ctx, "backup"); err != nil {
		return err
	}
	n, err := api.Restore(ctx, data)
	if err != nil {
		return err
	}
	fmt.Fprintf(c.Stdout, "Restored %d paths\n", n)
	return nil
}

// backupKey returns the key in $SECRET_MANAGER_BACKUP_KEY, nil when unset.
func (c *CLI) backupKey() ([]byte, error) {
	v := c.Getenv(EnvBackupKey)
	if v == "" {
		return nil, nil
	}
	key, err := encrypted.ParseKey(v)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", EnvBackupKey, err)
	}
	return key, nil
}

const (
	generateAlphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"
	generateLength   = 32
	maxGenerate      = 4096
)

func parseGenerate(v string) (string, int, error) {
	key, length, ok := strings.Cut(v, ":")
	if err := secrets.ValidateKey(key); err != nil {
		return "", 0, err
	}
	if !ok {
		return key, generateLength, nil
	}
	n, err := strconv.Atoi(length)
	if err != nil || n < 1 || n > maxGenerate {
		return "", 0, fmt.Errorf("length %q must be between 1 and %d", length, maxGenerate)
	}
	return key, n, nil
}

// randomValue returns n uniformly random letters and digits.
func randomValue(n int) string {
	out := make([]byte, 0, n)
	buf := make([]byte, n)
	for len(out) < n {
		_, _ = rand.Read(buf)
		for _, b := range buf {
			// 248 is the largest multiple of len(generateAlphabet) below 256.
			if b < 248 && len(out) < n {
				out = append(out, generateAlphabet[int(b)%len(generateAlphabet)])
			}
		}
	}
	return string(out)
}

func parseVersion(s string) (int, error) {
	n, err := strconv.Atoi(s)
	if err != nil || n < 1 {
		return 0, fmt.Errorf("%w: VERSION %q must be a positive integer", errUsage, s)
	}
	return n, nil
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
	data, err := c.getSecrets(ctx, f, api)
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
