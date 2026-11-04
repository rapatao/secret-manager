package cli

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"time"

	"golang.org/x/term"

	"github.com/rapatao/secret-manager/internal/local"
)

// unlockVault returns the key of the vault at path, creating the vault when
// missing. The passphrase is read from the first line of stdin when fromStdin,
// else prompted for on the terminal.
func (c *CLI) unlockVault(path string, fromStdin bool) (key []byte, created bool, err error) {
	create := !local.Exists(path)
	var passphrase string
	if fromStdin {
		if passphrase, err = c.readToken(); err != nil {
			return nil, false, err
		}
	} else {
		if passphrase, err = c.prompt("Passphrase for " + path + ": "); err != nil {
			return nil, false, err
		}
		if create {
			confirm, err := c.prompt("Repeat the passphrase: ")
			if err != nil {
				return nil, false, err
			}
			if confirm != passphrase {
				return nil, false, errors.New("passphrases do not match")
			}
		}
	}
	if create {
		key, err = local.Create(path, passphrase)
		return key, true, err
	}
	key, err = local.Unlock(path, passphrase)
	return key, false, err
}

// prompt reads a line from the terminal on stdin without echoing it.
func (c *CLI) prompt(label string) (string, error) {
	f, ok := c.Stdin.(*os.File)
	if !ok || !term.IsTerminal(int(f.Fd())) {
		return "", fmt.Errorf("%w: stdin is not a terminal; give --token-stdin and the passphrase on stdin", errUsage)
	}
	fmt.Fprint(c.Stderr, label)
	b, err := term.ReadPassword(int(f.Fd()))
	fmt.Fprintln(c.Stderr)
	return string(b), err
}

func (c *CLI) ui(ctx context.Context, args []string) error {
	f := c.flags("ui", false, false)
	addr := f.fs.String("addr", "127.0.0.1:0", "loopback listen address")
	noBrowser := f.fs.Bool("no-browser", false, "print the sign-in link without opening a browser")
	if err := f.parseFlags(args); err != nil {
		return err
	}
	if f.fs.NArg() > 0 {
		return fmt.Errorf("%w: ui takes no arguments", errUsage)
	}
	if _, ok := local.Path(f.server); !ok {
		return c.remoteUI(f, *noBrowser)
	}
	token, err := f.token()
	if err != nil {
		return err
	}
	v, err := f.vault(token)
	if err != nil {
		return err
	}
	v.PlainHTTP = true
	v.SetLogger(slog.New(slog.NewTextHandler(c.Stderr, nil)))

	ln, err := net.Listen("tcp", *addr)
	if err != nil {
		return err
	}
	if tcp, ok := ln.Addr().(*net.TCPAddr); !ok || !tcp.IP.IsLoopback() {
		_ = ln.Close()
		return fmt.Errorf("%w: --addr %s is not a loopback address", errUsage, *addr)
	}
	link := "http://" + ln.Addr().String() + v.LoginLink()
	fmt.Fprintf(c.Stdout, "Serving %s at http://%s, press Ctrl-C to stop.\n", f.server, ln.Addr())
	fmt.Fprintf(c.Stdout, "Sign in within a minute, once: %s\n", link)
	if !*noBrowser && c.OpenBrowser != nil {
		if err := c.OpenBrowser(link); err != nil {
			fmt.Fprintln(c.Stderr, "warning: cannot open a browser:", err)
		}
	}

	ctx, stop := signal.NotifyContext(ctx, os.Interrupt)
	defer stop()
	srv := &http.Server{Handler: v, ReadHeaderTimeout: 10 * time.Second}
	go func() {
		<-ctx.Done()
		shutdown, cancel := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
		defer cancel()
		_ = srv.Shutdown(shutdown)
	}()
	if err := srv.Serve(ln); !errors.Is(err, http.ErrServerClosed) {
		return err
	}
	return nil
}

// remoteUI opens the Web UI of the remote server f.server, which signs in
// with its admin token.
func (c *CLI) remoteUI(f *flags, noBrowser bool) error {
	addrSet := false
	f.fs.Visit(func(fl *flag.Flag) { addrSet = addrSet || fl.Name == "addr" })
	if addrSet {
		return fmt.Errorf("%w: --addr only applies to a local vault", errUsage)
	}
	fmt.Fprintf(c.Stdout, "Web UI of %s, sign in with its admin token: %s/\n", f.server, f.server)
	if !noBrowser && c.OpenBrowser != nil {
		if err := c.OpenBrowser(f.server + "/"); err != nil {
			fmt.Fprintln(c.Stderr, "warning: cannot open a browser:", err)
		}
	}
	return nil
}
