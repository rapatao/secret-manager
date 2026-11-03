package cli

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"html"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"regexp"
	"runtime"
	"strings"
	"time"

	"github.com/rapatao/secret-manager/internal/client"
)

// loginTimeout bounds how long a browser login waits for approval, matching
// the server's pending login lifetime.
const loginTimeout = 5 * time.Minute

// openBrowser opens u in the default browser.
func openBrowser(u string) error {
	var cmd *exec.Cmd
	switch runtime.GOOS {
	case "darwin":
		cmd = exec.Command("open", u)
	case "windows":
		cmd = exec.Command("rundll32", "url.dll,FileProtocolHandler", u)
	default:
		cmd = exec.Command("xdg-open", u)
	}
	return cmd.Run()
}

var nonName = regexp.MustCompile(`[^a-z0-9-]+`)

// integrationName suggests the integration name for a login from this host.
func integrationName() string {
	host, _ := os.Hostname()
	host, _, _ = strings.Cut(strings.ToLower(host), ".")
	name := strings.Trim(nonName.ReplaceAllString("cli-"+host, "-"), "-")
	return name[:min(len(name), 63)]
}

// browserLogin gets a token approved in the Web UI. The browser sends the
// approval to a listener on 127.0.0.1; with device, when the browser cannot
// be opened, or over SSH, the user opens the approval page and the CLI
// polls for the token instead.
func (c *CLI) browserLogin(ctx context.Context, server string, device bool) (client.Login, error) {
	ctx, cancel := context.WithTimeout(ctx, loginTimeout)
	defer cancel()
	api := client.New(server, "")
	if err := api.CheckBrowserLogin(ctx); err != nil {
		return client.Login{}, err
	}
	if !device && c.Getenv("SSH_CONNECTION") == "" {
		login, err := c.loopbackLogin(ctx, api)
		if !errors.Is(err, errNoBrowser) {
			return login, err
		}
		fmt.Fprintf(c.Stderr, "Could not open a browser (%v)\n", errors.Unwrap(err))
	}
	return c.deviceLogin(ctx, api)
}

var errNoBrowser = errors.New("no browser")

func (c *CLI) loopbackLogin(ctx context.Context, api *client.Client) (client.Login, error) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return client.Login{}, fmt.Errorf("%w: %w", errNoBrowser, err)
	}
	defer ln.Close()
	verifier, state := rand.Text()+rand.Text(), rand.Text()
	sum := sha256.Sum256([]byte(verifier))
	redirect := "http://" + ln.Addr().String() + "/callback"
	authURL := api.URL() + "/authorize?" + url.Values{
		"redirect_uri":   {redirect},
		"state":          {state},
		"code_challenge": {base64.RawURLEncoding.EncodeToString(sum[:])},
		"name":           {integrationName()},
	}.Encode()

	type result struct {
		code string
		err  error
	}
	done := make(chan result, 1)
	srv := &http.Server{ReadHeaderTimeout: 10 * time.Second, Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query()
		if r.URL.Path != "/callback" || q.Get("state") != state {
			http.Error(w, "unexpected request", http.StatusBadRequest)
			return
		}
		res := result{code: q.Get("code")}
		msg := "Login approved. Return to the terminal."
		if e := q.Get("error"); e != "" || res.code == "" {
			res.err = fmt.Errorf("login denied (%s)", e)
			msg = "Login denied. You can close this tab."
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		fmt.Fprintf(w, "<!DOCTYPE html><title>secret-manager</title><p>%s</p>", html.EscapeString(msg))
		select {
		case done <- res:
		default:
		}
	})}
	go func() { _ = srv.Serve(ln) }()
	defer srv.Close()

	if err := c.OpenBrowser(authURL); err != nil {
		return client.Login{}, fmt.Errorf("%w: %w", errNoBrowser, err)
	}
	fmt.Fprintf(c.Stderr, "Approve the login in your browser. If it did not open, visit:\n  %s\n", authURL)
	select {
	case <-ctx.Done():
		return client.Login{}, fmt.Errorf("login not approved: %w", ctx.Err())
	case res := <-done:
		if res.err != nil {
			return client.Login{}, res.err
		}
		return api.ExchangeCode(ctx, res.code, verifier)
	}
}

func (c *CLI) deviceLogin(ctx context.Context, api *client.Client) (client.Login, error) {
	d, err := api.StartDevice(ctx, integrationName())
	if err != nil {
		return client.Login{}, err
	}
	fmt.Fprintf(c.Stderr, "Open %s in a browser signed in to the Web UI and check that it shows the code %s\n", d.VerificationURI, d.UserCode)
	interval := time.Duration(max(d.Interval, 1)) * time.Second
	for {
		login, err := api.PollDevice(ctx, d)
		if !errors.Is(err, client.ErrPending) {
			if apiErr := (*client.Error)(nil); errors.As(err, &apiErr) && apiErr.Message == "access_denied" {
				return client.Login{}, errors.New("login denied")
			}
			return login, err
		}
		select {
		case <-ctx.Done():
			return client.Login{}, fmt.Errorf("login not approved: %w", ctx.Err())
		case <-time.After(interval):
		}
	}
}
