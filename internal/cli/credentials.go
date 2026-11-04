package cli

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"strings"

	"github.com/zalando/go-keyring"

	"github.com/rapatao/secret-manager/internal/local"
)

const keyringService = "secretmanager.rapatao.com"

// store keeps the known servers and the default in config.json and tokens in the OS
// keychain. Without a usable keychain, tokens go to credentials.json with
// 0600 permissions.
type store struct {
	dir string
}

type configFile struct {
	// Server is the default server.
	Server string `json:"server,omitempty"`
	// Servers lists every server with a stored token, sorted.
	Servers []string `json:"servers,omitempty"`
}

func (c *configFile) add(server string) {
	if !slices.Contains(c.Servers, server) {
		c.Servers = append(c.Servers, server)
		slices.Sort(c.Servers)
	}
}

func (c *configFile) remove(server string) {
	c.Servers = slices.DeleteFunc(c.Servers, func(s string) bool { return s == server })
	if c.Server == server {
		c.Server = ""
	}
}

type credentialsFile struct {
	Tokens map[string]string `json:"tokens"`
}

// DefaultConfigDir returns $XDG_CONFIG_HOME/secretmanager.rapatao.com, or
// ~/.config/secretmanager.rapatao.com when XDG_CONFIG_HOME is unset.
func DefaultConfigDir() string {
	base := os.Getenv("XDG_CONFIG_HOME")
	if base == "" {
		home, err := os.UserHomeDir()
		if err != nil {
			return ""
		}
		base = filepath.Join(home, ".config")
	}
	return filepath.Join(base, keyringService)
}

func normalizeServer(server string) string {
	return local.Normalize(strings.TrimSuffix(server, "/"))
}

func (s store) config() (configFile, error) {
	var cfg configFile
	err := s.read("config.json", &cfg)
	return cfg, err
}

func (s store) saveConfig(cfg configFile) error {
	return s.write("config.json", cfg)
}

// token returns the stored token for server, or "" when none is stored.
func (s store) token(server string) (string, error) {
	if t, err := keyring.Get(keyringService, server); err == nil {
		return t, nil
	}
	var creds credentialsFile
	if err := s.read("credentials.json", &creds); err != nil {
		return "", err
	}
	return creds.Tokens[server], nil
}

// saveToken stores token for server in the keychain. When the keychain is not
// usable, such as on headless Linux without Secret Service, it falls back to
// the 0600 file and returns the keychain error as fallback.
func (s store) saveToken(server, token string) (fallback error, err error) {
	if fallback = keyring.Set(keyringService, server, token); fallback == nil {
		return nil, s.removeFileToken(server)
	}
	var creds credentialsFile
	if err := s.read("credentials.json", &creds); err != nil {
		return fallback, err
	}
	if creds.Tokens == nil {
		creds.Tokens = map[string]string{}
	}
	creds.Tokens[server] = token
	return fallback, s.write("credentials.json", creds)
}

// removeToken deletes the token for server from the keychain and the file.
func (s store) removeToken(server string) error {
	if err := keyring.Delete(keyringService, server); err != nil && !errors.Is(err, keyring.ErrNotFound) {
		if _, getErr := keyring.Get(keyringService, server); getErr == nil {
			return fmt.Errorf("delete from keychain: %w", err)
		}
	}
	return s.removeFileToken(server)
}

func (s store) removeFileToken(server string) error {
	var creds credentialsFile
	if err := s.read("credentials.json", &creds); err != nil {
		return err
	}
	if _, ok := creds.Tokens[server]; !ok {
		return nil
	}
	delete(creds.Tokens, server)
	return s.write("credentials.json", creds)
}

func (s store) read(name string, v any) error {
	if s.dir == "" {
		return nil
	}
	b, err := os.ReadFile(filepath.Join(s.dir, name))
	if errors.Is(err, fs.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	if err := json.Unmarshal(b, v); err != nil {
		return fmt.Errorf("parse %s: %w", filepath.Join(s.dir, name), err)
	}
	return nil
}

// write replaces name atomically with 0600 permissions.
func (s store) write(name string, v any) error {
	if s.dir == "" {
		return errors.New("cannot determine the config directory; set XDG_CONFIG_HOME")
	}
	b, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return err
	}
	return writeAtomic(s.dir, name, append(b, '\n'))
}

// writeAtomic replaces dir/name with b, 0600 permissions, creating dir with
// 0700 when missing.
func writeAtomic(dir, name string, b []byte) error {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(dir, name+".*")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())
	_, err = tmp.Write(b)
	if closeErr := tmp.Close(); err == nil {
		err = closeErr
	}
	if err != nil {
		return err
	}
	return os.Rename(tmp.Name(), filepath.Join(dir, name))
}
