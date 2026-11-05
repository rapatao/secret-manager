package cli

import (
	"bytes"
	"crypto/sha256"
	"crypto/subtle"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"time"
)

// ClipClearAfter is how long a value copied with get --clip stays in the
// clipboard.
const ClipClearAfter = 60 * time.Second

// clipClearCommand is the hidden command that clears the clipboard after
// ClipClearAfter, run in the background by get --clip.
const clipClearCommand = "__clip-clear"

type clipboard struct {
	copy, paste []string
}

func systemClipboard() (clipboard, error) {
	var c clipboard
	switch {
	case runtime.GOOS == "darwin":
		c = clipboard{[]string{"pbcopy"}, []string{"pbpaste"}}
	case runtime.GOOS == "windows":
		c = clipboard{[]string{"clip"}, []string{"powershell", "-NoProfile", "-Command", "Get-Clipboard -Raw"}}
	case os.Getenv("WAYLAND_DISPLAY") != "":
		c = clipboard{[]string{"wl-copy"}, []string{"wl-paste", "-n"}}
	default:
		c = clipboard{[]string{"xclip", "-selection", "clipboard"}, []string{"xclip", "-selection", "clipboard", "-o"}}
	}
	if _, err := exec.LookPath(c.copy[0]); err != nil {
		return c, fmt.Errorf("no clipboard: %s not found; on Linux install wl-clipboard or xclip", c.copy[0])
	}
	return c, nil
}

func (c clipboard) set(value string) error {
	cmd := exec.Command(c.copy[0], c.copy[1:]...)
	cmd.Stdin = strings.NewReader(value)
	return cmd.Run()
}

func (c clipboard) get() (string, error) {
	out, err := exec.Command(c.paste[0], c.paste[1:]...).Output()
	return string(out), err
}

func clipSum(value string) []byte {
	sum := sha256.Sum256([]byte(strings.TrimRight(value, "\r\n")))
	return sum[:]
}

// copyToClipboard copies value and starts a background process that clears
// it after ClipClearAfter. The process gets the value's hash on stdin, not as
// an argument, so it does not show in the process list.
func copyToClipboard(value string) error {
	cb, err := systemClipboard()
	if err != nil {
		return err
	}
	if err := cb.set(value); err != nil {
		return fmt.Errorf("copy to clipboard: %w", err)
	}
	exe, err := os.Executable()
	if err != nil {
		return fmt.Errorf("copied, but cannot schedule clearing: %w", err)
	}
	cmd := exec.Command(exe, clipClearCommand)
	cmd.Stdin = bytes.NewReader(clipSum(value))
	if err := cmd.Start(); err != nil {
		return fmt.Errorf("copied, but cannot schedule clearing: %w", err)
	}
	return cmd.Process.Release()
}

// clipClear waits ClipClearAfter, then clears the clipboard if it still holds
// the value whose hash is read from stdin.
func (c *CLI) clipClear(args []string) error {
	if len(args) > 0 {
		return errors.New("takes no arguments")
	}
	sum, err := io.ReadAll(io.LimitReader(c.Stdin, sha256.Size+1))
	if err != nil || len(sum) != sha256.Size {
		return errors.New("want a SHA-256 hash on stdin")
	}
	time.Sleep(ClipClearAfter)
	cb, err := systemClipboard()
	if err != nil {
		return err
	}
	return clearIfUnchanged(cb.get, cb.set, sum)
}

func clearIfUnchanged(get func() (string, error), set func(string) error, sum []byte) error {
	current, err := get()
	if err != nil {
		return err
	}
	if subtle.ConstantTimeCompare(clipSum(current), sum) != 1 {
		return nil
	}
	return set("")
}
