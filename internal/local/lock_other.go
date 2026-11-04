//go:build !unix

package local

import "errors"

func lock(string, bool) (func(), error) {
	return nil, errors.New("local vaults need a Unix system")
}
