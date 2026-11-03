package secrets

import (
	"cmp"
	"slices"
)

// Change is a key that differs between two snapshots of a path. Op is "+"
// for an added key, "-" for a removed one and "~" for a changed value.
type Change struct {
	Op  string
	Key string
}

// Diff returns the keys that differ from before to after, sorted by key.
func Diff(before, after map[string]string) []Change {
	var out []Change
	for k, v := range after {
		if o, ok := before[k]; !ok {
			out = append(out, Change{"+", k})
		} else if o != v {
			out = append(out, Change{"~", k})
		}
	}
	for k := range before {
		if _, ok := after[k]; !ok {
			out = append(out, Change{"-", k})
		}
	}
	slices.SortFunc(out, func(a, b Change) int { return cmp.Compare(a.Key, b.Key) })
	return out
}
