// Package render builds the data of a target Secret from source values.
package render

import (
	"fmt"
	"strings"
	"text/template"
)

// Render returns values as Secret data. When templates is empty every value
// is copied as is; otherwise each template is executed with values as its
// data, so {{ .KEY }} reads a source value. Missing keys are errors.
func Render(values map[string]string, templates map[string]string) (map[string][]byte, error) {
	out := make(map[string][]byte)
	if len(templates) == 0 {
		for k, v := range values {
			out[k] = []byte(v)
		}
		return out, nil
	}
	for key, text := range templates {
		t, err := template.New(key).Option("missingkey=error").Parse(text)
		if err != nil {
			return nil, fmt.Errorf("parse template %q: %w", key, err)
		}
		var b strings.Builder
		if err := t.Execute(&b, values); err != nil {
			return nil, fmt.Errorf("execute template %q: %w", key, err)
		}
		out[key] = []byte(b.String())
	}
	return out, nil
}
