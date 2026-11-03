package render

import (
	"maps"
	"testing"
)

func TestRender(t *testing.T) {
	values := map[string]string{"USER": "bob", "PASS": "s3cret"}
	cases := []struct {
		name      string
		templates map[string]string
		want      map[string]string
		wantErr   bool
	}{
		{name: "copy all without template", want: values},
		{
			name:      "templated keys",
			templates: map[string]string{"username": "{{ .USER }}", "url": "https://{{ .USER }}:{{ .PASS }}@host", "static": "fixed"},
			want:      map[string]string{"username": "bob", "url": "https://bob:s3cret@host", "static": "fixed"},
		},
		{name: "missing key", templates: map[string]string{"x": "{{ .NOPE }}"}, wantErr: true},
		{name: "invalid template", templates: map[string]string{"x": "{{ .USER "}, wantErr: true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := Render(values, tc.templates)
			if tc.wantErr {
				if err == nil {
					t.Fatal("want error")
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			str := map[string]string{}
			for k, v := range got {
				str[k] = string(v)
			}
			if !maps.Equal(str, tc.want) {
				t.Fatalf("got %v, want %v", str, tc.want)
			}
		})
	}
}
