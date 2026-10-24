package spec

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
)

// ConfigName is the file name of the configuration inside a bundle.
const ConfigName = "config.json"

// maxConfigSize bounds how much of config.json is read. Real configs are a
// few tens of kilobytes even with a large inline seccomp profile.
const maxConfigSize = 4 << 20

// Bundle is a loaded OCI bundle: its directory, parsed config, and the
// configuration keys minirun did not understand.
type Bundle struct {
	Dir         string
	Spec        *Spec
	Unsupported []string
}

// RootfsPath returns the absolute path of the bundle's root filesystem.
func (b *Bundle) RootfsPath() string {
	if b.Spec.Root == nil {
		return ""
	}
	if filepath.IsAbs(b.Spec.Root.Path) {
		return filepath.Clean(b.Spec.Root.Path)
	}
	return filepath.Join(b.Dir, b.Spec.Root.Path)
}

// LoadBundle reads and parses dir/config.json. It does not validate; call
// Validate on the result.
func LoadBundle(dir string) (*Bundle, error) {
	abs, err := filepath.Abs(dir)
	if err != nil {
		return nil, fmt.Errorf("resolve bundle path: %w", err)
	}
	f, err := os.Open(filepath.Join(abs, ConfigName))
	if err != nil {
		return nil, fmt.Errorf("open bundle config: %w", err)
	}
	defer func() { _ = f.Close() }()
	s, unsupported, err := Parse(f)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", filepath.Join(abs, ConfigName), err)
	}
	return &Bundle{Dir: abs, Spec: s, Unsupported: unsupported}, nil
}

// Parse decodes a config.json document. It returns the parsed spec and the
// sorted list of JSON paths (e.g. "linux.resources.devices") that are not
// part of the subset minirun implements. Unknown keys are not an error:
// configs written by other tools routinely carry fields minirun ignores, and
// the caller decides whether to surface them.
func Parse(r io.Reader) (*Spec, []string, error) {
	data, err := io.ReadAll(io.LimitReader(r, maxConfigSize+1))
	if err != nil {
		return nil, nil, fmt.Errorf("read config: %w", err)
	}
	if len(data) > maxConfigSize {
		return nil, nil, fmt.Errorf("config is larger than %d bytes", maxConfigSize)
	}
	var s Spec
	dec := json.NewDecoder(bytes.NewReader(data))
	if err := dec.Decode(&s); err != nil {
		return nil, nil, fmt.Errorf("decode config: %w", describeJSONError(data, err))
	}
	if dec.More() {
		return nil, nil, errors.New("decode config: trailing data after JSON object")
	}
	var raw any
	if err := json.Unmarshal(data, &raw); err != nil {
		return nil, nil, fmt.Errorf("decode config: %w", err)
	}
	var unknown []string
	collectUnknown(raw, reflect.TypeFor[Spec](), "", &unknown)
	sort.Strings(unknown)
	return &s, unknown, nil
}

// describeJSONError adds a line:column position to syntax errors.
func describeJSONError(data []byte, err error) error {
	var syn *json.SyntaxError
	if errors.As(err, &syn) {
		line, col := position(data, syn.Offset)
		return fmt.Errorf("line %d column %d: %w", line, col, err)
	}
	var typ *json.UnmarshalTypeError
	if errors.As(err, &typ) {
		line, col := position(data, typ.Offset)
		return fmt.Errorf("line %d column %d: field %q: %w", line, col, typ.Field, err)
	}
	return err
}

func position(data []byte, offset int64) (line, col int) {
	if offset > int64(len(data)) {
		offset = int64(len(data))
	}
	line, col = 1, 1
	for _, b := range data[:offset] {
		if b == '\n' {
			line++
			col = 1
		} else {
			col++
		}
	}
	return line, col
}

// collectUnknown walks a generic JSON value alongside the Go type it was
// decoded into and records object keys that have no matching struct field.
func collectUnknown(v any, t reflect.Type, path string, out *[]string) {
	for t.Kind() == reflect.Pointer {
		t = t.Elem()
	}
	switch t.Kind() {
	case reflect.Struct:
		obj, ok := v.(map[string]any)
		if !ok {
			return
		}
		fields := jsonFields(t)
		for key, child := range obj {
			ft, known := fields[key]
			if !known {
				*out = append(*out, joinPath(path, key))
				continue
			}
			collectUnknown(child, ft, joinPath(path, key), out)
		}
	case reflect.Slice:
		arr, ok := v.([]any)
		if !ok {
			return
		}
		for i, child := range arr {
			collectUnknown(child, t.Elem(), fmt.Sprintf("%s[%d]", path, i), out)
		}
	default:
		// Scalars and free-form maps (annotations, unified) accept anything.
	}
}

func jsonFields(t reflect.Type) map[string]reflect.Type {
	fields := make(map[string]reflect.Type, t.NumField())
	for i := range t.NumField() {
		f := t.Field(i)
		name, _, _ := strings.Cut(f.Tag.Get("json"), ",")
		if name == "" || name == "-" {
			continue
		}
		fields[name] = f.Type
	}
	return fields
}

func joinPath(parent, key string) string {
	if parent == "" {
		return key
	}
	return parent + "." + key
}

// Marshal renders a spec as indented JSON with a trailing newline, the format
// `minirun spec` writes.
func Marshal(s *Spec) ([]byte, error) {
	data, err := json.MarshalIndent(s, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("encode config: %w", err)
	}
	return append(data, '\n'), nil
}
