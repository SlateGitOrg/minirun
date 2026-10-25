package caps

import (
	"strings"
	"testing"

	"github.com/SlateGitOrg/minirun/internal/spec"
)

func TestDefaultCapabilitiesMatchDockerMask(t *testing.T) {
	s, err := Parse(spec.DefaultCapabilities)
	if err != nil {
		t.Fatal(err)
	}
	// 00000000a80425fb is the CapEff Docker's default set produces; the
	// integration test asserts the same value inside a running container.
	if got := s.Hex(); got != "00000000a80425fb" {
		t.Fatalf("mask = %s", got)
	}
	if len(s.Names()) != len(spec.DefaultCapabilities) {
		t.Errorf("Names() = %v", s.Names())
	}
}

func TestLookupAndName(t *testing.T) {
	for _, n := range []string{"CAP_NET_RAW", "net_raw", "NET_RAW", "cap_net_raw"} {
		if c, ok := Lookup(n); !ok || c != 13 {
			t.Errorf("Lookup(%s) = %d %v", n, c, ok)
		}
	}
	if _, ok := Lookup("CAP_FLY"); ok {
		t.Error("unknown capability resolved")
	}
	if Name(40) != "CAP_CHECKPOINT_RESTORE" || Name(41) != "CAP_41" || Name(-1) != "CAP_-1" {
		t.Error("Name")
	}
	if Last != 40 {
		t.Errorf("Last = %d", Last)
	}
}

func TestParseRejectsUnknown(t *testing.T) {
	_, err := Parse([]string{"CAP_CHOWN", "CAP_FLY", "CAP_SWIM"})
	if err == nil || !strings.Contains(err.Error(), "CAP_FLY, CAP_SWIM") {
		t.Fatalf("err = %v", err)
	}
}

func TestSetHelpers(t *testing.T) {
	s := Set(1<<0 | 1<<40 | 1<<63)
	if !s.Has(40) || s.Has(1) || s.Has(64) || s.Has(-1) {
		t.Error("Has")
	}
	if got := s.Upto(39); got != 1 {
		t.Errorf("Upto(39) = %x", got)
	}
	if got := s.Upto(63); got != s {
		t.Errorf("Upto(63) = %x", got)
	}
	if got := strings.Join(s.Names(), ","); got != "CAP_CHOWN,CAP_CHECKPOINT_RESTORE,CAP_63" {
		t.Errorf("Names = %s", got)
	}
}

func TestFromSpec(t *testing.T) {
	s, err := FromSpec(nil)
	if err != nil || s != (Sets{}) {
		t.Fatalf("nil: %+v %v", s, err)
	}
	all := []string{"CAP_KILL", "CAP_CHOWN"}
	s, err = FromSpec(&spec.Capabilities{Bounding: all, Effective: all, Permitted: all, Inheritable: all, Ambient: []string{"CAP_KILL"}})
	if err != nil {
		t.Fatal(err)
	}
	if s.Ambient != 1<<5 || s.Bounding != 1<<5|1 {
		t.Errorf("sets = %+v", s)
	}
	cases := map[string]*spec.Capabilities{
		"unknown":   {Bounding: []string{"CAP_NOPE"}, Ambient: []string{"CAP_NADA"}},
		"effective": {Bounding: all, Permitted: []string{"CAP_KILL"}, Effective: all},
		"ambient":   {Bounding: all, Permitted: all, Ambient: []string{"CAP_KILL"}},
		"permitted": {Bounding: []string{"CAP_KILL"}, Permitted: all},
	}
	wants := map[string]string{
		"unknown":   "bounding: unknown capabilities: CAP_NOPE",
		"effective": "effective has capabilities not in permitted: CAP_CHOWN",
		"ambient":   "ambient capabilities must also be permitted and inheritable: CAP_KILL",
		"permitted": "outside the bounding set: CAP_CHOWN",
	}
	for name, c := range cases {
		_, err := FromSpec(c)
		if err == nil || !strings.Contains(err.Error(), wants[name]) {
			t.Errorf("%s: err = %v", name, err)
		}
	}
}
