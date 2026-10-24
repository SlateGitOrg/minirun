package signals

import "testing"

func TestParse(t *testing.T) {
	cases := map[string]int{
		"TERM": 15, "SIGTERM": 15, "sigkill": 9, "9": 9, "USR1": 10, "chld": 17,
		"RTMIN": 32, "SIGRTMIN+2": 34, "RTMAX": 64, "RTMAX-4": 60, "64": 64,
	}
	for in, want := range cases {
		got, err := Parse(in)
		if err != nil || got != want {
			t.Errorf("Parse(%q) = %d, %v; want %d", in, got, err, want)
		}
	}
	for _, bad := range []string{"", "0", "65", "-1", "FOO", "RTMIN-1", "RTMAX+1", "RTMIN+x", "RTMIN+40"} {
		if _, err := Parse(bad); err == nil {
			t.Errorf("Parse(%q) succeeded", bad)
		}
	}
}

func TestName(t *testing.T) {
	cases := map[int]string{15: "SIGTERM", 6: "SIGABRT", 29: "SIGIO", 34: "SIGRTMIN+2", 99: "SIG99"}
	for n, want := range cases {
		if got := Name(n); got != want {
			t.Errorf("Name(%d) = %s, want %s", n, got, want)
		}
	}
}
