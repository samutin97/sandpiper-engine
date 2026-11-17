package tiered

import (
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"
)

// A synthetic subscription of nine proxies: names, numbers and order like a panel's, nothing real.
var sampleTags = []string{
	"1 Alpha gRPC compact", "2 Bravo gRPC", "3 Charlie XHTTP", "4 Delta XHTTP compact", "5 Echo Naive",
	"6 Foxtrot gRPC two", "7 Golf XHTTP two", "9 India HTTP3", "10 Juliet WG",
}

func sampleUDP(tag string) bool { return strings.HasPrefix(tag, "9 ") || strings.HasPrefix(tag, "10 ") }

const samplePolicy = "v=1; n=2:545:main; n=3:545:main; n=1:544:compact; n=4:444:compact; n=5:435:alt-tls;" +
	" n=6:335:borrowed-sni; n=7:335:borrowed-sni; n=9:335:udp; n=10:424:udp+ip-risk;" +
	" t=auto:2,3; t=auto:1,4; t=fallback:5,6,7; t=fallback:9; t=last-resort,confirm,max=60:10; fail=2; up=900"

func TestPolicyParsesTheSample(t *testing.T) {
	p, err := Parse(samplePolicy)
	if err != nil {
		t.Fatal(err)
	}
	if len(p.Nodes) != 9 || len(p.Tiers) != 5 {
		t.Fatalf("nodes %d tiers %d", len(p.Nodes), len(p.Tiers))
	}
	last := p.Tiers[4]
	if last.Mode != ModeLastResort || !last.Confirm || last.Max != time.Hour {
		t.Fatalf("last tier %+v", last)
	}
	if p.Params.Fail != 2 || p.Params.Up != 900*time.Second || p.Params.Hold != 300*time.Second || p.Params.TTL != 168*time.Hour {
		t.Fatalf("params %+v", p.Params)
	}
	if got := p.Nodes[8]; got.Scores != (Scores{4, 2, 4}) || !slices.Equal(got.Captions, []string{"udp", "ip-risk"}) {
		t.Fatalf("node 10 %+v", got)
	}
	// the canonical form reads back the same
	again, err := Parse(p.Canonical())
	if err != nil || again.Canonical() != p.Canonical() {
		t.Fatalf("canonical %q: %v", p.Canonical(), err)
	}
	if !strings.HasPrefix(p.Canonical(), "v=1;n=2:545:main;") || strings.Contains(p.Canonical(), " ") {
		t.Fatalf("canonical %q", p.Canonical())
	}
}

func TestPolicyBindsByNumberAndOrdersByScore(t *testing.T) {
	p, _ := Parse(samplePolicy)
	plan := p.Bind(sampleTags, sampleUDP)
	want := []string{"2 Bravo gRPC", "3 Charlie XHTTP", "1 Alpha gRPC compact", "4 Delta XHTTP compact", "5 Echo Naive",
		"6 Foxtrot gRPC two", "7 Golf XHTTP two", "9 India HTTP3", "10 Juliet WG"}
	if !slices.Equal(plan.Tags(), want) {
		t.Fatalf("order %q", plan.Tags())
	}
	if !plan.Candidates[7].UDP || plan.Candidates[0].UDP || plan.Candidates[8].Mode != ModeLastResort {
		t.Fatalf("classes %+v", plan.Candidates)
	}
	if len(plan.Manual) != 0 {
		t.Fatalf("manual %q", plan.Manual)
	}
}

func TestPolicyRefs(t *testing.T) {
	tags := []string{"1 One", "10 Ten", "11§hide§x", "2. Two", "Plain name", "3 Three", "3 Three again", "04 Zero"}
	for _, c := range []struct {
		ref  Ref
		want string
	}{
		{Ref{Number: 1}, "1 One"},  // not "10 Ten"
		{Ref{Number: 10}, "10 Ten"},
		{Ref{Number: 11}, "11§hide§x"}, // the core's suffix does not count
		{Ref{Number: 2}, "2. Two"},
		{Ref{Number: 3}, ""}, // two of them: not applied
		{Ref{Number: 4}, ""}, // "04" is no number
		{Ref{Number: 5}, ""},
		{Ref{Name: "Plain name"}, "Plain name"},
		{Ref{Name: "Plain"}, ""},
	} {
		if got := Resolve(c.ref, tags); got != c.want {
			t.Errorf("%s -> %q, want %q", c.ref, got, c.want)
		}
	}
	p, err := Parse("v=1;n=@Plain%20name:333;t=auto:@Plain%20name,1,3,77")
	if err != nil {
		t.Fatal(err)
	}
	plan := p.Bind(tags, nil)
	if !slices.Equal(plan.Tags(), []string{"Plain name", "1 One"}) {
		t.Fatalf("bound %q", plan.Tags())
	}
	// every proxy the policy does not use, in the profile's order, manual
	if !slices.Equal(plan.Manual, []string{"10 Ten", "11§hide§x", "2. Two", "3 Three", "3 Three again", "04 Zero"}) {
		t.Fatalf("manual %q", plan.Manual)
	}
}

func TestPolicyBoundsAndUnknowns(t *testing.T) {
	p, err := Parse("v=1;t=auto,future-flag:1;t=last-resort,max=1000,confirm:2;fail=99;retry=1;up=5;hold=9999999;chk=600;ttl=1;x-new=abc;n=1:111:some-new-key")
	if err != nil {
		t.Fatal(err)
	}
	if p.Params.Fail != 4 || p.Params.Retry != 2*time.Second || p.Params.Up != 300*time.Second ||
		p.Params.Hold != 3600*time.Second || p.Params.TTL != 24*time.Hour {
		t.Fatalf("not brought to the bounds: %+v", p.Params)
	}
	if p.Tiers[1].Max != 240*time.Minute || !p.Tiers[1].Confirm {
		t.Fatalf("last resort %+v", p.Tiers[1])
	}
	// confirm and max mean nothing on another mode
	p, _ = Parse("v=1;t=fallback,confirm,max=30:1")
	if p.Tiers[0].Confirm || p.Tiers[0].Max != 0 {
		t.Fatalf("fallback %+v", p.Tiers[0])
	}
	// an empty policy: valid, no tiers
	p, err = Parse(" v=1 ; ; ")
	if err != nil || !p.Empty() {
		t.Fatalf("empty: %v", err)
	}
}

func TestPolicyGarbageIsRefusedWhole(t *testing.T) {
	for _, header := range []string{
		"",
		"v=2;t=auto:1",
		"t=auto:1;v=1",
		"v=1;v=1",
		"v=1;t=auto:1;t=fallback:1",     // one proxy in two tiers
		"v=1;t=auto:1,1",                // twice in a tier
		"v=1;n=1:555;n=1:444",           // scored twice
		"v=1;n=1:556",                   // score out of 1..5
		"v=1;n=1:055",                   // score 0
		"v=1;n=1:55",                    // two scores
		"v=1;n=1:5555",                  // four
		"v=1;n=1",                       // no scores
		"v=1;n=1:555:a+b+c",             // three captions
		"v=1;n=1:555:Bad",               // caption not lower case
		"v=1;n=1:555:a b",               // space in a caption
		"v=1;n=1:555:x:y",               // too many parts
		"v=1;t=auto:",                   // empty list
		"v=1;t=auto:0",                  // no proxy 0
		"v=1;t=auto:1000",               // beyond 999
		"v=1;t=auto:01",                 // leading zero
		"v=1;t=fast:1",                  // unknown mode
		"v=1;t=auto",                    // no list
		"v=1;t=auto,:1",                 // empty flag
		"v=1;t=last-resort,max=x:1",     // bad max
		"v=1;t=auto:@",                  // empty name
		"v=1;t=auto:@a%2",               // bad escape
		"v=1;t=auto:@a b",               // space in a name
		"v=1;t=auto:@a%00b",             // control character
		"v=1;fail=2;fail=3",             // repeated parameter
		"v=1;fail=-1",                   // signed
		"v=1;fail=02",                   // leading zero
		"v=1;fail=two",                  // not a number
		"v=1;up=12345678",               // too many digits
		"v=1;=1",                        // empty key
		"v=1;garbage",                   // no =
		"v=1;t=auto:1\x01",              // control byte
		"v=1;n=1:555:ру",                // not ASCII
		"v=1;" + strings.Repeat("t=auto:1;", 1) + strings.Repeat("x=1;", 600), // too long
		"v=1;t=auto:1;t=auto:2;t=auto:3;t=auto:4;t=auto:5;t=auto:6;t=auto:7;t=auto:8;t=auto:9", // nine tiers
	} {
		if p, err := Parse(header); err == nil {
			t.Errorf("accepted %q: %+v", header, p)
		}
	}
	many := func(n int, item func(int) string) []string {
		var out []string
		for i := 1; i <= n; i++ {
			out = append(out, item(i))
		}
		return out
	}
	if _, err := Parse("v=1;t=auto:" + strings.Join(many(32, strconv.Itoa), ",")); err != nil {
		t.Errorf("32 proxies in a tier refused: %v", err)
	}
	if _, err := Parse("v=1;t=auto:" + strings.Join(many(33, strconv.Itoa), ",")); err == nil {
		t.Error("33 proxies in a tier accepted")
	}
	node := func(i int) string { return "n=" + strconv.Itoa(i) + ":333" }
	if _, err := Parse("v=1;" + strings.Join(many(64, node), ";")); err != nil {
		t.Errorf("64 nodes refused: %v", err)
	}
	if _, err := Parse("v=1;" + strings.Join(many(65, node), ";")); err == nil {
		t.Error("65 nodes accepted")
	}
}
