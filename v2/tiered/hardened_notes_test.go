package tiered

import (
	"context"
	"strings"
	"testing"
	"time"
)

// notes collects what the controller tells OnNote, as kind:tag(why) for the order, and the notes.
type notes struct {
	all []Note
}

func (n *notes) add(note Note) { n.all = append(n.all, note) }

func (n *notes) kinds() string {
	var parts []string
	for _, note := range n.all {
		part := note.Kind
		if note.Tag != "" {
			part += ":" + number(note.Tag)
		}
		if note.Why != "" {
			part += "(" + note.Why + ")"
		}
		parts = append(parts, part)
	}
	return strings.Join(parts, " ")
}

func (n *notes) last(kind string) Note {
	for i := len(n.all) - 1; i >= 0; i-- {
		if n.all[i].Kind == kind {
			return n.all[i]
		}
	}
	return Note{}
}

// Every decision of a walk under a TCP freeze reaches OnNote with its proxy's server, tier and
// mode: the walk, TCP to the server out, the UDP proxy chosen.
func TestTierNotesOfAFreeze(t *testing.T) {
	env := newFakeEnv(t)
	freezeTCP(env)
	env.path = func(time.Time) (PathVerdict, time.Duration) { return PathBlocked, 6 * time.Second }
	plan := samplePlan(t)
	plan.SetServers(func(tag string) string {
		if sampleUDP(tag) {
			return "198.51.100.2/32"
		}
		return "192.0.2.1/32"
	})
	var got notes
	c := New(env, plan, nil)
	c.OnNote = got.add
	c.SetEnabled(context.Background(), true)
	if want := "walk(selected) tcp_out:2 use:9(walk)"; got.kinds() != want {
		t.Fatalf("notes %q, want %q", got.kinds(), want)
	}
	if out := got.last(NoteTCPOut); out.Server != "192.0.2.1/32" || out.Tier != 1 || out.Mode != ModeAuto {
		t.Fatalf("tcp_out %+v", out)
	}
	if use := got.last(NoteUse); use.Server != "198.51.100.2/32" || use.Tier != 4 || use.Mode != ModeFallback || use.From != "" {
		t.Fatalf("use %+v", use)
	}
}

// The last resort: asked when nothing else works (with the next try), the user's agreement, the
// walk it starts and the last resort chosen; then the way up brings the top proxy back, from it.
func TestTierNotesOfTheLastResort(t *testing.T) {
	env := newFakeEnv(t)
	onlyTheLastResortWorks(env)
	var got notes
	c := New(env, samplePlan(t), nil)
	c.OnNote = got.add
	c.SetEnabled(context.Background(), true)
	ask := got.last(NoteAsk)
	if number(ask.Tag) != "10" || ask.Wait != NoneFirst || ask.Mode != ModeLastResort {
		t.Fatalf("ask %+v (notes %q)", ask, got.kinds())
	}
	if !strings.Contains(got.kinds(), "mark:2") || !strings.Contains(got.kinds(), "mark:9") {
		t.Fatalf("no marks: %q", got.kinds())
	}
	got.all = nil
	c.Confirm(context.Background(), lastResort)
	if want := "agree:10 walk(the user agreed to the last resort)"; !strings.HasPrefix(got.kinds(), want) {
		t.Fatalf("notes %q, want %q first", got.kinds(), want)
	}
	if use := got.last(NoteUse); number(use.Tag) != "10" || use.Why != "walk" {
		t.Fatalf("use %+v (notes %q)", use, got.kinds())
	}
	// the servers come back: the way up finds 2 (two passes) and leaves 10
	env.script = func(string, time.Time) (Outcome, time.Duration) { return OK, time.Second }
	got.all = nil
	env.runFor(context.Background(), c, 2*time.Hour)
	use := got.last(NoteUse)
	if number(use.Tag) != "2" || use.Why != "up" || number(use.From) != "10" {
		t.Fatalf("use %+v (notes %q)", use, got.kinds())
	}
}

// The proxy in use failing its data check, and the user's own pick, are told too.
func TestTierNotesOfTheProxyInUse(t *testing.T) {
	env := newFakeEnv(t)
	var got notes
	picked := true
	env.picked = func() bool { return picked }
	c := New(env, samplePlan(t), nil)
	c.OnNote = got.add
	c.SetEnabled(context.Background(), true)
	env.script = func(tag string, _ time.Time) (Outcome, time.Duration) {
		if number(tag) == "2" {
			return Stall, 6 * time.Second
		}
		return OK, time.Second
	}
	got.all = nil
	c.ActiveFailed(context.Background())
	if !strings.HasPrefix(got.kinds(), "active_failed:2(stall)") || number(got.last(NoteUse).Tag) != "3" {
		t.Fatalf("notes %q", got.kinds())
	}
	if use := got.last(NoteUse); number(use.From) != "2" {
		t.Fatalf("use %+v", use)
	}
	got.all = nil
	picked = false
	c.SetEnabled(context.Background(), false)
	if got.kinds() != "idle" {
		t.Fatalf("notes %q", got.kinds())
	}
}
