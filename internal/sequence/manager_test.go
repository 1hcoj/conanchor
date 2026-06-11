package sequence

import "testing"

func TestManagerNext(t *testing.T) {
	m := NewManager()
	g, c := m.Next("a")
	if g != 1 || c != 1 {
		t.Fatalf("got %d/%d", g, c)
	}
	g, c = m.Next("a")
	if g != 2 || c != 2 {
		t.Fatalf("got %d/%d", g, c)
	}
	g, c = m.Next("b")
	if g != 3 || c != 1 {
		t.Fatalf("got %d/%d", g, c)
	}
}
