package event

import "testing"

func TestClassify(t *testing.T) {
	cases := []struct {
		name   string
		event  Event
		policy string
	}{
		{name: "wget exec", event: Event{EventType: EventExec, Comm: "wget", Path: "/usr/bin/wget"}, policy: "wget-exec"},
		{name: "secret open", event: Event{EventType: EventFileOpen, Path: "/var/run/secrets/kubernetes.io/serviceaccount/token"}, policy: "k8s-secret-access"},
		{name: "proc mount", event: Event{EventType: EventMount, Path: "/proc", Extra: "proc"}, policy: "suspicious-mount"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			evt := tc.event
			Classify(&evt)
			if evt.Risk != "high" || evt.Policy != tc.policy {
				t.Fatalf("Classify() risk=%q policy=%q, want high/%s", evt.Risk, evt.Policy, tc.policy)
			}
		})
	}
}
