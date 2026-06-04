package container

import "testing"

func TestExtractContainerdID(t *testing.T) {
	cases := map[string]string{
		"0::/kubepods.slice/kubepods-burstable.slice/kubepods-burstable-podabc.slice/cri-containerd-0123456789abcdef.scope": "0123456789abcdef",
		"0::/kubepods-podabc.slice:cri-containerd:fedcba9876543210":                                                         "fedcba9876543210",
		"0::/user.slice/user-1000.slice/session-1.scope":                                                                    "",
		"0::/docker/0123456789abcdef":                                                                                       "",
	}

	for input, want := range cases {
		if got := ExtractContainerdID(input); got != want {
			t.Fatalf("ExtractContainerdID(%q) = %q, want %q", input, got, want)
		}
	}
}
