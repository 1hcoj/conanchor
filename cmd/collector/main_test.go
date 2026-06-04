package main

import (
	"reflect"
	"testing"
)

func TestParseCgroupIDs(t *testing.T) {
	cases := []struct {
		name string
		in   string
		want []uint64
	}{
		{name: "empty", in: "", want: nil},
		{name: "single", in: "12345", want: []uint64{12345}},
		{name: "multiple", in: "12345,67890, 42", want: []uint64{12345, 67890, 42}},
		{name: "skip empty parts", in: "12345,,67890", want: []uint64{12345, 67890}},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := parseCgroupIDs(tc.in)
			if err != nil {
				t.Fatalf("parseCgroupIDs(%q) returned error: %v", tc.in, err)
			}
			if !reflect.DeepEqual(got, tc.want) {
				t.Fatalf("parseCgroupIDs(%q) = %#v, want %#v", tc.in, got, tc.want)
			}
		})
	}
}

func TestParseCgroupIDsRejectsInvalid(t *testing.T) {
	for _, in := range []string{"abc", "0", "123,abc"} {
		if _, err := parseCgroupIDs(in); err == nil {
			t.Fatalf("parseCgroupIDs(%q) returned nil error", in)
		}
	}
}
