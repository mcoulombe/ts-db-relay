package testutil

import (
	"flag"
	"testing"
)

var accMode = flag.Bool("acc", false, "enable acceptance tests")
var accDevControlMode = flag.Bool("accdevcontrol", false, "enable acceptance tests against dev control")

// SkipUnlessAcc skips unless -acc is passed to `go test -args`.
func SkipUnlessAcc(t *testing.T) {
	if !*accMode {
		t.Skip("skipping: -acc flag not provided")
	}
}

// SkipUnlessAcc skips unless -accdevcontrol is passed to `go test -args`.
func SkipUnlessAccDevControl(t *testing.T) {
	if !*accDevControlMode {
		t.Skip("skipping: -accdevcontrol flag not provided")
	}
}
