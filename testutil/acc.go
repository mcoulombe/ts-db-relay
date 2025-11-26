package testutil

import (
	"flag"
	"testing"
)

var accMode = flag.Bool("acc", false, "enable acceptance tests")

// SkipUnlessAcc skips unless -acc is passed to `go test -args`.
func SkipUnlessAcc(t *testing.T) {
	if !*accMode {
		t.Skip("skipping: -acc flag not provided")
	}
}
