package cmd

import (
	"testing"

	"github.com/spf13/cobra"
)

// W4-01: the core's process (`core`, the desktop app's engine) and the AppImage's foreground
// service (`core-service`) listen on a free port unless told otherwise, and print the address they
// took: upstream's 17078 and 18021 were taken whenever upstream Hiddify ran on the same computer.
func TestTheDesktopProcessesListenOnAFreePort(t *testing.T) {
	for _, command := range []*cobra.Command{commandCore, commandCoreService} {
		if listen := command.Flags().Lookup("listen").DefValue; listen != "127.0.0.1:0" {
			t.Errorf("%s listens on %q by default", command.Name(), listen)
		}
	}
	if CoreListenPrefix == CoreReadyPrefix || CoreServiceListenPrefix == CoreServiceCertPrefix {
		t.Error("the lines the app reads must differ")
	}
}
