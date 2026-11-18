package adminbg

import (
	"testing"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/hiddify/hiddify-core/v2/hcore"
)

// The block journal on the tunnel control service (the privileged core on Windows): its size, a
// clear and the report read back inline are allowed; a path to write to or files to put in the
// report are not, as for the diagnostics.
func TestBlockJournalOnTheTunnelControlService(t *testing.T) {
	method := hcore.Core_BlockJournal_FullMethodName
	if err := AllowCoreMethod(method); err != nil {
		t.Fatalf("BlockJournal is not allowed: %v", err)
	}
	for _, c := range []struct {
		name string
		req  any
		ok   bool
	}{
		{"the size", &hcore.BlockJournalRequest{}, true},
		{"a clear", &hcore.BlockJournalRequest{Clear: true}, true},
		{"the report inline", &hcore.BlockJournalRequest{Export: true, Inline: true}, true},
		{"the report to a file of the service", &hcore.BlockJournalRequest{Export: true}, false},
		{"the report to a path", &hcore.BlockJournalRequest{Export: true, Inline: true, DestinationPath: `C:\Windows\x.zip`}, false},
		{"a path without a report", &hcore.BlockJournalRequest{DestinationPath: "/etc/x"}, false},
		{"files of the caller", &hcore.BlockJournalRequest{Export: true, Inline: true, ExtraFiles: map[string][]byte{"app.log": nil}}, false},
		{"another request", &hcore.ExportDiagnosticsRequest{Inline: true}, false},
	} {
		err := AllowCoreRequest(method, c.req)
		if c.ok != (err == nil) {
			t.Errorf("%s: %v", c.name, err)
		}
		if err != nil && status.Code(err) != codes.PermissionDenied {
			t.Errorf("%s: %v, want PermissionDenied", c.name, err)
		}
	}
}
