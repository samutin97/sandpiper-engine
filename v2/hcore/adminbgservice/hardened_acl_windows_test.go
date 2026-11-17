//go:build windows

package adminbgservice

import (
	"os"
	"os/user"
	"path/filepath"
	"strings"
	"testing"

	"github.com/hectane/go-acl"
	"golang.org/x/sys/windows"
)

// makeRemovable gives the test's own account full control of what the test wrote under dir again:
// the endpoint and the build stamp get a protected DACL (Users read only), which the owner may
// always change, or the temporary folder could not be removed.
func makeRemovable(t *testing.T, dir string) {
	current, err := user.Current()
	if err != nil {
		t.Log(err)
		return
	}
	_ = filepath.Walk(dir, func(path string, info os.FileInfo, err error) error {
		if err == nil && !info.IsDir() {
			_ = acl.Apply(path, true, true, acl.GrantName(windows.GENERIC_ALL, current.Username))
		}
		return nil
	})
}

// The endpoint and the build stamp: SYSTEM and Administrators may change them, Users may only read.
func TestPublicFilesAreReadOnlyForUsers(t *testing.T) {
	dir := serviceDir(t)
	path := filepath.Join(dir, "public")
	if err := writePublicFile(path, []byte("x")); err != nil {
		t.Fatal(err)
	}
	if content, err := os.ReadFile(path); err != nil || string(content) != "x" {
		t.Fatalf("read %q, %v", content, err)
	}
	descriptor, err := windows.GetNamedSecurityInfo(path, windows.SE_FILE_OBJECT, windows.DACL_SECURITY_INFORMATION)
	if err != nil {
		t.Fatal(err)
	}
	control, _, err := descriptor.Control()
	if err != nil {
		t.Fatal(err)
	}
	if control&windows.SE_DACL_PROTECTED == 0 {
		t.Error("the DACL inherits from the folder")
	}
	text := descriptor.String()
	for _, want := range []string{";;;SY)", ";;;BA)", ";;;BU)"} {
		if !strings.Contains(text, want) {
			t.Errorf("%s has no ACE for %s", text, want)
		}
	}
	// the account the test runs as is not granted anything of its own
	current, _ := user.Current()
	if current != nil && strings.Contains(text, current.Uid) {
		t.Errorf("%s grants the user's own account", text)
	}
	// nobody but SYSTEM and Administrators may write it: Users have read only
	if strings.Contains(text, "(A;;FA;;;BU)") || strings.Contains(text, "(A;;GA;;;BU)") || strings.Contains(text, "(A;;FW;;;BU)") {
		t.Errorf("Users may change it: %s", text)
	}
}
