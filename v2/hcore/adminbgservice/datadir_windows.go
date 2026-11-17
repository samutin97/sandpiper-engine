//go:build windows

package adminbgservice

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/hectane/go-acl"
	"github.com/hiddify/hiddify-core/v2/hcore/vpnservice"
	"golang.org/x/sys/windows"
)

// dataDirectorySDDL is the DACL of the service's folders (B-01): SYSTEM and Administrators have
// full control, inherited by everything inside; Users may only list the folder itself. Under
// ProgramData a folder otherwise inherits the right of every user to create files and folders in
// it, so any program could put a secret it knows, an endpoint, a link or a junction where the
// SYSTEM service reads and writes. The control secret, the endpoint and the build stamp get their
// own ACL (chownSecret, allowUsersToRead); the engine's configuration and resources are readable
// by no user.
const dataDirectorySDDL = "D:PAI(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;;0x1200a9;;;BU)"

// prepareDataDirectory makes the service's folder, and ProgramData\Sandpiper above it, owned by
// Administrators with dataDirectorySDDL. Only the elevated install and the service call it: a
// folder the user's own commands made would belong to the user. A folder that exists already must
// belong to SYSTEM or Administrators and be a plain folder; any other (made first by a program
// without administrator rights, or a junction) is never taken over: it is moved aside, unopened,
// and a new one made.
func prepareDataDirectory(dir string) error {
	directories := []string{dir}
	if vpnservice.DataDirIsDefault() {
		directories = []string{filepath.Dir(dir), dir}
	}
	for _, directory := range directories {
		if err := secureDirectory(directory); err != nil {
			return err
		}
	}
	return nil
}

func secureDirectory(dir string) error {
	info, err := os.Lstat(dir)
	if err == nil && !trustedDirectory(dir, info) {
		aside := fmt.Sprintf("%s.untrusted-%d", dir, time.Now().UnixNano())
		if renameErr := os.Rename(dir, aside); renameErr != nil {
			return fmt.Errorf("%s was not made by an administrator and could not be moved aside (%v): delete it and try again", dir, renameErr)
		}
		err = os.ErrNotExist
	}
	if err != nil {
		if !errors.Is(err, os.ErrNotExist) {
			return err
		}
		if err := os.MkdirAll(dir, 0o700); err != nil {
			return err
		}
		// made by this elevated process: owned by Administrators whatever the owner policy is
		// ("object creator" makes the administrator's own account the owner)
		if err := setOwnerAdministrators(dir); err != nil {
			return fmt.Errorf("take ownership of %s: %w", dir, err)
		}
	}
	descriptor, err := windows.SecurityDescriptorFromString(dataDirectorySDDL)
	if err != nil {
		return err
	}
	dacl, _, err := descriptor.DACL()
	if err != nil {
		return err
	}
	if err := windows.SetNamedSecurityInfo(dir, windows.SE_FILE_OBJECT,
		windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION, nil, nil, dacl, nil); err != nil {
		return fmt.Errorf("restrict the ACL of %s: %w", dir, err)
	}
	return nil
}

// trustedDirectory: a plain folder (not a link or junction) owned by SYSTEM or Administrators.
func trustedDirectory(path string, info os.FileInfo) bool {
	if !info.IsDir() || info.Mode()&(os.ModeSymlink|os.ModeIrregular) != 0 {
		return false
	}
	descriptor, err := windows.GetNamedSecurityInfo(path, windows.SE_FILE_OBJECT, windows.OWNER_SECURITY_INFORMATION)
	if err != nil {
		return false
	}
	owner, _, err := descriptor.Owner()
	if err != nil || owner == nil {
		return false
	}
	return owner.IsWellKnown(windows.WinLocalSystemSid) || owner.IsWellKnown(windows.WinBuiltinAdministratorsSid)
}

func setOwnerAdministrators(path string) error {
	admins, err := windows.CreateWellKnownSid(windows.WinBuiltinAdministratorsSid)
	if err != nil {
		return err
	}
	return windows.SetNamedSecurityInfo(path, windows.SE_FILE_OBJECT, windows.OWNER_SECURITY_INFORMATION, admins, nil, nil, nil)
}

// allowUsersToRead gives the file a DACL of its own: SYSTEM and Administrators full control,
// Users read. The build stamp and the endpoint, which the app reads as the user and only the
// service writes.
func allowUsersToRead(path string) error {
	system, err := windows.CreateWellKnownSid(windows.WinLocalSystemSid)
	if err != nil {
		return err
	}
	admins, err := windows.CreateWellKnownSid(windows.WinBuiltinAdministratorsSid)
	if err != nil {
		return err
	}
	users, err := windows.CreateWellKnownSid(windows.WinBuiltinUsersSid)
	if err != nil {
		return err
	}
	return acl.Apply(path, true, false,
		acl.GrantSid(windows.GENERIC_ALL, system),
		acl.GrantSid(windows.GENERIC_ALL, admins),
		acl.GrantSid(windows.GENERIC_READ, users),
	)
}
