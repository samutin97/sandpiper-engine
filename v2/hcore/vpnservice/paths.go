package vpnservice

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime"
)

// DataDir is the service's folder on this computer: where its secret, endpoint and build stamp
// are, and its engine's data. The elevated install and the service make it; the app only reads
// the three files.
func DataDir() string {
	return dataDirOn(runtime.GOOS, os.Getenv)
}

func dataDirOn(goos string, getenv func(string) string) string {
	if dir := getenv(DataDirEnv); dir != "" {
		return dir
	}
	if dir := getenv(LegacyDataDirEnv); dir != "" {
		return dir
	}
	switch goos {
	case "darwin":
		return DarwinDataDir
	case "windows":
		base := getenv("PROGRAMDATA")
		if base == "" {
			base = `C:\ProgramData`
		}
		return filepath.Join(base, WindowsDataFolder, WindowsDataSubfolder)
	default:
		return LinuxDataDir
	}
}

// DataDirIsDefault reports whether DataDir is the standard folder, not one an environment
// variable named.
func DataDirIsDefault() bool {
	return os.Getenv(DataDirEnv) == "" && os.Getenv(LegacyDataDirEnv) == ""
}

func SecretPath() string     { return filepath.Join(DataDir(), SecretFile) }
func EndpointPath() string   { return filepath.Join(DataDir(), EndpointFile) }
func BuildStampPath() string { return filepath.Join(DataDir(), BuildStampFile) }

// LegacySecretPath is where a macOS service installed before the rename of its folder keeps its
// secret. Windows and Linux never read an older folder: those were upstream Hiddify's.
func LegacySecretPath() string {
	if runtime.GOOS != "darwin" {
		return ""
	}
	return filepath.Join(DarwinLegacyDataDir, SecretFile)
}

// ServiceNameOn is the OS service id of the service on goos (kardianos/service: the Windows
// service, the systemd unit without ".service", the launchd label).
func ServiceNameOn(goos string) string {
	if goos == "darwin" {
		return DarwinServiceName
	}
	return ServiceName
}

// ServiceDisplayNameOn is what the OS lists the service as.
func ServiceDisplayNameOn(goos string) string {
	if goos == "darwin" {
		return DarwinServiceDisplayName
	}
	return ServiceDisplayName
}

// ServiceDescriptionOn is the service's description.
func ServiceDescriptionOn(goos string) string {
	if goos == "darwin" {
		return DarwinServiceDescription
	}
	return ServiceDescription
}

// FixedPortOn is the loopback port of the service on goos when it has a fixed one: macOS only,
// whose app finds the service there (macos/Runner/AdminBgServiceController.swift). Elsewhere it
// is 0: the service takes a free port at each start and publishes it, with its certificate, in
// EndpointFile, so no other program can wait for the app on a known port.
func FixedPortOn(goos string) int {
	if goos == "darwin" {
		return DarwinServicePort
	}
	return 0
}

// ServiceListenAddress is the address the installed service listens on here.
func ServiceListenAddress() string {
	return fmt.Sprintf("127.0.0.1:%d", FixedPortOn(runtime.GOOS))
}

// PublishesEndpoint reports whether the service of this computer publishes its endpoint (and
// serves TLS) rather than listening on a fixed port.
func PublishesEndpoint() bool {
	return FixedPortOn(runtime.GOOS) == 0
}

// TunInterfaceNameOn is the name of the service engine's TUN on goos: macOS names its utun itself.
func TunInterfaceNameOn(goos string) string {
	if goos == "darwin" {
		return ""
	}
	return TunInterfaceName
}

// CLINameOn is the console launcher the service commands run through (the app's core passes its
// path, cli_path; this is its file name).
func CLINameOn(goos string) string {
	if goos == "windows" {
		return WindowsCLI
	}
	return LinuxCLI
}
