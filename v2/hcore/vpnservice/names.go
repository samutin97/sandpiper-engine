// Package vpnservice is the one place the core keeps what the desktop app, its core and the VPN
// service (adminbgservice) must agree on: the names of the programs and of the service, the
// service's folder and its files, and how a client finds and checks the service (endpoint.go).
//
// The app has the same values in lib/hiddifycore/core_interface/service_names.dart, and its test
// test/hiddifycore/service_names_test.dart reads the constants below from this file: keep them
// plain `Name = "value"` (or a number) lines, one per line.
package vpnservice

const (
	// Windows: the launchers beside the app (the core's Makefile, WIN_CLINAME, WIN_ADMINNAME and
	// WIN_ENGINENAME, builds them under these names).
	WindowsCLI    = "SandpiperCore.exe"
	WindowsAdmin  = "SandpiperAdmin.exe"
	WindowsEngine = "SandpiperCoreEngine.exe"
	// Linux: the launcher of the core (cmd/bydll), in the app's folder.
	LinuxCLI = "HiddifyCli"

	// Windows and Linux: the service. Never upstream Hiddify's (HiddifyAdminBG, ProgramData\Hiddify,
	// /var/lib/hiddify-admin-bgservice), which may be installed on the same computer.
	ServiceName        = "SandpiperAdminBG"
	ServiceDisplayName = "Sandpiper Service"
	ServiceDescription = "Runs the tunnel the Sandpiper app starts in VPN mode."
	// %ProgramData%\<WindowsDataFolder>\<WindowsDataSubfolder>
	WindowsDataFolder    = "Sandpiper"
	WindowsDataSubfolder = "AdminBgService"
	LinuxDataDir         = "/var/lib/sandpiper-admin-bgservice"
	// the TUN adapter of the service's engine; two adapters of one name would collide
	TunInterfaceName = "SandpiperAdminBg"
	// the temporary request file the app's core hands to the console launcher (connect)
	ConnectRequestPattern = "sandpiper-admin-bgservice-*.json"

	// macOS keeps upstream's label, folder and fixed port until the macOS app is renamed
	// (bundle id, helper, launchd label and install scripts go together).
	DarwinServiceName        = "HiddifyAdminBG"
	DarwinServiceDisplayName = "Hiddify VPN"
	DarwinServiceDescription = "Hiddify virtual private network"
	DarwinDataDir            = "/Library/Application Support/Hiddify/AdminBgService/data"
	DarwinLegacyDataDir      = "/Library/Application Support/Hiddify/TunnelService/data"
	DarwinServicePort        = 18420

	// The files in the service's folder.
	// SecretFile: the control secret, written by the elevated install; the installing user reads it.
	SecretFile = "control.secret"
	// EndpointFile: where the running service listens and the certificate it presents (JSON,
	// Endpoint), written by the service at each start; readable by users, written only by it.
	EndpointFile = "control.endpoint"
	// BuildStampFile: the build id of the running service, compared with the app's core's.
	BuildStampFile = "build.id"

	// Environment overrides of the folder (tests, a portable setup).
	DataDirEnv       = "HIDDIFY_ADMIN_BG_DATA"
	LegacyDataDirEnv = "HIDDIFY_TUNNEL_DATA"
)
