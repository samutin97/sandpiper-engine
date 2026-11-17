package mobile

import (
	hcore "github.com/hiddify/hiddify-core/v2/hcore"

	_ "github.com/sagernet/gomobile"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/experimental/libbox"
)

type SetupOptions struct {
	BasePath   string
	WorkingDir string
	TempDir    string
	// DataPath is where the core keeps its own data (settings database, cache file, logs): a
	// private directory of the app. Empty: BasePath on Android.
	DataPath        string
	Listen          string
	Secret          string
	Debug           bool
	Mode            int
	FixAndroidStack bool
	// MemoryLimit is what the core may use on this device, in bytes; 0 for none of its own.
	MemoryLimit int64
	// LowMemory is set on a device short of memory (a low-RAM TV): relaying trades speed for memory.
	LowMemory bool
}

func Setup(opt *SetupOptions, platformInterface libbox.PlatformInterface) error {
	hcore.SetDeviceMemory(opt.MemoryLimit, opt.LowMemory)
	return hcore.Setup(&hcore.SetupRequest{
		BasePath:          opt.BasePath,
		WorkingDir:        opt.WorkingDir,
		TempDir:           opt.TempDir,
		DataPath:          opt.DataPath,
		FlutterStatusPort: 0,
		Listen:            opt.Listen,
		Debug:             opt.Debug,
		Mode:              hcore.SetupMode(opt.Mode),
		Secret:            opt.Secret,
		FixAndroidStack:   opt.FixAndroidStack,
	}, platformInterface)

	// return hcore.Start(17078)
}

// func Start(configPath string, configContent string, platformInterface libbox.PlatformInterface) (*hcore.CoreInfoResponse, error) {
// 	state, err := hcore.StartWithPlatformInterface(&hcore.StartRequest{
// 		ConfigContent: configContent,
// 		ConfigPath:    configPath,
// 	}, platformInterface)
// 	return state, err
// }

// Start starts the core without the app (Always-on, a restart after the process was killed), in
// the context Setup made with the platform interface (see hcore.SetupContext).
func Start(configPath string, configContent string) error {
	_, err := hcore.StartService(hcore.SetupContext(), &hcore.StartRequest{
		ConfigPath:    configPath,
		ConfigContent: configContent,
	})
	return err
}

func Stop() error {
	_, err := hcore.Stop()
	return err
}

// GetListenAddress is the address the gRPC server of mode really listens on: "unix:/path",
// "unix-abstract:name" or "127.0.0.1:<port>" (after asking for port 0), "" if it does not run.
func GetListenAddress(mode int) string {
	return hcore.GetListenAddress(hcore.SetupMode(mode))
}

// ProtectsOwnSockets says that this core protects the sockets that carry its tunnel on Android
// (route auto_detect_interface: VpnService.protect through autoDetectInterfaceControl, and the
// default network): the app may stay inside its own VPN, and its own requests go through the
// tunnel (H-02). The app asks it by reflection (com.hiddify.core.mobile.Mobile.protectsOwnSockets);
// an older core has no such method, and the app then keeps itself out of the VPN as before.
func ProtectsOwnSockets() bool {
	return C.IsAndroid
}

func GetServerPublicKey() []byte {
	return hcore.GetGrpcServerPublicKey()
}

func AddGrpcClientPublicKey(clientPublicKey []byte) error {
	return hcore.AddGrpcClientPublicKey(clientPublicKey)
}

func Close(mode int) {
	hcore.Close(hcore.SetupMode(mode))
}

func Test() string {
	return "Hello from mobile"
}

func Pause() {
	hcore.Pause()
}

func Wake() {
	hcore.Wake()
}
