package adminbgservice

import (
	"fmt"
	"log"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"github.com/hiddify/hiddify-core/v2/hcore"
	"github.com/hiddify/hiddify-core/v2/hcore/adminbg"
	"github.com/hiddify/hiddify-core/v2/hcore/hprocess"
	"github.com/hiddify/hiddify-core/v2/hcore/vpnservice"
	"github.com/kardianos/service"
	"google.golang.org/grpc"
)

var logger service.Logger

type hiddifyNext struct {
	adminBg *hiddifyAdminBG
	secret  string
	// where the API listens and the certificate it presents (vpnservice.Endpoint); without a
	// certificate on macOS, whose service keeps its fixed port and serves without TLS
	endpoint vpnservice.Endpoint
}

func allowAdminBgMethod(method string) error {
	switch method {
	case HiddifyAdminBG_Start_FullMethodName, HiddifyAdminBG_Reload_FullMethodName, HiddifyAdminBG_Restart_FullMethodName,
		HiddifyAdminBG_Stop_FullMethodName, HiddifyAdminBG_Status_FullMethodName,
		HiddifyAdminBG_Exit_FullMethodName:
		return nil
	}
	return adminbg.AllowCoreMethod(method)
}

// CleanupLeftovers undoes what the service's engine left in the host when it died with the
// service: the routing of its TUN (see hcore.CleanupLeftovers).
func CleanupLeftovers() {
	_, work := fullCoreDirectories()
	hcore.CleanupLeftovers(work, func(_ hcore.LogLevel, message string) { log.Print(message) })
}

func (m *hiddifyNext) StartAdminBgGrpcServer(listenAddressG string) (*grpc.Server, error) {
	// an engine killed with the service (a crash, SIGKILL) left its TUN's routing behind: the host
	// has no network until the app connects again, so undo it before waiting for the app
	CleanupLeftovers()
	// B-01: never an API without the secret (upstream served one when the file was missing)
	if len(m.secret) < adminbg.MinSecretLength {
		return nil, fmt.Errorf("the VPN service has no control secret: install it again")
	}
	lis, err := net.Listen("tcp", listenAddressG)
	if err != nil {
		log.Printf("failed to listen: %v", err)
		return nil, err
	}
	serverOptions := adminbg.ServerOptions(m.secret, allowAdminBgMethod)
	m.endpoint = vpnservice.Endpoint{Address: lis.Addr().String()}
	if vpnservice.PublishesEndpoint() {
		endpoint, creds, err := serviceTLS(lis)
		if err != nil {
			lis.Close()
			return nil, fmt.Errorf("the VPN service's certificate: %w", err)
		}
		m.endpoint = endpoint
		serverOptions = append(serverOptions, creds)
	}
	s := grpc.NewServer(serverOptions...)
	m.adminBg = &hiddifyAdminBG{}
	RegisterHiddifyAdminBGServer(s, m.adminBg)
	adminbg.RegisterControl(s)

	log.Printf("Server listening on %s", m.endpoint.Address)
	go func() {
		if err := s.Serve(lis); err != nil {
			log.Printf("failed to serve: %v", err)
		}
		log.Printf("Server stopped")
	}()
	return s, nil
}

func (m *hiddifyNext) Start(s service.Service) error {
	if err := WriteRunningBinaryStamp(); err != nil {
		return fmt.Errorf("record tunnel binary stamp: %w", err)
	}
	// B-01: without its secret the service does not serve at all; the app installs it again, which
	// writes a new secret
	secret, err := LoadControlSecret()
	if err != nil {
		return fmt.Errorf("tunnel control secret: %w", err)
	}
	m.secret = secret
	// a free port on Windows and Linux, published with the certificate; macOS's fixed one
	if _, err := m.StartAdminBgGrpcServer(vpnservice.ServiceListenAddress()); err != nil {
		return err
	}
	if vpnservice.PublishesEndpoint() {
		if err := publishEndpoint(m.endpoint); err != nil {
			return err
		}
	}
	return nil
}

func (m *hiddifyNext) Stop(s service.Service) error {
	if vpnservice.PublishesEndpoint() {
		withdrawEndpoint()
	}
	if m.adminBg == nil {
		return nil
	}
	_, err := m.adminBg.Stop(nil, nil)
	if err != nil {
		return nil
	}
	return nil
}

func getCurrentExecutableDirectory() string {
	executablePath, err := os.Executable()
	if err != nil {
		return ""
	}
	return filepath.Dir(executablePath)
}

func serviceDataDirectory() string {
	// Windows/Linux: keep cache and the control secret under the OS data dir, never beside the
	// install tree in Program Files (writes there look suspicious and often fail).
	if runtime.GOOS != "darwin" {
		return controlDataDir()
	}
	return dataDirectoryFor(getCurrentExecutableDirectory())
}

func dataDirectoryFor(directory string) string {
	if filepath.Base(directory) == "MacOS" && filepath.Base(filepath.Dir(directory)) == "Contents" &&
		filepath.Ext(filepath.Dir(filepath.Dir(directory))) == ".app" {
		return filepath.Join(filepath.Dir(filepath.Dir(filepath.Dir(directory))), "data")
	}
	return directory
}

func installOwner() string {
	if owner := os.Getenv("HIDDIFY_ADMIN_BG_OWNER"); owner != "" {
		return owner
	}
	if owner := os.Getenv("HIDDIFY_TUNNEL_OWNER"); owner != "" {
		return owner
	}
	if owner := os.Getenv("USERNAME"); owner != "" {
		return owner
	}
	return os.Getenv("USER")
}

// osServiceName is the OS service id passed to kardianos/service.
// On Linux systemd, that library writes Name+".service" (do not include the suffix here).
//
// Windows and Linux: the fork's own, so that it never stops, replaces or removes the service of an
// upstream Hiddify installed on the same computer (HiddifyAdminBG), nor is taken for it. macOS keeps
// the upstream label until the macOS app is renamed (its install scripts and bundle use it).
func osServiceName() string {
	return vpnservice.ServiceNameOn(runtime.GOOS)
}

func serviceRunArguments() []string {
	if runtime.GOOS == "darwin" {
		return []string{"--tunnel", "run"}
	}
	return []string{"admin_bgservice", "run"}
}

func StartAdminBgService(goArg string) (int, string) {
	dataDirectory := serviceDataDirectory()
	// Made (and checked) only by the elevated install and by the service itself: the other commands
	// (start, stop, connect) run as the user, and a folder they made would belong to the user.
	if goArg == "install" || goArg == "run" {
		if err := prepareDataDirectory(dataDirectory); err != nil {
			return 3, fmt.Sprintf("Error: %v", err)
		}
	}
	if goArg == "install" {
		if _, err := EnsureControlSecret(installOwner()); err != nil {
			return 3, fmt.Sprintf("Error: %v", err)
		}
	}
	// Windows: SandpiperAdmin.exe admin_bgservice run; Linux: HiddifyCli admin_bgservice run.
	// macOS: the copied .app must get --tunnel so AppDelegate runs parseCli instead of the Flutter UI.
	svcConfig := &service.Config{
		Name:             osServiceName(),
		DisplayName:      serviceDisplayName(),
		Arguments:        serviceRunArguments(),
		Description:      serviceDescription(),
		WorkingDirectory: dataDirectory,
		Option: map[string]interface{}{
			"RunAtLoad":     true,
			"SystemdScript": systemdUnit,
		},
	}

	prg := &hiddifyNext{}
	s, err := service.New(prg, svcConfig)
	if err != nil {
		return 1, fmt.Sprintf("Error: %v", err)
	}

	if len(goArg) > 0 && goArg != "run" {
		return control(s, goArg)
	}

	if err := os.Chdir(dataDirectory); err != nil {
		return 3, fmt.Sprintf("Error: %v", err)
	}
	logger, err = s.Logger(nil)
	if err != nil {
		log.Printf("Error: %v", err)
	}
	// the service must not be slowed down as a background job (a launchd job has no ProcessType)
	hprocess.RaisePriority()
	err = s.Run()
	if err != nil {
		logger.Error(err)
		return 3, fmt.Sprintf("Error: %v", err)
	}
	return 0, ""
}

// installWhenRemoved installs the service, retrying while the old one is still being deleted: the
// service manager removes it only once its process has exited and every handle to it is closed.
func installWhenRemoved(s service.Service) error {
	deadline := time.Now().Add(15 * time.Second)
	for {
		err := s.Install()
		if err == nil || !strings.Contains(err.Error(), "already exists") || time.Now().After(deadline) {
			return err
		}
		time.Sleep(250 * time.Millisecond)
	}
}

func control(s service.Service, goArg string) (int, string) {
	dolog := false
	var err error
	status, serr := s.Status()
	if dolog {
		fmt.Printf("Current Status: %+v %+v!\n", status, serr)
	}
	switch goArg {
	case "uninstall":
		if status == service.StatusRunning {
			s.Stop()
		}
		err = s.Uninstall()
	case "start":
		if status == service.StatusRunning {
			return 0, "Tunnel Service Already Running."
		} else if status == service.StatusUnknown {
			s.Uninstall()
			s.Install()
			status, serr = s.Status()
			_ = serr
		}
		if status != service.StatusRunning {
			err = s.Start()
		}
	case "install":
		// A service left by another build (an update, or a portable copy beside an installed one)
		// may still run. Deleting a running service only marks it for deletion, so Install then
		// failed with "already exists" (exit code 2): stop it first and wait until it is gone.
		if status == service.StatusRunning {
			_ = s.Stop()
		}
		_ = s.Uninstall()
		err = installWhenRemoved(s)
		status, serr = s.Status()
		_ = serr
		if status != service.StatusRunning {
			err = s.Start()
		}
	case "stop":
		if status == service.StatusStopped {
			return 0, "Tunnel Service Already Stopped."
		}
		err = s.Stop()
	default:
		err = service.Control(s, goArg)
	}
	if err == nil {
		return 0, fmt.Sprintf("Tunnel Service %sed Successfully.", goArg)
	}
	return 2, fmt.Sprintf("Error: %v", err)
}

// serviceDisplayName and serviceDescription: what Windows' Services list shows (macOS: as upstream).
func serviceDisplayName() string {
	return vpnservice.ServiceDisplayNameOn(runtime.GOOS)
}

func serviceDescription() string {
	return vpnservice.ServiceDescriptionOn(runtime.GOOS)
}
