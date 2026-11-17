package cmd

import (
	"bufio"
	"encoding/base64"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/hiddify/hiddify-core/v2/hcore/adminbgservice"
	"github.com/hiddify/hiddify-core/v2/hcore/hprocess"

	"github.com/spf13/cobra"
)

// The AppImage's VPN: an AppImage cannot install the VPN service (its files live in the user's
// mount, which root cannot read), so the app starts the same AppImage as root, through pkexec, with
// this command. It serves the VPN service's API in the foreground for as long as the app runs: the
// app connects to it as to the installed service. The first stdin line is the control secret
// (pkexec clears the environment); stdin then stays open, and its end, like the app's exit, stops
// the engine and the process.
//
// Before the ready line, CoreServiceListenPrefix gives the address the API listens on (a free port
// by default, never upstream's 18021) and CoreServiceCertPrefix the certificate it presents (base64
// PEM): the app trusts only that one, as with the installed service's endpoint file.
const (
	CoreServiceReadyLine    = "HIDDIFY_SERVICE_READY"
	CoreServiceListenPrefix = "HIDDIFY_SERVICE_LISTEN "
	CoreServiceCertPrefix   = "HIDDIFY_SERVICE_CERT "
)

var coreServiceOptions struct {
	listen   string
	ownerPID int32
	cleanup  bool
}

var commandCoreService = &cobra.Command{
	Use:    "core-service",
	Short:  "Run the VPN service in the foreground for the app that starts it (AppImage, through pkexec)",
	Hidden: true,
	Args:   cobra.NoArgs,
	Run: func(cmd *cobra.Command, args []string) {
		os.Exit(runCoreService())
	},
}

func init() {
	flags := commandCoreService.Flags()
	flags.StringVar(&coreServiceOptions.listen, "listen", defaultCoreListen, "control API listen address (port 0: a free port, printed after "+strings.TrimSpace(CoreServiceListenPrefix)+")")
	flags.Int32Var(&coreServiceOptions.ownerPID, "owner-pid", 0, "the app's process: the service stops when it is gone")
	// The AppImage's AppRun runs this after the service exits: a service that crashed or was killed
	// left its engine's routing, and nothing restarts it as systemd does the installed one.
	flags.BoolVar(&coreServiceOptions.cleanup, "cleanup", false, "undo what a service that died left in the host, and exit")
	mainCommand.AddCommand(commandCoreService)
}

func runCoreService() int {
	if coreServiceOptions.cleanup {
		adminbgservice.CleanupLeftovers()
		return 0
	}
	hprocess.SetName(coreProcessName, cliArgs)
	hprocess.RaisePriority()
	stdin := bufio.NewReader(os.Stdin)
	secret, err := stdin.ReadString('\n')
	if err != nil {
		writeCoreLine(CoreErrorPrefix + "no control secret on stdin")
		return 1
	}
	service, err := adminbgservice.RunForeground(coreServiceOptions.listen, strings.TrimSpace(secret))
	if err != nil {
		writeCoreLine(CoreErrorPrefix + oneLine(err.Error()))
		return 1
	}
	endpoint := service.Endpoint()
	writeCoreLine(CoreServiceListenPrefix + endpoint.Address)
	writeCoreLine(CoreServiceCertPrefix + base64.StdEncoding.EncodeToString([]byte(endpoint.Certificate)))
	writeCoreLine(CoreServiceReadyLine)
	hprocess.DetachStdio()

	reason := waitForCoreEnd(stdin, coreServiceOptions.ownerPID)
	fmt.Fprintf(os.Stderr, "hiddify core service: stopping (%s)\n", reason)
	stopped := make(chan struct{})
	go func() {
		service.Close()
		close(stopped)
	}()
	select {
	case <-stopped:
	case <-time.After(coreStopTimeout):
	}
	return 0
}
