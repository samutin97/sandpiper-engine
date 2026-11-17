package hcore

import (
	"context"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"os"
	"os/signal"
	"runtime"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/hiddify/hiddify-core/v2/config"
	"github.com/hiddify/hiddify-core/v2/hcommon/constants"

	"github.com/sagernet/sing-box/option"
)

func RunStandalone(ctx context.Context, hiddifySettingPath string, configPath string, defaultConfig config.HiddifyOptions) error {
	fmt.Println("Running in standalone mode")
	current, err := readAndBuildConfig(ctx, hiddifySettingPath, configPath, &defaultConfig)
	if err != nil {
		fmt.Printf("Error in read and build config %v", err)
		return err
	}
	// the start sees the settings the config was built with: router mode, for one
	static.HiddifyOptions = current.HiddifyHiddifyOptions

	_, err = StartService(ctx, &StartRequest{
		ConfigContent:          current.Config,
		EnableOldCommandServer: false,
		DelayStart:             false,
		EnableRawConfig:        true,
	})
	if err != nil {
		fmt.Printf("Error in start service %v", err)
		return err
	}
	go updateConfigInterval(ctx, current, hiddifySettingPath, configPath)

	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM)

	fmt.Printf("Waiting for CTRL+C to stop\n")
	<-sigChan
	fmt.Printf("CTRL+C recived-->stopping\n")
	_, err = Stop()

	return err
}

type ConfigResult struct {
	Config                string
	RefreshInterval       int
	HiddifyHiddifyOptions *config.HiddifyOptions
}

func readAndBuildConfig(ctx context.Context, hiddifySettingPath string, configPath string, defaultConfig *config.HiddifyOptions) (ConfigResult, error) {
	var result ConfigResult

	result, err := readConfigContent(configPath)
	if err != nil {
		return result, err
	}

	hiddifyconfig := config.DefaultHiddifyOptions()

	if defaultConfig != nil {
		hiddifyconfig = defaultConfig
	}

	if hiddifySettingPath != "" {
		hiddifyconfig, err = ReadHiddifyOptionsAt(hiddifySettingPath)
		if err != nil {
			return result, err
		}
		// --router holds with a settings file too (the docker image's ROUTER_MODE, the OpenWrt mode)
		if defaultConfig != nil && defaultConfig.RouterMode {
			hiddifyconfig.RouterMode = true
		}
	}

	result.HiddifyHiddifyOptions = hiddifyconfig
	result.Config, err = buildStandaloneConfig(ctx, &config.ReadOptions{Content: result.Config}, result.HiddifyHiddifyOptions)
	if err != nil {
		return result, err
	}

	return result, nil
}

func readConfigContent(configPath string) (ConfigResult, error) {
	var content string
	var refreshInterval int

	if strings.HasPrefix(configPath, "http://") || strings.HasPrefix(configPath, "https://") {
		client := &http.Client{}

		// Create a new request
		req, err := http.NewRequest("GET", configPath, nil)
		if err != nil {
			fmt.Println("Error creating request:", err)
			return ConfigResult{}, err
		}
		req.Header.Set("User-Agent", standaloneUserAgent())
		resp, err := client.Do(req)
		if err != nil {
			fmt.Println("Error making GET request:", err)
			return ConfigResult{}, err
		}
		defer resp.Body.Close()

		body, err := ioutil.ReadAll(resp.Body)
		if err != nil {
			return ConfigResult{}, fmt.Errorf("failed to read config body: %w", err)
		}
		content = string(body)
		refreshInterval, _ = extractRefreshInterval(resp.Header, content)
		fmt.Printf("Refresh interval: %d\n", refreshInterval)

	} else {
		data, err := ioutil.ReadFile(configPath)
		if err != nil {
			return ConfigResult{}, fmt.Errorf("failed to read config file: %w", err)
		}
		content = string(data)
	}

	return ConfigResult{
		Config:          content,
		RefreshInterval: refreshInterval,
	}, nil
}

func extractRefreshInterval(header http.Header, bodyStr string) (int, error) {
	refreshIntervalStr := header.Get("profile-update-interval")
	if refreshIntervalStr != "" {
		refreshInterval, err := strconv.Atoi(refreshIntervalStr)
		if err != nil {
			return 0, fmt.Errorf("failed to parse refresh interval from header: %w", err)
		}
		return refreshInterval, nil
	}

	lines := strings.Split(bodyStr, "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "//profile-update-interval:") || strings.HasPrefix(line, "#profile-update-interval:") {
			parts := strings.SplitN(line, ":", 2)
			str := strings.TrimSpace(parts[1])
			refreshInterval, err := strconv.Atoi(str)
			if err != nil {
				return 0, fmt.Errorf("failed to parse refresh interval from body: %w", err)
			}
			return refreshInterval, nil
		}
	}
	return 0, nil
}

func buildStandaloneConfig(ctx context.Context, ropt *config.ReadOptions, hopts *config.HiddifyOptions) (string, error) {
	finalconfig, err := config.ParseBuildConfig(ctx, hopts, ropt)
	if err != nil {
		return "", fmt.Errorf("failed to parse config content: %w", err)
	}

	finalconfig.Log.Output = ""
	// W4-05: the experimental part is the builder's, as in the app: the cache file and the
	// monitoring the groups refer to (replacing it all failed the start with "outbound not found:
	// lowest in group select"), and the Clash API as the builder makes it. It used to open on the
	// fixed 16756 (0.0.0.0 with LAN access) without a secret; now it listens only when the settings
	// ask for it (clash-api-listen), on 127.0.0.1, a free port unless one is set, with a secret.
	if api := clashController(finalconfig.Experimental); api != nil {
		fmt.Printf("Clash API on http://%s (its secret is in the built config)\n", api.ExternalController)
	}

	if err := Setup(
		&SetupRequest{
			BasePath:          "./",
			WorkingDir:        "./",
			TempDir:           "./tmp",
			FlutterStatusPort: 0,
			Debug:             false,
			// no control server: an unauthenticated one is refused (HC-08), and the run needs none
			Mode: SetupMode_OLD,
		}, nil); err != nil {
		return "", fmt.Errorf("failed to set up global configuration: %w", err)
	}

	configStr, err := finalconfig.MarshalJSONContext(ctx)
	if err != nil {
		return "", fmt.Errorf("failed to convert config to JSON: %w", err)
	}

	return string(configStr), nil
}

func updateConfigInterval(ctx context.Context, current ConfigResult, hiddifySettingPath string, configPath string) {
	if current.RefreshInterval <= 0 {
		return
	}

	for {
		<-time.After(time.Duration(current.RefreshInterval) * time.Hour)
		new, err := readAndBuildConfig(ctx, hiddifySettingPath, configPath, current.HiddifyHiddifyOptions)
		if err != nil {
			continue
		}
		if new.Config != current.Config {
			Stop()
			StartService(ctx, &StartRequest{
				ConfigContent:          new.Config,
				DelayStart:             false,
				EnableOldCommandServer: false,
				DisableMemoryLimit:     false,
				EnableRawConfig:        true,
			})
		}
		current = new
	}
}

func ReadHiddifyOptionsAt(path string) (*config.HiddifyOptions, error) {
	content, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var options config.HiddifyOptions
	err = json.Unmarshal(content, &options)
	if err != nil {
		return nil, err
	}
	if options.Warp.WireguardConfigStr != "" {
		err := json.Unmarshal([]byte(options.Warp.WireguardConfigStr), &options.Warp.WireguardConfig)
		if err != nil {
			return nil, err
		}
	}
	if options.Warp2.WireguardConfigStr != "" {
		err := json.Unmarshal([]byte(options.Warp2.WireguardConfigStr), &options.Warp2.WireguardConfig)
		if err != nil {
			return nil, err
		}
	}
	return &options, nil
}

// clashController is the Clash API of the config when it listens, else nil.
func clashController(experimental *option.ExperimentalOptions) *option.ClashAPIOptions {
	if experimental == nil || experimental.ClashAPI == nil || experimental.ClashAPI.ExternalController == "" {
		return nil
	}
	return experimental.ClashAPI
}

// subscriptionAppVersion is the upstream app version the subscription user agent names when this
// core was built without a version.
const subscriptionAppVersion = "5.9.8"

// standaloneUserAgent is the user agent the CLI downloads a subscription with: the app's
// (lib/core/model/app_info_entity.dart, userAgentFor), so a server answers the CLI as it answers
// the app: "HiddifyNext/<upstream version> (<os>)" and the capability tokens.
func standaloneUserAgent() string {
	version := strings.TrimPrefix(constants.Version, "v")
	if cut := strings.IndexAny(version, "-+"); cut >= 0 {
		version = version[:cut]
	}
	if version == "" || version[0] < '0' || version[0] > '9' {
		version = subscriptionAppVersion
	}
	operatingSystem := runtime.GOOS
	if operatingSystem == "darwin" {
		operatingSystem = "macos" // as Dart names it
	}
	return fmt.Sprintf("HiddifyNext/%s (%s) awg31", version, operatingSystem)
}
