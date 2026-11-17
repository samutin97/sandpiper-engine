package config

import (
	"encoding/json"
	"strings"
	"testing"

	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/experimental/libbox"
	"github.com/sagernet/sing-box/option"
)

// synthetic keys (not real ones): 32 bytes in base64
const (
	testKeyA = "YWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWE="
	testKeyB = "YmJiYmJiYmJiYmJiYmJiYmJiYmJiYmJiYmJiYmJiYmI="
	testHPK  = "Y2NjY2NjY2NjY2NjY2NjY2NjY2NjY2NjY2NjY2NjY2M="
)

const awgEndpointJSON = `{"type":"awg","tag":"AWG 990","private_key":"` + testKeyA + `",
 "address":["10.8.0.2/32"],"mtu":1280,"listen_port":51820,"useIntegratedTun":true,"bind_interface":"wlan0",
 "awg":{"jc":4,"jmin":10,"jmax":50,"s1":15,"s2":18,"s3":20,"s4":23,"h1":"100000-100100","h2":"200000-200100",
  "h3":"300000-300100","h4":"400000-400100","i1":"<b 0x0102><r 16>","header_protection_key":"` + testHPK + `",
  "content_padding_addition":"0-16","random_trailers":true,"disable_cookies":true},
 "peers":[{"address":"192.0.2.20","port":51821,"public_key":"` + testKeyB + `","allowed_ips":["0.0.0.0/0","::/0"],"persistent_keepalive_interval":25}]}`

func sanitized(t *testing.T, profile string) (map[string]any, []string, error) {
	t.Helper()
	out, warnings, err := SanitizeProfileJSON([]byte(profile))
	if err != nil {
		return nil, warnings, err
	}
	var m map[string]any
	if err := json.Unmarshal(out, &m); err != nil {
		t.Fatal(err)
	}
	return m, warnings, nil
}

func TestSanitizeDropsProgramsFilesAndDirect(t *testing.T) {
	profile := `{"outbounds":[
	 {"type":"tor","tag":"t","executable_path":"/system/bin/sh","extra_args":["-c","id"]},
	 {"type":"direct","tag":"leak"},
	 {"type":"ssh","tag":"s","server":"192.0.2.1","user":"u","private_key_path":"/sdcard/id_rsa"},
	 {"type":"openconnect","tag":"oc","server":"192.0.2.2","csd":{"wrapper_path":"/x"}},
	 {"type":"vless","tag":"v","server":"192.0.2.3","server_port":443,"uuid":"00000000-0000-4000-8000-000000000001",
	  "bind_interface":"wlan0","routing_mark":1,"detour":"nowhere",
	  "tls":{"enabled":true,"server_name":"example.com","certificate_path":"/sdcard/ca.pem","ech":{"enabled":true,"config_path":"/x"}}}
	]}`
	m, warnings, err := sanitized(t, profile)
	if err != nil {
		t.Fatal(err)
	}
	outbounds := m["outbounds"].([]any)
	if len(outbounds) != 1 {
		t.Fatalf("kept %v (warnings %v)", outbounds, warnings)
	}
	v := outbounds[0].(map[string]any)
	if v["tag"] != "v" || v["bind_interface"] != nil || v["routing_mark"] != nil || v["detour"] != nil {
		t.Fatalf("vless kept dangerous fields: %v", v)
	}
	tls := v["tls"].(map[string]any)
	if tls["certificate_path"] != nil || tls["ech"].(map[string]any)["config_path"] != nil {
		t.Fatalf("tls paths kept: %v", tls)
	}
	if len(warnings) != 4 {
		t.Fatalf("warnings %v", warnings)
	}
}

func TestSanitizeNothingLeftFails(t *testing.T) {
	if _, _, err := sanitized(t, `{"outbounds":[{"type":"tor","tag":"t","executable_path":"/bin/sh"}]}`); err == nil {
		t.Fatal("a profile of only a tor outbound passed")
	}
}

// The AmneziaWG endpoint a subscription carries is kept, checked and cleaned (server mode, second
// TUN, interface binding removed; header protection key as hex).
func TestSanitizeKeepsTheAwgEndpoint(t *testing.T) {
	m, warnings, err := sanitized(t, `{"endpoints":[`+awgEndpointJSON+`]}`)
	if err != nil {
		t.Fatalf("%v %v", err, warnings)
	}
	end := m["endpoints"].([]any)[0].(map[string]any)
	for _, field := range []string{"listen_port", "useIntegratedTun", "bind_interface"} {
		if end[field] != nil {
			t.Fatalf("%s kept", field)
		}
	}
	awg := end["awg"].(map[string]any)
	if hpk := awg["header_protection_key"].(string); len(hpk) != 64 || strings.Contains(hpk, "=") {
		t.Fatalf("hpk %q", hpk)
	}
	if awg["random_trailers"] != true || awg["disable_cookies"] != true || awg["s4"].(float64) != 23 {
		t.Fatalf("awg values lost: %v", awg)
	}
}

func TestSanitizeRefusesBadAwgValues(t *testing.T) {
	cases := map[string]string{
		"line break": `"i1":"<b 0x01>\njc=1"`,
		"jmin>jmax":  `"jmin":60,"jmax":50`,
		"huge jc":    `"jc":100000,"jmax":10`,
		"negative":   `"s1":-1`,
		"bad hpk":    `"header_protection_key":"zz"`,
	}
	for name, awg := range cases {
		profile := `{"endpoints":[{"type":"awg","tag":"x","private_key":"` + testKeyA + `","address":["10.0.0.2/32"],"awg":{` + awg + `},
		 "peers":[{"address":"192.0.2.20","port":1,"public_key":"` + testKeyB + `"}]}],"outbounds":[{"type":"socks","tag":"s","server":"192.0.2.1","server_port":1}]}`
		m, _, err := sanitized(t, profile)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if ends, _ := m["endpoints"].([]any); len(ends) != 0 {
			t.Fatalf("%s: endpoint kept", name)
		}
	}
}

// End to end: a subscription of one AmneziaWG endpoint builds, and the endpoint reaches the config
// with its 3.1 values, as a member of the select group.
func TestAwgEndpointFromASubscriptionBuilds(t *testing.T) {
	opts := chainTestOptions(t, `{"enable-tun":true}`)
	options, err := BuildConfig(libbox.BaseContext(nil), opts, &ReadOptions{Content: `{"endpoints":[` + awgEndpointJSON + `]}`})
	if err != nil {
		t.Fatal(err)
	}
	if err := libbox.CheckConfigOptions(options); err != nil {
		t.Fatalf("sing-box rejected the config: %v", err)
	}
	var awg *option.AwgEndpointOptions
	for _, end := range options.Endpoints {
		if end.Type == C.TypeAwg {
			awg = end.Options.(*option.AwgEndpointOptions)
		}
	}
	if awg == nil {
		t.Fatal("no awg endpoint")
	}
	if !awg.Awg.RandomTrailers || !awg.Awg.DisableCookies || awg.Awg.S3 != 20 || awg.Awg.H1 != "100000-100100" || awg.ListenPort != 0 || awg.UseIntegratedTun {
		t.Fatalf("awg options: %+v", awg)
	}
	found := false
	for _, item := range selectorItems(options) {
		found = found || item == "AWG 990"
	}
	if !found {
		t.Fatalf("not selectable: %v", selectorItems(options))
	}
}

// insecure TLS without a pin: refused unless allow-insecure (HC-02, HC-24)
func TestInsecureWithoutAPinIsRefused(t *testing.T) {
	pin := strings.Repeat("ab", 32)
	profile := `hysteria2://pass@192.0.2.30:443/?insecure=1&sni=example.com#unpinned
hysteria2://pass@192.0.2.31:443/?insecure=1&pinSHA256=` + pin + `&sni=example.com#pinned
vless://00000000-0000-4000-8000-000000000001@192.0.2.32:443?security=tls&sni=example.com#checked`
	ctx := libbox.BaseContext(nil)
	parsed, err := ParseConfigBytes(ctx, &ReadOptions{Content: profile}, false, DefaultHiddifyOptions(), false)
	if err != nil {
		t.Fatal(err)
	}
	build := func(settings string) []string {
		options, err := BuildConfig(ctx, chainTestOptions(t, settings), &ReadOptions{Content: string(parsed)})
		if err != nil {
			t.Fatal(err)
		}
		return selectorItems(options)
	}
	items := build(`{}`)
	has := func(items []string, prefix string) bool {
		for _, item := range items {
			if strings.HasPrefix(item, prefix) {
				return true
			}
		}
		return false
	}
	if has(items, "unpinned") || !has(items, "pinned") || !has(items, "checked") {
		t.Fatalf("default: %v", items)
	}
	if items := build(`{"allow-insecure":true}`); !has(items, "unpinned") {
		t.Fatalf("allow-insecure: %v", items)
	}
}
