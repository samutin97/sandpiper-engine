package config

import (
	"encoding/json"
	"testing"

	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/option"
)

// Helpers shared by the config tests. Upstream keeps its helpers in an uncommitted file
// (**/*_test.go is ignored there); the hardened fork commits them so the tests build.

// chainTestOptions are the default settings with the app's JSON settings laid over them, the way
// hcore.ChangeHiddifySettings builds them.
func chainTestOptions(t *testing.T, settings string) *HiddifyOptions {
	t.Helper()
	opts := DefaultHiddifyOptions()
	if err := json.Unmarshal([]byte(settings), opts); err != nil {
		t.Fatalf("settings %s: %v", settings, err)
	}
	return opts
}

// Synthetic profiles: documentation addresses (RFC 5737) and made-up keys only.
const oneProxyProfile = `{"outbounds":[
 {"type":"vless","tag":"p1","server":"192.0.2.10","server_port":443,"uuid":"00000000-0000-4000-8000-000000000001",
  "tls":{"enabled":true,"server_name":"example.com"}}
]}`

const chainTestProfile = `{"outbounds":[
 {"type":"vless","tag":"p1","server":"192.0.2.10","server_port":443,"uuid":"00000000-0000-4000-8000-000000000001",
  "tls":{"enabled":true,"server_name":"example.com"}},
 {"type":"trojan","tag":"p2","server":"192.0.2.11","server_port":443,"password":"not-a-real-password",
  "tls":{"enabled":true,"server_name":"example.org"}}
]}`

// selectorItems are the members of the select group.
func selectorItems(options *option.Options) []string {
	for _, out := range options.Outbounds {
		if out.Type == C.TypeSelector && out.Tag == OutboundSelectTag {
			return out.Options.(*option.SelectorOutboundOptions).Outbounds
		}
	}
	return nil
}

// findInbounds returns the inbounds of the given type.
func findInbounds(options *option.Options, typ string) []option.Inbound {
	var res []option.Inbound
	for _, in := range options.Inbounds {
		if in.Type == typ {
			res = append(res, in)
		}
	}
	return res
}
