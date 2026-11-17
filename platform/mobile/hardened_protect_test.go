package mobile

import (
	"testing"

	C "github.com/sagernet/sing-box/constant"
)

func TestProtectsOwnSocketsOnAndroid(t *testing.T) {
	if ProtectsOwnSockets() != C.IsAndroid {
		t.Fatal("ProtectsOwnSockets must say true exactly on Android")
	}
}
