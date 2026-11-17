//go:build android && cgo

package hutils

/*
#include <stdlib.h>
#include <sys/system_properties.h>

static int hiddify_android_sdk_int(void) {
	char value[PROP_VALUE_MAX];
	int length = __system_property_get("ro.build.version.sdk", value);
	if (length <= 0) {
		return 0;
	}
	return atoi(value);
}
*/
import "C"

// AndroidSDKInt is the API level of the Android the core runs on (ro.build.version.sdk), 0 if
// unknown.
func AndroidSDKInt() int {
	return int(C.hiddify_android_sdk_int())
}
