package main

/*
#include <stdlib.h>
#include <signal.h>
#include "stdint.h"
*/
import "C"

import (
	// "os"
	// "os/signal"
	// "runtime"

	// "syscall"
	"unsafe"

	hcore "github.com/hiddify/hiddify-core/v2/hcore"
	"github.com/sagernet/sing-box/experimental/libbox"
	"github.com/sagernet/sing-box/log"
)

// func init() {
// 	runtime.LockOSThread()
// 	C.init_signals()
// 	runtime.UnlockOSThread()

// 	go handleSignals()

// 	// Your other initialization code can go here
// }

// // Signal handling function
// func handleSignals() {
// 	signalChan := make(chan os.Signal, 1)
// 	signal.Notify(signalChan, syscall.SIGINT, syscall.SIGURG)

// 	for {
// 		<-signalChan
// 		// switch sig {
// 		// case syscall.SIGINT, syscall.SIGTERM:
// 		// 	// runtime.LockOSThread() // Lock to the current OS thread
// 		// 	// defer runtime.UnlockOSThread()
// 		// 	log.Info("Received signal:", sig)

// 		// 	// Call stop function or perform cleanup
// 		// 	if err := stop(); err != nil {
// 		// 		log.Error("Error stopping the application:", err)
// 		// 	}
// 		// 	log.Info("Application stopped gracefully.")
// 		// }
// 	}
// }

func main() {}

//export cleanup
func cleanup() {
	// runtime.LockOSThread()
	// defer runtime.UnlockOSThread()
	// C.cleanup_signals()
}

// Strings across the C boundary: every *C.char an export of this library returns is allocated
// here with C.CString (C's malloc) and belongs to the caller from then on. The caller reads it and
// then hands it back to freeString; nothing here frees it. emptyOrErrorC used to free the error
// text before returning it, so the app read freed memory: the reason of a failed setup arrived as
// garbage ("FormatException: Invalid UTF-8 byte"), or not at all (W4-02).

// emptyOrErrorC is "" on success, else the error's text; the caller frees it with freeString.
func emptyOrErrorC(err error) *C.char {
	if err == nil {
		return C.CString("")
	}
	log.Error(err.Error())
	return C.CString(err.Error())
}

//export setup
func setup(baseDir *C.char, workingDir *C.char, tempDir *C.char, mode C.int, listen *C.char, secret *C.char, statusPort C.longlong, debug bool) *C.char {
	// runtime.LockOSThread()
	// defer runtime.UnlockOSThread()

	// // Ensure signals are initialized
	// C.init_signals()

	params := hcore.SetupRequest{
		BasePath:          C.GoString(baseDir),
		WorkingDir:        C.GoString(workingDir),
		TempDir:           C.GoString(tempDir),
		FlutterStatusPort: int64(statusPort),
		Debug:             bool(debug),
		Mode:              hcore.SetupMode(mode),
		Listen:            C.GoString(listen),
		Secret:            C.GoString(secret),
	}

	err := hcore.Setup(&params, nil)
	return emptyOrErrorC(err)
}

// freeString frees a string an export of this library returned, once the caller has read it.
//
//export freeString
func freeString(str *C.char) {
	if str == nil {
		return
	}
	C.free(unsafe.Pointer(str))
}

//export start
func start(configPath *C.char, disableMemoryLimit bool) *C.char {
	// runtime.LockOSThread()
	// defer runtime.UnlockOSThread()
	ctx := libbox.BaseContext(nil)
	_, err := hcore.Start(ctx, &hcore.StartRequest{
		ConfigPath:             C.GoString(configPath),
		EnableOldCommandServer: true,
		DisableMemoryLimit:     bool(disableMemoryLimit),
	})
	return emptyOrErrorC(err)
}

//export stop
func stop() *C.char {
	// runtime.LockOSThread()
	// defer runtime.UnlockOSThread()

	_, err := hcore.Stop()
	return emptyOrErrorC(err)
}

//export restart
func restart(configPath *C.char, disableMemoryLimit bool) *C.char {
	// runtime.LockOSThread()
	// defer runtime.UnlockOSThread()
	ctx := libbox.BaseContext(nil)
	_, err := hcore.Restart(ctx, &hcore.StartRequest{
		ConfigPath:             C.GoString(configPath),
		EnableOldCommandServer: true,
		DisableMemoryLimit:     bool(disableMemoryLimit),
	})
	return emptyOrErrorC(err)
}

//export GetServerPublicKey
func GetServerPublicKey() *C.char {
	// runtime.LockOSThread()
	// defer runtime.UnlockOSThread()

	publicKey := hcore.GetGrpcServerPublicKey()
	return C.CString(string(publicKey)) // the caller frees it with freeString
}

//export AddGrpcClientPublicKey
func AddGrpcClientPublicKey(clientPublicKey *C.char) *C.char {
	// runtime.LockOSThread()
	// defer runtime.UnlockOSThread()

	// Convert C string to Go byte slice
	clientKey := C.GoBytes(unsafe.Pointer(clientPublicKey), C.int(len(C.GoString(clientPublicKey))))
	err := hcore.AddGrpcClientPublicKey(clientKey)
	return emptyOrErrorC(err)
}

//export closeGrpc
func closeGrpc(mode C.int) {
	// runtime.LockOSThread()
	// defer runtime.UnlockOSThread()

	hcore.Close(hcore.SetupMode(mode))
}

// getListenAddress is the address the control server of mode listens on ("127.0.0.1:41234"), or
// "" when it does not run: the app sets the core up on port 0, a free port, and connects to the
// one this tells, as the Android app does through gomobile's Mobile.getListenAddress. Upstream's
// fixed 17078 was taken whenever upstream Hiddify ran on the same computer (W4-01). The caller
// frees the string with freeString.
//
//export getListenAddress
func getListenAddress(mode C.int) *C.char {
	return C.CString(hcore.GetListenAddress(hcore.SetupMode(mode)))
}
