package main

import (
	"errors"
	"go/ast"
	"go/parser"
	"go/token"
	"strings"
	"testing"
	"unsafe"
)

// readString reads a NUL-terminated string the library returned, as the app does over FFI.
func readString(p unsafe.Pointer) string {
	var b []byte
	for i := 0; ; i++ {
		c := *(*byte)(unsafe.Add(p, i))
		if c == 0 {
			return string(b)
		}
		b = append(b, c)
	}
}

// W4-02: the error text a failed setup returns is still there when the caller reads it, and the
// caller frees it.
func TestErrorTextOutlivesTheCall(t *testing.T) {
	const reason = "listen tcp 127.0.0.1:1: bind: Only one usage of each socket address is normally permitted."
	for i := 0; i < 100; i++ {
		text := emptyOrErrorC(errors.New(reason))
		// what the allocator hands out next must not overwrite it
		other := emptyOrErrorC(errors.New(strings.Repeat("x", len(reason))))
		if got := readString(unsafe.Pointer(text)); got != reason {
			t.Fatalf("read %q", got)
		}
		freeString(text)
		freeString(other)
	}
	empty := emptyOrErrorC(nil)
	if got := readString(unsafe.Pointer(empty)); got != "" {
		t.Fatalf("success read as %q", got)
	}
	freeString(empty)
	freeString(nil)
}

// W4-02: no export frees the string it returns; the caller does, with freeString.
func TestNoExportFreesWhatItReturns(t *testing.T) {
	files := token.NewFileSet()
	for _, name := range []string{"custom.go", "grpc_interface.go", "cmd_interface.go"} {
		file, err := parser.ParseFile(files, name, nil, 0)
		if err != nil {
			t.Fatal(err)
		}
		for _, decl := range file.Decls {
			function, ok := decl.(*ast.FuncDecl)
			if !ok || function.Name.Name == "freeString" || !returnsCString(function) {
				continue
			}
			ast.Inspect(function.Body, func(node ast.Node) bool {
				if call, ok := node.(*ast.CallExpr); ok {
					if selector, ok := call.Fun.(*ast.SelectorExpr); ok && selector.Sel.Name == "free" {
						if pkg, ok := selector.X.(*ast.Ident); ok && pkg.Name == "C" {
							t.Errorf("%s: %s frees memory although it returns a C string", files.Position(call.Pos()), function.Name.Name)
						}
					}
				}
				return true
			})
		}
	}
}

func returnsCString(function *ast.FuncDecl) bool {
	if function.Type.Results == nil {
		return false
	}
	for _, field := range function.Type.Results.List {
		if star, ok := field.Type.(*ast.StarExpr); ok {
			if selector, ok := star.X.(*ast.SelectorExpr); ok && selector.Sel.Name == "char" {
				return true
			}
		}
	}
	return false
}
