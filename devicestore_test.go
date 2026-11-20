package invite

import (
	"bytes"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestRecordDeviceFlag(t *testing.T) {
	secret := bytes.Repeat([]byte{5}, secretSize)
	id := mustKeys(secret).id
	dev := &record{secret: secret, created: 10, expires: 20, maxUses: 1, manual: true, device: true}
	got, err := decodeRecord(id, dev.encode())
	if err != nil || !got.device || !got.manual {
		t.Fatalf("device record = %+v, %v", got, err)
	}
	plain := &record{secret: secret, created: 10, maxUses: 2}
	if got, err := decodeRecord(id, plain.encode()); err != nil || got.device {
		t.Fatalf("plain record = %+v, %v", got, err)
	}
	// Version 0 records, written before the flag existed, still load and are not device invites.
	if got, err := decodeRecord(id, recordV0(plain)); err != nil || got.device || got.maxUses != 2 {
		t.Fatalf("version 0 record = %+v, %v", got, err)
	}
	// A device invite is manual and single use; a version 0 record with the flag byte appended is not valid.
	for name, b := range map[string][]byte{
		"device not manual":       (&record{secret: secret, created: 10, maxUses: 1, device: true}).encode(),
		"device with two uses":    (&record{secret: secret, created: 10, maxUses: 2, manual: true, device: true}).encode(),
		"version 0 with the flag": append(recordV0(plain), 1),
		"version 1 without it":    recordV0(plain)[:0],
		"version 2":               append([]byte{2}, dev.encode()[1:]...),
		"truncated":               dev.encode()[:len(dev.encode())-1],
		"trailing byte":           append(dev.encode(), 0),
	} {
		if _, err := decodeRecord(id, b); err == nil {
			t.Errorf("%s: decoded", name)
		}
	}
	// Only a device invite is written as version 1: any other record is written as version 0.
	if b := plain.encode(); b[0] != version || !bytes.Equal(b, recordV0(plain)) {
		t.Fatalf("a plain record starts with version %d or differs from the version 0 layout", b[0])
	}
	if b := dev.encode(); b[0] != recordVersion {
		t.Fatalf("a device record starts with version %d", b[0])
	}
	// A version 1 record is a device record: without the flag it is not canonical and is refused.
	v1plain := append(recordV0(plain), 0)
	v1plain[0] = recordVersion
	if _, err := decodeRecord(id, v1plain); err == nil {
		t.Fatal("a version 1 record without the device flag was read")
	}
}

// TestSourceHasNoPhraseAndNoLogging: the words never reach this library, and it prints nothing, so no word, code, seed
// or key can leak into a log from here.
func TestSourceHasNoPhraseAndNoLogging(t *testing.T) {
	files, err := filepath.Glob("*.go")
	if err != nil {
		t.Fatal(err)
	}
	fset := token.NewFileSet()
	checked := 0
	for _, name := range files {
		if strings.HasSuffix(name, "_test.go") {
			continue
		}
		src, err := os.ReadFile(name)
		if err != nil {
			t.Fatal(err)
		}
		f, err := parser.ParseFile(fset, name, src, 0)
		if err != nil {
			t.Fatal(err)
		}
		checked++
		for _, imp := range f.Imports {
			if p := strings.Trim(imp.Path.Value, `"`); p == "log" || p == "log/slog" || p == "os" {
				t.Errorf("%s imports %s", name, p)
			}
		}
		ast.Inspect(f, func(n ast.Node) bool {
			switch x := n.(type) {
			case *ast.Ident:
				switch x.Name {
				case "Phrase", "ParsePhrase", "ParseWords", "GeneratePhrase":
					t.Errorf("%s: %s names a phrase", name, x.Name)
				}
			case *ast.SelectorExpr:
				if id, ok := x.X.(*ast.Ident); ok && id.Name == "fmt" && (x.Sel.Name == "Print" || x.Sel.Name == "Println" || x.Sel.Name == "Printf") {
					t.Errorf("%s: fmt.%s prints", name, x.Sel.Name)
				}
			}
			return true
		})
	}
	if checked < 8 {
		t.Fatalf("checked only %d files", checked)
	}
}

// TestNoIgnoredCryptoErrors: no call of a crypto function drops its error in the code of this package.
func TestNoIgnoredCryptoErrors(t *testing.T) {
	files, _ := filepath.Glob("*.go")
	names := map[string]bool{"GenerateKey": true, "NewSender": true, "NewRecipient": true, "Sign": true, "Seal": true, "Open": true,
		"DeriveKeyPair": true, "Key": true, "Read": true, "NewPublicKey": true}
	fset := token.NewFileSet()
	for _, name := range files {
		if strings.HasSuffix(name, "_test.go") {
			continue
		}
		src, err := os.ReadFile(name)
		if err != nil {
			t.Fatal(err)
		}
		f, err := parser.ParseFile(fset, name, src, 0)
		if err != nil {
			t.Fatal(err)
		}
		ast.Inspect(f, func(n ast.Node) bool {
			call := func(e ast.Expr) (string, bool) {
				c, ok := e.(*ast.CallExpr)
				if !ok {
					return "", false
				}
				sel, ok := c.Fun.(*ast.SelectorExpr)
				if !ok || !names[sel.Sel.Name] {
					return "", false
				}
				if x, ok := sel.X.(*ast.Ident); sel.Sel.Name == "Read" && (!ok || x.Name != "rand") {
					return "", false // a stream read, not the random source
				}
				return sel.Sel.Name, true
			}
			switch x := n.(type) {
			case *ast.AssignStmt:
				if len(x.Rhs) == 1 {
					if fn, ok := call(x.Rhs[0]); ok {
						// the error is the last result
						if id, ok := x.Lhs[len(x.Lhs)-1].(*ast.Ident); ok && id.Name == "_" {
							t.Errorf("%s: the error of %s is dropped", fset.Position(x.Pos()), fn)
						}
					}
				}
			case *ast.ExprStmt:
				if fn, ok := call(x.X); ok {
					t.Errorf("%s: the result of %s is dropped", fset.Position(x.Pos()), fn)
				}
			}
			return true
		})
	}
}
