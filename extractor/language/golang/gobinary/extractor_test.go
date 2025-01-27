// Copyright 2024 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package gobinary_test

import (
	"context"
	"io/fs"
	"os"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"github.com/google/osv-scalibr/extractor"
	"github.com/google/osv-scalibr/extractor/language/golang/gobinary"
	"github.com/google/osv-scalibr/purl"
)

func TestFileRequired(t *testing.T) {
	var e extractor.InventoryExtractor = gobinary.Extractor{}

	tests := []struct {
		name string
		path string
		mode fs.FileMode
		want bool
	}{
		{
			name: "user executable",
			path: "some/path/a",
			mode: 0766,
			want: true,
		},
		{
			name: "group executable",
			path: "some/path/a",
			mode: 0676,
			want: true,
		},
		{
			name: "other executable",
			path: "some/path/a",
			mode: 0667,
			want: true,
		},
		{
			name: "windows exe",
			path: "some/path/a.exe",
			mode: 0666,
			want: true,
		},
		{
			name: "not executable bit set",
			path: "some/path/a",
			mode: 0640,
			want: false,
		},
		{
			name: "Non regular file, socket",
			path: "some/path/a",
			mode: fs.ModeSocket | 0777,
			want: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := e.FileRequired(tt.path, tt.mode); got != tt.want {
				t.Fatalf("FileRequired(%s): got %v, want %v", tt.path, got, tt.want)
			}
		})
	}
}

func TestExtract(t *testing.T) {
	e := gobinary.Extractor{}

	tests := []struct {
		name    string
		path    string
		want    []*extractor.Inventory
		wantErr error
	}{
		{
			name: "binary_with_module_replacement-darwin-amd64",
			path: "testdata/binary_with_module_replacement-darwin-amd64",
			want: createInventories(append(BinaryWithModuleReplacementPackages, Toolchain), "testdata/binary_with_module_replacement-darwin-amd64", e.Name()),
		},
		{
			name: "binary_with_module_replacement-darwin-arm64",
			path: "testdata/binary_with_module_replacement-darwin-arm64",
			want: createInventories(append(BinaryWithModuleReplacementPackages, Toolchain), "testdata/binary_with_module_replacement-darwin-arm64", e.Name()),
		},
		{
			name: "binary_with_module_replacement-linux-386",
			path: "testdata/binary_with_module_replacement-linux-386",
			want: createInventories(append(BinaryWithModuleReplacementPackages, Toolchain), "testdata/binary_with_module_replacement-linux-386", e.Name()),
		},
		{
			name: "binary_with_module_replacement-linux-amd64",
			path: "testdata/binary_with_module_replacement-linux-amd64",
			want: createInventories(append(BinaryWithModuleReplacementPackages, Toolchain), "testdata/binary_with_module_replacement-linux-amd64", e.Name()),
		},
		{
			name: "binary_with_module_replacement-linux-arm64",
			path: "testdata/binary_with_module_replacement-linux-arm64",
			want: createInventories(append(BinaryWithModuleReplacementPackages, Toolchain), "testdata/binary_with_module_replacement-linux-arm64", e.Name()),
		},
		{
			name: "binary_with_module_replacement-windows-386",
			path: "testdata/binary_with_module_replacement-windows-386",
			want: createInventories(append(BinaryWithModuleReplacementPackages, Toolchain), "testdata/binary_with_module_replacement-windows-386", e.Name()),
		},
		{
			name: "binary_with_module_replacement-windows-amd64",
			path: "testdata/binary_with_module_replacement-windows-amd64",
			want: createInventories(append(BinaryWithModuleReplacementPackages, Toolchain), "testdata/binary_with_module_replacement-windows-amd64", e.Name()),
		},
		{
			name: "binary_with_module_replacement-windows-arm64",
			path: "testdata/binary_with_module_replacement-windows-arm64",
			want: createInventories(append(BinaryWithModuleReplacementPackages, Toolchain), "testdata/binary_with_module_replacement-windows-arm64", e.Name()),
		},
		{
			name: "binary_with_modules-darwin-amd64",
			path: "testdata/binary_with_modules-darwin-amd64",
			want: createInventories(append(BinaryWithModulesPackages, Toolchain), "testdata/binary_with_modules-darwin-amd64", e.Name()),
		},
		{
			name: "binary_with_modules-darwin-arm64",
			path: "testdata/binary_with_modules-darwin-arm64",
			want: createInventories(append(BinaryWithModulesPackages, Toolchain), "testdata/binary_with_modules-darwin-arm64", e.Name()),
		},
		{
			name: "binary_with_modules-linux-386",
			path: "testdata/binary_with_modules-linux-386",
			want: createInventories(append(BinaryWithModulesPackages, Toolchain), "testdata/binary_with_modules-linux-386", e.Name()),
		},
		{
			name: "binary_with_modules-linux-amd64",
			path: "testdata/binary_with_modules-linux-amd64",
			want: createInventories(append(BinaryWithModulesPackages, Toolchain), "testdata/binary_with_modules-linux-amd64", e.Name()),
		},
		{
			name: "binary_with_modules-linux-arm64",
			path: "testdata/binary_with_modules-linux-arm64",
			want: createInventories(append(BinaryWithModulesPackages, Toolchain), "testdata/binary_with_modules-linux-arm64", e.Name()),
		},
		{
			name: "binary_with_modules-windows-386",
			path: "testdata/binary_with_modules-windows-386",
			want: createInventories(append(BinaryWithModulesPackagesWindows, Toolchain), "testdata/binary_with_modules-windows-386", e.Name()),
		},
		{
			name: "binary_with_modules-windows-amd64",
			path: "testdata/binary_with_modules-windows-amd64",
			want: createInventories(append(BinaryWithModulesPackagesWindows, Toolchain), "testdata/binary_with_modules-windows-amd64", e.Name()),
		},
		{
			name: "binary_with_modules-windows-arm64",
			path: "testdata/binary_with_modules-windows-arm64",
			want: createInventories(append(BinaryWithModulesPackagesWindows, Toolchain), "testdata/binary_with_modules-windows-arm64", e.Name()),
		},
		{
			name: "dummy",
			path: "testdata/dummy",
			want: []*extractor.Inventory{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f, err := os.Open(tt.path)
			if err != nil {
				t.Fatalf("os.Open(%s) unexpected error: %v", tt.path, err)
			}
			defer f.Close()

			info, err := f.Stat()
			if err != nil {
				t.Fatalf("f.Stat() for %q unexpected error: %v", tt.path, err)
			}

			input := &extractor.ScanInput{Path: tt.path, Info: info, Reader: f}

			got, err := e.Extract(context.Background(), input)
			if err != tt.wantErr {
				t.Fatalf("Extract(%s) got error: %v, want error: %v", tt.path, err, tt.wantErr)
			}
			sort := func(a, b *extractor.Inventory) bool { return a.Name < b.Name }
			if diff := cmp.Diff(tt.want, got, cmpopts.SortSlices(sort)); diff != "" {
				t.Fatalf("Extract(%s) (-want +got):\n%s", tt.path, diff)
			}
		})
	}
}

func TestToPURL(t *testing.T) {
	e := gobinary.Extractor{}
	i := &extractor.Inventory{
		Name:      "name",
		Version:   "1.2.3",
		Locations: []string{"location"},
	}
	want := &purl.PackageURL{
		Type:    purl.TypeGolang,
		Name:    "name",
		Version: "1.2.3",
	}
	got, err := e.ToPURL(i)
	if err != nil {
		t.Fatalf("ToPURL(%v): %v", i, err)
	}
	if diff := cmp.Diff(want, got); diff != "" {
		t.Errorf("ToPURL(%v) (-want +got):\n%s", i, diff)
	}
}

var (
	// BinaryWithModulesPackagesWindows is a list of packages built into the
	// binary_with_modules-* testdata binaries, but only on Windows, where there
	// is an indirect dependency that is not built-in.
	BinaryWithModulesPackagesWindows = []*extractor.Inventory{
		// direct dependencies
		goPackage("github.com/ulikunitz/xz", "0.5.11"),
		goPackage("github.com/gin-gonic/gin", "1.8.1"),

		// indirect dependencies
		goPackage("github.com/gin-contrib/sse", "0.1.0"),
		goPackage("github.com/go-playground/locales", "0.14.0"),
		goPackage("github.com/go-playground/universal-translator", "0.18.0"),
		goPackage("github.com/go-playground/validator/v10", "10.11.1"),
		goPackage("github.com/leodido/go-urn", "1.2.1"),
		goPackage("github.com/mattn/go-isatty", "0.0.16"),
		goPackage("github.com/pelletier/go-toml/v2", "2.0.6"),
		goPackage("github.com/ugorji/go/codec", "1.2.7"),
		goPackage("golang.org/x/crypto", "0.4.0"),
		goPackage("golang.org/x/net", "0.4.0"),
		goPackage("golang.org/x/text", "0.5.0"),
		goPackage("google.golang.org/protobuf", "1.28.1"),
		goPackage("gopkg.in/yaml.v2", "2.4.0"),
	}

	// BinaryWithModulesPackages is a list of packages built into the
	// binary_with_modules-* testdata binaries.
	BinaryWithModulesPackages = append(
		BinaryWithModulesPackagesWindows,
		goPackage("golang.org/x/sys", "0.3.0"),
	)

	// BinaryWithModuleReplacementPackages is a list of packages built into the
	// binary_with_module_replacement-* testdata binaries.
	BinaryWithModuleReplacementPackages = []*extractor.Inventory{
		// this binary replaces golang.org/x/xerrors => github.com/golang/xerrors
		goPackage("github.com/golang/xerrors", "0.0.0-20220907171357-04be3eba64a2"),
	}

	Toolchain = goPackage("go", "1.22.0")
)

func goPackage(name, version string) *extractor.Inventory {
	return &extractor.Inventory{Name: name, Version: version}
}

func createInventories(invs []*extractor.Inventory, location string, e string) []*extractor.Inventory {
	res := []*extractor.Inventory{}
	for _, i := range invs {
		res = append(res, &extractor.Inventory{
			Name: i.Name, Version: i.Version, Locations: []string{location}, Extractor: e,
		})
	}
	return res
}
