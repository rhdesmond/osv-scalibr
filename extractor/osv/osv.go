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

// Package osv provides a Wrapper for osv plugins.
package osv

import (
	"context"
	"fmt"
	"io/fs"
	"path/filepath"
	"strings"

	"github.com/google/osv-scanner/pkg/lockfile"
	"github.com/google/osv-scalibr/extractor"
	"github.com/google/osv-scalibr/purl"
)

// Wrapper contains all the data to wrap a osv extractor to a scalibr extractor.
type Wrapper struct {
	ExtractorName    string
	ExtractorVersion int
	PURLType         string
	Extractor        lockfile.Extractor
}

// Name of the extractor.
func (e Wrapper) Name() string { return e.ExtractorName }

// Version of the extractor.
func (e Wrapper) Version() int { return e.ExtractorVersion }

// FileRequired returns true if the specified file matches the extractor pattern.
func (e Wrapper) FileRequired(path string, _ fs.FileMode) bool {
	return e.Extractor.ShouldExtract(path)
}

// Extract wrapps the osv Extract method.
func (e Wrapper) Extract(ctx context.Context, input *extractor.ScanInput) ([]*extractor.Inventory, error) {
	full := filepath.Join(input.ScanRoot, input.Path)
	osvpkgs, err := e.Extractor.Extract(WrapInput(input))
	if err != nil {
		return nil, fmt.Errorf("osvExtractor.Extract(%s): %w", full, err)
	}

	r := []*extractor.Inventory{}
	for _, p := range osvpkgs {
		r = append(r, &extractor.Inventory{
			Name:    p.Name,
			Version: p.Version,
			Metadata: &Metadata{
				PURLType:  e.PURLType,
				Commit:    p.Commit,
				Ecosystem: string(p.Ecosystem),
				CompareAs: string(p.CompareAs),
			},
			Locations: []string{input.Path},
			Extractor: e.Name(),
		})
	}

	return r, nil
}

// WrapInput returns an implementation of OSVs DepFile using a scalibr ScanInput.
func WrapInput(input *extractor.ScanInput) lockfile.DepFile {
	return fileWrapper{input: input}
}

type fileWrapper struct {
	input *extractor.ScanInput
}

// Implement io.Reader interface
func (fw fileWrapper) Read(p []byte) (n int, err error) {
	return fw.input.Reader.Read(p)
}
func (fw fileWrapper) Open(path string) (lockfile.NestedDepFile, error) {
	cwd := fw.input.ScanRoot
	if !filepath.IsAbs(path) {
		cwd = filepath.Join(fw.input.ScanRoot, filepath.Dir(fw.input.Path))
	}
	return lockfile.OpenLocalDepFile(filepath.Join(cwd, path))
}

func (fw fileWrapper) Path() string {
	return fw.input.Path
}

// ToPURL converts an inventory created by this extractor into a PURL.
func (e Wrapper) ToPURL(i *extractor.Inventory) (*purl.PackageURL, error) {
	m := i.Metadata.(*Metadata)
	name := i.Name
	namespace := ""
	if m.PURLType == purl.TypeMaven && strings.Contains(name, ":") {
		t := strings.Split(name, ":")
		namespace = t[0] // group id
		name = t[1]      // artifact id
	}
	return &purl.PackageURL{
		Type:      m.PURLType,
		Namespace: namespace,
		Name:      name,
		Version:   i.Version,
	}, nil
}

// ToCPEs is not applicable as this extractor does not infer CPEs from the Inventory.
func (e Wrapper) ToCPEs(i *extractor.Inventory) ([]string, error) { return []string{}, nil }
