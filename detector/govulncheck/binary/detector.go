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

// Package binary implements a detector that uses govulncheck to scan for vulns on Go binaries found
// on the filesystem.
package binary

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"path"
	"strings"

	"golang.org/x/vuln/scan"
	"github.com/google/osv-scalibr/detector"
	"github.com/google/osv-scalibr/extractor/language/golang/gobinary"
	"github.com/google/osv-scalibr/inventoryindex"
	"github.com/google/osv-scalibr/log"
	"github.com/google/osv-scalibr/purl"
)

const (
	// Name is the unique name of this detector.
	Name = "govulncheck/binary"
)

// Detector is a SCALIBR Detector that uses govulncheck to scan for vulns on Go binaries found
// on the filesystem.
type Detector struct {
	OfflineVulnDBPath string
}

// Name of the detector.
func (Detector) Name() string { return Name }

// Version of the detector.
func (Detector) Version() int { return 0 }

// RequiredExtractors returns the go binary extractor.
func (Detector) RequiredExtractors() []string {
	return []string{gobinary.Name}
}

func (d Detector) Scan(ctx context.Context, scanRoot string, ix *inventoryindex.InventoryIndex) ([]*detector.Finding, error) {
	result := []*detector.Finding{}
	scanned := make(map[string]bool)
	var allErrs error = nil
	for _, i := range ix.GetAllOfType(purl.TypeGolang) {
		// We only look at Go binaries (no source code).
		if i.Extractor != gobinary.Name {
			continue
		}
		for _, l := range i.Locations {
			if scanned[l] {
				continue
			}
			scanned[l] = true
			if ctx.Err() != nil {
				return result, appendError(allErrs, ctx.Err())
			}
			out, err := d.runGovulncheck(ctx, l, scanRoot)
			if err != nil {
				allErrs = appendError(allErrs, fmt.Errorf("d.runGovulncheck(%s): %w", l, err))
				continue
			}
			r, err := parseVulnsFromOutput(out, l)
			if err != nil {
				allErrs = appendError(allErrs, fmt.Errorf("d.parseVulnsFromOutput(%v, %s): %w", out, l, err))
				continue
			}
			result = append(result, r...)
		}
	}
	return result, allErrs
}

func (d Detector) runGovulncheck(ctx context.Context, binaryPath, scanRoot string) (*bytes.Buffer, error) {
	fullPath := path.Join(scanRoot, binaryPath)
	log.Debugf("Running govulncheck on go binary %v", fullPath)
	args := []string{"--mode=binary", "--json"}
	if d.OfflineVulnDBPath != "" {
		args = append(args, "-db=file://"+d.OfflineVulnDBPath)
	}
	args = append(args, fullPath)
	cmd := scan.Command(ctx, args...)
	var out bytes.Buffer
	cmd.Stdout = &out
	if err := cmd.Start(); err != nil {
		return nil, err
	}
	if err := cmd.Wait(); err != nil {
		return nil, err
	}
	log.Debugf("govulncheck complete")
	return &out, nil
}

func parseVulnsFromOutput(out *bytes.Buffer, binaryPath string) ([]*detector.Finding, error) {
	result := []*detector.Finding{}
	dec := json.NewDecoder(bytes.NewReader(out.Bytes()))
	for dec.More() {
		msg := govulncheckMessage{}
		if err := dec.Decode(&msg); err != nil {
			return nil, err
		}
		if msg.OSV == nil {
			continue
		}
		recommendation := "Remove the binary or upgrade its affected dependencies to non-vulnerable versions"
		extra := ""
		affected, err := json.Marshal(msg.OSV.Affected)
		if err == nil {
			extra = fmt.Sprintf("Vulnerable dependencies for binary %s: %s", binaryPath, string(affected[:]))
		} else {
			log.Warnf("error serializing affected software: %w", err)
		}
		result = append(result, &detector.Finding{
			Adv: &detector.Advisory{
				ID:             getAdvisoryID(msg.OSV),
				Type:           detector.TypeVulnerability,
				Title:          msg.OSV.Summary,
				Description:    msg.OSV.Details,
				Recommendation: recommendation,
				Sev:            &detector.Severity{Severity: detector.SeverityMedium},
			},
			Target: &detector.TargetDetails{Location: []string{binaryPath}},
			Extra:  extra,
		})
	}
	return result, nil
}

func getAdvisoryID(e *osvEntry) *detector.AdvisoryID {
	// Get the CVE or GSHA advisory if it exists.
	for _, a := range e.Aliases {
		var publisher string
		if strings.HasPrefix(a, "CVE-") {
			publisher = "CVE"
		} else if strings.HasPrefix(a, "GHSA-") {
			publisher = "GSHA"
		} else {
			continue
		}
		return &detector.AdvisoryID{
			Publisher: publisher,
			Reference: a,
		}
	}
	// Fall back to the Go vuln DB advisory ID.
	return &detector.AdvisoryID{
		Publisher: "vuln.go.dev",
		Reference: e.ID,
	}
}

func appendError(err1, err2 error) error {
	if err1 == nil {
		return err2
	}
	return fmt.Errorf("%w\n%w", err1, err2)
}
