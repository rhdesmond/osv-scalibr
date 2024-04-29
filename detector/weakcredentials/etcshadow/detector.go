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

// Package etcshadow implements a detector for weak/guessable passwords stored in /etc/shadow.
package etcshadow

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"sort"
	"strings"

	"github.com/google/osv-scalibr/detector"
	"github.com/google/osv-scalibr/inventoryindex"
)

// Detector is a SCALIBR Detector for weak/guessable passwords from /etc/shadow.
type Detector struct{}

// Name of the detector.
func (Detector) Name() string { return "weakcredentials/etcshadow" }

// Version of the detector.
func (Detector) Version() int { return 0 }

// RequiredExtractors returns an empty list as there are no dependencies.
func (Detector) RequiredExtractors() []string { return []string{} }

// Scan starts the scan.
func (d Detector) Scan(ctx context.Context, scanRoot string, ix *inventoryindex.InventoryIndex) ([]*detector.Finding, error) {
	return d.ScanFS(ctx, os.DirFS(scanRoot), ix)
}

// ScanFS starts the scan from a pseudo-filesystem.
func (Detector) ScanFS(ctx context.Context, fs fs.FS, ix *inventoryindex.InventoryIndex) ([]*detector.Finding, error) {
	f, err := fs.Open("etc/shadow")
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			// File doesn't exist, check not applicable.
			return nil, nil
		}
		return nil, err
	}
	defer f.Close()

	users, err := parseShadowFile(f)
	if err != nil {
		return nil, err
	}

	cracker := NewPasswordCracker()

	// When looking at password hashes we strictly focus on hash strings
	// with the format $ALGO$SALT$HASH. There are many other things we choose
	// not to check for the sake of simplicity (e.g. hash strings preceded
	// by one or two ! characters are for locked logins - password can still be weak
	// and running as user can be done locally with the 'su' command).
	var problemUsers []string
	for k, v := range users {
		if _, err := cracker.Crack(v); err == nil { // if cracked
			// Report only user name to avoid PII leakage.
			problemUsers = append(problemUsers, k)
		}
	}

	if len(problemUsers) == 0 {
		return nil, nil
	}

	title := "Ensure all users have strong passwords configured"
	description := "The /etc/shadow file contains user account password hashes. " +
		"These passwords must be strong and not easily guessable."
	recommendation := "Run the following command to reset password for the reported users:\n" +
		"# change password for USER: sudo passwd USER"

	// Sort users to avoid non-determinism in the processing order from users map.
	sort.Strings(problemUsers)

	return []*detector.Finding{&detector.Finding{
		Adv: &detector.Advisory{
			ID: &detector.AdvisoryID{
				Publisher: "SCALIBR",
				Reference: "etc-shadow-weakcredentials",
			},
			Type:           detector.TypeVulnerability,
			Title:          title,
			Description:    description,
			Recommendation: recommendation,
			Sev:            &detector.Severity{Severity: detector.SeverityMinimal},
		},
		Target: &detector.TargetDetails{Location: []string{"/etc/shadow"}},
		Extra:  fmt.Sprintf("user(s) %v have a weak password", problemUsers),
	}}, nil
}

func parseShadowFile(f fs.File) (map[string]string, error) {
	users := make(map[string]string)
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		fields := strings.Split(scanner.Text(), ":")
		if len(fields) >= 2 {
			users[fields[0]] = fields[1]
		}
	}

	if err := scanner.Err(); err != nil {
		return nil, err
	}

	return users, nil
}
