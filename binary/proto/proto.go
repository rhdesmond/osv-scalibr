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

// Package proto provides protobuf related utilities for the SCALIBR binary.
package proto

import (
	"compress/gzip"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"google.golang.org/protobuf/encoding/prototext"
	"google.golang.org/protobuf/proto"
	"github.com/google/osv-scalibr/converter"
	"github.com/google/osv-scalibr/detector"
	"github.com/google/osv-scalibr/log"

	"github.com/google/osv-scalibr/extractor"
	"github.com/google/osv-scalibr/extractor/language/java/archive"
	"github.com/google/osv-scalibr/extractor/language/javascript/packagejson"
	"github.com/google/osv-scalibr/extractor/language/python/wheelegg"
	"github.com/google/osv-scalibr/extractor/os/apk"
	"github.com/google/osv-scalibr/extractor/os/cos"
	"github.com/google/osv-scalibr/extractor/os/dpkg"
	"github.com/google/osv-scalibr/extractor/os/rpm"
	"github.com/google/osv-scalibr/extractor/osv"
	"github.com/google/osv-scalibr/extractor/sbom/spdx"
	"github.com/google/osv-scalibr/plugin"
	"github.com/google/osv-scalibr/purl"
	scalibr "github.com/google/osv-scalibr"

	"google.golang.org/protobuf/types/known/timestamppb"
	spb "github.com/google/osv-scalibr/binary/proto/scan_result_go_proto"
)

// fileType represents the type of a proto result file.
type fileType struct {
	isGZipped  bool
	isBinProto bool
}

// typeForPath returns the proto type of a path, or an error if the path is not a valid proto file.
func typeForPath(filePath string) (*fileType, error) {
	ext := filepath.Ext(filePath)
	if ext == "" {
		return nil, errors.New("invalid filename: Doesn't have an extension")
	}

	isGZipped := false
	if ext == ".gz" {
		isGZipped = true
		ext = filepath.Ext(strings.TrimSuffix(filePath, ext))
		if ext == "" {
			return nil, errors.New("invalid filename: Gzipped file doesn't have an extension")
		}
	}

	isBinProto := false
	switch ext {
	case ".binproto":
		isBinProto = true
	case ".textproto":
		isBinProto = false
	default:
		return nil, errors.New("invalid filename: not a .textproto or .binproto")
	}

	return &fileType{isGZipped: isGZipped, isBinProto: isBinProto}, nil
}

// ValidExtension returns an error if the file extension is not a proto file.
func ValidExtension(path string) error {
	_, err := typeForPath(path)
	return err
}

// Write writes a proto message to a .textproto or .binproto file, based on the file extension.
// If the file name additionally has the .gz suffix, it's zipped before writing.
func Write(filePath string, outputProto proto.Message) error {
	ft, err := typeForPath(filePath)
	if err != nil {
		return err
	}
	return write(filePath, outputProto, ft)
}

// WriteWithFormat writes a proto message to a .textproto or .binproto file, based
// on the value of the format parameter ("textproto" or "binproto")
func WriteWithFormat(filePath string, outputProto proto.Message, format string) error {
	ft := &fileType{isGZipped: false, isBinProto: format == "binproto"}
	return write(filePath, outputProto, ft)
}

func write(filePath string, outputProto proto.Message, ft *fileType) error {
	var p []byte
	var err error
	if ft.isBinProto {
		if p, err = proto.Marshal(outputProto); err != nil {
			return err
		}
	} else {
		opts := prototext.MarshalOptions{Multiline: true}
		if p, err = (opts.Marshal(outputProto)); err != nil {
			return err
		}
	}

	log.Infof("Marshaled result proto has %d bytes", len(p))

	f, err := os.Create(filePath)
	if err != nil {
		return err
	}
	defer f.Close()
	if ft.isGZipped {
		writer := gzip.NewWriter(f)
		if _, err := writer.Write(p); err != nil {
			return err
		}
		if err := writer.Close(); err != nil {
			return err
		}
	} else if _, err := f.Write(p); err != nil {
		return err
	}
	return nil
}

// ScanResultToProto converts a ScanResult go struct into the equivalent proto.
func ScanResultToProto(r *scalibr.ScanResult) (*spb.ScanResult, error) {
	pluginStatus := make([]*spb.PluginStatus, 0, len(r.PluginStatus))
	for _, s := range r.PluginStatus {
		pluginStatus = append(pluginStatus, pluginStatusToProto(s))
	}

	inventories := make([]*spb.Inventory, 0, len(r.Inventories))
	for _, i := range r.Inventories {
		p, err := inventoryToProto(i)
		if err != nil {
			return nil, err
		}
		inventories = append(inventories, p)
	}

	findings := make([]*spb.Finding, 0, len(r.Findings))
	for _, f := range r.Findings {
		p, err := findingToProto(f)
		if err != nil {
			return nil, err
		}
		findings = append(findings, p)
	}

	return &spb.ScanResult{
		Version:      r.Version,
		StartTime:    timestamppb.New(r.StartTime),
		EndTime:      timestamppb.New(r.EndTime),
		Status:       scanStatusToProto(r.Status),
		PluginStatus: pluginStatus,
		Inventories:  inventories,
		Findings:     findings,
	}, nil
}

func scanStatusToProto(s *plugin.ScanStatus) *spb.ScanStatus {
	var e spb.ScanStatus_ScanStatusEnum
	switch s.Status {
	case plugin.ScanStatusSucceeded:
		e = spb.ScanStatus_SUCCEEDED
	case plugin.ScanStatusPartiallySucceeded:
		e = spb.ScanStatus_PARTIALLY_SUCCEEDED
	case plugin.ScanStatusFailed:
		e = spb.ScanStatus_FAILED
	default:
		e = spb.ScanStatus_UNSPECIFIED
	}
	return &spb.ScanStatus{Status: e, FailureReason: s.FailureReason}
}

func pluginStatusToProto(s *plugin.Status) *spb.PluginStatus {
	return &spb.PluginStatus{
		Name:    s.Name,
		Version: int32(s.Version),
		Status:  scanStatusToProto(s.Status),
	}
}

func inventoryToProto(i *extractor.Inventory) (*spb.Inventory, error) {
	if i == nil {
		return nil, nil
	}
	p, err := converter.ToPURL(i)
	if err != nil {
		return nil, err
	}
	cpes, err := converter.ToCPEs(i)
	if err != nil {
		return nil, err
	}
	inventoryProto := &spb.Inventory{
		Name:      i.Name,
		Version:   i.Version,
		Purl:      purlToProto(p),
		Cpes:      cpes,
		Locations: i.Locations,
		Extractor: i.Extractor,
	}
	setProtoMetadata(i.Metadata, inventoryProto)
	return inventoryProto, nil
}

func setProtoMetadata(meta any, i *spb.Inventory) {
	switch m := meta.(type) {
	case *wheelegg.PythonPackageMetadata:
		i.Metadata = &spb.Inventory_PythonMetadata{
			PythonMetadata: &spb.PythonPackageMetadata{
				Author:      m.Author,
				AuthorEmail: m.AuthorEmail,
			},
		}
	case *packagejson.JavascriptPackageJSONMetadata:
		i.Metadata = &spb.Inventory_JavascriptMetadata{
			JavascriptMetadata: &spb.JavascriptPackageJSONMetadata{
				Author:       m.Author.PersonString(),
				Contributors: personsToProto(m.Contributors),
				Maintainers:  personsToProto(m.Maintainers),
			},
		}
	case *apk.Metadata:
		i.Metadata = &spb.Inventory_ApkMetadata{
			ApkMetadata: &spb.APKPackageMetadata{
				PackageName:  m.PackageName,
				OriginName:   m.OriginName,
				OsId:         m.OSID,
				OsVersionId:  m.OSVersionID,
				Maintainer:   m.Maintainer,
				Architecture: m.Architecture,
				License:      m.License,
			},
		}
	case *dpkg.Metadata:
		i.Metadata = &spb.Inventory_DpkgMetadata{
			DpkgMetadata: &spb.DPKGPackageMetadata{
				PackageName:       m.PackageName,
				SourceName:        m.SourceName,
				SourceVersion:     m.SourceVersion,
				PackageVersion:    m.PackageVersion,
				OsId:              m.OSID,
				OsVersionCodename: m.OSVersionCodename,
				OsVersionId:       m.OSVersionID,
				Maintainer:        m.Maintainer,
				Architecture:      m.Architecture,
			},
		}
	case *rpm.Metadata:
		i.Metadata = &spb.Inventory_RpmMetadata{
			RpmMetadata: &spb.RPMPackageMetadata{
				PackageName:  m.PackageName,
				SourceRpm:    m.SourceRPM,
				Epoch:        int32(m.Epoch),
				OsName:       m.OSName,
				OsId:         m.OSID,
				OsVersionId:  m.OSVersionID,
				OsBuildId:    m.OSBuildID,
				Vendor:       m.Vendor,
				Architecture: m.Architecture,
				License:      m.License,
			},
		}
	case *cos.Metadata:
		i.Metadata = &spb.Inventory_CosMetadata{
			CosMetadata: &spb.COSPackageMetadata{
				Name:        m.Name,
				Version:     m.Version,
				Category:    m.Category,
				OsVersion:   m.OSVersion,
				OsVersionId: m.OSVersionID,
			},
		}
	case *spdx.Metadata:
		i.Metadata = &spb.Inventory_SpdxMetadata{
			SpdxMetadata: &spb.SPDXPackageMetadata{
				Purl: purlToProto(m.PURL),
				Cpes: m.CPEs,
			},
		}
	case *archive.Metadata:
		i.Metadata = &spb.Inventory_JavaArchiveMetadata{
			JavaArchiveMetadata: &spb.JavaArchiveMetadata{
				ArtifactId: m.ArtifactID,
				GroupId:    m.GroupID,
				Sha1:       m.SHA1,
			},
		}
	case *osv.Metadata:
		i.Metadata = &spb.Inventory_OsvMetadata{
			OsvMetadata: &spb.OSVPackageMetadata{
				PurlType:  m.PURLType,
				Commit:    m.Commit,
				Ecosystem: m.Ecosystem,
				CompareAs: m.CompareAs,
			},
		}
	}
}

func personsToProto(persons []*packagejson.Person) []string {
	var personStrings []string
	for _, p := range persons {
		personStrings = append(personStrings, p.PersonString())
	}
	return personStrings
}

func purlToProto(p *purl.PackageURL) *spb.Purl {
	if p == nil {
		return nil
	}
	return &spb.Purl{
		Purl:       p.String(),
		Type:       p.Type,
		Namespace:  p.Namespace,
		Name:       p.Name,
		Version:    p.Version,
		Qualifiers: qualifiersToProto(p.Qualifiers),
		Subpath:    p.Subpath,
	}
}

func qualifiersToProto(qs purl.Qualifiers) []*spb.Qualifier {
	result := make([]*spb.Qualifier, 0, len(qs))
	for _, q := range qs {
		result = append(result, &spb.Qualifier{Key: q.Key, Value: q.Value})
	}
	return result
}

// ErrAdvisoryMissing will be returned if the Advisory is not set on a finding.
var ErrAdvisoryMissing = fmt.Errorf("Advisory missing in finding")

// ErrAdvisoryIDMissing will be returned if the Advisory ID is not set on a finding.
var ErrAdvisoryIDMissing = fmt.Errorf("Advisory ID missing in finding")

func findingToProto(f *detector.Finding) (*spb.Finding, error) {
	if f.Adv == nil {
		return nil, ErrAdvisoryMissing
	}
	var target *spb.TargetDetails
	if f.Target != nil {
		i, err := inventoryToProto(f.Target.Inventory)
		if err != nil {
			return nil, err
		}
		target = &spb.TargetDetails{
			Location:  f.Target.Location,
			Inventory: i,
		}
	}
	if f.Adv.ID == nil {
		return nil, ErrAdvisoryIDMissing
	}
	return &spb.Finding{
		Adv: &spb.Advisory{
			Id: &spb.AdvisoryId{
				Publisher: f.Adv.ID.Publisher,
				Reference: f.Adv.ID.Reference,
			},
			Type:           typeEnumToProto(f.Adv.Type),
			Title:          f.Adv.Title,
			Description:    f.Adv.Description,
			Recommendation: f.Adv.Recommendation,
			Sev:            severityToProto(f.Adv.Sev),
		},
		Target: target,
		Extra:  f.Extra,
	}, nil
}

func typeEnumToProto(e detector.TypeEnum) spb.Advisory_TypeEnum {
	switch e {
	case detector.TypeVulnerability:
		return spb.Advisory_VULNERABILITY
	case detector.TypeCISFinding:
		return spb.Advisory_CIS_FINDING
	default:
		return spb.Advisory_UNKNOWN
	}
}

func severityToProto(s *detector.Severity) *spb.Severity {
	r := &spb.Severity{}
	switch s.Severity {
	case detector.SeverityMinimal:
		r.Severity = spb.Severity_MINIMAL
	case detector.SeverityLow:
		r.Severity = spb.Severity_LOW
	case detector.SeverityMedium:
		r.Severity = spb.Severity_MEDIUM
	case detector.SeverityHigh:
		r.Severity = spb.Severity_HIGH
	case detector.SeverityCritical:
		r.Severity = spb.Severity_CRITICAL
	default:
		r.Severity = spb.Severity_UNSPECIFIED
	}
	if s.CVSSV2 != nil {
		r.CvssV2 = cvssToProto(s.CVSSV2)
	}
	if s.CVSSV3 != nil {
		r.CvssV3 = cvssToProto(s.CVSSV3)
	}
	return r
}

func cvssToProto(c *detector.CVSS) *spb.CVSS {
	return &spb.CVSS{
		BaseScore:          c.BaseScore,
		TemporalScore:      c.TemporalScore,
		EnvironmentalScore: c.EnvironmentalScore,
	}
}
