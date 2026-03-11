//
// Copyright 2023 The GUAC Authors.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package common

import (
	"fmt"
	"hash/fnv"
	"slices"
	"strings"

	model "github.com/guacsec/guac/pkg/assembler/clients/generated"
	"github.com/github/go-spdx/v2/spdxexp/spdxlicenses"
)

// spdxIDCanonical maps lowercased SPDX license IDs to their canonical casing.
// Built once at init time for O(1) lookups.
var spdxIDCanonical map[string]string

func init() {
	active := spdxlicenses.GetLicenses()
	deprecated := spdxlicenses.GetDeprecated()
	spdxIDCanonical = make(map[string]string, len(active)+len(deprecated))
	for _, id := range active {
		spdxIDCanonical[strings.ToLower(id)] = id
	}
	for _, id := range deprecated {
		spdxIDCanonical[strings.ToLower(id)] = id
	}
}

// IsValidSPDXID returns true if the given identifier is a recognized SPDX license ID
// (case-insensitive). This covers both active and deprecated SPDX licenses.
func IsValidSPDXID(id string) bool {
	_, ok := spdxIDCanonical[strings.ToLower(id)]
	return ok
}

// LookupSPDXIDByName returns the SPDX license ID for a given license name
// (case-insensitive). Returns the ID and true if found, or empty string and
// false if no match. This checks if the name is already a valid SPDX ID, or
// if it matches a known SPDX license full name (e.g. "Apache License 2.0" -> "Apache-2.0").
func LookupSPDXIDByName(name string) (string, bool) {
	lower := strings.ToLower(name)

	// Check if the name is already a valid SPDX ID
	if canonical, ok := spdxIDCanonical[lower]; ok {
		return canonical, true
	}

	// Look up by full license name
	if id, ok := spdxNameToID[lower]; ok {
		return id, true
	}

	return "", false
}

var ignore = []string{
	"AND",
	"OR",
	"WITH",
}

// Could add exceptions to ignore list, as they are not licenses:
// "389-exception",
// "Autoconf-exception-2.0",
// "Autoconf-exception-3.0",
// "Bison-exception-2.2",
// "Bootloader-exception",
// "Classpath-exception-2.0",
// "CLISP-exception-2.0",
// "DigiRule-FOSS-exception",
// "eCos-exception-2.0",
// "Fawkes-Runtime-exception",
// "FLTK-exception",
// "Font-exception-2.0",
// "freertos-exception-2.0",
// "GCC-exception-2.0",
// "GCC-exception-3.1",
// "gnu-javamail-exception",
// "GPL-3.0-linking-exception",
// "GPL-3.0-linking-source-exception",
// "GPL-CC-1.0",
// "i2p-gpl-java-exception",
// "Libtool-exception",
// "Linux-syscall-note",
// "LLVM-exception",
// "LZMA-exception",
// "mif-exception",
// "OCaml-LGPL-linking-exception",
// "OCCT-exception-1.0",
// "OpenJDK-assembly-exception-1.0",
// "openvpn-openssl-exception",
// "PS-or-PDF-font-exception-20170817",
// "Qt-GPL-exception-1.0",
// "Qt-LGPL-exception-1.1",
// "Qwt-exception-1.0",
// "Swift-exception",
// "u-boot-exception-2.0",
// "Universal-FOSS-exception-1.0",
// "WxWindows-exception-3.1",

func ParseLicenses(exp string, lv *string, inLineMap map[string]string) []model.LicenseInputSpec {
	if exp == "" {
		return nil
	}
	var rv []model.LicenseInputSpec
	unknown := "UNKNOWN"
	for _, part := range strings.Split(exp, " ") {
		p := strings.Trim(part, "()+")
		if slices.Contains(ignore, p) {
			continue
		}
		var license *model.LicenseInputSpec
		if inline, ok := inLineMap[p]; ok {
			license = &model.LicenseInputSpec{
				Name:   p,
				Inline: &inline,
			}
		} else {
			if !strings.HasPrefix(p, "LicenseRef") {
				if lv != nil {
					license = &model.LicenseInputSpec{
						Name:        p,
						ListVersion: lv,
					}
				} else {
					license = &model.LicenseInputSpec{
						Name:        p,
						ListVersion: &unknown,
					}
				}
			}
		}
		if license != nil {
			rv = append(rv, *license)
		}
	}
	return rv
}

func HashLicense(inline string) string {
	h := fnv.New32a()
	h.Write([]byte(inline))
	s := h.Sum32()
	return fmt.Sprintf("LicenseRef-%x", s)
}

func CombineLicense(licenses []string) string {
	return strings.Join(licenses, " AND ")
}

func FixSPDXLicenseExpression(licenseExpression string, inLineMap map[string]string) string {
	modifiedLicenseExpression := licenseExpression
	for _, part := range strings.Split(licenseExpression, " ") {
		p := strings.Trim(part, "()+")
		if slices.Contains(ignore, p) {
			continue
		}
		if strings.HasPrefix(p, "LicenseRef-") {
			if inline, ok := inLineMap[p]; ok {
				newLicenseName := HashLicense(inline)
				inLineMap[newLicenseName] = inline
				modifiedLicenseExpression = strings.ReplaceAll(modifiedLicenseExpression, p, newLicenseName)
			}
		}
	}
	return modifiedLicenseExpression
}
