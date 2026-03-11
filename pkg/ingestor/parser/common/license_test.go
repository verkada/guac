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
	"testing"

	"github.com/google/go-cmp/cmp"
)

func TestLookupSPDXIDByName(t *testing.T) {
	tests := []struct {
		name   string
		input  string
		wantID string
		wantOK bool
	}{
		{
			name:   "exact SPDX ID",
			input:  "MIT",
			wantID: "MIT",
			wantOK: true,
		},
		{
			name:   "SPDX ID case insensitive",
			input:  "mit",
			wantID: "MIT",
			wantOK: true,
		},
		{
			name:   "full license name",
			input:  "Apache License 2.0",
			wantID: "Apache-2.0",
			wantOK: true,
		},
		{
			name:   "full license name case insensitive",
			input:  "apache license 2.0",
			wantID: "Apache-2.0",
			wantOK: true,
		},
		{
			name:   "full name MIT License",
			input:  "MIT License",
			wantID: "MIT",
			wantOK: true,
		},
		{
			name:   "GPL full name",
			input:  "GNU General Public License v3.0 only",
			wantID: "GPL-3.0-only",
			wantOK: true,
		},
		{
			name:   "unknown license",
			input:  "My Custom License",
			wantID: "",
			wantOK: false,
		},
		{
			name:   "empty string",
			input:  "",
			wantID: "",
			wantOK: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotID, gotOK := LookupSPDXIDByName(tt.input)
			if gotID != tt.wantID || gotOK != tt.wantOK {
				t.Errorf("LookupSPDXIDByName(%q) = (%q, %v), want (%q, %v)",
					tt.input, gotID, gotOK, tt.wantID, tt.wantOK)
			}
		})
	}
}

func TestCombineLicense(t *testing.T) {
	tests := []struct {
		name     string
		licenses []string
		want     string
	}{{
		name:     "multiple",
		licenses: []string{"GPL-2.0", "LGPL-3.0-or-later"},
		want:     "GPL-2.0 AND LGPL-3.0-or-later",
	}}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := CombineLicense(tt.licenses)
			if diff := cmp.Diff(got, tt.want); diff != "" {
				t.Errorf("Unexpected results. (-want +got):\n%s", diff)
			}
		})
	}
}
