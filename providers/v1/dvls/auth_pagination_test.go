/*
Copyright © The ESO Authors

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    https://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package dvls

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"

	"github.com/Devolutions/go-dvls"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// The client asks for 500 vaults per page; serving fewer makes 30 vaults span several pages.
const mockMaxPageSize = 10

type mockVault struct {
	id   string
	name string
}

func newPaginatedDVLSServer(t *testing.T, vaults []mockVault) *httptest.Server {
	t.Helper()

	mux := http.NewServeMux()
	mux.HandleFunc("POST /api/v2/login", func(w http.ResponseWriter, r *http.Request) {
		var body struct {
			AppKey    string `json:"appKey"`
			AppSecret string `json:"appSecret"`
		}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil || body.AppKey != "app-id" || body.AppSecret != "app-secret" {
			w.WriteHeader(http.StatusUnauthorized)
			_, _ = w.Write([]byte(`{"message":"The sign-in failed."}`))
			return
		}
		_, _ = w.Write([]byte(`{"tokenId":"test-token"}`))
	})
	mux.HandleFunc("GET /api/v2/vault", func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("tokenId") != "test-token" {
			w.WriteHeader(http.StatusUnauthorized)
			_, _ = w.Write([]byte(`{"message":"Missing or invalid token."}`))
			return
		}

		matches := vaults
		if name := r.URL.Query().Get("name"); name != "" {
			matches = nil
			for _, v := range vaults {
				if strings.EqualFold(v.name, name) {
					matches = append(matches, v)
				}
			}
		}

		pageSize := 25
		if v, err := strconv.Atoi(r.URL.Query().Get("pageSize")); err == nil && v > 0 {
			pageSize = v
		}
		pageSize = min(pageSize, mockMaxPageSize)
		pageNumber := 1
		if v, err := strconv.Atoi(r.URL.Query().Get("pageNumber")); err == nil && v > 0 {
			pageNumber = v
		}

		start := min((pageNumber-1)*pageSize, len(matches))
		end := min(start+pageSize, len(matches))
		totalPage := (len(matches) + pageSize - 1) / pageSize

		data := make([]map[string]any, 0, end-start)
		for _, v := range matches[start:end] {
			data = append(data, map[string]any{
				"id":            v.id,
				"name":          v.name,
				"description":   "",
				"type":          "Shared",
				"contentType":   "Default",
				"securityLevel": "Standard",
				"visibility":    "Default",
			})
		}

		_ = json.NewEncoder(w).Encode(map[string]any{
			"data":        data,
			"currentPage": pageNumber,
			"pageSize":    pageSize,
			"totalCount":  len(matches),
			"totalPage":   totalPage,
		})
	})

	server := httptest.NewServer(mux)
	t.Cleanup(server.Close)

	return server
}

func newMockVaults() []mockVault {
	vaults := make([]mockVault, 30)
	for i := range vaults {
		vaults[i] = mockVault{
			id:   fmt.Sprintf("00000000-0000-0000-0000-%012d", i+1),
			name: fmt.Sprintf("vault-%02d", i+1),
		}
	}
	return vaults
}

func TestResolveVaultRef_RealClient(t *testing.T) {
	vaults := newMockVaults()
	server := newPaginatedDVLSServer(t, vaults)

	client, err := dvls.NewClient("app-id", "app-secret", server.URL)
	require.NoError(t, err)

	vc := &realVaultClient{vaults: client.Vaults}

	tests := []struct {
		name   string
		vault  string
		wantID string
	}{
		{name: "first vault", vault: "vault-01", wantID: vaults[0].id},
		{name: "last vault", vault: "vault-30", wantID: vaults[29].id},
		{name: "name in another case", vault: "VAULT-30", wantID: vaults[29].id},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			id, err := resolveVaultRef(context.Background(), tt.vault, vc)
			require.NoError(t, err)
			assert.Equal(t, tt.wantID, id)
		})
	}
}

func TestResolveVault_RealClientIndexAcrossPages(t *testing.T) {
	vaults := append(newMockVaults(),
		mockVault{id: "00000000-0000-0000-0000-000000000031", name: "Payments"},
		mockVault{id: "00000000-0000-0000-0000-000000000032", name: "payments"},
	)
	server := newPaginatedDVLSServer(t, vaults)

	client, err := dvls.NewClient("app-id", "app-secret", server.URL)
	require.NoError(t, err)

	c := NewClient(nil, &realVaultClient{vaults: client.Vaults}, "", false)

	tests := []struct {
		name   string
		vault  string
		wantID string
	}{
		{name: "vault on the first page", vault: "vault-01", wantID: vaults[0].id},
		{name: "vault on the last page", vault: "vault-30", wantID: vaults[29].id},
		{name: "name in another case", vault: "Vault-30", wantID: vaults[29].id},
		{name: "exact name among names that differ by case", vault: "Payments", wantID: vaults[30].id},
		{name: "other exact name among names that differ by case", vault: "payments", wantID: vaults[31].id},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			id, err := c.resolveVault(context.Background(), tt.vault)
			require.NoError(t, err)
			assert.Equal(t, tt.wantID, id)
		})
	}

	t.Run("name in another case shared by several vaults", func(t *testing.T) {
		_, err := c.resolveVault(context.Background(), "PAYMENTS")
		require.Error(t, err)
		assert.Contains(t, err.Error(), "found multiple vaults named")
	})
}
