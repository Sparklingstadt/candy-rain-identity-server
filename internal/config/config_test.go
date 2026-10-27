package config

import (
	"strings"
	"testing"
)

func TestLoadClients(t *testing.T) {
	for _, tc := range []struct {
		name    string
		env     map[string]string
		wantIDs []string
		wantErr string
	}{
		{
			name: "single client variables",
			env: map[string]string{
				"OIDC_CLIENT_ID": "candy-rain-store", "OIDC_CLIENT_SECRET": "s",
				"OIDC_REDIRECT_URIS": "http://a.test/cb, http://b.test/cb",
			},
			wantIDs: []string{"candy-rain-store"},
		},
		{
			name: "OIDC_CLIENTS and single client together",
			env: map[string]string{
				"OIDC_CLIENTS":   `[{"id":"candy-rain-stores","secret":"s2","redirect_uris":["http://stores.test/cb"],"post_logout_redirect_uris":["http://stores.test/"]}]`,
				"OIDC_CLIENT_ID": "candy-rain-store", "OIDC_CLIENT_SECRET": "s", "OIDC_REDIRECT_URIS": "http://a.test/cb",
			},
			wantIDs: []string{"candy-rain-stores", "candy-rain-store"},
		},
		{name: "no clients", env: map[string]string{}, wantErr: "at least one client"},
		{
			name:    "duplicate id",
			env:     map[string]string{"OIDC_CLIENTS": `[{"id":"x","secret":"s","redirect_uris":["http://a.test/cb"]},{"id":"x","secret":"t","redirect_uris":["http://b.test/cb"]}]`},
			wantErr: "more than once",
		},
		{
			name:    "missing secret and redirect URI",
			env:     map[string]string{"OIDC_CLIENTS": `[{"id":"x"}]`},
			wantErr: "id and secret are required",
		},
		{
			name:    "misspelled field",
			env:     map[string]string{"OIDC_CLIENTS": `[{"id":"x","secret":"s","redirect_uri":["http://a.test/cb"]}]`},
			wantErr: "unknown field",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			for _, name := range []string{"OIDC_CLIENTS", "OIDC_CLIENT_ID", "OIDC_CLIENT_SECRET", "OIDC_REDIRECT_URIS", "OIDC_POST_LOGOUT_REDIRECT_URIS"} {
				t.Setenv(name, tc.env[name])
			}
			clients, err := loadClients()
			if tc.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
					t.Fatalf("err = %v, want %q", err, tc.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			var ids []string
			for _, c := range clients {
				ids = append(ids, c.ID)
			}
			if strings.Join(ids, ",") != strings.Join(tc.wantIDs, ",") {
				t.Fatalf("ids = %v, want %v", ids, tc.wantIDs)
			}
		})
	}
}
