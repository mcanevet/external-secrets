//go:build integration

/*
Copyright © 2025 ESO Maintainer Team

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

// Integration tests for the Proton Pass provider.
//
// These tests hit the real Proton Pass API and require a dedicated service
// account with 2FA disabled. They are skipped automatically when any of the
// required environment variables are absent.
//
// Required environment variables:
//
//	PROTON_USERNAME   Proton account username (email)
//	PROTON_PASSWORD   Proton account password
//
// Run with:
//
//	go test -v -tags integration -timeout 120s \
//	  -run TestIntegration \
//	  github.com/external-secrets/external-secrets/providers/v1/protonpass

package protonpass

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	sdkauth "github.com/mcanevet/proton-sdk-go/auth"
	sdkclient "github.com/mcanevet/proton-sdk-go/client"
	sdkpass "github.com/mcanevet/proton-sdk-go/pass"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	esv1 "github.com/external-secrets/external-secrets/apis/externalsecrets/v1"
	esv1alpha1 "github.com/external-secrets/external-secrets/apis/externalsecrets/v1alpha1"
)

// sharedIntegration holds the single logged-in client shared by all integration tests.
var sharedIntegration struct {
	client *Client
	vault  string
	skip   string
}

// sessionCachePath returns the path for the integration test session cache.
func sessionCachePath() string {
	if p := os.Getenv("PROTON_SESSION_FILE"); p != "" {
		return p
	}
	return filepath.Join(os.TempDir(), "protonpass-integration-session.json")
}

func loadCachedSession() (sdkauth.Session, bool) {
	data, err := os.ReadFile(sessionCachePath())
	if err != nil {
		return sdkauth.Session{}, false
	}
	var s sdkauth.Session
	if err := json.Unmarshal(data, &s); err != nil || s.UID == "" {
		return sdkauth.Session{}, false
	}
	return s, true
}

func saveCachedSession(s sdkauth.Session) {
	data, err := json.Marshal(s)
	if err != nil {
		return
	}
	_ = os.WriteFile(sessionCachePath(), data, 0o600)
}

func invalidateCachedSession() {
	_ = os.Remove(sessionCachePath())
}

// TestMain sets up a single Proton session for all integration tests.
// The session is cached in $TMPDIR/protonpass-integration-session.json to
// avoid repeated logins that trigger rate limits. Set PROTON_LOGOUT=1 to
// force a fresh login and clear the cache.
func TestMain(m *testing.M) {
	username := os.Getenv("PROTON_USERNAME")
	password := os.Getenv("PROTON_PASSWORD")

	if username == "" || password == "" {
		sharedIntegration.skip = "integration test requires PROTON_USERNAME and PROTON_PASSWORD"
		m.Run()
		return
	}

	vault := os.Getenv("PROTON_VAULT")
	if vault == "" {
		vault = "Personal"
	}

	ctx := context.Background()
	c := sdkclient.New(
		sdkclient.WithBaseURL(protonPassHostURL),
		sdkclient.WithAppVersion("web-pass@5.0.0"),
	)

	if os.Getenv("PROTON_LOGOUT") != "" {
		if cached, ok := loadCachedSession(); ok {
			// Resume sets auth on c so Revoke can send the DELETE /auth/v4 request.
			if _, err := sdkauth.Resume(ctx, c, cached); err == nil {
				sdkauth.Revoke(ctx, c)
			}
		}
		invalidateCachedSession()
		fmt.Println("TestMain: session invalidated")
		os.Exit(0)
	}

	var lr sdkauth.LoginResult
	if cached, ok := loadCachedSession(); ok {
		fmt.Printf("TestMain: trying cached session (uid=%s)\n", cached.UID)
		resumed, err := sdkauth.Resume(ctx, c, cached)
		if err == nil {
			lr = resumed
			fmt.Println("TestMain: session resumed from cache")
		} else {
			fmt.Printf("TestMain: resume failed (%v), logging in fresh\n", err)
			invalidateCachedSession()
		}
	}

	if lr.Session.UID == "" {
		var err error
		lr, err = sdkauth.Login(ctx, c, username, []byte(password))
		if err != nil {
			sharedIntegration.skip = fmt.Sprintf("login failed: %v", err)
			m.Run()
			return
		}
		saveCachedSession(lr.Session)
		fmt.Printf("TestMain: new session cached (uid=%s)\n", lr.Session.UID)
	}

	pc := sdkpass.NewClient(c, lr.UserKR, lr.AddrKR, lr.AddressID)
	sharedIntegration.client = &Client{passClient: pc}
	sharedIntegration.vault = vault

	os.Exit(m.Run())
}

func integrationSetup(t *testing.T) (*Client, string) {
	t.Helper()
	if sharedIntegration.skip != "" {
		t.Skip(sharedIntegration.skip)
	}
	return sharedIntegration.client, sharedIntegration.vault
}

// TestIntegrationGetAllSecrets lists all secrets in the configured vault.
func TestIntegrationGetAllSecrets(t *testing.T) {
	c, vault := integrationSetup(t)
	ctx := context.Background()

	refs, err := c.GetAllSecrets(ctx, esv1.ExternalSecretFind{
		Path: &vault,
	})
	if err != nil {
		t.Fatalf("GetAllSecrets(vault=%q): %v", vault, err)
	}
	t.Logf("GetAllSecrets found %d items in vault %q", len(refs), vault)
	for k, v := range refs {
		t.Logf("  %s = %q", k, string(v))
	}
}

// TestIntegrationFullCycle performs a complete create → read → update → read → delete cycle.
func TestIntegrationFullCycle(t *testing.T) {
	c, vault := integrationSetup(t)
	ctx := context.Background()

	const itemName = "eso-full-cycle-test"
	remoteKey := strings.Join([]string{vault, itemName}, "/")

	const (
		passwordKey   = "password"
		passwordValue = "initial-password-123"
	)

	secret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{Name: itemName, Namespace: "default"},
		Data: map[string][]byte{
			passwordKey: []byte(passwordValue),
		},
	}
	pushData := esv1alpha1.PushSecretData{
		Match: esv1alpha1.PushSecretMatch{
			SecretKey: passwordKey,
			RemoteRef: esv1alpha1.PushSecretRemoteRef{RemoteKey: remoteKey},
		},
	}

	if err := c.PushSecret(ctx, secret, pushData); err != nil {
		t.Fatalf("PushSecret (create): %v", err)
	}
	t.Logf("created item %q", remoteKey)

	ref := esv1.ExternalSecretDataRemoteRef{Key: remoteKey + "/" + passwordKey}
	val, err := c.GetSecret(ctx, ref)
	if err != nil {
		t.Fatalf("GetSecret (verify create): %v", err)
	}
	if string(val) != passwordValue {
		t.Errorf("password mismatch: got %q, want %q", string(val), passwordValue)
	}

	const updatedPassword = "updated-password-456"
	secret.Data[passwordKey] = []byte(updatedPassword)
	if err := c.PushSecret(ctx, secret, pushData); err != nil {
		t.Fatalf("PushSecret (update): %v", err)
	}

	val, err = c.GetSecret(ctx, ref)
	if err != nil {
		t.Fatalf("GetSecret (verify update): %v", err)
	}
	if string(val) != updatedPassword {
		t.Errorf("password mismatch after update: got %q, want %q", string(val), updatedPassword)
	}

	delRef := esv1alpha1.PushSecretRemoteRef{RemoteKey: remoteKey}
	if err := c.DeleteSecret(ctx, delRef); err != nil {
		t.Fatalf("DeleteSecret: %v", err)
	}
	t.Logf("deleted item %q", remoteKey)

	exists, err := c.SecretExists(ctx, delRef)
	if err != nil {
		t.Fatalf("SecretExists after delete: %v", err)
	}
	if exists {
		t.Error("item still exists after deletion")
	}
}

// TestIntegrationDeleteSecret creates and deletes a throwaway item.
func TestIntegrationDeleteSecret(t *testing.T) {
	c, vault := integrationSetup(t)
	ctx := context.Background()

	const itemName = "eso-delete-test"
	remoteKey := strings.Join([]string{vault, itemName}, "/")

	secret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{Name: itemName, Namespace: "default"},
		Data: map[string][]byte{"password": []byte("delete-me")},
	}
	pushData := esv1alpha1.PushSecretData{
		Match: esv1alpha1.PushSecretMatch{
			SecretKey: "password",
			RemoteRef: esv1alpha1.PushSecretRemoteRef{RemoteKey: remoteKey},
		},
	}
	if err := c.PushSecret(ctx, secret, pushData); err != nil {
		t.Fatalf("PushSecret (create throwaway): %v", err)
	}

	delRef := esv1alpha1.PushSecretRemoteRef{RemoteKey: remoteKey}
	if err := c.DeleteSecret(ctx, delRef); err != nil {
		t.Fatalf("DeleteSecret(%q): %v", remoteKey, err)
	}

	exists, err := c.SecretExists(ctx, &esv1alpha1.PushSecretRemoteRef{RemoteKey: remoteKey})
	if err != nil {
		t.Fatalf("SecretExists(%q) after delete: %v", remoteKey, err)
	}
	if exists {
		t.Errorf("expected item %q to be gone, but SecretExists returned true", remoteKey)
	}
}

// TestIntegrationCleanupPushTest removes the "eso-push-test" item if it exists.
func TestIntegrationCleanupPushTest(t *testing.T) {
	c, vault := integrationSetup(t)
	ctx := context.Background()

	const itemName = "eso-push-test"
	remoteKey := strings.Join([]string{vault, itemName}, "/")

	exists, err := c.SecretExists(ctx, &esv1alpha1.PushSecretRemoteRef{RemoteKey: remoteKey})
	if err != nil {
		t.Fatalf("SecretExists(%q): %v", remoteKey, err)
	}
	if !exists {
		t.Skipf("item %q does not exist — nothing to clean up", remoteKey)
	}

	if err := c.DeleteSecret(ctx, &esv1alpha1.PushSecretRemoteRef{RemoteKey: remoteKey}); err != nil {
		t.Fatalf("DeleteSecret(%q): %v", remoteKey, err)
	}
	t.Logf("cleaned up item %q", remoteKey)
}

// TestIntegrationPushSecretUpdateUsername updates the username field of "eso-push-test".
func TestIntegrationPushSecretUpdateUsername(t *testing.T) {
	c, vault := integrationSetup(t)
	ctx := context.Background()

	const (
		itemName    = "eso-push-test"
		secretKey   = "username"
		secretValue = "eso-service-account"
	)
	remoteKey := strings.Join([]string{vault, itemName}, "/")

	secret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{Name: itemName, Namespace: "default"},
		Data: map[string][]byte{secretKey: []byte(secretValue)},
	}
	pushData := esv1alpha1.PushSecretData{
		Match: esv1alpha1.PushSecretMatch{
			SecretKey: secretKey,
			RemoteRef: esv1alpha1.PushSecretRemoteRef{RemoteKey: remoteKey},
		},
	}
	if err := c.PushSecret(ctx, secret, pushData); err != nil {
		t.Fatalf("PushSecret(%q, field=%q): %v", remoteKey, secretKey, err)
	}
	t.Logf("PushSecret succeeded — username set to %q", secretValue)
}
