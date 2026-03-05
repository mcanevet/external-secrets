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

package protonpass

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/google/go-cmp/cmp"
	corev1 "k8s.io/api/core/v1"

	esv1 "github.com/external-secrets/external-secrets/apis/externalsecrets/v1"
	esv1alpha1 "github.com/external-secrets/external-secrets/apis/externalsecrets/v1alpha1"
	sdkpass "github.com/mcanevet/proton-sdk-go/pass"
	sdkproto "github.com/mcanevet/proton-sdk-go/pass/proto"
)

const (
	testShareID   = "share-abc123"
	testItemID    = "item-xyz789"
	testVaultName = "Personal"
	testItemName  = "My Login"
	testUsername  = "alice@example.com"
	testPassword  = "s3cr3tP@ssw0rd"
	testEmail     = "alice@example.com"
	testURL       = "https://example.com"
	testNote      = "some note"
	testTOTP      = "otpauth://totp/example?secret=JBSWY3DPEHPK3PXP"
)

// fakePassClient is a configurable mock of the passClient interface.
type fakePassClient struct {
	getField   func(ctx context.Context, uri string) (string, error)
	findItem   func(ctx context.Context, vaultName, itemTitle string) (*sdkpass.DecryptedItem, error)
	listVaults func(ctx context.Context) ([]sdkpass.Vault, error)
	listItems  func(ctx context.Context, shareID string) ([]sdkpass.DecryptedItem, error)
	createItem func(ctx context.Context, shareID string, content *sdkproto.Item) (string, error)
	updateItem func(ctx context.Context, shareID, itemID string, revision int64, content *sdkproto.Item) error
	trashItem  func(ctx context.Context, shareID, itemID string, revision int64) error
	deleteItem func(ctx context.Context, shareID, itemID string, revision int64) error
}

func (f *fakePassClient) GetField(ctx context.Context, uri string) (string, error) {
	if f.getField != nil {
		return f.getField(ctx, uri)
	}
	return "", errors.New("GetField not configured")
}

func (f *fakePassClient) FindItem(ctx context.Context, vaultName, itemTitle string) (*sdkpass.DecryptedItem, error) {
	if f.findItem != nil {
		return f.findItem(ctx, vaultName, itemTitle)
	}
	return nil, errors.New("FindItem not configured")
}

func (f *fakePassClient) ListVaults(ctx context.Context) ([]sdkpass.Vault, error) {
	if f.listVaults != nil {
		return f.listVaults(ctx)
	}
	return nil, errors.New("ListVaults not configured")
}

func (f *fakePassClient) ListItems(ctx context.Context, shareID string) ([]sdkpass.DecryptedItem, error) {
	if f.listItems != nil {
		return f.listItems(ctx, shareID)
	}
	return nil, errors.New("ListItems not configured")
}

func (f *fakePassClient) CreateItem(ctx context.Context, shareID string, content *sdkproto.Item) (string, error) {
	if f.createItem != nil {
		return f.createItem(ctx, shareID, content)
	}
	return "", errors.New("CreateItem not configured")
}

func (f *fakePassClient) UpdateItem(ctx context.Context, shareID, itemID string, revision int64, content *sdkproto.Item) error {
	if f.updateItem != nil {
		return f.updateItem(ctx, shareID, itemID, revision, content)
	}
	return errors.New("UpdateItem not configured")
}

func (f *fakePassClient) TrashItem(ctx context.Context, shareID, itemID string, revision int64) error {
	if f.trashItem != nil {
		return f.trashItem(ctx, shareID, itemID, revision)
	}
	return errors.New("TrashItem not configured")
}

func (f *fakePassClient) DeleteItem(ctx context.Context, shareID, itemID string, revision int64) error {
	if f.deleteItem != nil {
		return f.deleteItem(ctx, shareID, itemID, revision)
	}
	return errors.New("DeleteItem not configured")
}

// makeTestVault returns a test vault.
func makeTestVault() sdkpass.Vault {
	return sdkpass.Vault{
		ID:   testShareID,
		Name: testVaultName,
	}
}

// makeTestLoginItem returns a pre-built DecryptedItem with login content.
func makeTestLoginItem() sdkpass.DecryptedItem {
	return sdkpass.DecryptedItem{
		ShareID:  testShareID,
		ItemID:   testItemID,
		Revision: 1,
		Proto: &sdkproto.Item{
			Metadata: &sdkproto.Metadata{
				Name: testItemName,
				Note: testNote,
			},
			Content: &sdkproto.Content{
				Content: &sdkproto.Content_Login{
					Login: &sdkproto.ItemLogin{
						ItemUsername: testUsername,
						Password:     testPassword,
						ItemEmail:    testEmail,
						Urls:         []string{testURL},
						TotpUri:      testTOTP,
					},
				},
			},
		},
	}
}

func makeClientWithFake(f *fakePassClient) *Client {
	return &Client{passClient: f}
}

// ─── TestGetSecret ───────────────────────────────────────────────────────────

func TestGetSecret(t *testing.T) {
	cases := []struct {
		label       string
		key         string
		expectValue string
		expectError string
		setupFake   func() *fakePassClient
	}{
		{
			label:       "get password field",
			key:         testVaultName + "/" + testItemName + "/password",
			expectValue: testPassword,
			setupFake: func() *fakePassClient {
				item := makeTestLoginItem()
				return &fakePassClient{
					getField: func(_ context.Context, uri string) (string, error) {
						// delegate to real itemToMap logic via FindItem → getFieldFromItem
						parts := strings.SplitN(uri, "/", 3)
						if len(parts) != 3 {
							return "", errors.New("bad uri")
						}
						fields := sdkpass.ItemToMap(&item)
						v, ok := fields[parts[2]]
						if !ok {
							return "", errors.New("field not found")
						}
						return v, nil
					},
				}
			},
		},
		{
			label:       "get username field",
			key:         testVaultName + "/" + testItemName + "/username",
			expectValue: testUsername,
			setupFake: func() *fakePassClient {
				item := makeTestLoginItem()
				return &fakePassClient{
					getField: func(_ context.Context, uri string) (string, error) {
						parts := strings.SplitN(uri, "/", 3)
						fields := sdkpass.ItemToMap(&item)
						v, ok := fields[parts[2]]
						if !ok {
							return "", errors.New("field not found")
						}
						return v, nil
					},
				}
			},
		},
		{
			label:       "item not found",
			key:         testVaultName + "/" + testItemName + "/password",
			expectError: "could not get secret",
			setupFake: func() *fakePassClient {
				return &fakePassClient{
					getField: func(_ context.Context, _ string) (string, error) {
						return "", errors.New("pass: item not found")
					},
				}
			},
		},
		{
			label:       "invalid key format (2 segments)",
			key:         testVaultName + "/" + testItemName,
			expectError: "could not get secret",
			setupFake: func() *fakePassClient {
				return &fakePassClient{
					getField: func(_ context.Context, _ string) (string, error) {
						return "", errors.New("pass: GetField: URI must be vault/item/field")
					},
				}
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.label, func(t *testing.T) {
			c := makeClientWithFake(tc.setupFake())
			out, err := c.GetSecret(context.Background(), esv1.ExternalSecretDataRemoteRef{Key: tc.key})
			if tc.expectError != "" {
				if err == nil || !strings.Contains(err.Error(), tc.expectError) {
					t.Errorf("want error containing %q, got %v", tc.expectError, err)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if string(out) != tc.expectValue {
				t.Errorf("got %q, want %q", string(out), tc.expectValue)
			}
		})
	}
}

// ─── TestGetSecretMap ────────────────────────────────────────────────────────

func TestGetSecretMap(t *testing.T) {
	cases := []struct {
		label        string
		key          string
		expectFields map[string]string
		expectError  string
		setupFake    func() *fakePassClient
	}{
		{
			label: "get all fields",
			key:   testVaultName + "/" + testItemName,
			expectFields: map[string]string{
				"username": testUsername,
				"password": testPassword,
				"email":    testEmail,
				"url":      testURL,
				"note":     testNote,
				"totp":     testTOTP,
			},
			setupFake: func() *fakePassClient {
				item := makeTestLoginItem()
				return &fakePassClient{
					findItem: func(_ context.Context, vaultName, itemTitle string) (*sdkpass.DecryptedItem, error) {
						if vaultName == testVaultName && itemTitle == testItemName {
							return &item, nil
						}
						return nil, nil
					},
				}
			},
		},
		{
			label:       "item not found",
			key:         testVaultName + "/NoSuchItem",
			expectError: "could not get secret map",
			setupFake: func() *fakePassClient {
				return &fakePassClient{
					findItem: func(_ context.Context, _, _ string) (*sdkpass.DecryptedItem, error) {
						return nil, nil
					},
				}
			},
		},
		{
			label:       "invalid key (one segment)",
			key:         testVaultName,
			expectError: "could not get secret map",
			setupFake: func() *fakePassClient {
				return &fakePassClient{}
			},
		},
		{
			label:       "FindItem error propagates",
			key:         testVaultName + "/" + testItemName,
			expectError: "could not get secret map",
			setupFake: func() *fakePassClient {
				return &fakePassClient{
					findItem: func(_ context.Context, _, _ string) (*sdkpass.DecryptedItem, error) {
						return nil, errors.New("api error")
					},
				}
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.label, func(t *testing.T) {
			c := makeClientWithFake(tc.setupFake())
			out, err := c.GetSecretMap(context.Background(), esv1.ExternalSecretDataRemoteRef{Key: tc.key})
			if tc.expectError != "" {
				if err == nil || !strings.Contains(err.Error(), tc.expectError) {
					t.Errorf("want error containing %q, got %v", tc.expectError, err)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			for field, want := range tc.expectFields {
				got, ok := out[field]
				if !ok {
					t.Errorf("missing field %q", field)
					continue
				}
				if diff := cmp.Diff(string(got), want); diff != "" {
					t.Errorf("field %q mismatch (-got +want):\n%s", field, diff)
				}
			}
		})
	}
}

// ─── TestGetAllSecrets ───────────────────────────────────────────────────────

func TestGetAllSecrets(t *testing.T) {
	makeDefaultFake := func() *fakePassClient {
		vault := makeTestVault()
		item := makeTestLoginItem()
		return &fakePassClient{
			listVaults: func(_ context.Context) ([]sdkpass.Vault, error) {
				return []sdkpass.Vault{vault}, nil
			},
			listItems: func(_ context.Context, shareID string) ([]sdkpass.DecryptedItem, error) {
				if shareID == testShareID {
					return []sdkpass.DecryptedItem{item}, nil
				}
				return nil, nil
			},
		}
	}

	cases := []struct {
		label       string
		find        esv1.ExternalSecretFind
		expectKeys  []string
		expectError string
		setupFake   func() *fakePassClient
	}{
		{
			label: "returns all fields for all items",
			find:  esv1.ExternalSecretFind{},
			expectKeys: []string{
				testVaultName + "/" + testItemName + "/username",
				testVaultName + "/" + testItemName + "/password",
				testVaultName + "/" + testItemName + "/email",
				testVaultName + "/" + testItemName + "/url",
				testVaultName + "/" + testItemName + "/note",
				testVaultName + "/" + testItemName + "/totp",
			},
			setupFake: makeDefaultFake,
		},
		{
			label: "name matcher filters results",
			find: esv1.ExternalSecretFind{
				Name: &esv1.FindName{RegExp: ".*password.*"},
			},
			expectKeys: []string{
				testVaultName + "/" + testItemName + "/password",
			},
			setupFake: makeDefaultFake,
		},
		{
			label: "path filter limits results",
			find: esv1.ExternalSecretFind{
				Path: strPtr(testVaultName + "/" + testItemName + "/password"),
			},
			expectKeys: []string{
				testVaultName + "/" + testItemName + "/password",
			},
			setupFake: makeDefaultFake,
		},
		{
			label: "tag filter returns error",
			find: esv1.ExternalSecretFind{
				Tags: map[string]string{"env": "prod"},
			},
			expectError: "tag filtering is not supported",
			setupFake:   makeDefaultFake,
		},
		{
			label:       "list vaults error propagates",
			find:        esv1.ExternalSecretFind{},
			expectError: "could not get all secrets",
			setupFake: func() *fakePassClient {
				return &fakePassClient{
					listVaults: func(_ context.Context) ([]sdkpass.Vault, error) {
						return nil, errors.New("api error")
					},
				}
			},
		},
		{
			label:       "list items error propagates",
			find:        esv1.ExternalSecretFind{},
			expectError: "could not get all secrets",
			setupFake: func() *fakePassClient {
				vault := makeTestVault()
				return &fakePassClient{
					listVaults: func(_ context.Context) ([]sdkpass.Vault, error) {
						return []sdkpass.Vault{vault}, nil
					},
					listItems: func(_ context.Context, _ string) ([]sdkpass.DecryptedItem, error) {
						return nil, errors.New("network error")
					},
				}
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.label, func(t *testing.T) {
			c := makeClientWithFake(tc.setupFake())
			out, err := c.GetAllSecrets(context.Background(), tc.find)
			if tc.expectError != "" {
				if err == nil || !strings.Contains(err.Error(), tc.expectError) {
					t.Errorf("want error containing %q, got %v", tc.expectError, err)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			for _, k := range tc.expectKeys {
				if _, ok := out[k]; !ok {
					t.Errorf("expected key %q not found in result (keys: %v)", k, mapKeys(out))
				}
			}
		})
	}
}

// ─── TestSecretExists ────────────────────────────────────────────────────────

func TestSecretExists(t *testing.T) {
	cases := []struct {
		label       string
		remoteKey   string
		expectExist bool
		expectError string
		setupFake   func() *fakePassClient
	}{
		{
			label:       "item exists",
			remoteKey:   testVaultName + "/" + testItemName,
			expectExist: true,
			setupFake: func() *fakePassClient {
				item := makeTestLoginItem()
				return &fakePassClient{
					findItem: func(_ context.Context, _, _ string) (*sdkpass.DecryptedItem, error) {
						return &item, nil
					},
				}
			},
		},
		{
			label:       "item does not exist",
			remoteKey:   testVaultName + "/NoSuchItem",
			expectExist: false,
			setupFake: func() *fakePassClient {
				return &fakePassClient{
					findItem: func(_ context.Context, _, _ string) (*sdkpass.DecryptedItem, error) {
						return nil, nil
					},
				}
			},
		},
		{
			label:       "FindItem error propagates",
			remoteKey:   testVaultName + "/SomeItem",
			expectError: "find item",
			setupFake: func() *fakePassClient {
				return &fakePassClient{
					findItem: func(_ context.Context, _, _ string) (*sdkpass.DecryptedItem, error) {
						return nil, errors.New("network error")
					},
				}
			},
		},
		{
			label:       "invalid key format",
			remoteKey:   "no-slash",
			expectError: "must be in format",
			setupFake: func() *fakePassClient {
				return &fakePassClient{}
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.label, func(t *testing.T) {
			c := makeClientWithFake(tc.setupFake())
			exists, err := c.SecretExists(context.Background(), &esv1alpha1.PushSecretRemoteRef{
				RemoteKey: tc.remoteKey,
			})
			if tc.expectError != "" {
				if err == nil || !strings.Contains(err.Error(), tc.expectError) {
					t.Errorf("want error containing %q, got %v", tc.expectError, err)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if exists != tc.expectExist {
				t.Errorf("got exists=%v, want %v", exists, tc.expectExist)
			}
		})
	}
}

// ─── TestPushSecret ──────────────────────────────────────────────────────────

func TestPushSecret(t *testing.T) {
	cases := []struct {
		label       string
		remoteKey   string
		secretKey   string
		secretValue string
		expectError string
		setupFake   func() *fakePassClient
	}{
		{
			label:       "create new item",
			remoteKey:   testVaultName + "/NewItem",
			secretKey:   "password",
			secretValue: "newpassword123",
			setupFake: func() *fakePassClient {
				vault := makeTestVault()
				return &fakePassClient{
					listVaults: func(_ context.Context) ([]sdkpass.Vault, error) {
						return []sdkpass.Vault{vault}, nil
					},
					listItems: func(_ context.Context, _ string) ([]sdkpass.DecryptedItem, error) {
						return []sdkpass.DecryptedItem{}, nil
					},
					createItem: func(_ context.Context, _ string, _ *sdkproto.Item) (string, error) {
						return "new-item-id", nil
					},
				}
			},
		},
		{
			label:       "update existing item",
			remoteKey:   testVaultName + "/" + testItemName,
			secretKey:   "password",
			secretValue: "updatedpassword",
			setupFake: func() *fakePassClient {
				vault := makeTestVault()
				item := makeTestLoginItem()
				return &fakePassClient{
					listVaults: func(_ context.Context) ([]sdkpass.Vault, error) {
						return []sdkpass.Vault{vault}, nil
					},
					listItems: func(_ context.Context, _ string) ([]sdkpass.DecryptedItem, error) {
						return []sdkpass.DecryptedItem{item}, nil
					},
					updateItem: func(_ context.Context, _, _ string, _ int64, _ *sdkproto.Item) error {
						return nil
					},
				}
			},
		},
		{
			label:       "vault not found",
			remoteKey:   "no-such-vault/SomeItem",
			secretKey:   "password",
			secretValue: "value",
			expectError: "could not push secret",
			setupFake: func() *fakePassClient {
				return &fakePassClient{
					listVaults: func(_ context.Context) ([]sdkpass.Vault, error) {
						return []sdkpass.Vault{}, nil
					},
				}
			},
		},
		{
			label:       "invalid remote key format",
			remoteKey:   "no-slash",
			secretKey:   "password",
			secretValue: "value",
			expectError: "could not push secret",
			setupFake: func() *fakePassClient {
				return &fakePassClient{}
			},
		},
		{
			label:       "update item with non-login content returns error",
			remoteKey:   testVaultName + "/" + testItemName,
			secretKey:   "password",
			secretValue: "value",
			expectError: "could not push secret",
			setupFake: func() *fakePassClient {
				vault := makeTestVault()
				noteItem := sdkpass.DecryptedItem{
					ShareID:  testShareID,
					ItemID:   testItemID,
					Revision: 1,
					Proto: &sdkproto.Item{
						Metadata: &sdkproto.Metadata{Name: testItemName},
						Content: &sdkproto.Content{
							Content: &sdkproto.Content_Note{Note: &sdkproto.ItemNote{}},
						},
					},
				}
				return &fakePassClient{
					listVaults: func(_ context.Context) ([]sdkpass.Vault, error) {
						return []sdkpass.Vault{vault}, nil
					},
					listItems: func(_ context.Context, _ string) ([]sdkpass.DecryptedItem, error) {
						return []sdkpass.DecryptedItem{noteItem}, nil
					},
				}
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.label, func(t *testing.T) {
			c := makeClientWithFake(tc.setupFake())
			err := c.PushSecret(context.Background(), &corev1.Secret{
				Data: map[string][]byte{
					tc.secretKey: []byte(tc.secretValue),
				},
			}, esv1alpha1.PushSecretData{
				Match: esv1alpha1.PushSecretMatch{
					SecretKey: tc.secretKey,
					RemoteRef: esv1alpha1.PushSecretRemoteRef{
						RemoteKey: tc.remoteKey,
					},
				},
			})
			if tc.expectError != "" {
				if err == nil || !strings.Contains(err.Error(), tc.expectError) {
					t.Errorf("want error containing %q, got %v", tc.expectError, err)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
		})
	}
}

// ─── TestDeleteSecret ────────────────────────────────────────────────────────

func TestDeleteSecret(t *testing.T) {
	cases := []struct {
		label       string
		remoteKey   string
		expectError string
		setupFake   func() *fakePassClient
	}{
		{
			label:     "delete existing item",
			remoteKey: testVaultName + "/" + testItemName,
			setupFake: func() *fakePassClient {
				item := makeTestLoginItem()
				return &fakePassClient{
					findItem: func(_ context.Context, _, _ string) (*sdkpass.DecryptedItem, error) {
						return &item, nil
					},
					trashItem: func(_ context.Context, _, _ string, _ int64) error {
						return nil
					},
					deleteItem: func(_ context.Context, _, _ string, _ int64) error {
						return nil
					},
				}
			},
		},
		{
			label:       "item not found",
			remoteKey:   testVaultName + "/NoSuchItem",
			expectError: "could not delete secret",
			setupFake: func() *fakePassClient {
				return &fakePassClient{
					findItem: func(_ context.Context, _, _ string) (*sdkpass.DecryptedItem, error) {
						return nil, nil
					},
				}
			},
		},
		{
			label:       "trash fails",
			remoteKey:   testVaultName + "/" + testItemName,
			expectError: "could not delete secret",
			setupFake: func() *fakePassClient {
				item := makeTestLoginItem()
				return &fakePassClient{
					findItem: func(_ context.Context, _, _ string) (*sdkpass.DecryptedItem, error) {
						return &item, nil
					},
					trashItem: func(_ context.Context, _, _ string, _ int64) error {
						return errors.New("trash failed")
					},
				}
			},
		},
		{
			label:       "permanent delete fails",
			remoteKey:   testVaultName + "/" + testItemName,
			expectError: "could not delete secret",
			setupFake: func() *fakePassClient {
				item := makeTestLoginItem()
				return &fakePassClient{
					findItem: func(_ context.Context, _, _ string) (*sdkpass.DecryptedItem, error) {
						return &item, nil
					},
					trashItem: func(_ context.Context, _, _ string, _ int64) error {
						return nil
					},
					deleteItem: func(_ context.Context, _, _ string, _ int64) error {
						return errors.New("delete failed")
					},
				}
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.label, func(t *testing.T) {
			c := makeClientWithFake(tc.setupFake())
			err := c.DeleteSecret(context.Background(), &esv1alpha1.PushSecretRemoteRef{
				RemoteKey: tc.remoteKey,
			})
			if tc.expectError != "" {
				if err == nil || !strings.Contains(err.Error(), tc.expectError) {
					t.Errorf("want error containing %q, got %v", tc.expectError, err)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
		})
	}
}

// ─── TestUpdateProtoFieldNonLogin ─────────────────────────────────────────────

func TestUpdateProtoFieldNonLogin(t *testing.T) {
	noteItem := sdkpass.DecryptedItem{
		ShareID:  testShareID,
		ItemID:   testItemID,
		Revision: 1,
		Proto: &sdkproto.Item{
			Metadata: &sdkproto.Metadata{Name: "note item"},
			Content: &sdkproto.Content{
				Content: &sdkproto.Content_Note{Note: &sdkproto.ItemNote{}},
			},
		},
	}

	c := makeClientWithFake(&fakePassClient{})
	err := c.updateProtoField(context.Background(), &noteItem, "password", "value")
	if err == nil || !strings.Contains(err.Error(), "no login content") {
		t.Errorf("want error containing 'no login content', got %v", err)
	}
}

// ─── helpers ─────────────────────────────────────────────────────────────────

func strPtr(s string) *string { return &s }

func mapKeys(m map[string][]byte) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	return keys
}
