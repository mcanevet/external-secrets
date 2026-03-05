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
	"fmt"
	"strings"

	sdkpass "github.com/mcanevet/proton-sdk-go/pass"
	sdkproto "github.com/mcanevet/proton-sdk-go/pass/proto"
	corev1 "k8s.io/api/core/v1"

	esv1 "github.com/external-secrets/external-secrets/apis/externalsecrets/v1"
	"github.com/external-secrets/external-secrets/runtime/find"
)

const (
	errGetSecret     = "could not get secret %q: %w"
	errGetSecretMap  = "could not get secret map %q: %w"
	errGetAllSecrets = "could not get all secrets: %w"
	errPushSecret    = "could not push secret %q: %w"
	errDeleteSecret  = "could not delete secret %q: %w"
)

// passClient is the interface used by Client to interact with the Proton Pass SDK.
// Defined as an interface to allow mocking in unit tests; the real implementation
// is *sdkpass.Client which satisfies it automatically.
type passClient interface {
	GetField(ctx context.Context, uri string) (string, error)
	FindItem(ctx context.Context, vaultName, itemTitle string) (*sdkpass.DecryptedItem, error)
	ListVaults(ctx context.Context) ([]sdkpass.Vault, error)
	ListItems(ctx context.Context, shareID string) ([]sdkpass.DecryptedItem, error)
	CreateItem(ctx context.Context, shareID string, content *sdkproto.Item) (string, error)
	UpdateItem(ctx context.Context, shareID, itemID string, revision int64, content *sdkproto.Item) error
	TrashItem(ctx context.Context, shareID, itemID string, revision int64) error
	DeleteItem(ctx context.Context, shareID, itemID string, revision int64) error
}

// Client implements esv1.SecretsClient for Proton Pass by delegating to the SDK.
type Client struct {
	passClient passClient
}

// Validate checks that the Pass API is reachable.
func (c *Client) Validate() (esv1.ValidationResult, error) {
	_, err := c.passClient.ListVaults(context.Background())
	if err != nil {
		return esv1.ValidationResultError, fmt.Errorf("proton pass validation: %w", err)
	}
	return esv1.ValidationResultReady, nil
}

// Close is a no-op for Proton Pass.
func (c *Client) Close(_ context.Context) error {
	return nil
}

// GetSecret retrieves a single field from a Proton Pass item.
// ref.Key must be in the format: <vault-name>/<item-name>/<field-name>
func (c *Client) GetSecret(ctx context.Context, ref esv1.ExternalSecretDataRemoteRef) ([]byte, error) {
	val, err := c.passClient.GetField(ctx, ref.Key)
	if err != nil {
		return nil, fmt.Errorf(errGetSecret, ref.Key, err)
	}
	return []byte(val), nil
}

// GetSecretMap retrieves all fields of a Proton Pass item as a map.
// ref.Key must be in the format: <vault-name>/<item-name>
func (c *Client) GetSecretMap(ctx context.Context, ref esv1.ExternalSecretDataRemoteRef) (map[string][]byte, error) {
	parts := strings.SplitN(ref.Key, "/", 3)
	if len(parts) < 2 || parts[0] == "" || parts[1] == "" {
		return nil, fmt.Errorf(errGetSecretMap, ref.Key, fmt.Errorf("key must be in format vault/item"))
	}
	vaultName, itemName := parts[0], parts[1]

	item, err := c.passClient.FindItem(ctx, vaultName, itemName)
	if err != nil {
		return nil, fmt.Errorf(errGetSecretMap, ref.Key, err)
	}
	if item == nil {
		return nil, fmt.Errorf(errGetSecretMap, ref.Key, fmt.Errorf("item %q not found in vault %q", itemName, vaultName))
	}

	fields := sdkpass.ItemToMap(item)
	result := make(map[string][]byte, len(fields))
	for k, v := range fields {
		result[k] = []byte(v)
	}
	return result, nil
}

// GetAllSecrets retrieves all active items from all vaults as a flat map.
// Keys are in the format: <vault-name>/<item-name>/<field-name>.
func (c *Client) GetAllSecrets(ctx context.Context, ref esv1.ExternalSecretFind) (map[string][]byte, error) {
	if ref.Tags != nil {
		return nil, fmt.Errorf(errGetAllSecrets, fmt.Errorf("tag filtering is not supported by the Proton Pass provider"))
	}

	var matcher *find.Matcher
	if ref.Name != nil {
		m, err := find.New(*ref.Name)
		if err != nil {
			return nil, fmt.Errorf(errGetAllSecrets, err)
		}
		matcher = m
	}

	vaults, err := c.passClient.ListVaults(ctx)
	if err != nil {
		return nil, fmt.Errorf(errGetAllSecrets, err)
	}

	result := make(map[string][]byte)
	for _, vault := range vaults {
		items, err := c.passClient.ListItems(ctx, vault.ID)
		if err != nil {
			return nil, fmt.Errorf(errGetAllSecrets, fmt.Errorf("list items for vault %q: %w", vault.Name, err))
		}

		for i := range items {
			item := &items[i]
			itemName := item.Proto.GetMetadata().GetName()
			if itemName == "" {
				itemName = item.ItemID
			}

			for field, val := range sdkpass.ItemToMap(item) {
				key := vault.Name + "/" + itemName + "/" + field
				if ref.Path != nil && !strings.HasPrefix(key, *ref.Path) {
					continue
				}
				if matcher != nil && !matcher.MatchName(key) {
					continue
				}
				result[key] = []byte(val)
			}
		}
	}
	return result, nil
}

// PushSecret creates or updates a Proton Pass login item.
// data.GetRemoteKey() must be in the format: <vault-name>/<item-name>
// The field identified by data.GetSecretKey() is set on the item.
func (c *Client) PushSecret(ctx context.Context, secret *corev1.Secret, data esv1.PushSecretData) error {
	remoteKey := data.GetRemoteKey()
	parts := strings.SplitN(remoteKey, "/", 2)
	if len(parts) != 2 || parts[0] == "" || parts[1] == "" {
		return fmt.Errorf(errPushSecret, remoteKey, fmt.Errorf("remote key must be in format vault/item"))
	}
	vaultName, itemName := parts[0], parts[1]
	fieldName := data.GetSecretKey()
	secretValue := string(secret.Data[fieldName])

	// List vaults to find the target vault ID.
	vaults, err := c.passClient.ListVaults(ctx)
	if err != nil {
		return fmt.Errorf(errPushSecret, remoteKey, err)
	}
	var targetVaultID string
	for _, v := range vaults {
		if v.Name == vaultName || v.ID == vaultName {
			targetVaultID = v.ID
			break
		}
	}
	if targetVaultID == "" {
		return fmt.Errorf(errPushSecret, remoteKey, fmt.Errorf("vault %q not found", vaultName))
	}

	// Look for an existing item with the same name.
	items, err := c.passClient.ListItems(ctx, targetVaultID)
	if err != nil {
		return fmt.Errorf(errPushSecret, remoteKey, err)
	}
	for i := range items {
		if items[i].Proto.GetMetadata().GetName() == itemName {
			if err := c.updateProtoField(ctx, &items[i], fieldName, secretValue); err != nil {
				return fmt.Errorf(errPushSecret, remoteKey, err)
			}
			return nil
		}
	}

	// Create a new login item.
	_, err = c.passClient.CreateItem(ctx, targetVaultID, buildLoginItem(itemName, fieldName, secretValue))
	if err != nil {
		return fmt.Errorf(errPushSecret, remoteKey, err)
	}
	return nil
}

// SecretExists returns true if a secret with the given remote ref exists.
func (c *Client) SecretExists(ctx context.Context, ref esv1.PushSecretRemoteRef) (bool, error) {
	parts := strings.SplitN(ref.GetRemoteKey(), "/", 2)
	if len(parts) != 2 || parts[0] == "" || parts[1] == "" {
		return false, fmt.Errorf("remote key must be in format vault/item, got %q", ref.GetRemoteKey())
	}

	item, err := c.passClient.FindItem(ctx, parts[0], parts[1])
	if err != nil {
		return false, fmt.Errorf("find item: %w", err)
	}
	return item != nil, nil
}

// DeleteSecret trashes and permanently deletes a Proton Pass item.
func (c *Client) DeleteSecret(ctx context.Context, ref esv1.PushSecretRemoteRef) error {
	parts := strings.SplitN(ref.GetRemoteKey(), "/", 2)
	if len(parts) != 2 || parts[0] == "" || parts[1] == "" {
		return fmt.Errorf(errDeleteSecret, ref.GetRemoteKey(), fmt.Errorf("remote key must be in format vault/item"))
	}

	item, err := c.passClient.FindItem(ctx, parts[0], parts[1])
	if err != nil {
		return fmt.Errorf(errDeleteSecret, ref.GetRemoteKey(), err)
	}
	if item == nil {
		return fmt.Errorf(errDeleteSecret, ref.GetRemoteKey(), fmt.Errorf("item not found"))
	}

	if err := c.passClient.TrashItem(ctx, item.ShareID, item.ItemID, item.Revision); err != nil {
		return fmt.Errorf(errDeleteSecret, ref.GetRemoteKey(), err)
	}
	if err := c.passClient.DeleteItem(ctx, item.ShareID, item.ItemID, item.Revision); err != nil {
		return fmt.Errorf(errDeleteSecret, ref.GetRemoteKey(), err)
	}
	return nil
}

// updateProtoField modifies a single field on an existing login item and calls UpdateItem.
func (c *Client) updateProtoField(ctx context.Context, item *sdkpass.DecryptedItem, fieldName, value string) error {
	p := item.Proto
	login := p.GetContent().GetLogin()
	if login == nil {
		return fmt.Errorf("item has no login content")
	}

	switch strings.ToLower(fieldName) {
	case "password":
		login.Password = value
	case "username":
		login.ItemUsername = value
	case "email":
		login.ItemEmail = value
	case "url":
		if len(login.Urls) > 0 {
			login.Urls[0] = value
		} else {
			login.Urls = []string{value}
		}
	case "note":
		if p.Metadata != nil {
			p.Metadata.Note = value
		}
	case "totp":
		login.TotpUri = value
	default:
		found := false
		for _, ef := range p.ExtraFields {
			if ef.GetFieldName() == fieldName {
				switch f := ef.Content.(type) {
				case *sdkproto.ExtraField_Text:
					f.Text.Content = value
				case *sdkproto.ExtraField_Hidden:
					f.Hidden.Content = value
				}
				found = true
				break
			}
		}
		if !found {
			p.ExtraFields = append(p.ExtraFields, &sdkproto.ExtraField{
				FieldName: fieldName,
				Content:   &sdkproto.ExtraField_Hidden{Hidden: &sdkproto.ExtraHiddenField{Content: value}},
			})
		}
	}

	return c.passClient.UpdateItem(ctx, item.ShareID, item.ItemID, item.Revision, p)
}

// buildLoginItem constructs a new proto login item with a single field set.
func buildLoginItem(name, fieldName, value string) *sdkproto.Item {
	login := &sdkproto.ItemLogin{}
	item := &sdkproto.Item{
		Metadata: &sdkproto.Metadata{Name: name},
		Content: &sdkproto.Content{
			Content: &sdkproto.Content_Login{Login: login},
		},
	}

	switch strings.ToLower(fieldName) {
	case "password":
		login.Password = value
	case "username":
		login.ItemUsername = value
	case "email":
		login.ItemEmail = value
	case "url":
		login.Urls = []string{value}
	case "note":
		item.Metadata.Note = value
	case "totp":
		login.TotpUri = value
	default:
		item.ExtraFields = []*sdkproto.ExtraField{{
			FieldName: fieldName,
			Content:   &sdkproto.ExtraField_Hidden{Hidden: &sdkproto.ExtraHiddenField{Content: value}},
		}}
	}
	return item
}
