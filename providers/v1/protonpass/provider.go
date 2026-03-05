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

// Package protonpass implements a read/write secrets provider for Proton Pass.
//
// Authentication uses a dedicated Proton account (username + password) without
// two-factor authentication. Two-factor authentication is intentionally not
// supported because storing a TOTP seed in a Kubernetes Secret collapses 2FA to
// a single effective factor. Users should create a dedicated service account with
// 2FA disabled, following the same pattern used by the Barbican and SecretServer
// providers.
//
// Secret reference format:
//
//	<vault-name>/<item-name>/<field-name>
//
// Supported field names: username, password, email, url, note, totp,
// or the exact name of a custom field on the item.
package protonpass

import (
	"context"
	"fmt"

	sdkauth "github.com/mcanevet/proton-sdk-go/auth"
	sdkclient "github.com/mcanevet/proton-sdk-go/client"
	sdkpass "github.com/mcanevet/proton-sdk-go/pass"
	kclient "sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/webhook/admission"

	esv1 "github.com/external-secrets/external-secrets/apis/externalsecrets/v1"
	"github.com/external-secrets/external-secrets/runtime/esutils"
	"github.com/external-secrets/external-secrets/runtime/esutils/resolvers"
)

const (
	protonPassHostURL = "https://pass.proton.me/api"

	errInvalidStore    = "invalid store: %s"
	errProtonPassStore = "missing or invalid Proton Pass SecretStore"
)

// Provider is a stateless Proton Pass provider implementing esv1.Provider.
type Provider struct{}

// Compile-time interface checks.
var _ esv1.SecretsClient = &Client{}
var _ esv1.Provider = &Provider{}

// Capabilities returns ReadWrite — Proton Pass supports both read and write.
func (p *Provider) Capabilities() esv1.SecretStoreCapabilities {
	return esv1.SecretStoreReadWrite
}

// NewClient authenticates against Proton via SRP, unlocks the user PGP keyring,
// and returns a ready-to-use Client. When SessionSecretRef is configured, it
// attempts to resume a cached session before falling back to a full SRP login.
func (p *Provider) NewClient(ctx context.Context, store esv1.GenericStore, kube kclient.Client, namespace string) (esv1.SecretsClient, error) {
	storeSpec := store.GetSpec()
	if storeSpec == nil || storeSpec.Provider == nil || storeSpec.Provider.ProtonPass == nil {
		return nil, fmt.Errorf("%s", errProtonPassStore)
	}

	ppSpec := storeSpec.Provider.ProtonPass
	storeKind := store.GetObjectKind().GroupVersionKind().Kind

	username, err := resolvers.SecretKeyRef(ctx, kube, storeKind, namespace, &ppSpec.Auth.SecretRef.Username)
	if err != nil {
		return nil, fmt.Errorf("resolve username: %w", err)
	}

	password, err := resolvers.SecretKeyRef(ctx, kube, storeKind, namespace, &ppSpec.Auth.SecretRef.Password)
	if err != nil {
		return nil, fmt.Errorf("resolve password: %w", err)
	}

	// lrSession is captured by the OnRefresh closure to persist token rotations.
	var lrSession sdkauth.Session

	opts := []sdkclient.Option{
		sdkclient.WithBaseURL(protonPassHostURL),
		sdkclient.WithAppVersion("web-pass@5.0.0"),
	}
	if ppSpec.SessionSecretRef != nil {
		sessRef := ppSpec.SessionSecretRef
		opts = append(opts, sdkclient.WithOnRefresh(func(newAccess, newRefresh string) {
			updated := sdkauth.Session{
				UID:           lrSession.UID,
				SaltedKeyPass: lrSession.SaltedKeyPass,
				AccessToken:   newAccess,
				RefreshToken:  newRefresh,
			}
			_ = writeSession(context.Background(), kube, storeKind, namespace, sessRef, updated)
		}))
	}
	c := sdkclient.New(opts...)

	var lr sdkauth.LoginResult
	if ppSpec.SessionSecretRef != nil {
		if session, readErr := readSession(ctx, kube, storeKind, namespace, ppSpec.SessionSecretRef); readErr == nil {
			lr, _ = sdkauth.Resume(ctx, c, session)
		}
	}

	if lr.Session.UID == "" {
		lr, err = sdkauth.Login(ctx, c, username, []byte(password))
		if err != nil {
			return nil, fmt.Errorf("proton pass login: %w", err)
		}
	}

	lrSession = lr.Session
	if ppSpec.SessionSecretRef != nil {
		_ = writeSession(ctx, kube, storeKind, namespace, ppSpec.SessionSecretRef, lr.Session)
	}

	pc := sdkpass.NewClient(c, lr.UserKR, lr.AddrKR, lr.AddressID)
	return &Client{passClient: pc}, nil
}

// ValidateStore validates the Proton Pass SecretStore configuration.
func (p *Provider) ValidateStore(store esv1.GenericStore) (admission.Warnings, error) {
	storeSpec := store.GetSpec()
	if storeSpec == nil || storeSpec.Provider == nil || storeSpec.Provider.ProtonPass == nil {
		return nil, fmt.Errorf(errInvalidStore, "provider.protonpass is required")
	}

	ppSpec := storeSpec.Provider.ProtonPass
	if ppSpec.Auth.SecretRef == nil {
		return nil, fmt.Errorf(errInvalidStore, "auth.secretRef is required")
	}

	if err := esutils.ValidateSecretSelector(store, ppSpec.Auth.SecretRef.Username); err != nil {
		return nil, fmt.Errorf(errInvalidStore, fmt.Sprintf("auth.secretRef.username: %s", err))
	}
	if ppSpec.Auth.SecretRef.Username.Name == "" {
		return nil, fmt.Errorf(errInvalidStore, "auth.secretRef.username.name cannot be empty")
	}

	if err := esutils.ValidateSecretSelector(store, ppSpec.Auth.SecretRef.Password); err != nil {
		return nil, fmt.Errorf(errInvalidStore, fmt.Sprintf("auth.secretRef.password: %s", err))
	}
	if ppSpec.Auth.SecretRef.Password.Name == "" {
		return nil, fmt.Errorf(errInvalidStore, "auth.secretRef.password.name cannot be empty")
	}

	return nil, nil
}

// NewProvider returns a new Provider instance (called by the registration file).
func NewProvider() esv1.Provider {
	return &Provider{}
}

// ProviderSpec returns the provider spec used for registration.
func ProviderSpec() *esv1.SecretStoreProvider {
	return &esv1.SecretStoreProvider{
		ProtonPass: &esv1.ProtonPassProvider{},
	}
}

// MaintenanceStatus returns the provider maintenance status.
func MaintenanceStatus() esv1.MaintenanceStatus {
	return esv1.MaintenanceStatusMaintained
}
