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
	"errors"
	"testing"

	esv1 "github.com/external-secrets/external-secrets/apis/externalsecrets/v1"
	v1 "github.com/external-secrets/external-secrets/apis/meta/v1"
)

type storeModifier func(*esv1.SecretStore) *esv1.SecretStore

func makeSecretStore(fns ...storeModifier) *esv1.SecretStore {
	store := &esv1.SecretStore{
		Spec: esv1.SecretStoreSpec{
			Provider: &esv1.SecretStoreProvider{
				ProtonPass: &esv1.ProtonPassProvider{
					Auth: esv1.ProtonPassAuth{
						SecretRef: &esv1.ProtonPassSecretRef{},
					},
				},
			},
		},
	}
	for _, fn := range fns {
		store = fn(store)
	}
	return store
}

func withUsernameRef(name, key string, namespace *string) storeModifier {
	return func(store *esv1.SecretStore) *esv1.SecretStore {
		store.Spec.Provider.ProtonPass.Auth.SecretRef.Username = v1.SecretKeySelector{
			Name:      name,
			Key:       key,
			Namespace: namespace,
		}
		return store
	}
}

func withPasswordRef(name, key string, namespace *string) storeModifier {
	return func(store *esv1.SecretStore) *esv1.SecretStore {
		store.Spec.Provider.ProtonPass.Auth.SecretRef.Password = v1.SecretKeySelector{
			Name:      name,
			Key:       key,
			Namespace: namespace,
		}
		return store
	}
}

type ValidateStoreTestCase struct {
	label string
	store *esv1.SecretStore
	err   error
}

func TestValidateStore(t *testing.T) {
	ns := "test-ns"
	secretName := "proton-credentials"

	testCases := []ValidateStoreTestCase{
		{
			label: "valid store",
			store: makeSecretStore(
				withUsernameRef(secretName, "username", nil),
				withPasswordRef(secretName, "password", nil),
			),
			err: nil,
		},
		{
			label: "missing username.name",
			store: makeSecretStore(
				withUsernameRef("", "username", nil),
				withPasswordRef(secretName, "password", nil),
			),
			err: errors.New("invalid store: auth.secretRef.username.name cannot be empty"),
		},
		{
			label: "missing password.name",
			store: makeSecretStore(
				withUsernameRef(secretName, "username", nil),
				withPasswordRef("", "password", nil),
			),
			err: errors.New("invalid store: auth.secretRef.password.name cannot be empty"),
		},
		{
			label: "username namespace not allowed on namespaced store",
			store: makeSecretStore(
				withUsernameRef(secretName, "username", &ns),
				withPasswordRef(secretName, "password", nil),
			),
			err: errors.New("invalid store: auth.secretRef.username: namespace should either be empty or match the namespace of the SecretStore for a namespaced SecretStore"),
		},
		{
			label: "password namespace not allowed on namespaced store",
			store: makeSecretStore(
				withUsernameRef(secretName, "username", nil),
				withPasswordRef(secretName, "password", &ns),
			),
			err: errors.New("invalid store: auth.secretRef.password: namespace should either be empty or match the namespace of the SecretStore for a namespaced SecretStore"),
		},
		{
			label: "missing secretRef",
			store: &esv1.SecretStore{
				Spec: esv1.SecretStoreSpec{
					Provider: &esv1.SecretStoreProvider{
						ProtonPass: &esv1.ProtonPassProvider{
							Auth: esv1.ProtonPassAuth{},
						},
					},
				},
			},
			err: errors.New("invalid store: auth.secretRef is required"),
		},
		{
			label: "missing protonpass provider",
			store: &esv1.SecretStore{
				Spec: esv1.SecretStoreSpec{
					Provider: &esv1.SecretStoreProvider{},
				},
			},
			err: errors.New("invalid store: provider.protonpass is required"),
		},
	}

	p := Provider{}
	for _, tc := range testCases {
		t.Run(tc.label, func(t *testing.T) {
			_, err := p.ValidateStore(tc.store)
			if tc.err != nil && err != nil && err.Error() != tc.err.Error() {
				t.Errorf("want error %q, got %q", tc.err, err)
			} else if tc.err == nil && err != nil {
				t.Errorf("want nil error, got %q", err)
			} else if tc.err != nil && err == nil {
				t.Errorf("want error %q, got nil", tc.err)
			}
		})
	}
}
