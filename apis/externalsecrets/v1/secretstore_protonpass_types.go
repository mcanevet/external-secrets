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

package v1

import (
	esmeta "github.com/external-secrets/external-secrets/apis/meta/v1"
)

// ProtonPassAuth contains references to Kubernetes Secrets holding Proton Pass credentials.
type ProtonPassAuth struct {
	// SecretRef holds references to Secrets containing the Proton account credentials.
	SecretRef *ProtonPassSecretRef `json:"secretRef"`
}

// ProtonPassSecretRef holds Secret key selectors for Proton Pass authentication.
type ProtonPassSecretRef struct {
	// Username is a reference to the Kubernetes Secret key that contains
	// the Proton account username (email address).
	Username esmeta.SecretKeySelector `json:"username"`

	// Password is a reference to the Kubernetes Secret key that contains
	// the Proton account password.
	Password esmeta.SecretKeySelector `json:"password"`
}

// ProtonPassProvider configures a store to sync secrets using the Proton Pass provider.
type ProtonPassProvider struct {
	// Auth contains references to Kubernetes Secrets holding Proton account credentials
	// (username and password). The provider will authenticate via Proton's SRP protocol
	// and decrypt vault contents client-side.
	Auth ProtonPassAuth `json:"auth"`

	// SessionSecretRef is an optional reference to a Kubernetes Secret that caches the
	// serialized Proton session (UID, tokens, salted key passphrase). When set, the
	// provider will attempt to resume an existing session from this Secret on each
	// reconcile instead of performing a full SRP login. After a successful login or
	// resume the session is written back automatically. Token rotations are also
	// persisted via the OnRefresh callback.
	// +optional
	SessionSecretRef *esmeta.SecretKeySelector `json:"sessionSecretRef,omitempty"`
}
