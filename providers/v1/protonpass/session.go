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
	"encoding/json"
	"fmt"

	sdkauth "github.com/mcanevet/proton-sdk-go/auth"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	kclient "sigs.k8s.io/controller-runtime/pkg/client"

	esmeta "github.com/external-secrets/external-secrets/apis/meta/v1"
)

// sessionNamespace returns the effective namespace for the session Secret.
// For ClusterSecretStore, the ref may specify its own namespace. For namespaced
// SecretStore, the store's namespace is always used.
func sessionNamespace(storeKind, storeNamespace string, ref *esmeta.SecretKeySelector) string {
	if ref.Namespace != nil && *ref.Namespace != "" {
		return *ref.Namespace
	}
	return storeNamespace
}

// readSession reads a serialized auth.Session from a Kubernetes Secret.
// Returns an error if the Secret or the key within it does not exist, or if
// the stored JSON cannot be decoded.
func readSession(ctx context.Context, kube kclient.Client, storeKind, namespace string, ref *esmeta.SecretKeySelector) (sdkauth.Session, error) {
	ns := sessionNamespace(storeKind, namespace, ref)
	var secret corev1.Secret
	if err := kube.Get(ctx, types.NamespacedName{Name: ref.Name, Namespace: ns}, &secret); err != nil {
		return sdkauth.Session{}, fmt.Errorf("get session secret: %w", err)
	}
	data, ok := secret.Data[ref.Key]
	if !ok {
		return sdkauth.Session{}, fmt.Errorf("key %q not found in session secret %s/%s", ref.Key, ns, ref.Name)
	}
	var s sdkauth.Session
	if err := json.Unmarshal(data, &s); err != nil {
		return sdkauth.Session{}, fmt.Errorf("unmarshal session: %w", err)
	}
	return s, nil
}

// writeSession persists a serialized auth.Session to a Kubernetes Secret.
// If the Secret does not exist it is created. If it already exists, only the
// session key is patched using optimistic locking (MergeFrom) so that concurrent
// reconcilers do not clobber each other's writes.
func writeSession(ctx context.Context, kube kclient.Client, storeKind, namespace string, ref *esmeta.SecretKeySelector, session sdkauth.Session) error {
	data, err := json.Marshal(session)
	if err != nil {
		return fmt.Errorf("marshal session: %w", err)
	}

	ns := sessionNamespace(storeKind, namespace, ref)
	var existing corev1.Secret
	if err := kube.Get(ctx, types.NamespacedName{Name: ref.Name, Namespace: ns}, &existing); err != nil {
		if !apierrors.IsNotFound(err) {
			return fmt.Errorf("get session secret for write: %w", err)
		}
		created := corev1.Secret{
			ObjectMeta: metav1.ObjectMeta{
				Name:      ref.Name,
				Namespace: ns,
			},
			Data: map[string][]byte{ref.Key: data},
		}
		return kube.Create(ctx, &created)
	}

	base := existing.DeepCopy()
	if existing.Data == nil {
		existing.Data = make(map[string][]byte)
	}
	existing.Data[ref.Key] = data
	return kube.Patch(ctx, &existing, kclient.MergeFrom(base))
}
