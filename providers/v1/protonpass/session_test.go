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
	"testing"

	sdkauth "github.com/mcanevet/proton-sdk-go/auth"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	esmeta "github.com/external-secrets/external-secrets/apis/meta/v1"
)

const (
	testSessionName = "proton-session"
	testSessionKey  = "session.json"
	testNamespace   = "default"
)

func makeSessionRef() *esmeta.SecretKeySelector {
	return &esmeta.SecretKeySelector{
		Name: testSessionName,
		Key:  testSessionKey,
	}
}

func marshalSession(t *testing.T, s sdkauth.Session) []byte {
	t.Helper()
	data, err := json.Marshal(s)
	if err != nil {
		t.Fatalf("marshal session: %v", err)
	}
	return data
}

// ─── readSession ─────────────────────────────────────────────────────────────

func TestReadSession(t *testing.T) {
	session := sdkauth.Session{
		UID:          "test-uid",
		AccessToken:  "test-access",
		RefreshToken: "test-refresh",
	}
	secret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      testSessionName,
			Namespace: testNamespace,
		},
		Data: map[string][]byte{
			testSessionKey: marshalSession(t, session),
		},
	}

	kube := fake.NewClientBuilder().WithObjects(secret).Build()
	got, err := readSession(context.Background(), kube, "SecretStore", testNamespace, makeSessionRef())
	if err != nil {
		t.Fatalf("readSession: %v", err)
	}
	if got.UID != session.UID {
		t.Errorf("UID: got %q, want %q", got.UID, session.UID)
	}
	if got.AccessToken != session.AccessToken {
		t.Errorf("AccessToken: got %q, want %q", got.AccessToken, session.AccessToken)
	}
}

func TestReadSessionSecretNotFound(t *testing.T) {
	kube := fake.NewClientBuilder().Build()
	_, err := readSession(context.Background(), kube, "SecretStore", testNamespace, makeSessionRef())
	if err == nil {
		t.Error("expected error when secret does not exist, got nil")
	}
}

func TestReadSessionKeyMissing(t *testing.T) {
	secret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      testSessionName,
			Namespace: testNamespace,
		},
		Data: map[string][]byte{
			"other-key": []byte("data"),
		},
	}
	kube := fake.NewClientBuilder().WithObjects(secret).Build()
	_, err := readSession(context.Background(), kube, "SecretStore", testNamespace, makeSessionRef())
	if err == nil {
		t.Error("expected error when key is missing, got nil")
	}
}

// ─── writeSession ─────────────────────────────────────────────────────────────

func TestWriteSessionCreate(t *testing.T) {
	kube := fake.NewClientBuilder().Build()
	session := sdkauth.Session{
		UID:          "new-uid",
		AccessToken:  "new-access",
		RefreshToken: "new-refresh",
	}

	err := writeSession(context.Background(), kube, "SecretStore", testNamespace, makeSessionRef(), session)
	if err != nil {
		t.Fatalf("writeSession (create): %v", err)
	}

	got, err := readSession(context.Background(), kube, "SecretStore", testNamespace, makeSessionRef())
	if err != nil {
		t.Fatalf("readSession after write: %v", err)
	}
	if got.UID != session.UID {
		t.Errorf("UID after create: got %q, want %q", got.UID, session.UID)
	}
}

func TestWriteSessionUpdate(t *testing.T) {
	initial := sdkauth.Session{
		UID:          "old-uid",
		AccessToken:  "old-access",
		RefreshToken: "old-refresh",
	}
	secret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      testSessionName,
			Namespace: testNamespace,
		},
		Data: map[string][]byte{
			testSessionKey: marshalSession(t, initial),
		},
	}
	kube := fake.NewClientBuilder().WithObjects(secret).Build()

	updated := sdkauth.Session{
		UID:          "old-uid",
		AccessToken:  "new-access-token",
		RefreshToken: "new-refresh-token",
	}
	err := writeSession(context.Background(), kube, "SecretStore", testNamespace, makeSessionRef(), updated)
	if err != nil {
		t.Fatalf("writeSession (update): %v", err)
	}

	got, err := readSession(context.Background(), kube, "SecretStore", testNamespace, makeSessionRef())
	if err != nil {
		t.Fatalf("readSession after update: %v", err)
	}
	if got.AccessToken != updated.AccessToken {
		t.Errorf("AccessToken: got %q, want %q", got.AccessToken, updated.AccessToken)
	}
}

// ─── sessionNamespace ─────────────────────────────────────────────────────────

func TestSessionNamespace(t *testing.T) {
	cases := []struct {
		label      string
		storeKind  string
		storeNS    string
		ref        *esmeta.SecretKeySelector
		expectNS   string
	}{
		{
			label:     "SecretStore uses store namespace",
			storeKind: "SecretStore",
			storeNS:   "my-ns",
			ref:       &esmeta.SecretKeySelector{Name: "s"},
			expectNS:  "my-ns",
		},
		{
			label:     "ref namespace overrides store namespace",
			storeKind: "ClusterSecretStore",
			storeNS:   "cluster-ns",
			ref: &esmeta.SecretKeySelector{
				Name:      "s",
				Namespace: strPtr("target-ns"),
			},
			expectNS: "target-ns",
		},
		{
			label:     "nil ref namespace falls back to store namespace",
			storeKind: "ClusterSecretStore",
			storeNS:   "default",
			ref:       &esmeta.SecretKeySelector{Name: "s"},
			expectNS:  "default",
		},
	}

	for _, tc := range cases {
		t.Run(tc.label, func(t *testing.T) {
			got := sessionNamespace(tc.storeKind, tc.storeNS, tc.ref)
			if got != tc.expectNS {
				t.Errorf("got %q, want %q", got, tc.expectNS)
			}
		})
	}
}
