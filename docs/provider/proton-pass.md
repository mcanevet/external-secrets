# Proton Pass

Sync secrets from [Proton Pass](https://proton.me/pass) to Kubernetes using the External Secrets Operator.

## Authentication

Proton Pass uses username/password authentication via SRP (Secure Remote Password). You must use a dedicated Proton account with 2FA disabled.

> **NOTE:** Two-factor authentication is intentionally not supported because storing a TOTP seed in a Kubernetes Secret collapses 2FA to a single effective factor.

### Creating a Service Account

1. Create a new Proton account at [proton.me/pass](https://proton.me/pass)
2. Disable two-factor authentication in Account Settings → Security
3. Create a vault (or use the default "Personal" vault)

### Storing Credentials

Create a Kubernetes Secret containing your Proton credentials:

```yaml
apiVersion: v1
kind: Secret
metadata:
  name: proton-pass-credentials
  namespace: external-secrets
type: Opaque
stringData:
  username: your-email@example.com
  password: your-password
```

## Creating a SecretStore

```yaml
apiVersion: external-secrets.io/v1
kind: SecretStore
metadata:
  name: proton-pass-store
  namespace: external-secrets
spec:
  provider:
    protonpass:
      auth:
        secretRef:
          username:
            name: proton-pass-credentials
            key: username
          password:
            name: proton-pass-credentials
            key: password
```

For a cluster-wide `ClusterSecretStore`, add a `namespace` field to each `secretRef` to specify where the credentials Secret lives:

```yaml
apiVersion: external-secrets.io/v1
kind: ClusterSecretStore
metadata:
  name: proton-pass-store
spec:
  provider:
    protonpass:
      auth:
        secretRef:
          username:
            name: proton-pass-credentials
            key: username
            namespace: external-secrets
          password:
            name: proton-pass-credentials
            key: password
            namespace: external-secrets
```

## Session Caching

By default, the provider performs a full SRP login on every Kubernetes reconcile (~2 seconds per reconcile, counts toward Proton's API rate limits).

To avoid this, configure `sessionSecretRef` to cache the session in a Kubernetes Secret. The provider resumes the cached session on each reconcile and falls back to a full login only if the session has expired.

```yaml
apiVersion: external-secrets.io/v1
kind: SecretStore
metadata:
  name: proton-pass-store
  namespace: external-secrets
spec:
  provider:
    protonpass:
      auth:
        secretRef:
          username:
            name: proton-pass-credentials
            key: username
          password:
            name: proton-pass-credentials
            key: password
      sessionSecretRef:
        name: proton-pass-session
        key: session.json
```

The session Secret is created automatically on first login and updated automatically when tokens are rotated. The ESO controller's service account must have `get`, `create`, and `patch` RBAC on it:

```yaml
apiVersion: rbac.authorization.k8s.io/v1
kind: Role
metadata:
  name: proton-pass-session
  namespace: external-secrets
rules:
  - apiGroups: [""]
    resources: ["secrets"]
    resourceNames: ["proton-pass-session"]
    verbs: ["get", "create", "patch"]
---
apiVersion: rbac.authorization.k8s.io/v1
kind: RoleBinding
metadata:
  name: proton-pass-session
  namespace: external-secrets
subjects:
  - kind: ServiceAccount
    name: external-secrets
    namespace: external-secrets
roleRef:
  kind: Role
  name: proton-pass-session
  apiGroup: rbac.authorization.k8s.io
```

## Secret Reference Format

Proton Pass secrets are referenced using the format:

```
<vault-name>/<item-name>/<field-name>
```

### Supported Field Names

All item types expose their fields as a flat map. The available field names depend on the item type:

| Item type   | Fields |
|-------------|--------|
| Login       | `username`, `password`, `email`, `url`, `note`, `totp` |
| Note        | `note` |
| Credit card | `cardholder_name`, `number`, `verification_number`, `expiration_date`, `pin` |
| Identity    | `full_name`, `email`, `phone_number`, `first_name`, `last_name` |
| SSH key     | `private_key`, `public_key` |
| Wi-Fi       | `ssid`, `password` |
| Custom      | Any custom field name (text, hidden, TOTP, or timestamp) |

## Use Cases

### 1. Fetch a Single Field

```yaml
apiVersion: external-secrets.io/v1
kind: ExternalSecret
metadata:
  name: proton-pass-example
  namespace: external-secrets
spec:
  refreshInterval: 1h
  secretStoreRef:
    name: proton-pass-store
    kind: SecretStore
  target:
    name: k8s-secret-name
  data:
    - secretKey: password
      remoteRef:
        key: Personal/my-login/password
```

### 2. Fetch All Fields from an Item

Use the `vault/item` format (without a field name) with `dataFrom.extract`:

```yaml
apiVersion: external-secrets.io/v1
kind: ExternalSecret
metadata:
  name: proton-pass-item
  namespace: external-secrets
spec:
  refreshInterval: 1h
  secretStoreRef:
    name: proton-pass-store
    kind: SecretStore
  target:
    name: k8s-secret-name
  dataFrom:
    - extract:
        key: Personal/my-login
```

### 3. Fetch All Secrets from a Vault

```yaml
apiVersion: external-secrets.io/v1
kind: ExternalSecret
metadata:
  name: proton-pass-all
  namespace: external-secrets
spec:
  refreshInterval: 1h
  secretStoreRef:
    name: proton-pass-store
    kind: SecretStore
  target:
    name: k8s-secret-name
  dataFrom:
    - find:
        path: Personal
```

Keys in the resulting Secret follow the format `Personal/<item-name>/<field-name>`.

### 4. Push a Secret

`PushSecret` creates a new login item if one does not exist, or updates the specified field on an existing item with the same name.

```yaml
apiVersion: external-secrets.io/v1alpha1
kind: PushSecret
metadata:
  name: proton-pass-push
  namespace: external-secrets
spec:
  refreshInterval: 1h
  secretStoreRefs:
    - name: proton-pass-store
      kind: SecretStore
  selector:
    secret:
      name: k8s-source-secret
  data:
    - match:
        secretKey: password
        remoteRef:
          remoteKey: Personal/my-new-login
```

The `secretKey` value (`password` here) determines which field on the Proton Pass item is written. Any field name from the login table above is valid.

### 5. Delete a Remote Secret

Set `deletionPolicy: Delete` so that when the `PushSecret` CR is deleted, the corresponding Proton Pass item is permanently removed.

```yaml
apiVersion: external-secrets.io/v1alpha1
kind: PushSecret
metadata:
  name: proton-pass-cleanup
  namespace: external-secrets
spec:
  deletionPolicy: Delete
  secretStoreRefs:
    - name: proton-pass-store
      kind: SecretStore
  selector:
    secret:
      name: k8s-source-secret
  data:
    - match:
        secretKey: password
        remoteRef:
          remoteKey: Personal/obsolete-login
```

Delete the `PushSecret` CR to trigger the remote item deletion:

```bash
kubectl delete pushsecret proton-pass-cleanup -n external-secrets
```

## Troubleshooting

### Rate limits

Proton enforces API rate limits. If you see `429 Too Many Requests` errors:

- Enable session caching via `sessionSecretRef` to avoid a full SRP login on every reconcile
- Increase the `refreshInterval` on your ExternalSecrets (e.g. `1h` instead of `15m`)

### 2FA accounts

The provider refuses to authenticate against accounts with 2FA enabled. Create a dedicated service account with 2FA disabled.

### Session expired

Cached sessions expire after roughly 30 days of inactivity. The provider automatically falls back to a full login and writes a fresh session to the cache Secret.

## Limitations

- Only login items support field-level writes via `PushSecret`
- Vault lookup is by name only (vault IDs are not supported in secret references)
