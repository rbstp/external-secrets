/*
Copyright © The ESO Authors

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

package dvls

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/Devolutions/go-dvls"
	"github.com/google/uuid"
	corev1 "k8s.io/api/core/v1"

	esv1 "github.com/external-secrets/external-secrets/apis/externalsecrets/v1"
)

const errFailedToGetEntry = "failed to get entry: %w"

var errNotImplemented = errors.New("not implemented")

var _ esv1.SecretsClient = &Client{}

// Client implements the SecretsClient interface for DVLS.
// The nameCache avoids repeated GetEntries calls when the same
// entry name is referenced more than once during a single reconciliation.
type Client struct {
	cred      credentialClient
	vaultID   string
	nameCache map[string]string
}

type credentialClient interface {
	GetByID(ctx context.Context, vaultID, entryID string) (dvls.Entry, error)
	GetEntries(ctx context.Context, vaultID string, opts dvls.GetEntriesOptions) ([]dvls.Entry, error)
	Update(ctx context.Context, entry dvls.Entry) (dvls.Entry, error)
	DeleteByID(ctx context.Context, vaultID, entryID string) error
}

type vaultNameGetter interface {
	GetByName(ctx context.Context, name string) (dvls.Vault, error)
}

type realCredentialClient struct {
	cred *dvls.EntryCredentialService
}

func (r *realCredentialClient) GetByID(ctx context.Context, vaultID, entryID string) (dvls.Entry, error) {
	return r.cred.GetByIdWithContext(ctx, vaultID, entryID)
}

func (r *realCredentialClient) GetEntries(ctx context.Context, vaultID string, opts dvls.GetEntriesOptions) ([]dvls.Entry, error) {
	return r.cred.GetEntriesWithContext(ctx, vaultID, opts)
}

func (r *realCredentialClient) Update(ctx context.Context, entry dvls.Entry) (dvls.Entry, error) {
	return r.cred.UpdateWithContext(ctx, entry)
}

func (r *realCredentialClient) DeleteByID(ctx context.Context, vaultID, entryID string) error {
	return r.cred.DeleteByIdWithContext(ctx, vaultID, entryID)
}

// NewClient creates a new DVLS secrets client.
func NewClient(cred credentialClient, vaultID string) *Client {
	return &Client{cred: cred, vaultID: vaultID, nameCache: make(map[string]string)}
}

// GetSecret retrieves a secret from DVLS.
func (c *Client) GetSecret(ctx context.Context, ref esv1.ExternalSecretDataRemoteRef) ([]byte, error) {
	entryID, err := c.resolveEntryRef(ctx, ref.Key)
	if isNotFoundError(err) {
		return nil, esv1.NoSecretErr
	}
	if err != nil {
		return nil, err
	}

	entry, err := c.cred.GetByID(ctx, c.vaultID, entryID)
	if isNotFoundError(err) {
		return nil, esv1.NoSecretErr
	}
	if err != nil {
		return nil, fmt.Errorf(errFailedToGetEntry, err)
	}

	secretMap, err := entryToSecretMap(entry)
	if err != nil {
		return nil, err
	}

	// Default to "password" when no property specified (consistent with 1Password provider).
	property := ref.Property
	if property == "" {
		property = "password"
	}

	value, ok := secretMap[property]
	if !ok {
		return nil, fmt.Errorf("property %q not found in entry", property)
	}
	return value, nil
}

// GetSecretMap retrieves all fields from a DVLS entry.
func (c *Client) GetSecretMap(ctx context.Context, ref esv1.ExternalSecretDataRemoteRef) (map[string][]byte, error) {
	entryID, err := c.resolveEntryRef(ctx, ref.Key)
	if isNotFoundError(err) {
		return nil, esv1.NoSecretErr
	}
	if err != nil {
		return nil, err
	}

	entry, err := c.cred.GetByID(ctx, c.vaultID, entryID)
	if isNotFoundError(err) {
		return nil, esv1.NoSecretErr
	}
	if err != nil {
		return nil, fmt.Errorf(errFailedToGetEntry, err)
	}

	return entryToSecretMap(entry)
}

// GetAllSecrets is not implemented for DVLS.
func (c *Client) GetAllSecrets(_ context.Context, _ esv1.ExternalSecretFind) (map[string][]byte, error) {
	return nil, errNotImplemented
}

// PushSecret updates an existing entry's password field.
func (c *Client) PushSecret(ctx context.Context, secret *corev1.Secret, data esv1.PushSecretData) error {
	if secret == nil {
		return errors.New("secret is required for DVLS push")
	}
	entryID, err := c.resolveEntryRef(ctx, data.GetRemoteKey())
	if isNotFoundError(err) {
		return fmt.Errorf("entry %s not found in vault %s: entry must exist before pushing secrets", data.GetRemoteKey(), c.vaultID)
	}
	if err != nil {
		return err
	}

	value, err := extractPushValue(secret, data)
	if err != nil {
		return err
	}

	existingEntry, err := c.cred.GetByID(ctx, c.vaultID, entryID)
	if isNotFoundError(err) {
		return fmt.Errorf("entry %s not found in vault %s: entry must exist before pushing secrets", entryID, c.vaultID)
	}
	if err != nil {
		return fmt.Errorf(errFailedToGetEntry, err)
	}

	// SetCredentialSecret only updates the password/secret field.
	if err := existingEntry.SetCredentialSecret(string(value)); err != nil {
		return err
	}

	_, err = c.cred.Update(ctx, existingEntry)
	if err != nil {
		return fmt.Errorf("failed to update entry: %w", err)
	}
	return nil
}

// DeleteSecret deletes a secret from DVLS.
func (c *Client) DeleteSecret(ctx context.Context, ref esv1.PushSecretRemoteRef) error {
	entryID, err := c.resolveEntryRef(ctx, ref.GetRemoteKey())
	if isNotFoundError(err) {
		return nil
	}
	if err != nil {
		return err
	}
	if err := c.cred.DeleteByID(ctx, c.vaultID, entryID); err != nil {
		if isNotFoundError(err) {
			return nil
		}
		return fmt.Errorf("failed to delete entry %q from vault %q: %w", entryID, c.vaultID, err)
	}
	return nil
}

// SecretExists checks if a secret exists in DVLS.
func (c *Client) SecretExists(ctx context.Context, ref esv1.PushSecretRemoteRef) (bool, error) {
	entryID, err := c.resolveEntryRef(ctx, ref.GetRemoteKey())
	if isNotFoundError(err) {
		return false, nil
	}
	if err != nil {
		return false, err
	}

	_, err = c.cred.GetByID(ctx, c.vaultID, entryID)
	if isNotFoundError(err) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	return true, nil
}

// Validate checks if the client is properly configured.
func (c *Client) Validate() (esv1.ValidationResult, error) {
	if c.cred == nil {
		return esv1.ValidationResultError, errors.New("DVLS client is not initialized")
	}
	if c.vaultID == "" {
		return esv1.ValidationResultError, errors.New("DVLS vault ID is not set")
	}
	return esv1.ValidationResultReady, nil
}

// Close is a no-op for the DVLS client.
func (c *Client) Close(_ context.Context) error {
	return nil
}

// resolveEntryRef resolves an entry reference to a UUID.
// The key can be:
//   - A UUID: used directly.
//   - A name: looked up via GetEntries.
//   - A path/name: "folder/subfolder/entry-name" — path is used to filter.
func (c *Client) resolveEntryRef(ctx context.Context, key string) (entryID string, err error) {
	key = strings.TrimSpace(key)
	if key == "" {
		return "", errors.New("entry reference cannot be empty")
	}

	// UUID passes through directly.
	if isUUID(key) {
		return key, nil
	}

	// Return cached result if available.
	if id, ok := c.nameCache[key]; ok {
		return id, nil
	}

	// Split into optional path + entry name.
	entryName, entryPath := parseEntryRef(key)
	if entryName == "" {
		return "", errors.New("entry name cannot be empty")
	}

	opts := dvls.GetEntriesOptions{Name: &entryName}
	if entryPath != "" {
		opts.Path = &entryPath
	}

	entries, err := c.cred.GetEntries(ctx, c.vaultID, opts)
	if err != nil {
		return "", fmt.Errorf("failed to resolve entry %q: %w", key, err)
	}

	switch len(entries) {
	case 0:
		return "", fmt.Errorf("entry %q not found in vault: %w", key, dvls.ErrEntryNotFound)
	case 1:
		c.nameCache[key] = entries[0].Id
		return entries[0].Id, nil
	default:
		return "", fmt.Errorf("found %d credential entries named %q; use the entry UUID or add a folder path for disambiguation", len(entries), entryName)
	}
}

// resolveVaultRef resolves a vault reference (name or UUID) to a vault UUID.
func resolveVaultRef(ctx context.Context, vaultRef string, vc vaultNameGetter) (string, error) {
	if isUUID(vaultRef) {
		return vaultRef, nil
	}
	vault, err := vc.GetByName(ctx, vaultRef)
	if err != nil {
		return "", fmt.Errorf("failed to resolve vault %q: %w", vaultRef, err)
	}
	return vault.Id, nil
}

// parseEntryRef splits an entry reference into name and optional path.
// Both forward slashes and backslashes are accepted as path separators.
// The last separator splits the path from the entry name.
// Paths are normalized to backslashes to match the DVLS path format.
// e.g. "folder/subfolder/my-entry" → name="my-entry", path="folder\subfolder".
// e.g. "folder\subfolder\my-entry" → name="my-entry", path="folder\subfolder".
func parseEntryRef(ref string) (name, path string) {
	// Normalize forward slashes to backslashes.
	normalized := strings.ReplaceAll(ref, "/", `\`)
	if idx := strings.LastIndex(normalized, `\`); idx >= 0 {
		return normalized[idx+1:], normalized[:idx]
	}
	return ref, ""
}

// isUUID returns true if the string is a valid UUID.
func isUUID(s string) bool {
	_, err := uuid.Parse(s)
	return err == nil
}

// entryToSecretMap converts a DVLS entry to a map of secret values.
func entryToSecretMap(entry dvls.Entry) (map[string][]byte, error) {
	secretMap, err := entry.ToCredentialMap()
	if err != nil {
		return nil, err
	}

	result := make(map[string][]byte, len(secretMap))
	for k, v := range secretMap {
		result[k] = []byte(v)
	}

	return result, nil
}

func extractPushValue(secret *corev1.Secret, data esv1.PushSecretData) ([]byte, error) {
	if data.GetSecretKey() == "" {
		return nil, fmt.Errorf("secretKey is required for DVLS push")
	}

	if secret.Data == nil {
		return nil, fmt.Errorf("secret %q has no data", secret.Name)
	}

	value, ok := secret.Data[data.GetSecretKey()]
	if !ok {
		return nil, fmt.Errorf("key %q not found in secret %q", data.GetSecretKey(), secret.Name)
	}

	if len(value) == 0 {
		return nil, fmt.Errorf("key %q in secret %q is empty", data.GetSecretKey(), secret.Name)
	}

	return value, nil
}

func isNotFoundError(err error) bool {
	if err == nil {
		return false
	}

	if errors.Is(err, dvls.ErrVaultNotFound) {
		return false
	}

	if dvls.IsNotFound(err) {
		return true
	}

	if errors.Is(err, dvls.ErrEntryNotFound) {
		return true
	}

	return false
}
