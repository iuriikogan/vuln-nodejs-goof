// Package secrets provides least-privilege access to Google Secret Manager
// via Application Default Credentials (ADC) with zero local .env fallbacks.
package secrets

import (
	"context"
	"fmt"
	"hash/crc32"

	secretmanager "cloud.google.com/go/secretmanager/apiv1"
	"cloud.google.com/go/secretmanager/apiv1/secretmanagerpb"
)

// Client wraps the Google Secret Manager API client.
type Client struct {
	projectID string
	sm        *secretmanager.Client
}

// NewClient initializes a Secret Manager client authenticated via ADC.
func NewClient(ctx context.Context, projectID string) (*Client, error) {
	if projectID == "" {
		return nil, fmt.Errorf("projectID is required for Secret Manager initialization")
	}
	smClient, err := secretmanager.NewClient(ctx)
	if err != nil {
		return nil, fmt.Errorf("creating Secret Manager client via ADC: %w", err)
	}
	return &Client{
		projectID: projectID,
		sm:        smClient,
	}, nil
}

// AccessSecret fetches the latest version of a secret and verifies its CRC32C checksum.
func (c *Client) AccessSecret(ctx context.Context, secretID string) (string, error) {
	name := fmt.Sprintf("projects/%s/secrets/%s/versions/latest", c.projectID, secretID)
	req := &secretmanagerpb.AccessSecretVersionRequest{
		Name: name,
	}

	result, err := c.sm.AccessSecretVersion(ctx, req)
	if err != nil {
		return "", fmt.Errorf("accessing secret version %s: %w", name, err)
	}

	payload := result.GetPayload()
	if payload == nil {
		return "", fmt.Errorf("empty secret payload returned for %s", name)
	}

	crc32c := crc32.MakeTable(crc32.Castagnoli)
	checksum := int64(crc32.Checksum(payload.GetData(), crc32c))
	if payload.DataCrc32C != nil && checksum != payload.GetDataCrc32C() {
		return "", fmt.Errorf("secret payload CRC32C checksum mismatch for %s", name)
	}

	return string(payload.GetData()), nil
}

// Close releases the underlying gRPC connection.
func (c *Client) Close() error {
	if c.sm == nil {
		return nil
	}
	if err := c.sm.Close(); err != nil {
		return fmt.Errorf("closing Secret Manager client: %w", err)
	}
	return nil
}
