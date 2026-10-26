// Package vertex integrates with Vertex AI and AI Platform via official Google Cloud Go SDKs
// to classify findings and synthesize SARIF security reports.
package vertex

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"

	aiplatform "cloud.google.com/go/aiplatform/apiv1"
	"cloud.google.com/go/vertexai/genai"
	"google.golang.org/api/iterator"
	"google.golang.org/api/option"
)

const (
	// DefaultFlashModel is the default model for routine classification, scanning, and summarization (Objective 4.2).
	DefaultFlashModel = "gemini-3.8-flash"
	// DefaultProModel is the model reserved for complex multi-step architectural reasoning and large-context synthesis (Objective 4.2).
	DefaultProModel = "gemini-3.1-pro"
)

// Config holds Vertex AI connection and configurable model parameters.
type Config struct {
	ProjectID    string
	Location     string
	FlashModelID string
	ProModelID   string
}

// ConfigFromEnv constructs a Config using environment variables with Objective 4.2 defaults.
func ConfigFromEnv() Config {
	flashModel := os.Getenv("CODEMENDER_MODEL")
	if flashModel == "" {
		flashModel = DefaultFlashModel
	}
	proModel := os.Getenv("CODEMENDER_PRO_MODEL")
	if proModel == "" {
		proModel = DefaultProModel
	}
	location := os.Getenv("GOOGLE_CLOUD_LOCATION")
	if location == "" {
		location = "us-central1"
	}
	return Config{
		ProjectID:    os.Getenv("GOOGLE_CLOUD_PROJECT"),
		Location:     location,
		FlashModelID: flashModel,
		ProModelID:   proModel,
	}
}

// Advisor wraps official Vertex AI (`cloud.google.com/go/vertexai`) and AI Platform (`cloud.google.com/go/aiplatform`) SDK clients.
type Advisor struct {
	cfg        Config
	genaiCli   *genai.Client
	endptCli   *aiplatform.EndpointClient
}

// NewAdvisor initializes Vertex AI and AI Platform clients using Application Default Credentials (ADC).
func NewAdvisor(ctx context.Context, cfg Config) (*Advisor, error) {
	if cfg.ProjectID == "" {
		return nil, fmt.Errorf("project ID is required for Vertex AI initialization")
	}
	if cfg.Location == "" {
		cfg.Location = "us-central1"
	}
	if cfg.FlashModelID == "" {
		cfg.FlashModelID = DefaultFlashModel
	}
	if cfg.ProModelID == "" {
		cfg.ProModelID = DefaultProModel
	}

	gClient, err := genai.NewClient(ctx, cfg.ProjectID, cfg.Location)
	if err != nil {
		return nil, fmt.Errorf("creating Vertex AI genai client via ADC: %w", err)
	}

	regionalEndpoint := fmt.Sprintf("%s-aiplatform.googleapis.com:443", cfg.Location)
	epClient, err := aiplatform.NewEndpointClient(ctx, option.WithEndpoint(regionalEndpoint))
	if err != nil {
		_ = gClient.Close()
		return nil, fmt.Errorf("creating AI Platform endpoint client via ADC: %w", err)
	}

	return &Advisor{
		cfg:      cfg,
		genaiCli: gClient,
		endptCli: epClient,
	}, nil
}

// StreamSARIFSummary streams a security gate executive summary from a CodeMender SARIF report.
// Uses FlashModelID by default, or ProModelID when deepSynthesis is requested.
func (a *Advisor) StreamSARIFSummary(ctx context.Context, sarifJSON string, deepSynthesis bool, out io.Writer) error {
	modelID := a.cfg.FlashModelID
	if deepSynthesis {
		modelID = a.cfg.ProModelID
	}

	model := a.genaiCli.GenerativeModel(modelID)
	model.SetTemperature(0.1)

	prompt := fmt.Sprintf(
		"Summarize the following Google CodeMender SARIF report for a pull request security gate. "+
			"Highlight net-new CRITICAL/HIGH findings versus [LEGACY / UNTOUCHED] issues and list exact `cm verify` / `cm fix` commands:\n\n%s",
		sarifJSON,
	)

	iter := model.GenerateContentStream(ctx, genai.Text(prompt))
	for {
		resp, err := iter.Next()
		if errors.Is(err, iterator.Done) {
			break
		}
		if err != nil {
			return fmt.Errorf("streaming content from Vertex AI model %s: %w", modelID, err)
		}
		for _, cand := range resp.Candidates {
			if cand.Content == nil {
				continue
			}
			for _, part := range cand.Content.Parts {
				if txt, ok := part.(genai.Text); ok {
					if _, wErr := io.WriteString(out, strings.TrimSpace(string(txt))+"\n"); wErr != nil {
						return fmt.Errorf("writing streamed response: %w", wErr)
					}
				}
			}
		}
	}
	return nil
}

// Close closes the underlying Vertex AI and AI Platform clients.
func (a *Advisor) Close() error {
	var firstErr error
	if a.genaiCli != nil {
		if err := a.genaiCli.Close(); err != nil && firstErr == nil {
			firstErr = fmt.Errorf("closing Vertex AI genai client: %w", err)
		}
	}
	if a.endptCli != nil {
		if err := a.endptCli.Close(); err != nil && firstErr == nil {
			firstErr = fmt.Errorf("closing AI Platform endpoint client: %w", err)
		}
	}
	return firstErr
}
