package gcpjwtvalidate

import (
	"fmt"
	"strings"
)

// ExtractBearerToken parses an Authorization header in the form "Bearer <token>".
func ExtractBearerToken(authorizationHeader string) (string, error) {
	if strings.TrimSpace(authorizationHeader) == "" {
		return "", fmt.Errorf("missing Authorization header")
	}

	parts := strings.Fields(authorizationHeader)
	if len(parts) == 0 {
		return "", fmt.Errorf("missing Authorization header")
	}
	if !strings.EqualFold(parts[0], "Bearer") {
		return "", fmt.Errorf("invalid Authorization header format")
	}
	if len(parts) == 1 {
		return "", fmt.Errorf("missing bearer token")
	}
	if len(parts) != 2 {
		return "", fmt.Errorf("invalid Authorization header format")
	}

	token := strings.TrimSpace(parts[1])
	if token == "" {
		return "", fmt.Errorf("missing bearer token")
	}

	return token, nil
}
