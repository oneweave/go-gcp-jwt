package gcpjwtvalidate

import (
	"context"
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/api/idtoken"
)

func TestExtractBearerToken(t *testing.T) {
	t.Run("missing header", func(t *testing.T) {
		token, err := ExtractBearerToken("")
		require.Error(t, err)
		assert.Empty(t, token)
		assert.Contains(t, err.Error(), "missing Authorization header")
	})

	t.Run("invalid format", func(t *testing.T) {
		token, err := ExtractBearerToken("Token abc")
		require.Error(t, err)
		assert.Empty(t, token)
		assert.Contains(t, err.Error(), "invalid Authorization header format")
	})

	t.Run("missing token", func(t *testing.T) {
		token, err := ExtractBearerToken("Bearer   ")
		require.Error(t, err)
		assert.Empty(t, token)
		assert.Contains(t, err.Error(), "missing bearer token")
	})

	t.Run("success", func(t *testing.T) {
		token, err := ExtractBearerToken("Bearer abc.def.ghi")
		require.NoError(t, err)
		assert.Equal(t, "abc.def.ghi", token)
	})
}

func TestNewValidator(t *testing.T) {
	t.Run("default issuers and allowlist enabled", func(t *testing.T) {
		validator, err := NewValidator(Config{
			Audience:               "https://service.example",
			AllowedServiceAccounts: []string{"sa@example.iam.gserviceaccount.com"},
		})
		require.NoError(t, err)
		require.NotNil(t, validator)
		assert.True(t, validator.requireEmailVerified)
		_, hasAccounts := validator.allowedIssuers[googleIssuerAccounts]
		_, hasHTTPS := validator.allowedIssuers[googleIssuerHTTPS]
		assert.True(t, hasAccounts)
		assert.True(t, hasHTTPS)
	})
}

func TestValidateAuthorizationHeader(t *testing.T) {
	validator, err := NewValidator(Config{Audience: "https://service.example"}, WithTokenValidator(func(_ context.Context, token, audience string) (*idtoken.Payload, error) {
		assert.Equal(t, "token-123", token)
		assert.Equal(t, "https://service.example", audience)
		return &idtoken.Payload{
			Issuer:   googleIssuerHTTPS,
			Audience: audience,
			Subject:  "sub-1",
			Claims: map[string]any{
				"email":          "sa@example.iam.gserviceaccount.com",
				"email_verified": true,
			},
		}, nil
	}))
	require.NoError(t, err)

	claims, err := validator.ValidateAuthorizationHeader(context.Background(), "Bearer token-123")
	require.NoError(t, err)
	require.NotNil(t, claims)
	assert.Equal(t, "sa@example.iam.gserviceaccount.com", claims.Email)
	assert.True(t, claims.EmailVerified)
}

func TestValidateTokenErrors(t *testing.T) {
	payload := &idtoken.Payload{
		Issuer:   googleIssuerHTTPS,
		Audience: "https://service.example",
		Subject:  "sub-1",
		Claims: map[string]any{
			"email":          "pubsub-pusher@project.iam.gserviceaccount.com",
			"email_verified": true,
		},
	}

	t.Run("validator failure", func(t *testing.T) {
		validator, err := NewValidator(Config{Audience: "https://service.example"}, WithTokenValidator(func(_ context.Context, _, _ string) (*idtoken.Payload, error) {
			return nil, errors.New("invalid token")
		}))
		require.NoError(t, err)

		claims, err := validator.ValidateToken(context.Background(), "bad")
		require.Error(t, err)
		assert.Nil(t, claims)
		assert.Contains(t, err.Error(), "token validation failed")
	})

	t.Run("unexpected issuer", func(t *testing.T) {
		validator, err := NewValidator(Config{Audience: "https://service.example"}, WithTokenValidator(func(_ context.Context, _, _ string) (*idtoken.Payload, error) {
			p := *payload
			p.Issuer = "https://evil.example"
			return &p, nil
		}))
		require.NoError(t, err)

		claims, err := validator.ValidateToken(context.Background(), "token")
		require.Error(t, err)
		assert.Nil(t, claims)
		assert.Contains(t, err.Error(), "unexpected issuer")
	})

	t.Run("service account allowlist mismatch", func(t *testing.T) {
		validator, err := NewValidator(Config{
			Audience:               "https://service.example",
			AllowedServiceAccounts: []string{"allowed@project.iam.gserviceaccount.com"},
		}, WithTokenValidator(func(_ context.Context, _, _ string) (*idtoken.Payload, error) {
			return payload, nil
		}))
		require.NoError(t, err)

		claims, err := validator.ValidateToken(context.Background(), "token")
		require.Error(t, err)
		assert.Nil(t, claims)
		assert.Contains(t, err.Error(), "service account not allowed")
	})

	t.Run("email must be verified when allowlist configured", func(t *testing.T) {
		validator, err := NewValidator(Config{
			Audience:               "https://service.example",
			AllowedServiceAccounts: []string{"pubsub-pusher@project.iam.gserviceaccount.com"},
		}, WithTokenValidator(func(_ context.Context, _, _ string) (*idtoken.Payload, error) {
			p := *payload
			claims := make(map[string]any, len(payload.Claims))
			for k, v := range payload.Claims {
				claims[k] = v
			}
			claims["email_verified"] = false
			p.Claims = claims
			return &p, nil
		}))
		require.NoError(t, err)

		claims, err := validator.ValidateToken(context.Background(), "token")
		require.Error(t, err)
		assert.Nil(t, claims)
		assert.Contains(t, err.Error(), "email claim is not verified")
	})
}

func TestValidateTokenSuccess(t *testing.T) {
	validator, err := NewValidator(Config{
		Audience:               "https://service.example",
		AllowedServiceAccounts: []string{"pubsub-pusher@project.iam.gserviceaccount.com"},
	}, WithTokenValidator(func(_ context.Context, _, _ string) (*idtoken.Payload, error) {
		return &idtoken.Payload{
			Issuer:   googleIssuerAccounts,
			Audience: "https://service.example",
			Subject:  "subject-1",
			Expires:  100,
			IssuedAt: 10,
			Claims: map[string]any{
				"email":          "pubsub-pusher@project.iam.gserviceaccount.com",
				"email_verified": "true",
			},
		}, nil
	}))
	require.NoError(t, err)

	claims, err := validator.ValidateToken(context.Background(), "token")
	require.NoError(t, err)
	require.NotNil(t, claims)
	assert.Equal(t, googleIssuerAccounts, claims.Issuer)
	assert.Equal(t, "https://service.example", claims.Audience)
	assert.Equal(t, "subject-1", claims.Subject)
	assert.Equal(t, "pubsub-pusher@project.iam.gserviceaccount.com", claims.Email)
	assert.True(t, claims.EmailVerified)
}
