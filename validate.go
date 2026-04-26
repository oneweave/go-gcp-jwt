package gcpjwtvalidate

import (
	"context"
	"fmt"
	"net/http"
	"strings"

	"google.golang.org/api/idtoken"
)

const (
	googleIssuerAccounts = "accounts.google.com"
	googleIssuerHTTPS    = "https://accounts.google.com"
)

// TokenValidateFunc validates the token and returns decoded claims.
type TokenValidateFunc func(ctx context.Context, idToken, audience string) (*idtoken.Payload, error)

// Config controls validator behavior.
type Config struct {
	Audience               string
	AllowedServiceAccounts []string
	AllowedIssuers         []string
	RequireEmailVerified   bool
}

// Claims is a normalized token claim view returned by the validator.
type Claims struct {
	Issuer        string
	Audience      string
	Subject       string
	Email         string
	EmailVerified bool
	Expires       int64
	IssuedAt      int64
	Raw           map[string]any
}

// Option customizes validator construction.
type Option func(*Validator)

// WithTokenValidator injects a custom token validator (useful in tests).
func WithTokenValidator(fn TokenValidateFunc) Option {
	return func(v *Validator) {
		if fn != nil {
			v.validateToken = fn
		}
	}
}

// Validator verifies Google-issued ID tokens for push endpoints.
type Validator struct {
	audience             string
	allowedIssuers       map[string]struct{}
	allowedServiceEmails map[string]struct{}
	requireEmailVerified bool
	validateToken        TokenValidateFunc
}

// NewValidator creates a validator with secure defaults.
func NewValidator(config Config, opts ...Option) (*Validator, error) {
	if strings.TrimSpace(config.Audience) == "" {
		return nil, fmt.Errorf("audience is required")
	}

	issuers := config.AllowedIssuers
	if len(issuers) == 0 {
		issuers = []string{googleIssuerAccounts, googleIssuerHTTPS}
	}

	allowedServiceEmails := make(map[string]struct{}, len(config.AllowedServiceAccounts))
	for _, email := range config.AllowedServiceAccounts {
		normalized := strings.ToLower(strings.TrimSpace(email))
		if normalized == "" {
			continue
		}
		allowedServiceEmails[normalized] = struct{}{}
	}

	requireEmailVerified := config.RequireEmailVerified
	if len(allowedServiceEmails) > 0 {
		requireEmailVerified = true
	}

	v := &Validator{
		audience:             config.Audience,
		allowedIssuers:       makeSet(issuers),
		allowedServiceEmails: allowedServiceEmails,
		requireEmailVerified: requireEmailVerified,
		validateToken:        idtoken.Validate,
	}

	for _, opt := range opts {
		opt(v)
	}

	return v, nil
}

// ValidateAuthorizationHeader extracts and verifies a bearer token.
func (v *Validator) ValidateAuthorizationHeader(ctx context.Context, authorizationHeader string) (*Claims, error) {
	token, err := ExtractBearerToken(authorizationHeader)
	if err != nil {
		return nil, err
	}
	return v.ValidateToken(ctx, token)
}

// ValidateRequest validates the Authorization header from an HTTP request.
func (v *Validator) ValidateRequest(r *http.Request) (*Claims, error) {
	if r == nil {
		return nil, fmt.Errorf("request is required")
	}
	return v.ValidateAuthorizationHeader(r.Context(), r.Header.Get("Authorization"))
}

// ValidateToken validates token signature and configured claims.
func (v *Validator) ValidateToken(ctx context.Context, token string) (*Claims, error) {
	if strings.TrimSpace(token) == "" {
		return nil, fmt.Errorf("token is required")
	}

	payload, err := v.validateToken(ctx, token, v.audience)
	if err != nil {
		return nil, fmt.Errorf("token validation failed: %w", err)
	}

	if _, ok := v.allowedIssuers[payload.Issuer]; !ok {
		return nil, fmt.Errorf("unexpected issuer: %s", payload.Issuer)
	}

	claims := toClaims(payload)
	if len(v.allowedServiceEmails) > 0 {
		email := strings.ToLower(strings.TrimSpace(claims.Email))
		if email == "" {
			return nil, fmt.Errorf("missing email claim")
		}
		if _, ok := v.allowedServiceEmails[email]; !ok {
			return nil, fmt.Errorf("service account not allowed: %s", claims.Email)
		}
	}

	if v.requireEmailVerified && !claims.EmailVerified {
		return nil, fmt.Errorf("email claim is not verified")
	}

	return claims, nil
}

func toClaims(payload *idtoken.Payload) *Claims {
	claims := &Claims{
		Issuer:   payload.Issuer,
		Audience: payload.Audience,
		Subject:  payload.Subject,
		Expires:  payload.Expires,
		IssuedAt: payload.IssuedAt,
		Raw:      payload.Claims,
	}

	if email, ok := payload.Claims["email"].(string); ok {
		claims.Email = email
	}
	claims.EmailVerified = claimBool(payload.Claims["email_verified"])

	return claims
}

func claimBool(value any) bool {
	switch v := value.(type) {
	case bool:
		return v
	case string:
		return strings.EqualFold(v, "true")
	default:
		return false
	}
}

func makeSet(values []string) map[string]struct{} {
	set := make(map[string]struct{}, len(values))
	for _, v := range values {
		normalized := strings.TrimSpace(v)
		if normalized == "" {
			continue
		}
		set[normalized] = struct{}{}
	}
	return set
}
