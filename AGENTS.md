# go-gcp-jwt Agent Guide

Treat [README.md](README.md) as the primary usage and package overview.

## Scope

- This repository is a Go library, not an application service.
- Keep APIs small and focused on token extraction and JWT verification.
- Preserve backwards compatibility for exported symbols.

## Package Boundaries

- `header.go`: parse and validate `Authorization: Bearer <token>` headers.
- `validate.go`: verify Google-issued JWT tokens and enforce claim policy.
- `validate_test.go`: table-driven/behavior tests for validation paths and error handling.

## Validation Conventions

- Use `google.golang.org/api/idtoken` for signature and audience validation.
- Keep default accepted issuers to Google issuer values unless explicitly overridden.
- Treat service-account allowlist checks as optional policy layered on top of token validation.
- Return explicit, wrapped errors so callers can map auth failures to HTTP 401 responses.

## Go Conventions

- Propagate caller context; avoid introducing `context.Background()` in library paths.
- Handle and return errors explicitly.
- Wrap propagated errors with `fmt.Errorf(... %w ...)`.

## Validation

Run before handoff:

```bash
./test.sh   
```

```
./lint.sh
```