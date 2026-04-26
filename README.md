# go-gcp-jwt

`go-gcp-jwt` is a small Go library for validating Google-issued JWTs used by Pub/Sub push subscriptions (for example, Cloud Run push endpoints).

It follows the same core pattern from Google's guidance:

- Extract bearer token from `Authorization`.
- Validate token signature and audience with `google.golang.org/api/idtoken`.
- Enforce issuer checks.
- Optionally enforce service-account email allowlists.

## Install

```bash
go get github.com/oneweave/go-gcp-jwt
```

## Quick Start

```go
package main

import (
	"context"
	"log"
	"net/http"

	jwtvalidate "github.com/oneweave/go-gcp-jwt"
)

func main() {
	validator, err := jwtvalidate.NewValidator(jwtvalidate.Config{
		Audience: "https://your-service-xxxxx.run.app",
		AllowedServiceAccounts: []string{
			"pubsub-pusher@your-project.iam.gserviceaccount.com",
		},
	})
	if err != nil {
		log.Fatal(err)
	}

	http.HandleFunc("/push", func(w http.ResponseWriter, r *http.Request) {
		claims, err := validator.ValidateAuthorizationHeader(r.Context(), r.Header.Get("Authorization"))
		if err != nil {
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}

		_ = claims
		w.WriteHeader(http.StatusOK)
	})

	_ = http.ListenAndServe(":8080", nil)
}
```

## Notes

- Audience should match the push token audience you configured on the Pub/Sub subscription.
- By default, accepted issuers are `accounts.google.com` and `https://accounts.google.com`.
- If `AllowedServiceAccounts` is set, email and email verification checks are enforced.

## Development

```bash
./test.sh
./lint.sh
```
