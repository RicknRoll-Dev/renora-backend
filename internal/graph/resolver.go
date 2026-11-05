// Package graph holds the GraphQL resolvers. Resolvers stay thin: they map
// GraphQL input to domain calls and domain results back to GraphQL models.
package graph

//go:generate go tool gqlgen generate

import (
	"time"

	"github.com/renora/renora-api/internal/account"
	"github.com/renora/renora-api/internal/authn"
	"github.com/renora/renora-api/internal/platform/queue"
)

// Resolver carries the dependencies shared by every resolver.
type Resolver struct {
	Queue    *queue.Client
	Now      func() time.Time
	Accounts *account.Service
	Cookies  authn.CookieConfig
}
