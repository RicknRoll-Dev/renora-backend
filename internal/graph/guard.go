package graph

import (
	"context"
	"slices"
	"strings"

	"github.com/99designs/gqlgen/graphql"

	"github.com/renora/renora-api/internal/apperr"
	"github.com/renora/renora-api/internal/authn"
	"github.com/renora/renora-api/internal/graph/generated"
	"github.com/renora/renora-api/internal/graph/model"
)

// Access rules, in the order the contract's mock applies them (mock/index.ts, enforce):
//
//  1. A root field without @public needs a session: UNAUTHENTICATED.
//  2. A mutation on a cookie session needs X-CSRF-Token: CSRF_FAILED.
//  3. @allow(roles:) admits only those roles: FORBIDDEN.
//  4. @private(to:) on any field reads null for every other role, without an error.

var roots = map[string]bool{"Query": true, "Mutation": true, "Subscription": true}

// guardRoot enforces rules 1 and 2. It runs as field middleware, so a refusal
// is a field error and nulls propagate as the schema's nullability says.
func guardRoot(ctx context.Context, next graphql.Resolver) (any, error) {
	fc := graphql.GetFieldContext(ctx)
	if fc == nil || !roots[fc.Object] || strings.HasPrefix(fc.Field.Name, "__") {
		return next(ctx)
	}
	if fc.Field.Definition != nil && fc.Field.Definition.Directives.ForName("public") != nil {
		return next(ctx)
	}
	v := authn.From(ctx)
	if !v.SignedIn() {
		return nil, apperr.Unauthenticated()
	}
	if fc.Object == "Mutation" && !v.CSRFValid() {
		return nil, apperr.CSRFFailed()
	}
	return next(ctx)
}

func directives() generated.DirectiveRoot {
	return generated.DirectiveRoot{
		Public: func(ctx context.Context, _ any, next graphql.Resolver) (any, error) {
			return next(ctx) // guardRoot reads @public from the schema
		},
		Allow: func(ctx context.Context, _ any, next graphql.Resolver, roles []model.Role) (any, error) {
			if !hasRole(ctx, roles) {
				return nil, apperr.Forbidden()
			}
			return next(ctx)
		},
		Private: func(ctx context.Context, _ any, next graphql.Resolver, to []model.Role) (any, error) {
			if !hasRole(ctx, to) {
				return nil, nil
			}
			return next(ctx)
		},
	}
}

// hasRole reports whether the caller's role is one of roles. Today that is the
// role the session signed in as, as in the mock; per-job roles refine it once
// jobs exist ("the caller's role on the job", schema.graphql @private).
func hasRole(ctx context.Context, roles []model.Role) bool {
	v := authn.From(ctx)
	if v.Session == nil {
		return false
	}
	return slices.Contains(roles, model.Role(v.Session.Role))
}
