package graph

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"runtime/debug"
	"time"

	"github.com/99designs/gqlgen/graphql"
	"github.com/99designs/gqlgen/graphql/handler"
	"github.com/99designs/gqlgen/graphql/handler/extension"
	"github.com/99designs/gqlgen/graphql/handler/lru"
	"github.com/99designs/gqlgen/graphql/handler/transport"
	"github.com/coder/websocket"
	"github.com/vektah/gqlparser/v2/ast"
	"github.com/vektah/gqlparser/v2/gqlerror"

	"github.com/renora/renora-api/internal/apperr"
	"github.com/renora/renora-api/internal/authn"
	"github.com/renora/renora-api/internal/config"
	"github.com/renora/renora-api/internal/graph/generated"
	"github.com/renora/renora-api/internal/i18n"
	"github.com/renora/renora-api/internal/problem"
)

type ServerOptions struct {
	Config   config.GraphQL
	Logger   *slog.Logger
	APQCache graphql.Cache[string] // nil disables automatic persisted queries
	Sessions authn.SessionStore
	// OriginHosts are the browser origins allowed to open the WebSocket, as
	// hosts ("app.renora.id", "localhost:5173"). Same-host requests are always
	// allowed; requests without an Origin (the mobile app) are too.
	OriginHosts []string
}

// NewHandler builds the /graphql handler: HTTP and graphql-ws, the contract's
// access rules, and production limits.
func NewHandler(r *Resolver, opts ServerOptions) http.Handler {
	srv := handler.New(generated.NewExecutableSchema(generated.Config{
		Resolvers:  r,
		Directives: directives(),
	}))

	// Uploads go straight to object storage through presigned URLs (createUpload),
	// so there is no multipart transport.
	srv.AddTransport(transport.Websocket{
		Implementation: transport.CoderWebsocketImplementation{
			AcceptOptions: websocket.AcceptOptions{OriginPatterns: opts.OriginHosts},
		},
		InitFunc:              wsInit(opts.Sessions),
		InitTimeout:           10 * time.Second,
		KeepAlivePingInterval: 25 * time.Second,
	})
	srv.AddTransport(transport.Options{})
	srv.AddTransport(transport.GET{})
	srv.AddTransport(transport.POST{})

	srv.SetQueryCache(lru.New[*ast.QueryDocument](1000))

	if *opts.Config.Introspection {
		srv.Use(extension.Introspection{})
	}
	if opts.APQCache != nil {
		srv.Use(extension.AutomaticPersistedQuery{Cache: opts.APQCache})
	}
	srv.Use(extension.FixedComplexityLimit(opts.Config.ComplexityLimit))
	srv.Use(DepthLimit{Max: opts.Config.DepthLimit})
	srv.AroundFields(guardRoot)

	srv.SetErrorPresenter(errorPresenter(opts.Logger))
	srv.SetRecoverFunc(func(ctx context.Context, v any) error {
		opts.Logger.ErrorContext(ctx, "graphql resolver panic", "panic", v, "stack", string(debug.Stack()))
		return errors.New("internal panic")
	})
	return srv
}

// wsInit authenticates a graphql-ws connection the way HTTP is authenticated:
// mobile sends `Authorization: Bearer …` in connectionParams; web relies on the
// session cookie of the upgrade request, already resolved by the HTTP middleware.
// Both send Accept-Language in connectionParams.
func wsInit(sessions authn.SessionStore) transport.WebsocketInitFunc {
	return func(ctx context.Context, p transport.InitPayload) (context.Context, *transport.InitPayload, error) {
		v := authn.From(ctx)
		if auth := p.Authorization(); auth != "" {
			s, err := authn.ResolveBearer(ctx, sessions, auth)
			if err != nil {
				return ctx, nil, err
			}
			v = authn.Viewer{Session: s}
		}
		// A browser cannot set X-CSRF-Token on the upgrade request, so a cookie
		// session over the socket never passes CSRF: no cookie-authenticated
		// mutation can ride a WebSocket.
		ctx = authn.WithViewer(ctx, v)

		var userLang i18n.Lang
		if v.Session != nil {
			userLang = v.Session.Language
		}
		if header := p.GetString("Accept-Language"); header != "" {
			ctx = i18n.WithLang(ctx, i18n.Resolve(header, userLang))
		}
		return ctx, nil, nil
	}
}

// Error codes gqlgen sets on requests it rejects before execution. The contract
// calls all of them BAD_USER_INPUT. Persisted-query codes stay as they are: Apollo
// clients rely on them to resend the full query.
var badInputCodes = map[string]bool{
	"GRAPHQL_PARSE_FAILED":      true,
	"GRAPHQL_VALIDATION_FAILED": true,
	"COMPLEXITY_LIMIT_EXCEEDED": true,
	"DEPTH_LIMIT_EXCEEDED":      true,
}

// errorPresenter maps errors to the contract's `errors[].extensions.code`:
// transport and auth errors keep their code and show their message in the
// request's language; rejected requests become BAD_USER_INPUT; anything else is
// logged and masked as INTERNAL.
func errorPresenter(logger *slog.Logger) graphql.ErrorPresenterFunc {
	return func(ctx context.Context, err error) *gqlerror.Error {
		if ae, ok := apperr.As(err); ok {
			gqlErr := graphql.DefaultErrorPresenter(ctx, err)
			gqlErr.Message = ae.Message.In(i18n.From(ctx))
			gqlErr.Extensions = map[string]any{"code": string(ae.Code)}
			if ae.Code == apperr.CodeInternal {
				logger.ErrorContext(ctx, "graphql internal error", "error", err, "path", gqlErr.Path.String())
			}
			return gqlErr
		}

		var gqlErr *gqlerror.Error
		if errors.As(err, &gqlErr) && gqlErr.Err == nil {
			out := graphql.DefaultErrorPresenter(ctx, err)
			if code, _ := out.Extensions["code"].(string); badInputCodes[code] {
				out.Extensions["code"] = string(apperr.CodeBadUserInput)
			}
			return out
		}

		masked := graphql.DefaultErrorPresenter(ctx, err)
		msg := "graphql internal error"
		var p *problem.Problem
		if errors.As(err, &p) {
			// Problems are data in the result union; one reaching here is a resolver bug.
			msg = "domain problem returned as an error instead of a result"
		}
		logger.ErrorContext(ctx, msg, "error", err, "path", masked.Path.String())
		internal := apperr.Internal(err)
		masked.Message = internal.Message.In(i18n.From(ctx))
		masked.Extensions = map[string]any{"code": string(apperr.CodeInternal)}
		return masked
	}
}
