package graph

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"testing"

	"github.com/vektah/gqlparser/v2/gqlerror"

	"github.com/renora/renora-api/internal/apperr"
	"github.com/renora/renora-api/internal/authn"
	"github.com/renora/renora-api/internal/graph/model"
	"github.com/renora/renora-api/internal/i18n"
	"github.com/renora/renora-api/internal/problem"
)

func TestErrorPresenter(t *testing.T) {
	present := errorPresenter(slog.New(slog.NewTextHandler(io.Discard, nil)))
	bahasa := i18n.WithLang(context.Background(), i18n.ID)

	tests := []struct {
		name     string
		ctx      context.Context
		err      error
		wantMsg  string
		wantCode any
	}{
		{
			name:     "transport error keeps its code",
			ctx:      context.Background(),
			err:      fmt.Errorf("guard: %w", apperr.Forbidden()),
			wantMsg:  "Not allowed for your role",
			wantCode: "FORBIDDEN",
		},
		{
			name:     "message follows the request's language",
			ctx:      bahasa,
			err:      apperr.Unauthenticated(),
			wantMsg:  "Masuk dulu",
			wantCode: "UNAUTHENTICATED",
		},
		{
			name:     "validation becomes BAD_USER_INPUT",
			ctx:      context.Background(),
			err:      &gqlerror.Error{Message: `Cannot query field "foo"`, Extensions: map[string]any{"code": "GRAPHQL_VALIDATION_FAILED"}},
			wantMsg:  `Cannot query field "foo"`,
			wantCode: "BAD_USER_INPUT",
		},
		{
			name:     "persisted query code stays for Apollo",
			ctx:      context.Background(),
			err:      &gqlerror.Error{Message: "PersistedQueryNotFound", Extensions: map[string]any{"code": "PERSISTED_QUERY_NOT_FOUND"}},
			wantMsg:  "PersistedQueryNotFound",
			wantCode: "PERSISTED_QUERY_NOT_FOUND",
		},
		{
			name:     "unknown error is masked",
			ctx:      context.Background(),
			err:      errors.New("dial tcp 10.0.0.5:5432: connection refused"),
			wantMsg:  "Something went wrong. Try again",
			wantCode: "INTERNAL",
		},
		{
			name:     "internal cause stays hidden",
			ctx:      context.Background(),
			err:      apperr.Internal(errors.New("pq: relation app.jobs does not exist")),
			wantMsg:  "Something went wrong. Try again",
			wantCode: "INTERNAL",
		},
		{
			name:     "a problem returned as an error is a bug, so masked",
			ctx:      context.Background(),
			err:      problem.NotFound(i18n.T("Job not found", "Pekerjaan tidak ditemukan")),
			wantMsg:  "Something went wrong. Try again",
			wantCode: "INTERNAL",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := present(tt.ctx, tt.err)
			if got.Message != tt.wantMsg {
				t.Errorf("message = %q, want %q", got.Message, tt.wantMsg)
			}
			if got.Extensions["code"] != tt.wantCode {
				t.Errorf("code = %v, want %v", got.Extensions["code"], tt.wantCode)
			}
		})
	}
}

func TestProblemResult(t *testing.T) {
	ctx := i18n.WithLang(context.Background(), i18n.ID)

	p := problem.InvalidCode("wrong_code", "code", "wrong_code", i18n.T("That code is not right", "Kode itu salah"))
	res := problemResult[model.VerifyCodeResult](ctx, p)
	ii, ok := res.(*model.InvalidInput)
	if !ok {
		t.Fatalf("result = %T, want *model.InvalidInput", res)
	}
	if ii.Code != model.ProblemCodeWrongCode || ii.Message != "Kode itu salah" || ii.Field != "code" || ii.Reason != "wrong_code" {
		t.Errorf("InvalidInput = %+v", ii)
	}

	t.Run("kind outside the union panics", func(t *testing.T) {
		defer func() {
			if recover() == nil {
				t.Error("want a panic: VerifyCodeResult has no NotFound member")
			}
		}()
		problemResult[model.VerifyCodeResult](ctx, problem.NotFound(i18n.T("x", "x")))
	})

	t.Run("code outside the contract panics", func(t *testing.T) {
		defer func() {
			if recover() == nil {
				t.Error("want a panic for an unknown ProblemCode")
			}
		}()
		toModel(ctx, problem.Conflict("made_up_code", i18n.T("x", "x")))
	})
}

// Every code the problem package hard-codes must be a contract ProblemCode.
func TestProblemPackageCodesAreInContract(t *testing.T) {
	for _, p := range []*problem.Problem{
		problem.NotFound(i18n.Text{}),
		problem.LinkExpired(i18n.Text{}),
		problem.Invalid("f", "required", i18n.Text{}),
		problem.QuotaReached(i18n.Text{}),
		problem.IdempotencyMismatch(),
	} {
		if !model.ProblemCode(p.Code).IsValid() {
			t.Errorf("%q is not a contract ProblemCode", p.Code)
		}
	}
}

func TestPrivateDirective(t *testing.T) {
	private := directives().Private
	next := func(context.Context) (any, error) { return "buying price", nil }
	to := []model.Role{model.RoleContractor, model.RoleOps}

	for role, want := range map[authn.Role]any{
		authn.RoleContractor: "buying price",
		authn.RoleOps:        "buying price",
		authn.RoleOwner:      nil,
	} {
		ctx := authn.WithViewer(context.Background(), authn.Viewer{Session: &authn.Session{Role: role}})
		got, err := private(ctx, nil, next, to)
		if err != nil || got != want {
			t.Errorf("%s reads %v (%v), want %v", role, got, err, want)
		}
	}

	got, err := private(context.Background(), nil, next, to)
	if err != nil || got != nil {
		t.Errorf("anonymous reads %v (%v), want null without an error", got, err)
	}
}
