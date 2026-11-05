package graph

import (
	"context"
	"fmt"

	"github.com/renora/renora-api/internal/graph/model"
	"github.com/renora/renora-api/internal/i18n"
	"github.com/renora/renora-api/internal/problem"
)

// toModel turns a domain problem into its GraphQL union member, in the request's language.
func toModel(ctx context.Context, p *problem.Problem) model.Problem {
	code := model.ProblemCode(p.Code)
	if !code.IsValid() {
		panic(fmt.Sprintf("problem code %q is not a contract ProblemCode", p.Code))
	}
	msg := p.Message.In(i18n.From(ctx))
	switch p.Kind {
	case problem.KindNotFound:
		return &model.NotFound{Code: code, Message: msg}
	case problem.KindConflict:
		return &model.Conflict{Code: code, Message: msg}
	case problem.KindInvalidInput:
		return &model.InvalidInput{Code: code, Message: msg, Field: p.Field, Reason: p.Reason}
	case problem.KindQuotaReached:
		return &model.QuotaReached{Code: code, Message: msg}
	}
	panic(fmt.Sprintf("unknown problem kind %v", p.Kind))
}

// problemResult returns p as a member of the mutation's result union R:
//
//	return problemResult[model.FundStageResult](ctx, p), nil
//
// It panics when R has no member of p's kind, which is a resolver bug the
// schema would have rejected anyway.
func problemResult[R any](ctx context.Context, p *problem.Problem) R {
	if p == nil {
		panic("problemResult called without a problem")
	}
	m := toModel(ctx, p)
	r, ok := m.(R)
	if !ok {
		var zero R
		panic(fmt.Sprintf("%T is not a member of result union %T", m, zero))
	}
	return r
}
