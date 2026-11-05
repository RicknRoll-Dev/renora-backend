// Package i18n carries the request's language. Every string the server composes
// (clock lines, ledger lines, notifications, problem messages) answers in it.
package i18n

import (
	"context"
	"strings"
)

// Lang is a contract `Language` wire value.
type Lang string

const (
	ID Lang = "id" // Bahasa Indonesia
	EN Lang = "en"
)

// Text is a composed string in both languages; the reader gets one.
type Text struct {
	EN string
	ID string
}

// T is shorthand for a Text literal: i18n.T("Sign in first", "Masuk dulu").
func T(en, id string) Text { return Text{EN: en, ID: id} }

// In returns the text in lang, falling back to English.
func (t Text) In(lang Lang) string {
	if lang == ID && t.ID != "" {
		return t.ID
	}
	return t.EN
}

// FromHeader reads the first tag of an Accept-Language header: `id` (or the legacy
// `in`) is Bahasa Indonesia, any other tag English. ok is false when the header is empty.
func FromHeader(header string) (lang Lang, ok bool) {
	tag := strings.TrimSpace(header)
	if tag == "" {
		return "", false
	}
	if i := strings.IndexAny(tag, ",;"); i >= 0 {
		tag = strings.TrimSpace(tag[:i])
	}
	if len(tag) >= 2 {
		switch strings.ToLower(tag[:2]) {
		case "id", "in":
			return ID, true
		}
	}
	return EN, true
}

// Resolve picks the request's language: the header's, else the signed-in user's, else English.
func Resolve(header string, userLang Lang) Lang {
	if lang, ok := FromHeader(header); ok {
		return lang
	}
	if userLang == ID {
		return ID
	}
	return EN
}

type ctxKey struct{}

func WithLang(ctx context.Context, lang Lang) context.Context {
	return context.WithValue(ctx, ctxKey{}, lang)
}

// From returns the request's language, English when none was set.
func From(ctx context.Context) Lang {
	if lang, ok := ctx.Value(ctxKey{}).(Lang); ok {
		return lang
	}
	return EN
}
