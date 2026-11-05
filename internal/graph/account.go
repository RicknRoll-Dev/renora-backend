package graph

import (
	"context"

	"github.com/renora/renora-api/internal/apperr"
	"github.com/renora/renora-api/internal/i18n"

	"github.com/renora/renora-api/internal/account"
	"github.com/renora/renora-api/internal/authn"
	"github.com/renora/renora-api/internal/graph/model"
)

// toMe maps an account to `Me` as read through sess.
func toMe(u account.User, sess authn.Session) *model.Me {
	roles := make([]model.Role, len(u.Roles))
	for i, r := range u.Roles {
		roles[i] = model.Role(r)
	}
	var bank *model.Bank
	if u.PreferredVABank != nil {
		b := model.Bank(*u.PreferredVABank)
		bank = &b
	}
	created := u.CreatedAt
	return &model.Me{
		ID:              u.ID,
		Name:            u.Name,
		DisplayName:     u.DisplayName,
		Initials:        u.Initials(),
		Phone:           u.Phone,
		Email:           u.Email,
		Language:        model.Language(u.Language),
		PreferredVaBank: bank,
		VoiceHelp:       u.VoiceHelp,
		Roles:           roles,
		Consents:        toConsents(u.Consents),
		CreatedAt:       &created,
		SessionID:       sess.ID,
		SessionRole:     model.Role(sess.Role),
	}
}

func toConsents(c account.Consents) *model.Consents {
	return &model.Consents{
		AiProcessing:     c.AIProcessing,
		AiProcessingAt:   c.AIProcessingAt,
		AiTrainingPhotos: c.AITrainingPhotos,
		PriceBookSharing: c.PriceBookSharing,
	}
}

func toSignedInSessions(list []account.SignedInSession, current string) []model.SignedInSession {
	out := make([]model.SignedInSession, len(list))
	for i, s := range list {
		out[i] = model.SignedInSession{
			ID:           s.ID,
			Label:        s.Label,
			Place:        s.Place,
			LastActiveAt: s.LastActiveAt,
			Current:      s.ID == current,
		}
	}
	return out
}

// toSession is the `Session` a sign-in returns: the token for mobile, the CSRF
// token for web (whose session token travels only in the httpOnly cookie).
func toSession(st account.Started) *model.Session {
	out := &model.Session{
		Viewer:    toMe(st.User, st.Session),
		ExpiresAt: st.Session.ExpiresAt,
		Guest:     st.Session.Guest,
	}
	switch st.Session.Client {
	case authn.ClientMobile:
		out.Token = &st.Token
	case authn.ClientWeb:
		out.CsrfToken = &st.Session.CSRFToken
	}
	return out
}

// viewerSession is the signed-in caller's session. Root fields without @public
// run only for signed-in callers (guardRoot), so it is never nil there.
func viewerSession(ctx context.Context) authn.Session {
	return *authn.From(ctx).Session
}

// errNeedsHTTP refuses a sign-in over the WebSocket: web sessions live in
// cookies, which only an HTTP response can set.
var errNeedsHTTP = apperr.BadUserInput(i18n.T("Sign in over HTTP, not the WebSocket", "Masuk lewat HTTP, bukan WebSocket"))

// toQRSignIn maps a QR sign-in. The payload is shown only while it waits; the
// session only on the poll that collected it.
func toQRSignIn(q account.QRSignIn, started *account.Started) *model.QRSignIn {
	out := &model.QRSignIn{ID: q.ID, Status: model.QRStatus(q.Status), ExpiresAt: q.ExpiresAt}
	if q.Status == account.QRWaiting {
		payload := q.Payload()
		out.Payload = &payload
	}
	if started != nil {
		out.Session = toSession(*started)
	}
	return out
}
