package account

import (
	"context"
	"log/slog"

	"github.com/renora/renora-api/internal/i18n"
)

// Code is one sign-in code to deliver.
type Code struct {
	Phone   string
	Channel Channel
	Code    string
	Lang    i18n.Lang
	// AndroidAppHash lets Android fill the code in with one tap (WhatsApp OTP autofill).
	AndroidAppHash string
}

// Sender delivers sign-in codes over WhatsApp, SMS or a voice call.
type Sender interface {
	Send(ctx context.Context, c Code) error
}

// LogSender writes codes to the log instead of sending them. Config refuses it
// in production; it lets development and staging sign in without a provider.
type LogSender struct {
	Logger *slog.Logger
}

func (s LogSender) Send(ctx context.Context, c Code) error {
	s.Logger.WarnContext(ctx, "sign-in code (not sent: AUTH_CODE_SENDER=log)",
		"phone", MaskPhone(c.Phone), "channel", c.Channel, "code", c.Code)
	return nil
}
