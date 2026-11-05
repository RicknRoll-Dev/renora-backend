package account

import (
	"context"
	"errors"
	"fmt"
	"net/mail"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/jackc/pgx/v5"

	"github.com/renora/renora-api/internal/authn"
	"github.com/renora/renora-api/internal/i18n"
	"github.com/renora/renora-api/internal/problem"
)

const userColumns = `id, phone, email, name, display_name, language, preferred_va_bank, voice_help, roles,
	ai_processing, ai_processing_at, ai_training_photos, price_book_sharing, created_at`

func scanUser(row pgx.Row) (User, error) {
	var (
		u     User
		lang  string
		roles []string
	)
	err := row.Scan(&u.ID, &u.Phone, &u.Email, &u.Name, &u.DisplayName, &lang, &u.PreferredVABank, &u.VoiceHelp, &roles,
		&u.Consents.AIProcessing, &u.Consents.AIProcessingAt, &u.Consents.AITrainingPhotos, &u.Consents.PriceBookSharing, &u.CreatedAt)
	if err != nil {
		return User{}, err
	}
	u.Language = i18n.Lang(lang)
	for _, r := range roles {
		u.Roles = append(u.Roles, authn.Role(r))
	}
	return u, nil
}

func userByPhone(ctx context.Context, q querier, phone string) (User, bool, error) {
	u, err := scanUser(q.QueryRow(ctx, `SELECT `+userColumns+` FROM app.users WHERE phone = $1`, phone))
	if errors.Is(err, pgx.ErrNoRows) {
		return User{}, false, nil
	}
	if err != nil {
		return User{}, false, fmt.Errorf("load user: %w", err)
	}
	return u, true, nil
}

// User loads an account by id.
func (s *Service) User(ctx context.Context, id string) (User, error) {
	u, err := scanUser(s.pool.QueryRow(ctx, `SELECT `+userColumns+` FROM app.users WHERE id = $1`, id))
	if err != nil {
		return User{}, fmt.Errorf("load user %s: %w", id, err)
	}
	return u, nil
}

// UpdateMe changes the fields that are set; nil leaves a field as it is.
type UpdateMe struct {
	Name            *string
	DisplayName     *string
	Email           *string
	Language        *i18n.Lang
	PreferredVABank *string
	VoiceHelp       *bool
}

const maxNameLen = 80

var (
	msgNameRequired = i18n.T("Enter a name.", "Isi nama.")
	msgNameTooLong  = i18n.T("Keep the name under 80 letters.", "Nama maksimal 80 huruf.")
	msgEmailFormat  = i18n.T("Check the email address.", "Periksa alamat email.")
	msgVABank       = i18n.T("Choose BCA, BRI, Mandiri or BNI.", "Pilih BCA, BRI, Mandiri, atau BNI.")
)

var vaBanks = map[string]bool{"BCA": true, "BRI": true, "Mandiri": true, "BNI": true}

// UpdateMe changes the account's own details. Problems: invalid_input.
func (s *Service) UpdateMe(ctx context.Context, userID string, in UpdateMe) (User, *problem.Problem, error) {
	for field, v := range map[string]**string{"name": &in.Name, "displayName": &in.DisplayName} {
		if *v == nil {
			continue
		}
		t := strings.Join(strings.Fields(**v), " ")
		switch {
		case t == "":
			return User{}, problem.Invalid(field, "required", msgNameRequired), nil
		case utf8.RuneCountInString(t) > maxNameLen:
			return User{}, problem.Invalid(field, "out_of_range", msgNameTooLong), nil
		}
		*v = &t
	}
	if in.Email != nil {
		e := strings.TrimSpace(*in.Email)
		if e != "" {
			a, err := mail.ParseAddress(e)
			if err != nil || a.Address != e {
				return User{}, problem.Invalid("email", "invalid_format", msgEmailFormat), nil
			}
		}
		in.Email = &e
	}
	if in.PreferredVABank != nil && !vaBanks[*in.PreferredVABank] {
		return User{}, problem.Invalid("preferredVaBank", "unknown_option", msgVABank), nil
	}
	var lang *string
	if in.Language != nil {
		l := string(*in.Language)
		lang = &l
	}

	// An empty email clears it (NULLIF), unless the account has no phone: staff
	// accounts sign in by email, and the table's check keeps one of the two.
	u, err := scanUser(s.pool.QueryRow(ctx, `
		UPDATE app.users SET
			name              = COALESCE($2, name),
			display_name      = COALESCE($3, display_name),
			email             = CASE WHEN $4::text IS NULL THEN email
			                         WHEN phone IS NULL THEN COALESCE(NULLIF($4, ''), email)
			                         ELSE NULLIF($4, '') END,
			language          = COALESCE($5, language),
			preferred_va_bank = COALESCE($6, preferred_va_bank),
			voice_help        = COALESCE($7, voice_help)
		WHERE id = $1
		RETURNING `+userColumns,
		userID, in.Name, in.DisplayName, in.Email, lang, in.PreferredVABank, in.VoiceHelp))
	if err != nil {
		return User{}, nil, fmt.Errorf("update me: %w", err)
	}
	return u, nil, nil
}

type UpdateConsents struct {
	AIProcessing     *bool
	AITrainingPhotos *bool
	PriceBookSharing *bool
}

// UpdateConsents changes the consents that are set. Saying yes to AI processing
// records when, as the mock does; saying no keeps the time of the last yes.
func (s *Service) UpdateConsents(ctx context.Context, userID string, in UpdateConsents) (Consents, error) {
	u, err := scanUser(s.pool.QueryRow(ctx, `
		UPDATE app.users SET
			ai_processing_at   = CASE WHEN $2::boolean THEN $5::timestamptz ELSE ai_processing_at END,
			ai_processing      = COALESCE($2, ai_processing),
			ai_training_photos = COALESCE($3, ai_training_photos),
			price_book_sharing = COALESCE($4, price_book_sharing)
		WHERE id = $1
		RETURNING `+userColumns,
		userID, in.AIProcessing, in.AITrainingPhotos, in.PriceBookSharing, s.now().Truncate(time.Microsecond)))
	if err != nil {
		return Consents{}, fmt.Errorf("update consents: %w", err)
	}
	return u.Consents, nil
}
