package model

import "time"

// Me is bound in gqlgen.yml instead of generated. It holds the account's own
// fields; every other field of `Me` (person, sessions, and the parts owned by
// later modules: contractor profile, shops, bank accounts, ...) gets a resolver.
type Me struct {
	ID              string
	Name            string
	DisplayName     string
	Initials        string
	Phone           *string
	Email           *string
	Language        Language
	PreferredVaBank *Bank
	VoiceHelp       bool
	Roles           []Role
	Consents        *Consents
	CreatedAt       *time.Time

	// Not in the schema: what the field resolvers need to know about the session
	// this `Me` was read through.
	SessionID   string
	SessionRole Role
}
