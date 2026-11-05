// Command staff provisions ops staff accounts. The contract has no mutation for
// it: staff are added by an operator with database access.
//
//	staff add -email arif@renora.id -name Arif -role lead -permissions read_money,decide_cases
//	staff authenticator -email arif@renora.id
//
// `authenticator` prints an otpauth:// URI for the person to scan into their
// authenticator app (turn it into a QR code with any QR tool). Hand it over in
// person or over a channel only they can read: it is the second factor. Running
// it again replaces the previous authenticator.
//
// It needs DATABASE_URL and the same AUTH_SECRET as the api, which seals the
// authenticator secret.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"strings"
	"syscall"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/renora/renora-api/internal/account"
)

const usage = "usage: staff add -email E -name N -role R [-permissions p1,p2] | staff authenticator -email E"

func main() {
	if err := run(os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, "staff:", err)
		os.Exit(1)
	}
}

func run(args []string) error {
	if len(args) == 0 {
		return errors.New(usage)
	}
	dsn, secret := os.Getenv("DATABASE_URL"), os.Getenv("AUTH_SECRET")
	if dsn == "" {
		return errors.New("DATABASE_URL is required")
	}
	if len(secret) < 32 {
		return errors.New("AUTH_SECRET must be the api's secret (at least 32 bytes)")
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	pool, err := pgxpool.New(ctx, dsn)
	if err != nil {
		return err
	}
	defer pool.Close()
	svc := account.New(account.Options{Pool: pool, Secret: []byte(secret)})

	fs := flag.NewFlagSet(args[0], flag.ContinueOnError)
	email := fs.String("email", "", "work email")
	switch args[0] {
	case "add":
		name := fs.String("name", "", "full name")
		role := fs.String("role", "", "mediator, support, finance, lead or verification")
		perms := fs.String("permissions", "", "comma-separated: read_money, retry_payouts, decide_cases, verify_users, edit_price_book, reply_support")
		if err := fs.Parse(args[1:]); err != nil {
			return err
		}
		var list []string
		for p := range strings.SplitSeq(*perms, ",") {
			if p = strings.TrimSpace(p); p != "" {
				list = append(list, p)
			}
		}
		id, err := svc.AddStaff(ctx, account.NewStaff{Email: *email, Name: *name, Role: *role, Permissions: list})
		if err != nil {
			return err
		}
		fmt.Printf("staff %s saved (%s). Next: staff authenticator -email %s\n", *email, id, *email)
	case "authenticator":
		if err := fs.Parse(args[1:]); err != nil {
			return err
		}
		uri, err := svc.EnrollAuthenticator(ctx, *email)
		if err != nil {
			return err
		}
		fmt.Println(uri)
	default:
		return errors.New(usage)
	}
	return nil
}
