package main

import (
	"context"
	"fmt"
	"os"
	"time"

	"github.com/brianm/oktadance"
)

func main() {
	clientID, ok := os.LookupEnv("OKTA_CLIENT_ID")
	if !ok {
		fmt.Fprintln(os.Stderr, "must set $OKTA_CLIENT_ID to the clientId for the app")
		os.Exit(1)
	}

	if len(os.Args) != 2 {
		fmt.Fprintf(os.Stderr, "Usage: %s OKTA_DOMAIN\n", os.Args[0])
		os.Exit(1)
	}

	err := run(clientID, os.Args[1])
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func run(clientID, domain string) error {
	ctx := context.Background()

	mfa, err := oktadance.NewConsoleMultifactor()
	if err != nil {
		return err
	}

	username, password, err := mfa.RequestUsernamePassword()
	if err != nil {
		return err
	}

	okta := oktadance.New(domain, oktadance.WithClientID(clientID))

	sessionToken, err := okta.Authenticate(ctx, username, password, mfa)
	if err != nil {
		return err
	}

	sid, err := okta.Authorize(ctx, sessionToken)
	if err != nil {
		return err
	}

	sess, err := okta.Session(ctx, sid)
	if err != nil {
		return err
	}

	d := time.Until(sess.ExpiresAt)
	fmt.Printf("sid\t%s\n", sid)
	fmt.Printf("expires\t%s\n", d)

	err = okta.CloseSession(ctx, sid)
	if err != nil {
		return err
	}

	return nil
}
