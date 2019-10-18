package main

import (
	"context"
	"fmt"
	"os"
	"strings"

	"github.com/brianm/oktadance"
	"github.com/chzyer/readline"
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

	rl, err := readline.New("")
	if err != nil {
		return err
	}

	rl.SetPrompt("username: ")
	username, err := rl.Readline()
	if err != nil {
		return err
	}
	username = strings.TrimSpace(username)

	password, err := rl.ReadPassword("password: ")
	if err != nil {
		return err
	}
	pass := strings.TrimSpace(string(password))

	okta := oktadance.New(domain, oktadance.WithClientID(clientID))

	mfa, err := oktadance.NewConsoleMultifactor()
	if err != nil {
		return err
	}

	sessionToken, err := okta.Authenticate(ctx, username, pass, mfa)
	if err != nil {
		return err
	}

	sid, err := okta.Authorize(ctx, sessionToken)
	if err != nil {
		return err
	}

	fmt.Printf("sid=%s\n", sid)

	err = okta.CloseSession(ctx, sid)
	if err != nil {
		return err
	}

	return nil
}
