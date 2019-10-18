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

	sessionToken, err := okta.Authenticate(ctx, username, pass, Console{rl})
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

// Console handles the user input
type Console struct {
	*readline.Instance
}

// Select the factor to use for the challenge
func (c Console) Select(factors []oktadance.Factor) (oktadance.Factor, error) {
	fm := map[string]oktadance.Factor{}
	options := []readline.PrefixCompleterInterface{}
	fs := []string{}
	for _, f := range factors {
		options = append(options, readline.PcItem(f.FactorType()))
		fs = append(fs, f.FactorType())
		fm[f.FactorType()] = f
	}

	completer := readline.NewPrefixCompleter(options...)
	c.Config.AutoComplete = completer
	c.SetPrompt(fmt.Sprintf("factor [%s]: ", strings.Join(fs, ", ")))
	choice, err := c.Readline()
	if err != nil {
		return nil, err
	}
	choice = strings.TrimSpace(choice)

	return fm[choice], nil
}

func (c Console) ReadCode(oktadance.Factor) (string, error) {
	c.SetPrompt("code: ")
	code, err := c.Readline()
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(code), nil
}
