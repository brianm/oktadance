package oktadance_test

import (
	"context"
	"errors"
	"log"
	"os"
	"testing"

	"github.com/brianm/oktadance"
	"github.com/stretchr/testify/require"
)

func TestDance_Authenticate_NoMFA(t *testing.T) {
	ctx := context.Background()
	require := require.New(t)
	oktaDomain, ok := os.LookupEnv("OKTA_DOMAIN")
	require.True(ok, "must set $OKTA_DOMAIN to a valid okta domain to run this test")

	user, ok := os.LookupEnv("OKTA_USER")
	require.True(ok, "must set $OKTA_USER to a valid okta user (email) for this test")

	pass, ok := os.LookupEnv("OKTA_PASS")
	require.True(ok, "must set $OKTA_PASS to a valid okta password for $OKTA_USER")

	d := oktadance.New(
		oktaDomain,
		//oktadance.WithLogger(log.Println),
	)

	sessionToken, err := d.Authenticate(ctx, user, pass, nil)
	require.NoError(err)

	require.NotEmpty(sessionToken)
}

func TestDance_WholeFlow_NoMFA(t *testing.T) {
	ctx := context.Background()
	require := require.New(t)
	oktaDomain, ok := os.LookupEnv("OKTA_DOMAIN")
	require.True(ok, "must set $OKTA_DOMAIN to a valid okta domain to run this test")

	user, ok := os.LookupEnv("OKTA_USER")
	require.True(ok, "must set $OKTA_USER to a valid okta user (email) for this test")

	pass, ok := os.LookupEnv("OKTA_PASS")
	require.True(ok, "must set $OKTA_PASS to a valid okta password for $OKTA_USER")

	clientId, ok := os.LookupEnv("OKTA_CLIENT_ID")
	require.True(ok, "must set $OKTA_CLIENT_ID to a valid okta clientId")

	d := oktadance.New(
		oktaDomain,
		oktadance.WithClientID(clientId),
		//oktadance.WithLogger(log.Println),
	)

	sessionToken, err := d.Authenticate(ctx, user, pass, nil)
	require.NoError(err)

	sessionID, err := d.Authorize(ctx, sessionToken)
	require.NoError(err)

	it, err := d.Session(ctx, sessionID)
	require.NoError(err)

	require.Equal(user, it.Login)

	it, err = d.Session(ctx, sessionID)
	require.NoError(err)

	require.Equal(user, it.Login)

	err = d.CloseSession(ctx, sessionID)
	require.NoError(err)
}

func TestDance_WholeFlow_MFA(t *testing.T) {
	ctx := context.Background()
	require := require.New(t)
	oktaDomain, ok := os.LookupEnv("OKTA_DOMAIN")
	require.True(ok, "must set $OKTA_DOMAIN to a valid okta domain to run this test")

	user, ok := os.LookupEnv("OKTA_MFA_USER")
	require.True(ok, "must set $OKTA_MFA_USER to a valid okta user (email) for this test")

	pass, ok := os.LookupEnv("OKTA_MFA_PASS")
	require.True(ok, "must set $OKTA_MFA_PASS to a valid okta password for $OKTA_MFA_USER")

	clientId, ok := os.LookupEnv("OKTA_MFA_CLIENT_ID")
	require.True(ok, "must set $OKTA_MFA_CLIENT_ID to a valid okta clientId")

	d := oktadance.New(
		oktaDomain,
		oktadance.WithClientID(clientId),
		oktadance.WithLogger(log.Println),
		oktadance.WithPrettyJSON(),
	)

	sessionToken, err := d.Authenticate(ctx, user, pass, testMFA{})
	require.NoError(err)

	sessionID, err := d.Authorize(ctx, sessionToken)
	require.NoError(err)

	it, err := d.Session(ctx, sessionID)
	require.NoError(err)

	require.Equal(user, it.Login)

	it, err = d.Session(ctx, sessionID)
	require.NoError(err)

	require.Equal(user, it.Login)

	err = d.CloseSession(ctx, sessionID)
	require.NoError(err)
}

type testMFA struct{}

func (t testMFA) Select(factors []oktadance.Factor) (oktadance.Factor, error) {
	for _, f := range factors {
		log.Printf("factorType: %s", f.FactorType())
		if f.FactorType() == "push" {
			return f, nil
		}
	}
	return nil, errors.New("test requires push type")
}
