package oktadance_test

import (
	"context"
	"os"
	"testing"

	"github.com/brianm/oktadance"
	"github.com/stretchr/testify/require"
)

func TestDance_WholeFlow(t *testing.T) {
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

	d := oktadance.New(oktaDomain, oktadance.WithClientID(clientId))

	sessionToken, err := d.Authenticate(ctx, user, pass)
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

func TestDance_Authenticate(t *testing.T) {
	ctx := context.Background()
	require := require.New(t)
	oktaDomain, ok := os.LookupEnv("OKTA_DOMAIN")
	require.True(ok, "must set $OKTA_DOMAIN to a valid okta domain to run this test")

	user, ok := os.LookupEnv("OKTA_USER")
	require.True(ok, "must set $OKTA_USER to a valid okta user (email) for this test")

	pass, ok := os.LookupEnv("OKTA_PASS")
	require.True(ok, "must set $OKTA_PASS to a valid okta password for $OKTA_USER")

	d := oktadance.New(oktaDomain)

	sessionToken, err := d.Authenticate(ctx, user, pass)
	require.NoError(err)

	require.NotEmpty(sessionToken)
}
