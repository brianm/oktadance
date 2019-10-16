package oktadance

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/url"
	"time"
)

// SessionToken is an OKTA sessionToken
type SessionToken string

// SessionID is an OKTA sessionId or sid
type SessionID string

// Option configures the dance
type Option interface {
	apply(*Dance)
}

type option func(*Dance)

func (f option) apply(a *Dance) {
	f(a)
}

// WithClientID configures a clientID on the dance. This is needed for
// some operations. Those operations call it out. If all you are doing
// is authenticating, you should not need the client_id
func WithClientID(clientID string) Option {
	return option(func(d *Dance) {
		d.clientID = clientID
	})
}

// WithHTTPClient allows you to specify your own http client.
// it is critical that this client be configured to not follow
// redirects:
// ```
// httpClient := &http.Client{
//     CheckRedirect: func(req *http.Request, via []*http.Request) error {
//         return http.ErrUseLastResponse
//     },
// }
// ```
func WithHTTPClient(hc *http.Client) Option {
	return option(func(d *Dance) {
		d.httpClient = hc
	})
}

// Dance performs the authentication & authorization dance
// with Okta
type Dance struct {
	httpClient *http.Client
	oktaDomain string
	clientID   string
}

// New dance client. If you need to use `Authenticate` make sure to
// pass in a clientID option via `WithClientID`
func New(oktaDomain string, options ...Option) *Dance {
	d := &Dance{
		oktaDomain: oktaDomain,
	}

	for _, o := range options {
		o.apply(d)
	}

	if d.httpClient == nil {
		d.httpClient = &http.Client{
			CheckRedirect: func(req *http.Request, via []*http.Request) error {
				return http.ErrUseLastResponse
			},
		}
	}

	return d
}

// Authenticate authenticates the user against Okta and returns a sessionToken.
// The sessionToken needs to be given to the App which will then use `Authenticate`
// to authenticate the user for that App. The sessionToken is only usable once.
func (d *Dance) Authenticate(ctx context.Context, username, password string) (SessionToken, error) {
	body, err := json.Marshal(map[string]string{
		"username": username,
		"password": password,
	})
	if err != nil {
		return "", err
	}

	req, err := http.NewRequest(
		"POST",
		fmt.Sprintf("https://%s/api/v1/authn", d.oktaDomain),
		bytes.NewReader(body),
	)
	if err != nil {
		return "", err
	}

	req.Header["Content-type"] = []string{"application/json"}
	req.Header["Accept"] = []string{"application/json"}

	res, err := d.httpClient.Do(req.WithContext(ctx))
	if err != nil {
		return "", err
	}
	defer res.Body.Close()

	rb, err := ioutil.ReadAll(res.Body)
	if err != nil {
		return "", err
	}

	ar := authnResponse{}
	err = json.Unmarshal(rb, &ar)
	if err != nil {
		return "", err
	}

	return SessionToken(ar.SessionToken), nil
}

// Authorize establishes the session and returns the sid. It
// ensures the authentication token (sessionToken) is valid
// for the specific App (as identified by the clientId)
//
// This method reuires a configured clientID as it verifies
// the pairing of the authenticated user and the application.
func (d *Dance) Authorize(ctx context.Context, sessionToken SessionToken) (SessionID, error) {
	u, err := url.Parse(fmt.Sprintf("https://%s/oauth2/v1/authorize", d.oktaDomain))
	if err != nil {
		return "", err
	}

	q := u.Query()
	q.Add("client_id", d.clientID)
	q.Add("redirect_uri", "https://epithet.io/okta-callback")
	q.Add("sessionToken", string(sessionToken))
	q.Add("prompt", "none")
	q.Add("response_type", "id_token")
	q.Add("scope", "openid")
	//q.Add("nonce", "waffles")
	//q.Add("state", "fuzzy")

	u.RawQuery = q.Encode()

	req, err := http.NewRequest("GET", u.String(), nil)
	if err != nil {
		return "", err
	}
	req.Header["Accept"] = []string{"application/json"}

	res, err := d.httpClient.Do(req.WithContext(ctx))
	if err != nil {
		return "", err
	}
	defer res.Body.Close()
	if res.StatusCode >= 400 {
		buf, _ := ioutil.ReadAll(res.Body)
		return "", errors.New(string(buf))
	}

	sid := ""
	for _, c := range res.Cookies() {
		if c.Name == "sid" {
			sid = c.Value
		}
	}

	return SessionID(sid), nil
}

// Session retrieves the user session information from Okta for a
// given SessionID (obtained via `Authenticate`). It can be run
// from an untrusted client, if that client has the sessionId. The
// sessionId is often referred to as the session cookie or sid.
func (d *Dance) Session(ctx context.Context, sessionID SessionID) (*Session, error) {
	u := fmt.Sprintf("https://%s/api/v1/sessions/me", d.oktaDomain)
	req, err := http.NewRequest("GET", u, nil)
	if err != nil {
		return nil, err
	}
	req.AddCookie(&http.Cookie{
		Name:  "sid",
		Value: string(sessionID),
	})

	res, err := d.httpClient.Do(req.WithContext(ctx))
	if err != nil {
		return nil, err
	}
	defer res.Body.Close()

	body, err := ioutil.ReadAll(res.Body)
	if err != nil {
		return nil, err
	}

	sess := &Session{}
	err = json.Unmarshal(body, sess)
	if err != nil {
		return nil, err
	}

	return sess, nil

}

// CloseSession closes the specified session
func (d *Dance) CloseSession(ctx context.Context, sessionID SessionID) error {
	u := fmt.Sprintf("https://%s/api/v1/sessions/me", d.oktaDomain)
	req, err := http.NewRequest("DELETE", u, nil)
	if err != nil {
		return err
	}
	req.AddCookie(&http.Cookie{
		Name:  "sid",
		Value: string(sessionID),
	})

	res, err := d.httpClient.Do(req.WithContext(ctx))
	if err != nil {
		return err
	}
	defer res.Body.Close()

	if res.StatusCode >= 300 {
		body, _ := ioutil.ReadAll(res.Body)
		return fmt.Errorf("Error closing session, status %d: %s", res.StatusCode, string(body))
	}

	return nil
}

type authnResponse struct {
	SessionToken string `json:"sessionToken"`
}

// Session is an OKTA Session, see
// [Session Model](https://developer.okta.com/docs/reference/api/sessions/#session-model)
type Session struct {
	ID                       string    `json:"id"`
	UserID                   string    `json:"userId"`
	Login                    string    `json:"login"`
	CreatedAt                time.Time `json:"createdAt"`
	ExpiresAt                time.Time `json:"expiresAt"`
	Status                   string    `json:"status"`
	LastPasswordVerification time.Time `json:"lastPasswordVerification"`
	LastFactorVerification   time.Time `json:"lastFactorVerification"`
	Amr                      []string  `json:"amr"`
	Idp                      struct {
		ID   string `json:"id"`
		Type string `json:"type"`
	} `json:"idp"`
	MfaActive bool `json:"mfaActive"`
	Links     struct {
		Self struct {
			Href  string `json:"href"`
			Hints struct {
				Allow []string `json:"allow"`
			} `json:"hints"`
		} `json:"self"`
		Refresh struct {
			Href  string `json:"href"`
			Hints struct {
				Allow []string `json:"allow"`
			} `json:"hints"`
		} `json:"refresh"`
		User struct {
			Name  string `json:"name"`
			Href  string `json:"href"`
			Hints struct {
				Allow []string `json:"allow"`
			} `json:"hints"`
		} `json:"user"`
	} `json:"_links"`
}
