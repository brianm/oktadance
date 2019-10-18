package oktadance

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/http/httputil"
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

// WithLogger Pass in a logging function, such as `log.Println`
func WithLogger(log func(...interface{})) Option {
	return option(func(d *Dance) {
		d.logger = log
	})
}

// WithPrettyJSON forces pretty printed JSON on requests
// and in logs
func WithPrettyJSON() Option {
	return option(func(d *Dance) {
		d.prettyJSON = true
	})
}

// Dance performs the authentication & authorization dance
// with Okta
type Dance struct {
	httpClient *http.Client
	appID      string
	oktaDomain string
	clientID   string
	logger     func(...interface{})
	prettyJSON bool
}

// New dance client. If you need to use `Authenticate` make sure to
// pass in a clientID option via `WithClientID`
func New(oktaDomain string, options ...Option) *Dance {
	d := &Dance{
		oktaDomain: oktaDomain,
		logger:     nil,
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
func (d *Dance) Authenticate(ctx context.Context, username, password string, mfa MultiFactor) (SessionToken, error) {
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

	req = req.WithContext(ctx)
	d.pre("Authenticate", req)
	res, err := d.httpClient.Do(req)
	if err != nil {
		return "", err
	}
	defer res.Body.Close()
	d.post("Authenticate", res)

	rb, err := ioutil.ReadAll(res.Body)
	if err != nil {
		return "", err
	}

	ar := oktaUserAuthn{}
	err = json.Unmarshal(rb, &ar)
	if err != nil {
		return "", err
	}

	if ar.Status == "MFA_REQUIRED" {
		var factor Factor
		if len(ar.Embedded.Factors) == 1 {
			factor = ar.Embedded.Factors[0].factor()
		} else if len(ar.Embedded.Factors) == 0 {
			return "", errors.New("MFA needed but no factoirs available")
		} else {
			factors := ar.Embedded.factors()
			factor, err = mfa.Select(factors)
			if err != nil {
				return "", fmt.Errorf("error selecting MFA factor: %w", err)
			}
			if factor == nil {
				return "", errors.New("no MFA was factor selected")
			}
			if factor == nil {
				return "", errors.New("a factor was returned which was not passed in")
			}
		}

		if factor == nil {
			return "", errors.New("MFA required but no factor selected")
		}

		return factor.perform(d, mfa, ar.StateToken)
	}

	if ar.Status != "SUCCESS" {
		return "", fmt.Errorf("Status: %s", ar.Status)
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

	d.pre("Authorize", req)
	res, err := d.httpClient.Do(req.WithContext(ctx))
	if err != nil {
		return "", err
	}
	defer res.Body.Close()
	d.post("Authorize", res)
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

	d.pre("Session", req)
	res, err := d.httpClient.Do(req.WithContext(ctx))
	if err != nil {
		return nil, err
	}
	defer res.Body.Close()
	d.post("Session", res)

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

	d.pre("CloseSession", req)
	res, err := d.httpClient.Do(req.WithContext(ctx))
	if err != nil {
		return err
	}
	defer res.Body.Close()
	d.post("CloseSession", res)

	if res.StatusCode >= 300 {
		body, _ := ioutil.ReadAll(res.Body)
		return fmt.Errorf("Error closing session, status %d: %s", res.StatusCode, string(body))
	}

	return nil
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

func (d *Dance) pre(name string, req *http.Request) error {
	if d.prettyJSON && req.Body != nil {
		body, err := ioutil.ReadAll(req.Body)
		if err != nil {
			return err
		}
		s := map[string]interface{}{}
		err = json.Unmarshal(body, &s)
		body, err = json.MarshalIndent(s, "", "  ")
		if err != nil {
			return err
		}
		req.Body = ioutil.NopCloser(bytes.NewBuffer(body))
		req.ContentLength = int64(len(body))
	}

	if d.logger == nil {
		return nil
	}

	dmp, err := httputil.DumpRequest(req, true)
	if err != nil {
		return err
	}

	d.logger(name, string(dmp))
	return nil
}

func (d *Dance) post(name string, res *http.Response) error {
	if d.prettyJSON && res.Body != nil {
		body, err := ioutil.ReadAll(res.Body)
		if err != nil {
			return err
		}
		s := map[string]interface{}{}
		err = json.Unmarshal(body, &s)
		body, err = json.MarshalIndent(s, "", "  ")
		if err != nil {
			return err
		}
		res.Body = ioutil.NopCloser(bytes.NewBuffer(body))
	}

	if d.logger == nil {
		return nil
	}

	dmp, err := httputil.DumpResponse(res, true)
	if err != nil {
		return err
	}

	d.logger(name, string(dmp))
	return nil
}
