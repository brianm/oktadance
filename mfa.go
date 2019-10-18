package oktadance

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"net/http"
	"time"
)

// Factor identifies a factor
type Factor interface {
	ID() string
	FactorType() string
	Provider() string

	perform(*Dance, Multifactor, string) (SessionToken, error)
}

// Multifactor responds to MFA requests
type Multifactor interface {

	// Select the factor to use for the challenge
	Select([]Factor) (Factor, error)

	// Obtain the MFA code
	ReadCode(Factor) (string, error)
}

type factor struct {
	id, provider, factorType string
}

func (f factor) ID() string         { return f.id }
func (f factor) Provider() string   { return f.provider }
func (f factor) FactorType() string { return f.factorType }

func (o oktaUserAuthnFactor) factor() Factor {
	if o.FactorType == "push" {
		return pushFactor{factor{o.ID, o.Provider, o.FactorType}}
	} else {
		return inputFactor{factor{o.ID, o.Provider, o.FactorType}}
	}
}

type inputFactor struct {
	factor
}

func (f inputFactor) perform(d *Dance, m Multifactor, stateToken string) (SessionToken, error) {
	for {
		vu := fmt.Sprintf("https://%s/api/v1/authn/factors/%s/verify", d.oktaDomain, f.ID())
		req, err := http.NewRequest("POST", vu, nil)
		if err != nil {
			return "", err
		}

		code, err := m.ReadCode(f)
		if err != nil {
			return "", fmt.Errorf("error reading MFA input: %w", err)
		}

		state := map[string]interface{}{
			"stateToken": stateToken,
			"passCode":   code,
		}
		buf, err := json.Marshal(state)
		if err != nil {
			return "", err
		}
		req.Header.Add("Content-type", "application/json")
		req.Header.Add("Accept", "application/json")
		req.Body = ioutil.NopCloser(bytes.NewBuffer(buf))

		d.pre("performMFA", req)
		res, err := d.httpClient.Do(req)
		if err != nil {
			return "", err
		}
		defer res.Body.Close()
		d.post("performMFA", res)

		buf, err = ioutil.ReadAll(res.Body)
		if err != nil {
			return "", err
		}

		auth := oktaUserAuthn{}
		json.Unmarshal(buf, &auth)
		if auth.Status == "SUCCESS" {
			return SessionToken(auth.SessionToken), nil
		}
		if auth.Status != "MFA_CHALLENGE" {
			return "", errors.New(string(buf))
		}
		stateToken = auth.StateToken
		time.Sleep(2 * time.Second)
	}
}

type pushFactor struct {
	factor
}

func (f pushFactor) perform(d *Dance, _ Multifactor, stateToken string) (SessionToken, error) {
	for {
		vu := fmt.Sprintf("https://%s/api/v1/authn/factors/%s/verify", d.oktaDomain, f.ID())
		req, err := http.NewRequest("POST", vu, nil)
		if err != nil {
			return "", err
		}

		state := map[string]interface{}{
			"stateToken": stateToken,
		}
		buf, err := json.Marshal(state)
		if err != nil {
			return "", err
		}
		req.Header.Add("Content-type", "application/json")
		req.Header.Add("Accept", "application/json")
		req.Body = ioutil.NopCloser(bytes.NewBuffer(buf))

		d.pre("performMFA", req)
		res, err := d.httpClient.Do(req)
		if err != nil {
			return "", err
		}
		defer res.Body.Close()
		d.post("performMFA", res)

		buf, err = ioutil.ReadAll(res.Body)
		if err != nil {
			return "", err
		}

		auth := oktaUserAuthn{}
		json.Unmarshal(buf, &auth)
		if auth.Status == "SUCCESS" {
			return SessionToken(auth.SessionToken), nil
		}
		if auth.Status != "MFA_CHALLENGE" {
			return "", errors.New(string(buf))
		}
		stateToken = auth.StateToken
		time.Sleep(2 * time.Second)
	}
}
