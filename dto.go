package oktadance

/*
From: https://github.com/segmentio/aws-okta/blob/47e49fc370584c1509fe378fdff232a63219ce0e/lib/struct.go


The MIT License (MIT)

Copyright © 2017 Segment

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in
all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
THE SOFTWARE.
*/

// http://developer.okta.com/docs/api/resources/authn.html
type oktaUser struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

type oktaStateToken struct {
	StateToken string `json:"stateToken"`
	PassCode   string `json:"passCode"`
}

type oktaUserAuthn struct {
	StateToken   string                `json:"stateToken"`
	SessionToken string                `json:"sessionToken"`
	ExpiresAt    string                `json:"expiresAt"`
	Status       string                `json:"status"`
	Embedded     oktaUserAuthnEmbedded `json:"_embedded"`
	FactorResult string                `json:"factorResult"`
}

type oktaUserAuthnEmbedded struct {
	Factors []oktaUserAuthnFactor `json:"factors"`
	Factor  oktaUserAuthnFactor   `json:"factor"`
}

func (ouae oktaUserAuthnEmbedded) factors() []Factor {
	rs := []Factor{}
	for _, f := range ouae.Factors {
		rs = append(rs, f.factor())
	}
	return rs
}

type oktaUserAuthnFactor struct {
	ID         string                      `json:"id"`
	FactorType string                      `json:"factorType"`
	Provider   string                      `json:"provider"`
	Embedded   oktaUserAuthnFactorEmbedded `json:"_embedded"`
	Profile    oktaUserAuthnFactorProfile  `json:"profile"`
}

type oktaUserAuthnFactorProfile struct {
	CredentialID string `json:"credentialId"`
	AppID        string `json:"appId"`
	Version      string `json:"version"`
}

type oktaUserAuthnFactorEmbedded struct {
	Verification oktaUserAuthnFactorEmbeddedVerification `json:"verification"`
	Challenge    oktaUserAuthnFactorEmbeddedChallenge    `json:"challenge"`
}

type oktaUserAuthnFactorEmbeddedVerification struct {
	Host         string                                       `json:"host"`
	Signature    string                                       `json:"signature"`
	FactorResult string                                       `json:"factorResult"`
	Links        oktaUserAuthnFactorEmbeddedVerificationLinks `json:"_links"`
}

type oktaUserAuthnFactorEmbeddedChallenge struct {
	Nonce           string `json:"nonce"`
	TimeoutSeconnds int    `json:"timeoutSeconds"`
}
type oktaUserAuthnFactorEmbeddedVerificationLinks struct {
	Complete oktaUserAuthnFactorEmbeddedVerificationLinksComplete `json:"complete"`
}

type oktaUserAuthnFactorEmbeddedVerificationLinksComplete struct {
	Href string `json:"href"`
}
