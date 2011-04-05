// Copyright 2011 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// The oauth package provides support for making
// OAuth2-authenticated HTTP requests.
package oauth

// TODO(adg): Documentation.

// BUG(adg): doesn't support refreshing Credentials when expired.

import (
	"http"
	"json"
	"log"
	"os"
	"time"
)

type Config struct {
	ClientId     string
	ClientSecret string
	Scope        string
	AuthURL      string
	TokenURL     string
	RedirectURL  string // Defaults to out-of-band mode if empty.

	// Transport is the HTTP transport to use.
	// It will default to http.DefaultTransport if nil.
	Transport http.RoundTripper
}

type Credentials struct {
	AccessToken  string "access_token"
	RefreshToken string "refresh_token"
	TokenExpiry  int64  "expires_in"
}

type Transport struct {
	*Config
	*Credentials
}

// AuthURL returns a URL that the end-user should be redirected to,
// so that they may obtain an code (that will be provided to Exchange).
func AuthURL(c *Config) string {
	url, err := http.ParseURL(c.AuthURL)
	if err != nil {
		panic("AuthURL malformed: " + err.String())
	}
	q := http.EncodeQuery(map[string][]string{
		"response_type": {"code"},
		"client_id":     {c.ClientId},
		"redirect_uri":  {c.redirectURL()},
		"scope":         {c.Scope},
	})
	if url.RawQuery == "" {
		url.RawQuery = q
	} else {
		url.RawQuery += "&" + q
	}
	return url.String()
}

// Exchange takes a code and gets access Credentials from the remote server.
// If successful, the Credentials will be stored in the Transport so that
// it may be used immediately to make authenticated requests as an
// http.RoundTripper.
func Exchange(c *Config, code string) (*Credentials, os.Error) {
	form := map[string]string{
		"grant_type":    "authorization_code",
		"client_id":     c.ClientId,
		"client_secret": c.ClientSecret,
		"redirect_uri":  c.redirectURL(),
		"scop":          c.Scope,
		"code":          code,
	}
	resp, err := (&http.Client{c.transport()}).PostForm(c.TokenURL, form)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != 200 {
		return nil, os.NewError("invalid response: " + resp.Status)
	}
	cred := new(Credentials)
	defer resp.Body.Close()
	if err = json.NewDecoder(resp.Body).Decode(cred); err != nil {
		return nil, err
	}
	if cred.TokenExpiry != 0 {
		cred.TokenExpiry = time.Seconds() + cred.TokenExpiry
	}
	return cred, nil
}

// RoundTrip executes a single HTTP transaction using the Transport's
// Credentials as authorization headers.
func (t *Transport) RoundTrip(req *http.Request) (resp *http.Response, err os.Error) {
	if t.Credentials == nil {
		return nil, os.NewError("no Credentials supplied")
	}

	// Set OAuth header
	req.Header.Set("Authorization", "OAuth "+t.AccessToken)

	// Make the HTTP request
	if resp, err = t.transport().RoundTrip(req); err != nil {
		return
	}

	if resp.StatusCode == 401 {
		// TODO(adg): Refresh credentials if we get a 401
		log.Println("Token refresh required")
	}

	return
}

func (c *Config) transport() http.RoundTripper {
	if c.Transport != nil {
		return c.Transport
	}
	return http.DefaultTransport
}

func (c *Config) redirectURL() string {
	if c.RedirectURL != "" {
		return c.RedirectURL
	}
	return "oob"
}
