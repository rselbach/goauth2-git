// Copyright 2011 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// The oauth package provides support for making
// OAuth2-authenticated HTTP requests.
package oauth

// TODO(adg): A means of automatically saving credentials when updated.

import (
	"http"
	"json"
	"os"
	"time"
)

// Config is the configuration of an OAuth consumer.
type Config struct {
	ClientId     string
	ClientSecret string
	Scope        string
	AuthURL      string
	TokenURL     string
	RedirectURL  string // Defaults to out-of-band mode if empty.

	// Transport is the HTTP transport to use when making requests.
	// It will default to http.DefaultTransport if nil.
	// (It should never be an oauth.Transport.)
	Transport http.RoundTripper
}

// Credentials contain an end-user's tokens.
// This is the data you must store to persist authentication.
type Credentials struct {
	AccessToken  string "access_token"
	RefreshToken string "refresh_token"
	TokenExpiry  int64  "expires_in"
}

// Transport implements http.RoundTripper. When configured with a valid
// Config and Credentials it can be used to make authenticated HTTP requests.
//
//	t := &oauth.Transport{config, credentials}
//	c := &http.Client{t}
//	r, _, err := c.Get("http://example.org/url/requiring/auth")
//	// etc
//
// It will automatically refresh the Credentials if it can,
// updating the supplied Credentials in place.
type Transport struct {
	*Config
	*Credentials
}

// AuthURL returns a URL that the end-user should be redirected to,
// so that they may obtain an authorization code.
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
func Exchange(c *Config, code string) (*Credentials, os.Error) {
	form := map[string]string{
		"grant_type":    "authorization_code",
		"client_id":     c.ClientId,
		"client_secret": c.ClientSecret,
		"redirect_uri":  c.redirectURL(),
		"scope":         c.Scope,
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
	if t.Config == nil {
		return nil, os.NewError("no Config supplied")
	}
	if t.Credentials == nil {
		return nil, os.NewError("no Credentials supplied")
	}

	// Make the HTTP request
	req.Header.Set("Authorization", "OAuth "+t.AccessToken)
	if resp, err = t.transport().RoundTrip(req); err != nil {
		return
	}

	// Refresh credentials if they're stale
	if resp.StatusCode == 401 {
		if err = t.refresh(); err != nil {
			return
		}
		resp, err = t.transport().RoundTrip(req)
	}

	return
}

func (t *Transport) refresh() os.Error {
	form := map[string]string{
		"grant_type":    "refresh_token",
		"client_id":     t.ClientId,
		"client_secret": t.ClientSecret,
		"refresh_token": t.RefreshToken,
	}
	resp, err := (&http.Client{t.transport()}).PostForm(t.TokenURL, form)
	if err != nil {
		return err
	}
	if resp.StatusCode != 200 {
		return os.NewError("invalid response: " + resp.Status)
	}
	defer resp.Body.Close()
	if err = json.NewDecoder(resp.Body).Decode(t.Credentials); err != nil {
		return err
	}
	if t.TokenExpiry != 0 {
		t.TokenExpiry = time.Seconds() + t.TokenExpiry
	}
	return nil

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
