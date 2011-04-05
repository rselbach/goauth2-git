// Copyright 2011 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// The oauth package provides support for making
// OAuth2-authenticated HTTP requests.
package oauth

// TODO(adg): Documentation.

// BUG(adg): doesn't support refreshing Credentials when expired.

import (
	"bytes"
	"http"
	"io/ioutil"
	"json"
	"log"
	"os"
	"time"
)

type Credentials struct {
	AccessToken  string "access_token"
	RefreshToken string "refresh_token"
	TokenExpiry  int64  "expires_in"
}

type Transport struct {
	ClientId     string
	ClientSecret string
	Scope        string
	UserAgent    string
	AuthURL      string
	TokenURL     string
	RedirectURL  string // may be empty for out-of-band mode

	// Credentials may be provided or nil.
	// If provided, the AuthorizeURL and Exchange steps may be skipped.
	Credentials *Credentials

	// Transport will default to http.DefaultTransport when nil.
	Transport http.RoundTripper
}

// AuthorizeURL returns a URL that the end-user should be redirected to,
// so that they may obtain an code (that will be provided to Exchange).
func (t *Transport) AuthorizeURL() string {
	url, err := http.ParseURL(t.AuthURL)
	if err != nil {
		panic("AuthURL malformed: " + err.String())
	}
	q := http.EncodeQuery(map[string][]string{
		"response_type": {"code"},
		"client_id":     {t.ClientId},
		"redirect_uri":  {t.redirectURL()},
		"scope":         {t.Scope},
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
func (t *Transport) Exchange(code string) (*Credentials, os.Error) {
	url, err := http.ParseURL(t.TokenURL)
	if err != nil {
		panic("TokenURL malformed: " + err.String())
	}
	body := new(bytes.Buffer)
	body.WriteString(http.EncodeQuery(map[string][]string{
		"grant_type":    {"authorization_code"},
		"client_id":     {t.ClientId},
		"client_secret": {t.ClientSecret},
		"redirect_uri":  {t.redirectURL()},
		"scop":          {t.Scope},
		"code":          {code},
	}))
	req := &http.Request{
		Method:        "POST",
		URL:           url,
		Host:          url.Host,
		ProtoMajor:    1,
		ProtoMinor:    1,
		Close:         true,
		UserAgent:     t.UserAgent,
		Body:          ioutil.NopCloser(body),
		ContentLength: int64(body.Len()),
		Header: http.Header{
			"User-Agent":   {t.UserAgent},
			"Content-Type": {"application/x-www-form-urlencoded"},
		},
	}
	resp, err := t.transport().RoundTrip(req)
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
	t.Credentials = cred
	return cred, nil
}

// RoundTrip executes a single HTTP transaction using the Transport's
// Credentials as authorization headers.
func (t *Transport) RoundTrip(req *http.Request) (resp *http.Response, err os.Error) {
	// Set OAuth headers
	if t.Credentials == nil {
		return nil, os.NewError("no Credentials supplied")
	}
	h := req.Header
	h.Set("Authorization", "OAuth "+t.Credentials.AccessToken)
	if ua := h.Get("User-Agent"); ua != "" {
		h.Set("User-Agent", t.UserAgent+" "+ua)
	} else {
		h.Set("User-Agent", t.UserAgent)
	}

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

func (t *Transport) transport() http.RoundTripper {
	if t.Transport != nil {
		return t.Transport
	}
	return http.DefaultTransport
}

func (t *Transport) redirectURL() string {
	if t.RedirectURL != "" {
		return t.RedirectURL
	}
	return "oob"
}
