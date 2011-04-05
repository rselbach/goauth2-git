// Copyright 2011 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// This program makes a call to the buzz API, authenticated with OAuth2.
package main

import (
	"flag"
	"fmt"
	"http"
	"io"
	"log"
	"os"

	"goauth2.googlecode.com/hg/oauth"
)

var (
	code         = flag.String("code", "", "Authorization Code")
	token        = flag.String("token", "", "Access Token")
	clientId     = flag.String("id", "", "Client ID")
	clientSecret = flag.String("secret", "", "Client Secret")
)

const usageMsg = `
You must specify at least -id and -secret.
To obtain these details, see the "OAuth 2 Credentials" section under
the "API Access" tab on this page: https://code.google.com/apis/console/
`

const activities = "https://www.googleapis.com/buzz/v1/activities/@me/@public?max-results=1&alt=json"

func main() {
	flag.Parse()
	if *clientId == "" || *clientSecret == "" {
		flag.Usage()
		fmt.Fprint(os.Stderr, usageMsg)
		return
	}

	// Set up a Transport for making OAuth2-authenticated calls
	rt := &oauth.Transport{
		ClientId:     *clientId,
		ClientSecret: *clientSecret,
		Scope:        "https://www.googleapis.com/auth/buzz",
		AuthURL:      "https://accounts.google.com/o/oauth2/auth",
		TokenURL:     "https://accounts.google.com/o/oauth2/token",
	}

	// Step one, get an authorization code from the data provider.
	// ("Please ask the user if I can access this resource.")
	if *code == "" && *token == "" {
		url := rt.AuthorizeURL()
		fmt.Println("Visit this URL to get a code, then run again with -code=YOUR_CODE")
		fmt.Println(url)
		return
	}

	// Step two, exchange the authorization code for an access token.
	// ("Here's the code you gave the user, now give me a token!")
	if *token == "" {
		cred, err := rt.Exchange(*code)
		if err != nil {
			log.Fatal(err)
		}
		fmt.Printf("Now run again with -token=%s\n", cred.AccessToken)
		// We needn't return here; the Transport is actually all set
		// up with the right credentials by this point (making the
		// following 'rt.Credentials = ...' line redundant).
		// The process has been split up to demonstrate how one might
		// set up Credentials that have been stored elsewhere.
		return
	}

	// Step three, make the actual request using the token to authenticate.
	// ("Here's the token, let me in!")
	rt.Credentials = &oauth.Credentials{
		AccessToken: *token,
		// If you were storing this information somewhere,
		// you'd want to store the RefreshToken field as well.
	}
	c := &http.Client{rt}
	r, _, err := c.Get(activities)
	if err != nil {
		log.Fatal(err)
	}
	defer r.Body.Close()
	io.Copy(os.Stdout, r.Body)
	fmt.Println()
}
