// Copyright 2011 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

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

const activities = "https://www.googleapis.com/buzz/v1/activities/@me/@public?max-results=1"

func main() {
	flag.Parse()
	rt := &oauth.Transport{
		ClientId:     *clientId,
		ClientSecret: *clientSecret,
		Scope:        "https://www.googleapis.com/auth/buzz",
		AuthURL:      "https://accounts.google.com/o/oauth2/auth",
		TokenURL:     "https://accounts.google.com/o/oauth2/token",
	}
	if *code == "" && *token == "" {
		url := rt.AuthorizeURL()
		fmt.Println("Visit this URL to get a code:")
		fmt.Println(url)
		return
	}
	if *token == "" {
		_, err := rt.Exchange(*code)
		if err != nil {
			log.Fatal(err)
		}
	} else {
		rt.Credentials = &oauth.Credentials{
			AccessToken: *token,
		}
	}
	c := &http.Client{rt}
	r, _, err := c.Get(activities)
	if err != nil {
		log.Fatal(err)
	}
	io.Copy(os.Stdout, r.Body)
	r.Body.Close()
	fmt.Println()
	fmt.Println("Access Token:", rt.Credentials.AccessToken)
}
