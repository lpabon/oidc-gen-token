/*
Copyright 2018 Luis Pabón <lpabon@gmail.com>

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

        http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/
// Lot of this content is borrowed from https://github.com/coreos/go-oidbc/examples

package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"math/rand"
	"net/http"
	"os"
	"os/user"
	"path"
	"time"

	oidc "github.com/coreos/go-oidc/v3/oidc"

	"golang.org/x/oauth2"
)

type cliConfig struct {
	clientID     string
	clientSecret string
	issuer       string
	port         string
	saveToken    bool
	daemon       bool
	tokenFile    string
}

var (
	cfg         cliConfig
	usr, _      = user.Current()
	letterRunes = []rune("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ")
)

func randStringRunes(n int) string {
	b := make([]rune, n)
	for i := range b {
		b[i] = letterRunes[rand.Intn(len(letterRunes))]
	}
	return string(b)
}

func init() {
	rand.Seed(time.Now().UnixNano())
	cfg.tokenFile = usr.HomeDir + "/.oidc/token"

	flagset := flag.NewFlagSet(os.Args[0], flag.ExitOnError)
	flagset.StringVar(&cfg.clientID, "client-id", "", "Token issuer client id")
	flagset.StringVar(&cfg.clientSecret, "client-secret", "", "Token issuer client secret")
	flagset.StringVar(&cfg.issuer, "issuer", "", "Token issuer, e.g. https://accounts.google.com")
	flagset.StringVar(&cfg.port, "port", "5556", "Local port number for oidc-gen-token web url location")
	flagset.BoolVar(&cfg.saveToken, "save-token", false, "Save the token to a file. Default is not to save")
	flagset.StringVar(&cfg.tokenFile, "token-file", cfg.tokenFile, "Name of the file to save token")
	flagset.BoolVar(&cfg.daemon, "daemon", false, "Run continously. Cannot be used with save-token")
	flagset.Parse(os.Args[1:])

	if clientID := os.Getenv("OIDC_CLIENT_ID"); len(clientID) != 0 {
		cfg.clientID = clientID
	}
	if clientSecret := os.Getenv("OIDC_CLIENT_SECRET"); len(clientSecret) != 0 {
		cfg.clientSecret = clientSecret
	}
}

func main() {

	// Check arguments
	if len(cfg.issuer) == 0 {
		fmt.Println("Must provide an issuer")
		os.Exit(1)
	} else if len(cfg.clientID) == 0 {
		fmt.Println("Must provide a client id")
		os.Exit(1)
	} else if len(cfg.clientSecret) == 0 {
		fmt.Println("Must provide a client secret")
		os.Exit(1)
	} else if cfg.daemon && cfg.saveToken {
		fmt.Println("Cannot set both daemon and saveToken")
		os.Exit(1)
	}

	ctx := context.Background()
	provider, err := oidc.NewProvider(ctx, cfg.issuer)
	if err != nil {
		log.Fatal(err)
	}
	oidcConfig := &oidc.Config{
		ClientID: cfg.clientID,
	}
	verifier := provider.Verifier(oidcConfig)
	config := oauth2.Config{
		ClientID:     cfg.clientID,
		ClientSecret: cfg.clientSecret,
		Endpoint:     provider.Endpoint(),
		RedirectURL:  "http://127.0.0.1:" + cfg.port + "/auth/callback",
		Scopes:       []string{oidc.ScopeOpenID, "profile", "email"},
	}

	state := randStringRunes(16)
	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, config.AuthCodeURL(state), http.StatusFound)
	})

	http.HandleFunc("/auth/callback", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("state") != state {
			fmt.Printf("my state[%v] != returned state[%v]. URL: %v\n",
				state,
				r.URL.Query().Get("state"), r.URL)

			http.Error(w, "state did not match", http.StatusBadRequest)
			return
		}

		oauth2Token, err := config.Exchange(ctx, r.URL.Query().Get("code"))
		if err != nil {
			http.Error(w, "Failed to exchange token: "+err.Error(), http.StatusInternalServerError)
			return
		}
		rawIDToken, ok := oauth2Token.Extra("id_token").(string)
		if !ok {
			http.Error(w, "No id_token field in oauth2 token.", http.StatusInternalServerError)
			return
		}
		_, err = verifier.Verify(ctx, rawIDToken)
		if err != nil {
			http.Error(w, "Failed to verify ID Token: "+err.Error(), http.StatusInternalServerError)
			return
		}
		w.Write([]byte(`<html><head><style>
pre {
 overflow-x: auto; /* Use horizontal scroller if needed; for Firefox 2, not needed in Firefox 3 */
 white-space: pre-wrap; /* css-3 */
 white-space: -moz-pre-wrap !important; /* Mozilla, since 1999 */
 white-space: -pre-wrap; /* Opera 4-6 */
 white-space: -o-pre-wrap; /* Opera 7 */
 /* width: 99%; */
 word-wrap: break-word; /* Internet Explorer 5.5+ */
}</style></head>
		`))
		w.Write([]byte("<body><h1>Token</h1><br />"))
		w.Write([]byte(fmt.Sprintf("<pre>%s</pre>", rawIDToken)))
		w.Write([]byte("<br /><a href=\"/\">Get another token</a>"))
		w.Write([]byte("</body></head>"))

		if cfg.daemon {
			return
		}

		if cfg.saveToken {
			if err = os.MkdirAll(path.Dir(cfg.tokenFile), 0700); err != nil {
				fmt.Fprintf(os.Stderr, "Failed to create diretory for token file: %s", err)
				os.Exit(1)
			}

			f, err := os.OpenFile(cfg.tokenFile, os.O_TRUNC|os.O_CREATE|os.O_RDWR, 0600)
			if err != nil {
				fmt.Fprintf(os.Stderr, "Failed to create token file: %s", err)
				os.Exit(1)
			}

			f.Write([]byte(rawIDToken))
			fmt.Printf("Token saved on to %s\n", cfg.tokenFile)
			f.Close()

			go func() {
				time.Sleep(time.Second)
				os.Exit(0)
			}()
		}

		fmt.Println("Done")
	})

	log.Printf("listening on http://127.0.0.1:%s/", cfg.port)
	log.Fatal(http.ListenAndServe("127.0.0.1:"+cfg.port, nil))
}
