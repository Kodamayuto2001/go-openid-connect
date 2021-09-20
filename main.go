package main

import (
	"github.com/coreos/go-oidc"
	"golang.org/x/oauth2"
	"net/http"
	"log"
	"github.com/joho/godotenv"
	"os"

	"crypto/rand"
    "encoding/base64"
	"fmt"
)

func randomString() string {
	c := 40
    b := make([]byte, c)
    rand.Read(b)

    return base64.URLEncoding.EncodeToString(b)
}

func main(){
	err := godotenv.Load()
	if err != nil {
		log.Fatal(err)
	}

	issuer := "https://" + os.Getenv("DOMAIN") + "/";

	CLIENT_ID := os.Getenv("CLIENT_ID")
	CLIENT_SECRET := os.Getenv("CLIENT_SECRET")
	REDIRECT_URL := os.Getenv("REDIRECT_URL")

	STATE := randomString()

	http.HandleFunc("/auth",func(w http.ResponseWriter, r *http.Request){
		provider, err := oidc.NewProvider(r.Context(),issuer)

		if err != nil {
			log.Fatal(err)
		}

		config := oauth2.Config{
			ClientID:		CLIENT_ID,
			ClientSecret:	CLIENT_SECRET,
			Endpoint:		provider.Endpoint(),
			RedirectURL:	REDIRECT_URL,
			Scopes:			[]string{oidc.ScopeOpenID},
		}

		state := STATE

		authURL := config.AuthCodeURL(state)
		http.Redirect(w, r, authURL, http.StatusFound)
	})

	http.HandleFunc("/callback",func(w http.ResponseWriter, r *http.Request){
		ctx := r.Context()

		provider, err := oidc.NewProvider(ctx, issuer)
		
		if err != nil {
			log.Fatal(err)
		}

		config := oauth2.Config{
			ClientID:		CLIENT_ID,
			ClientSecret:	CLIENT_SECRET,
			Endpoint:		provider.Endpoint(),
			RedirectURL:	REDIRECT_URL,
			Scopes:			[]string{oidc.ScopeOpenID},
		}

		state := r.URL.Query().Get("state")
		fmt.Println(state)
		if state != STATE {
			// fmt.Println("クロスサイトリクエストフォージェリ（CSRF）")
			http.Error(w, "This request is not allowed.", http.StatusForbidden)
			return
		} else {
			fmt.Println("ok")
		}

		code := r.URL.Query().Get("code")
		oauth2Token, err := config.Exchange(ctx, code)
		if err != nil {
			http.Error(w, "Failed to exchange token: "+err.Error(), http.StatusInternalServerError)
			return
		}

		//	IDトークンを取り出す
		rawIDToken, ok := oauth2Token.Extra("id_token").(string)
		if !ok {
			http.Error(w, "missing token", http.StatusInternalServerError)
			return
		}

		oidcConfig := &oidc.Config{
			ClientID:	CLIENT_ID,
		}

		verifier := provider.Verifier(oidcConfig)

		//	IDトークンの正当性の検証
		idToken, err := verifier.Verify(ctx, rawIDToken)
		if err != nil {
			http.Error(w, "Failed to verify ID Token: "+err.Error(), http.StatusInternalServerError)
			return
		}

		//	アプリケーションのデータ構造に落とすときは以下のように書く
		idTokenClaims := map[string]interface{}{}
		if err := idToken.Claims(&idTokenClaims); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		fmt.Printf("%#v", idTokenClaims)

		fmt.Fprintf(w, "認証成功")
	})

	http.ListenAndServe(":3000",nil)
}