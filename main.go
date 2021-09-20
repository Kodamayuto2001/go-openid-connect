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

	http.HandleFunc("/auth",func(w http.ResponseWriter, r *http.Request){
		provider, err := oidc.NewProvider(r.Context(),issuer)

		if err != nil {
			log.Fatal(err)
		}

		config := oauth2.Config{
			ClientID:		os.Getenv("CLIENT_ID"),
			ClientSecret:	os.Getenv("CLIENT_SECRET"),
			Endpoint:		provider.Endpoint(),
			RedirectURL:	os.Getenv("REDIRECT_URL"),
			Scopes:			[]string{oidc.ScopeOpenID},
		}

		state := randomString()

		authURL := config.AuthCodeURL(state)
		http.Redirect(w, r, authURL, http.StatusFound)
	})

	http.ListenAndServe(":3000",nil)
}