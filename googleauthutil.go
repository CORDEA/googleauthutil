package googleauthutil

import (
	"context"
	"encoding/json"
	"fmt"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/google"
	"math/rand"
	"net/http"
	"os"
)

func Authorize(ctx context.Context, secret []byte, tokenFilename string, scope ...string) (*http.Client, error) {
	config, err := google.ConfigFromJSON(secret, scope...)
	if err != nil {
		return nil, err
	}

	token, err := restoreToken(tokenFilename)
	if err == nil {
		return config.Client(ctx, token), nil
	}

	state := generateState()
	url := config.AuthCodeURL(state, oauth2.AccessTypeOffline)
	fmt.Println(url)

	var code string
	if _, err := fmt.Scan(&code); err != nil {
		return nil, err
	}
	token, err = config.Exchange(ctx, code)
	if err != nil {
		return nil, err
	}
	err = storeToken(tokenFilename, token)
	return config.Client(ctx, token), err
}

func restoreToken(path string) (*oauth2.Token, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer func(f *os.File) {
		if e := f.Close(); err != nil {
			err = e
		}
	}(f)
	t := &oauth2.Token{}
	err = json.NewDecoder(f).Decode(t)
	return t, err
}

func storeToken(path string, token *oauth2.Token) error {
	f, err := os.OpenFile(path, os.O_RDWR|os.O_CREATE|os.O_TRUNC, 0600)
	if err != nil {
		return err
	}
	defer func(f *os.File) {
		if e := f.Close(); err != nil {
			err = e
		}
	}(f)
	err = json.NewEncoder(f).Encode(token)
	return err
}

func generateState() string {
	state := ""
	for i := 0; i < 3; i++ {
		state += fmt.Sprintf("%c", rand.Intn(26)+97)
	}
	return state
}
