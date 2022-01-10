package googleauthutil

import (
	"context"
	"encoding/json"
	"fmt"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/google"
	"io/ioutil"
	"math/rand"
	"net/http"
	"os"
)

type Authorizer struct {
	config        *oauth2.Config
	tokenFilename string
}

func NewAuthorizer(config *oauth2.Config, tokenFilename string) *Authorizer {
	return &Authorizer{
		config:        config,
		tokenFilename: tokenFilename,
	}
}

func ConfigFromJSON(filename string, scope ...string) (*oauth2.Config, error) {
	file, err := ioutil.ReadFile(filename)
	if err != nil {
		return nil, err
	}
	return google.ConfigFromJSON(file, scope...)
}

func (a *Authorizer) Restore(ctx context.Context) (*http.Client, error) {
	token, err := a.restoreToken()
	if err != nil {
		return nil, err
	}
	return a.config.Client(ctx, token), nil
}

func (a *Authorizer) AuthCodeUrl() string {
	// TODO
	state := generateState()
	return a.config.AuthCodeURL(state, oauth2.AccessTypeOffline)
}

func (a *Authorizer) Authorize(ctx context.Context, code string) (*http.Client, error) {
	token, err := a.config.Exchange(ctx, code)
	if err != nil {
		return nil, err
	}
	err = a.storeToken(token)
	return a.config.Client(ctx, token), err
}

func (a *Authorizer) restoreToken() (*oauth2.Token, error) {
	f, err := os.Open(a.tokenFilename)
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

func (a *Authorizer) storeToken(token *oauth2.Token) error {
	f, err := os.OpenFile(a.tokenFilename, os.O_RDWR|os.O_CREATE|os.O_TRUNC, 0600)
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
