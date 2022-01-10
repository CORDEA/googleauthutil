package googleauthutil

import (
	"context"
	"fmt"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/google"
	"math/rand"
	"net/http"
)

func Authorize(ctx context.Context, secret []byte, scope ...string) (*http.Client, error) {
	config, err := google.ConfigFromJSON(secret, scope...)
	if err != nil {
		return nil, err
	}
	state := generateState()
	url := config.AuthCodeURL(state, oauth2.AccessTypeOffline)
	fmt.Println(url)

	var code string
	if _, err := fmt.Scan(&code); err != nil {
		return nil, err
	}
	token, err := config.Exchange(ctx, code)
	if err != nil {
		return nil, err
	}
	return config.Client(ctx, token), nil
}

func generateState() string {
	state := ""
	for i := 0; i < 3; i++ {
		state += fmt.Sprintf("%c", rand.Intn(26)+97)
	}
	return state
}
