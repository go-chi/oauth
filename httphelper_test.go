package oauth

import (
	"net/http"
	"net/url"
	"strings"
	"testing"
)

func TestFormExtractor(t *testing.T) {
	formList := []string{"name", "password", "client_id", "response_type", "redirect_uri", "scope", "nonce", "state"}
	formMap := map[string][]string{"name": {"name"}, "password": {"password"}, "client_id": {"client_id"},
		"response_type": {"response_type"}, "redirect_uri": {"redirect_uri"}, "nonce": {"nonce"}, "state": {"state"}, "scope": {"scope"}}
	form := url.Values{}

	t.Run("Registration Test 1", func(t *testing.T) {
		want := map[string][]string{"name": {"name"}, "password": {"password"}, "client_id": {"client_id"}, "response_type": {"response_type"}, "redirect_uri": {"redirect_uri"}, "nonce": {"nonce"}, "state": {"state"}, "scope": {"scope"}}

		req, err := http.NewRequest(http.MethodPost, "/", strings.NewReader(form.Encode()))
		qAddList(req, formMap)
		if err != nil {
			t.Error(err)
		}
		got, err := UrlExtractor(req, formList)
		if err != nil {
			t.Error(err)
		}

		assertCorrectMessage(t, got, want)
	})

	t.Run("Registration Test 2", func(t *testing.T) {
		formAddList(&form, formMap)
		want := map[string][]string{"name": {"name"}, "password": {"password"}, "client_id": {"client_id"}, "response_type": {"response_type"}, "redirect_uri": {"redirect_uri"}, "nonce": {"nonce"}, "state": {"state"}, "scope": {"scope"}}

		req, err := http.NewRequest(http.MethodPost, "/", strings.NewReader(form.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		if err != nil {
			t.Error(err)
		}
		got, _, err := formExtractor(req, formList)
		if err != nil {
			t.Error(err)
		}
		assertCorrectMessage(t, got, want)
	})

	t.Run("Registration Test 3", func(t *testing.T) {
		formAddList(&form, formMap)
		want := []string{"scope"}
		form.Del(want[0])
		req, err := http.NewRequest(http.MethodPost, "/", strings.NewReader(form.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		if err != nil {
			t.Error(err)
		}
		_, got, err := formExtractor(req, formList)
		if err != nil {
			t.Error(err)
		}
		assertGeneric(t, got[0], want[0])
	})

}
