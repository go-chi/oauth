package oauth

import (
	"reflect"
	"testing"
)

func assertNoError(t testing.TB, got interface{}) {
	t.Helper()
	if got != nil {
		t.Errorf("expected no error got %v", got)
	}
}

func assertError(t testing.TB, got interface{}) {
	t.Helper()
	if got == nil {
		t.Errorf("expected error got %v", got)
	}
}

func assertEmptyString(t testing.TB, got string) {
	t.Helper()
	if got == "" {
		t.Errorf("expected string but got %v", got)
	}
}

func assertString(t testing.TB, got, want string) {
	t.Helper()
	if got != want {
		t.Errorf("got: %v, expected: %v", got, want)
	}
}

func assertResponseCode(t testing.TB, got, want int) {
	t.Helper()
	if got != want {
		t.Errorf("expected  %v, got %v", want, got)
	}
}
func assertCorrectMessage(t testing.TB, got, want map[string][]string) {
	t.Helper()
	if !reflect.DeepEqual(got, want) {
		t.Errorf("Not equal maps, got %q want %q", got, want)
	}
}
func assertFormError(t testing.TB, got error) {
	t.Helper()
	if got == nil {
		t.Errorf("response body is wrong, got %q ", got)
	}
}
