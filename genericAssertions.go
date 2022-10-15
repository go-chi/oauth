package oauth

import "testing"

func assertNoError(t testing.TB, got interface{}) {
	t.Helper()
	if got != nil {
		t.Errorf("expected no Error got %v", got)
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
