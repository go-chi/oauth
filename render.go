package oauth

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
)

// renderJSON marshals 'v' to JSON, automatically escaping HTML, setting the
// Content-Type as application/json, and sending the status code header.
func renderJSON(w http.ResponseWriter, v interface{}, statusCode int) {
	buf := &bytes.Buffer{}
	enc := json.NewEncoder(buf)
	enc.SetEscapeHTML(true)
	b, err := json.MarshalIndent(v, "", "\t")
	if err != nil {
		fmt.Println("error:", err)
	}

	/* if err := enc.Encode(v); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	} */
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(statusCode)

	_, _ = w.Write(b)
}
