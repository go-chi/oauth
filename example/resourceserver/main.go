package main

import (
	"bytes"
	"encoding/json"
	"net/http"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
	"github.com/go-chi/cors"

	"github.com/christhirst/oauth"
)

/*
   Resource Server Example

	Get Customers

		GET http://localhost:3200/customers
		User-Agent: Fiddler
		Host: localhost:3200
		Content-Length: 0
		Content-Type: application/json
		Authorization: Bearer {access_token}

	Get Orders

		GET http://localhost:3200/customers/12345/orders
		User-Agent: Fiddler
		Host: localhost:3200
		Content-Length: 0
		Content-Type: application/json
		Authorization: Bearer {access_token}

	{access_token} is produced by the Authorization Server response (see example /test/authserver).

*/
func main() {
	r := chi.NewRouter()
	r.Use(middleware.Logger)
	r.Use(middleware.Recoverer)
	r.Use(cors.Handler(cors.Options{
		AllowedOrigins:   []string{"*"},
		AllowedMethods:   []string{"GET", "PUT", "POST", "DELETE", "HEAD", "OPTION"},
		AllowedHeaders:   []string{"User-Agent", "Content-Type", "Accept", "Accept-Encoding", "Accept-Language", "Cache-Control", "Connection", "DNT", "Host", "Origin", "Pragma", "Referer"},
		ExposedHeaders:   []string{"Link"},
		AllowCredentials: true,
		MaxAge:           300, // Maximum value not ignored by any of major browsers
	}))
	registerAPI(r)
	_ = http.ListenAndServe(":8081", r)
}

func registerAPI(r *chi.Mux) {
	r.Route("/", func(r chi.Router) {
		// use the Bearer Authentication middleware
		r.Use(oauth.Authorize("mySecretKey-10101", nil))
		r.Get("/customers", GetCustomers)
		r.Get("/customers/{id}/orders", GetOrders)
	})
}

func renderJSON(w http.ResponseWriter, v interface{}, statusCode int) {
	buf := &bytes.Buffer{}
	enc := json.NewEncoder(buf)
	enc.SetEscapeHTML(true)
	if err := enc.Encode(v); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(statusCode)
	_, _ = w.Write(buf.Bytes())
}

func GetCustomers(w http.ResponseWriter, _ *http.Request) {
	renderJSON(w, `{
		"Status":        "verified",
		"Customer":      "test001",
		"Customer_name":  "Max",
		"Customer_email": "test@test.com",
	}`, http.StatusOK)
}

func GetOrders(w http.ResponseWriter, _ *http.Request) {
	renderJSON(w, `{
		"status":            "sent",
		"customer":          "test001",
		"order_id":          "100234",
		"total_order_items": "199",
	}`, http.StatusOK)
}
