// cmd/gateway/main.go
package main

import (
	"log"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strings"
)

// authMiddleware is our security guard. It's a function that takes a "handler"
// (like our reverse proxy) and returns a new handler that has the security check.
func authMiddleware(next http.Handler) http.Handler {
	// http.HandlerFunc is a special type that lets us use a simple function
	// as an HTTP handler.
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		log.Println("Executing auth middleware")

		// 1. Get the token from the request header
		authHeader := r.Header.Get("Authorization")
		if authHeader == "" {
			// If the header is missing, they are not authorized.
			http.Error(w, "Missing Authorization Header", http.StatusUnauthorized)
			return // Stop processing the request
		}

		// The header is usually in the format "Bearer <token>"
		// We need to split the string to get just the token.
		headerParts := strings.Split(authHeader, " ")
		if len(headerParts) != 2 || strings.ToLower(headerParts[0]) != "bearer" {
			http.Error(w, "Invalid Authorization Header", http.StatusUnauthorized)
			return
		}
		
		token := headerParts[1]
		
		// 2. Validate the token
		// THIS IS A FAKE VALIDATION. In a real app, you would use a JWT library
		// to verify the token's signature against a public key.
		if token != "a-very-secure-mock-jwt-token-from-8081" {
			http.Error(w, "Invalid Token", http.StatusUnauthorized)
			return
		}
		
		log.Println("Token is valid.")

		// 3. If the token is valid, call the next handler in the chain.
		// For us, this will be the reverse proxy that forwards to the appointment service.
		next.ServeHTTP(w, r)
	})
}


func main() {
	// --- Define Backend Service URLs ---
	authServiceURL, _ := url.Parse("http://localhost:8081")
	appointmentServiceURL, _ := url.Parse("http://localhost:8082")

	// --- Create Reverse Proxies ---
	authProxy := httputil.NewSingleHostReverseProxy(authServiceURL)
	appointmentProxy := httputil.NewSingleHostReverseProxy(appointmentServiceURL)

	router := http.NewServeMux()

	// --- Define Routing Rules ---
	// The /auth/ path is UNPROTECTED. Anyone can access it.
	router.Handle("/api/v1/auth/", authProxy)

	// The /appointments/ path is PROTECTED.
	// We wrap our appointmentProxy with the authMiddleware.
	// Now, any request to this path must first pass the middleware's check.
	router.Handle("/api/v1/appointments/", authMiddleware(appointmentProxy))


	log.Println("API Gateway listening on http://localhost:8080")
	if err := http.ListenAndServe(":8080", router); err != nil {
		log.Fatal(err)
	}
}