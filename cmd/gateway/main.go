// cmd/gateway/main.go
package main

import (
	"log"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strings"
)

func authMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		log.Printf("Executing auth middleware for %s", r.URL.Path)

		authHeader := r.Header.Get("Authorization")
		if authHeader == "" {
			http.Error(w, "Missing Authorization Header", http.StatusUnauthorized)
			return
		}

		headerParts := strings.Split(authHeader, " ")
		if len(headerParts) != 2 || strings.ToLower(headerParts[0]) != "bearer" {
			http.Error(w, "Invalid Authorization Header", http.StatusUnauthorized)
			return
		}

		token := headerParts[1]
		if token != "a-very-secure-mock-jwt-token-from-8081" {
			http.Error(w, "Invalid Token", http.StatusUnauthorized)
			return
		}
		
		log.Printf("Token is valid for %s", r.URL.Path)
		next.ServeHTTP(w, r)
	})
}

func main() {
	// --- Define ALL Backend Service URLs ---
	authServiceURL, _ := url.Parse("http://localhost:8081")
	appointmentServiceURL, _ := url.Parse("http://localhost:8082")
	serviceMgmtURL, _ := url.Parse("http://localhost:8083")
	notificationURL, _ := url.Parse("http://localhost:8084")
	aiChatbotURL, _ := url.Parse("http://localhost:3000")

	// --- Create a Reverse Proxy for EACH service ---
	authProxy := httputil.NewSingleHostReverseProxy(authServiceURL)
	appointmentProxy := httputil.NewSingleHostReverseProxy(appointmentServiceURL)
	serviceMgmtProxy := httputil.NewSingleHostReverseProxy(serviceMgmtURL)
	notificationProxy := httputil.NewSingleHostReverseProxy(notificationURL)
	aiChatbotProxy := httputil.NewSingleHostReverseProxy(aiChatbotURL)

	router := http.NewServeMux()

	// --- Define Public (Unprotected) Routes ---
	router.Handle("/api/v1/auth/", authProxy)

	// --- Define Private (Protected) Routes using our middleware ---
	// Your architecture diagram routes: /appointment, /service, /ws, /ai
	// We'll use RESTful names: /appointments, /services, /ws, /ai
	router.Handle("/api/v1/appointments/", authMiddleware(appointmentProxy))
	router.Handle("/api/v1/services/", authMiddleware(serviceMgmtProxy))
	router.Handle("/api/v1/ws/", authMiddleware(notificationProxy))
	router.Handle("/api/v1/ai/", authMiddleware(aiChatbotProxy))

	log.Println("API Gateway listening on http://localhost:8080")
	if err := http.ListenAndServe(":8080", router); err != nil {
		log.Fatal(err)
	}
}