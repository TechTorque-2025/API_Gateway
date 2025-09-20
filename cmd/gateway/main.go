// cmd/gateway/main.go
package main

import (
	"fmt"
	"log"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strings"

	"github.com/golang-jwt/jwt/v5"
)

// This is the same secret key we defined in the Java application.properties
var jwtSecret = []byte("ThisIsASecretKeyForOurAutomobileApplicationThatIsVeryLongAndSecure12345")

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

		tokenString := headerParts[1]

		// --- REAL JWT VALIDATION ---
		// Parse the token with our secret key.
		token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
			// Don't forget to validate the alg is what you expect:
			if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
				return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
			}
			return jwtSecret, nil
		})

		if err != nil {
			log.Printf("Error parsing token: %v", err)
			http.Error(w, "Invalid Token", http.StatusUnauthorized)
			return
		}

		if claims, ok := token.Claims.(jwt.MapClaims); ok && token.Valid {
			// The token is valid! Log the user and proceed.
			log.Printf("Token is valid for user: %v", claims["sub"]) // "sub" is the standard claim for subject (username)
			next.ServeHTTP(w, r)
		} else {
			http.Error(w, "Invalid Token", http.StatusUnauthorized)
			return
		}
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
