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

var jwtSecret = []byte("YourSuperSecretKeyForJWTGoesHereAndItMustBeVeryLongForSecurityPurposes")

// --- NEW HELPER FUNCTION FOR CREATING PROXIES ---
// This function creates a reverse proxy that also strips a given prefix from the request path.
func newProxy(targetUrl string, prefixToStrip string) (*httputil.ReverseProxy, error) {
	target, err := url.Parse(targetUrl)
	if err != nil {
		return nil, err
	}

	proxy := httputil.NewSingleHostReverseProxy(target)
	
	// The Director is a function that modifies the request before it's sent.
	// This is where we will do our path rewriting.
	originalDirector := proxy.Director
	proxy.Director = func(req *http.Request) {
		// First, run the original director to set up the host, scheme, etc.
		originalDirector(req)
		
		// Now, rewrite the path.
		req.URL.Path = strings.TrimPrefix(req.URL.Path, prefixToStrip)
		log.Printf("Forwarding request to: %s", req.URL.Path)
	}

	return proxy, nil
}


// The authMiddleware function remains exactly the same as before.
func authMiddleware(next http.Handler) http.Handler {
    // ... (no changes here) ...
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
		token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
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
			log.Printf("Token is valid for user: %v", claims["sub"])
			next.ServeHTTP(w, r)
		} else {
			http.Error(w, "Invalid Token", http.StatusUnauthorized)
			return
		}
	})
}

func main() {
	// --- Create Reverse Proxies using our NEW helper function ---
	authProxy, _ := newProxy("http://localhost:8081", "/api/v1/auth")
	appointmentProxy, _ := newProxy("http://localhost:8082", "/api/v1/appointments")
	serviceMgmtProxy, _ := newProxy("http://localhost:8083", "/api/v1/services")
	notificationProxy, _ := newProxy("http://localhost:8084", "/api/v1/ws")
	aiChatbotProxy, _ := newProxy("http://localhost:3000", "/api/v1/ai")

	router := http.NewServeMux()

	// --- Routing rules remain the same, but the proxies are now smarter ---
	router.Handle("/api/v1/auth/", authProxy)
	router.Handle("/api/v1/appointments/", authMiddleware(appointmentProxy))
	router.Handle("/api/v1/services/", authMiddleware(serviceMgmtProxy))
	router.Handle("/api/v1/ws/", authMiddleware(notificationProxy))
	router.Handle("/api/v1/ai/", authMiddleware(aiChatbotProxy))

	log.Println("API Gateway (with path rewriting) listening on http://localhost:8080")
	if err := http.ListenAndServe(":8080", router); err != nil {
		log.Fatal(err)
	}
}