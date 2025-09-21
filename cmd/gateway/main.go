// cmd/gateway/main.go
package main

import (
	"context"
	"fmt"
	"log"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// --- Structs for configuration remain the same ---

// Config holds the configuration for the gateway.
type Config struct {
	JWTSecret string
	Services  map[string]ServiceConfig
}

// ServiceConfig defines the configuration for a backend service.
type ServiceConfig struct {
	URL           string
	AuthRequired  bool
	PrefixToStrip string
}

// --- MODIFIED loadConfig FUNCTION ---

// loadConfig loads the configuration, checking for an environment variable for the
// JWT secret and using a hardcoded value as a fallback for development.
func loadConfig() (*Config, error) {
	// Attempt to get the JWT secret from the environment variable.
	jwtSecret := os.Getenv("JWT_SECRET")

	// If the environment variable is not set, use the fallback and log a warning.
	if jwtSecret == "" {
		jwtSecret = "YourSuperSecretKeyForJWTGoesHereAndItMustBeVeryLongForSecurityPurposes"
		log.Println("WARNING: JWT_SECRET environment variable not set. Using insecure fallback key. DO NOT use this in production.")
	}

	// Service configurations remain the same.
	services := map[string]ServiceConfig{
		"/api/v1/auth/": {
			URL:           "http://localhost:8081",
			AuthRequired:  false,
			PrefixToStrip: "/api/v1/auth",
		},
		"/api/v1/appointments/": {
			URL:           "http://localhost:8082",
			AuthRequired:  true,
			PrefixToStrip: "/api/v1/appointments",
		},
		"/api/v1/services/": {
			URL:           "http://localhost:8083",
			AuthRequired:  true,
			PrefixToStrip: "/api/v1/services",
		},
		"/api/v1/ws/": {
			URL:           "http://localhost:8084",
			AuthRequired:  true,
			PrefixToStrip: "/api/v1/ws",
		},
		"/api/v1/ai/": {
			URL:           "http://localhost:3000",
			AuthRequired:  true,
			PrefixToStrip: "/api/v1/ai",
		},
	}

	return &Config{
		JWTSecret: jwtSecret,
		Services:  services,
	}, nil
}

// --- The rest of the functions (newProxy, authMiddleware, main) are unchanged ---

// newProxy creates a new reverse proxy with path stripping.
func newProxy(targetURL string, prefixToStrip string) (*httputil.ReverseProxy, error) {
	target, err := url.Parse(targetURL)
	if err != nil {
		return nil, fmt.Errorf("invalid target URL: %w", err)
	}

	proxy := httputil.NewSingleHostReverseProxy(target)
	originalDirector := proxy.Director
	proxy.Director = func(req *http.Request) {
		originalDirector(req)
		req.URL.Path = strings.TrimPrefix(req.URL.Path, prefixToStrip)
		log.Printf("Forwarding request to: %s", req.URL.String())
	}

	return proxy, nil
}

// authMiddleware creates a middleware to validate JWT tokens.
func authMiddleware(jwtSecret []byte) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			log.Printf("Executing auth middleware for %s", r.URL.Path)

			authHeader := r.Header.Get("Authorization")
			if authHeader == "" {
				http.Error(w, "Missing Authorization Header", http.StatusUnauthorized)
				return
			}

			tokenString, found := strings.CutPrefix(authHeader, "Bearer ")
			if !found {
				http.Error(w, "Invalid Authorization Header format", http.StatusUnauthorized)
				return
			}

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
			}
		})
	}
}

func main() {
	config, err := loadConfig()
	if err != nil {
		log.Fatalf("Failed to load configuration: %v", err)
	}

	router := http.NewServeMux()
	authMW := authMiddleware([]byte(config.JWTSecret))

	for path, serviceConfig := range config.Services {
		proxy, err := newProxy(serviceConfig.URL, serviceConfig.PrefixToStrip)
		if err != nil {
			log.Fatalf("Failed to create proxy for %s: %v", path, err)
		}

		var handler http.Handler = proxy
		if serviceConfig.AuthRequired {
			handler = authMW(proxy)
		}
		router.Handle(path, handler)
	}

	server := &http.Server{
		Addr:    ":8080",
		Handler: router,
	}

	// Graceful shutdown
	stop := make(chan os.Signal, 1)
	signal.Notify(stop, syscall.SIGINT, syscall.SIGTERM)

	go func() {
		log.Println("API Gateway listening on http://localhost:8080")
		if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Fatalf("Could not listen on %s: %v\n", server.Addr, err)
		}
	}()

	<-stop
	log.Println("Shutting down server...")

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if err := server.Shutdown(ctx); err != nil {
		log.Fatalf("Server forced to shutdown: %v", err)
	}

	log.Println("Server exiting")
}