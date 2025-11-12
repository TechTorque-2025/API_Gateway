package main

import (
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
	"github.com/golang-jwt/jwt/v5"
	"github.com/rs/cors"
	"gopkg.in/yaml.v3"
)

// Config --- Configuration Structs ---
type Config struct {
	Server    ServerConfig    `yaml:"server"`
	JWTSecret string          `yaml:"jwt_secret"`
	Services  []ServiceConfig `yaml:"services"`
}

type ServerConfig struct {
	Port string `yaml:"port"`
}

type ServiceConfig struct {
	Name         string `yaml:"name"`
	PathPrefix   string `yaml:"path_prefix"`
	TargetURL    string `yaml:"target_url"`
	StripPrefix  string `yaml:"strip_prefix"`
	AuthRequired bool   `yaml:"auth_required"`
	EnvVar       string `yaml:"env_var"` // Optional: custom environment variable name
}

// --- Global Logger ---
var logger *slog.Logger

// --- Configuration Loading ---
func loadConfig(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read config file: %w", err)
	}

	var config Config
	if err := yaml.Unmarshal(data, &config); err != nil {
		return nil, fmt.Errorf("failed to unmarshal config yaml: %w", err)
	}

	// Override with environment variables
	if secret := os.Getenv("JWT_SECRET"); secret != "" {
		config.JWTSecret = secret
	}

	// Override service URLs from environment variables
	// If env_var is specified in config, use it; otherwise generate from service name
	for i := range config.Services {
		var envVarName string

		// Use custom env_var if specified, otherwise auto-generate
		if config.Services[i].EnvVar != "" {
			envVarName = config.Services[i].EnvVar
		} else {
			// Auto-generate: convert "service-name" to "SERVICE_NAME_SERVICE_URL"
			// e.g., "time-logs" -> "TIME_LOGS_SERVICE_URL"
			normalizedName := strings.ToUpper(strings.ReplaceAll(config.Services[i].Name, "-", "_"))
			envVarName = normalizedName + "_SERVICE_URL"
		}

		// Override target URL if environment variable is set
		if envURL := os.Getenv(envVarName); envURL != "" {
			config.Services[i].TargetURL = envURL
			logger.Info("Service URL overridden from environment",
				"service", config.Services[i].Name,
				"env_var", envVarName,
				"url", envURL)
		}
	}

	return &config, nil
}

// --- Reverse Proxy ---
func newProxy(targetURL, stripPrefix string) (*httputil.ReverseProxy, error) {
	target, err := url.Parse(targetURL)
	if err != nil {
		return nil, fmt.Errorf("invalid target URL: %w", err)
	}

	proxy := httputil.NewSingleHostReverseProxy(target)
	originalDirector := proxy.Director
	proxy.Director = func(req *http.Request) {
		originalDirector(req)
		req.Host = target.Host
		if stripPrefix != "" {
			req.URL.Path = strings.TrimPrefix(req.URL.Path, stripPrefix)
		}
	}

	proxy.ModifyResponse = func(resp *http.Response) error {
		logger.Info("response received from downstream",
			"service", targetURL,
			"status", resp.Status,
			"request_path", resp.Request.URL.Path,
		)
		return nil
	}

	return proxy, nil
}

// Context key for storing user claims
type contextKey string

const userClaimsKey contextKey = "userClaims"

// --- Authentication Middleware ---
func authMiddleware(jwtSecret []byte) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
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
				logger.Warn("Error parsing token", "error", err)
				http.Error(w, "Invalid Token", http.StatusUnauthorized)
				return
			}

			if claims, ok := token.Claims.(jwt.MapClaims); ok && token.Valid {
				ctx := context.WithValue(r.Context(), userClaimsKey, claims)
				next.ServeHTTP(w, r.WithContext(ctx))
			} else {
				http.Error(w, "Invalid Token", http.StatusUnauthorized)
			}
		})
	}
}

// --- Director Modifier Middleware ---
func injectUserInfo(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if claims, ok := r.Context().Value(userClaimsKey).(jwt.MapClaims); ok {
			if sub, exists := claims["sub"]; exists {
				r.Header.Set("X-User-Subject", fmt.Sprintf("%v", sub))
			}
			if roles, exists := claims["roles"]; exists {
				// The roles claim from the Java JWT is likely a []interface{}.
				// We need to convert it to a comma-separated string.
				roleSlice, ok := roles.([]interface{})
				if ok {
					var roleStrings []string
					for _, role := range roleSlice {
						roleStrings = append(roleStrings, fmt.Sprintf("%v", role))
					}
					r.Header.Set("X-User-Roles", strings.Join(roleStrings, ","))
				}
			}
			logger.Info("Injecting user info into headers", "subject", r.Header.Get("X-User-Subject"), "roles", r.Header.Get("X-User-Roles"))
		}
		next.ServeHTTP(w, r)
	})
}

func main() {
	logger = slog.New(slog.NewJSONHandler(os.Stdout, nil))
	slog.SetDefault(logger)

	config, err := loadConfig("config.yaml")
	if err != nil {
		logger.Error("Failed to load configuration", "error", err)
		os.Exit(1)
	}

	router := chi.NewRouter()

	router.Use(middleware.RequestID)
	router.Use(middleware.RealIP)
	router.Use(middleware.Logger)
	router.Use(middleware.Recoverer)

	// CORS Configuration - Allow frontend origins
	// In production, replace with actual frontend domain(s) via environment variable
	router.Use(cors.New(cors.Options{
		AllowedOrigins: []string{
			"http://localhost:3000",
			"http://127.0.0.1:3000",
			"https://techtorque.vercel.app",
			"https://techtorque.randitha.net",
		},
		AllowedMethods:   []string{"GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS"},
		AllowedHeaders:   []string{"Accept", "Authorization", "Content-Type", "X-CSRF-Token"},
		ExposedHeaders:   []string{"Link"},
		AllowCredentials: true,
		MaxAge:           300,
	}).Handler)

	router.Get("/healthz", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("OK"))
	})

	authMW := authMiddleware([]byte(config.JWTSecret))

	for _, service := range config.Services {
		proxy, err := newProxy(service.TargetURL, service.StripPrefix)
		if err != nil {
			logger.Error("Failed to create proxy", "service", service.Name, "error", err)
			os.Exit(1)
		}

		handler := http.Handler(proxy)

		router.Group(func(r chi.Router) {
			if service.AuthRequired {
				r.Use(authMW)
				r.Use(injectUserInfo)
			}
			r.Handle(service.PathPrefix+"*", handler)
		})

		logger.Info("Registered service", "name", service.Name, "prefix", service.PathPrefix, "target", service.TargetURL)
	}

	server := &http.Server{
		Addr:    config.Server.Port,
		Handler: router,
	}

	stop := make(chan os.Signal, 1)
	signal.Notify(stop, syscall.SIGINT, syscall.SIGTERM)

	go func() {
		logger.Info("API Gateway listening", "address", server.Addr)
		if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			logger.Error("Could not listen on address", "address", server.Addr, "error", err)
			os.Exit(1)
		}
	}()

	<-stop
	logger.Info("Shutting down server...")

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if err := server.Shutdown(ctx); err != nil {
		logger.Error("Server forced to shutdown", "error", err)
		os.Exit(1)
	}

	logger.Info("Server exiting")
}
