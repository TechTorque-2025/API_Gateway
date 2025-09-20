// cmd/gateway/main.gopackage gateway

package main

import (
	"log"
	"net/http"
	"net/http/httputil"
	"net/url"
)

func main() {
	// --- Define our Mock Backend Service URL ---
	// url.Parse will figure out the scheme and host for our backend.
	authServiceURL, err := url.Parse("http://localhost:8081")
	if err != nil {
		log.Fatalf("Failed to parse auth service URL: %v", err)
	}

	// --- Create a Reverse Proxy ---
	// NewSingleHostReverseProxy creates a new proxy that will pass requests
	// to the URL we just defined. It takes care of all the heavy lifting.
	authProxy := httputil.NewSingleHostReverseProxy(authServiceURL)

	// --- Create our Router (also called a "mux") ---
	// The router is responsible for matching incoming requests to the correct handler.
	router := http.NewServeMux()

	// --- Define the Routing Rule ---
	// Any request that comes into our gateway with a path starting with "/api/v1/auth/"
	// will be handled by our authProxy.
	router.Handle("/api/v1/auth/", authProxy)

	// --- Start the Gateway Server ---
	log.Println("API Gateway listening on http://localhost:8080")
	if err := http.ListenAndServe(":8080", router); err != nil {
		log.Fatal(err)
	}
}
