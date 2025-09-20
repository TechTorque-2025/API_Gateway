// temp-mocks/auth.gopackage tempmocks

package main

import (
	"log"
	"net/http"
)

// This is a simple handler that simulates the Auth Service.
func loginHandler(w http.ResponseWriter, r *http.Request) {
	log.Println("Mock Auth Service: Received login request.")

	// Set the content type to JSON
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)

	// Write a fake JSON response
	w.Write([]byte(`{"token": "a-very-secure-mock-jwt-token-from-8081"}`))
}

func main() {
	// This mock service will handle all requests to it with our loginHandler.
	http.HandleFunc("/", loginHandler)

	// Start the server on port 8081.
	log.Println("Mock Auth Service listening on http://localhost:8081")
	if err := http.ListenAndServe(":8081", nil); err != nil {
		log.Fatal(err)
	}
}
