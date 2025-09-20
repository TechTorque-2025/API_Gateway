// temp-mocks/ai_chatbot.go
package main

import (
	"log"
	"net/http"
)

func main() {
	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		log.Println("Mock AI Chatbot: Received authorized query.")
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"answer": "According to my analysis, a slot is available tomorrow at 3 PM."}`))
	})
	log.Println("Mock AI Chatbot Service listening on http://localhost:3000")
	if err := http.ListenAndServe(":3000", nil); err != nil {
		log.Fatal(err)
	}
}