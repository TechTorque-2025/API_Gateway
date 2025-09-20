// temp-mocks/appointments.go
package main

import (
	"log"
	"net/http"
)

func appointmentsHandler(w http.ResponseWriter, r *http.Request) {
	log.Println("Mock Appointment Service: Received a valid, authorized request.")

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	w.Write([]byte(`{"message": "Successfully accessed protected appointment data from 8082"}`))
}

func main() {
	http.HandleFunc("/", appointmentsHandler)
	
	log.Println("Mock Appointment Service listening on http://localhost:8082")
	if err := http.ListenAndServe(":8082", nil); err != nil {
		log.Fatal(err)
	}
}