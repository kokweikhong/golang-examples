package main

import (
	"encoding/json"
	"log"
	"net/http"
)

func handleGetRecords(w http.ResponseWriter, r *http.Request) {
    log.Println("handleGetRecords hit!")
    // get all records
    records := randomRecords()

    // send all records as JSON response
    sendJSONResponse(w, records)
}

// sendJSONResponse to send a JSON response
func sendJSONResponse(w http.ResponseWriter, data interface{}) {
    // set header
    w.Header().Set("Content-Type", "application/json")

    // send response
    json.NewEncoder(w).Encode(data)
}

type Record struct {
	ID      int    `json:"id"`
	Name    string `json:"name"`
	Age     int    `json:"age"`
	Address string `json:"address"`
}

// randomRecords to generate a random record in with
// id, name, age, and address
func randomRecords() []Record {
	return []Record{
		{1, "John", 20, "123 St. New York"},
		{2, "Smith", 25, "456 St. New York"},
		{3, "Jane", 30, "789 St. New York"},
	}
}
