package main

import (
	"log"
	"net/http"
)

func main() {

	http.Handle("/records/", validateToken(handleGetRecords))

	// register handler
	http.HandleFunc("/register/", handleRegister)

	// login handler
	http.HandleFunc("/login/", handleLogin)

    // logout handler
    http.HandleFunc("/logout/", handleLogout)

	// listen to port with log fatal
	log.Println("Listening on port 8080")
	log.Fatal(http.ListenAndServe(":8080", nil))
}
