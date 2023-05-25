package main

import (
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"golang.org/x/crypto/bcrypt"
)

// User is a struct to store username and password
type User struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

// users is a map to store username and password
var users = make(map[string]string)

// handleRegister is a handler to register user
func handleRegister(w http.ResponseWriter, r *http.Request) {
	var data User

	// decode request body into data
	body, err := io.ReadAll(r.Body)
	if err != nil {
		// return bad request if body is not correct
		http.Error(w, fmt.Sprintf("Bad request: %v", err.Error()), http.StatusBadRequest)
		return
	}

    // unmarshal body into data
	err = json.Unmarshal(body, &data)
	if err != nil {
		http.Error(w, "Bad Request", http.StatusBadRequest)
		return
	}

    // check if username already exists
	password, err := bcrypt.GenerateFromPassword([]byte(data.Password), 14)
	users[data.Username] = string(password)

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(users)
}

func handleLogin(w http.ResponseWriter, r *http.Request) {
	var data User

	// decode request body into data
	body, err := io.ReadAll(r.Body)
	if err != nil {
		// return bad request if body is not correct
		http.Error(w, fmt.Sprintf("Bad request: %v", err.Error()), http.StatusBadRequest)
		return
	}
	err = json.Unmarshal(body, &data)
	if err != nil {
		http.Error(w, "Bad Request", http.StatusBadRequest)
		return
	}

	_, ok := users[data.Username]
	if !ok {
		http.Error(w, "User not found", http.StatusNotFound)
		return
	}

	// compare password
	err = bcrypt.CompareHashAndPassword([]byte(users[data.Username]), []byte(data.Password))
	if err != nil {
		http.Error(w, "Wrong password", http.StatusUnauthorized)
		return
	}

	claims := jwt.RegisteredClaims{
		Issuer:    "test",
		ExpiresAt: jwt.NewNumericDate(time.Now().Add(5 * time.Minute)),
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	tokenString, err := token.SignedString([]byte("secret"))

	if err != nil {
		http.Error(w, "Error signing token", http.StatusInternalServerError)
		return
	}

	// Set token in cookie
	cookie := http.Cookie{
		Name:     "token",
		Value:    tokenString,
		Path:     "/",
		Expires:  time.Now().Add(5 * time.Minute),
        // Secure:   true,
		HttpOnly: true,
	}

	http.SetCookie(w, &cookie)

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(tokenString)

}

// validate token
func validateToken(next func(w http.ResponseWriter, r *http.Request)) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization")

		// get token from cookie
		cookie, err := r.Cookie("token")
		fmt.Println(cookie)
		if err != nil {
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}

		tokenString := cookie.Value
		log.Println(tokenString)

		// parse with claims
		token, err := jwt.ParseWithClaims(tokenString, &jwt.RegisteredClaims{}, func(token *jwt.Token) (interface{}, error) {
			return []byte("secret"), nil
		})

		if err != nil {
			http.Error(w, "Parse Token Failed: Unauthorized", http.StatusUnauthorized)
			return
		}

		_, ok := token.Claims.(*jwt.RegisteredClaims)
		if !ok || !token.Valid {
			http.Error(w, "Failed to Get Claims: Unauthorized", http.StatusUnauthorized)
			return
		}
		next(w, r)
	})
}

// handleLogout
func handleLogout(w http.ResponseWriter, r *http.Request) {
	cookie := http.Cookie{
		Name:    "token",
		Value:   "",
		Path:    "/",
        // Secure:  true,
        HttpOnly: true,
		Expires: time.Now().Add(-1 * time.Minute),
	}

	http.SetCookie(w, &cookie)

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode("Logout success")

}
