package main

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"strings"
	"time"

	jwt "github.com/dgrijalva/jwt-go"
	"github.com/gorilla/context"
	"github.com/gorilla/mux"
	"github.com/mitchellh/mapstructure"
	uuid "github.com/satori/go.uuid"
)

type User struct {
	UUID     string `json:"public_id"`
	Username string `json:"username"`
	Password string `json:"password"`
}

type JwtToken struct {
	Token string `json:"token"`
}

type Exception struct {
	Message string `json:"message"`
}

func CreateTokenAuth(w http.ResponseWriter, r *http.Request) {
	var user User
	_ = json.NewDecoder(r.Body).Decode(&user)
	token := jwt.NewWithClaims(jwt.SigningMethodHS512, jwt.MapClaims{
		"exp":      time.Now().Add(time.Hour * time.Duration(1)).Unix(),
		"uuid":     uuid.Must(uuid.NewV4()),
		"username": user.Username,
		"password": user.Password,
	})
	tokenString, error := token.SignedString([]byte("e0037393-0596-4e41-9f37-459fd262623c-00d219d5-456f-4158-8635-35f36522f299"))
	if error != nil {
		fmt.Println(error)
	}
	json.NewEncoder(w).Encode(JwtToken{Token: tokenString})
}

func RequireTokenAuth(next http.HandlerFunc) http.HandlerFunc {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		authorizationHeader := r.Header.Get("authorization")
		if authorizationHeader != "" {
			bearerToken := strings.Split(authorizationHeader, "Bearer ")
			if len(bearerToken) == 2 {
				token, _ := jwt.Parse(bearerToken[1], func(token *jwt.Token) (interface{}, error) {
					if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
						return nil, fmt.Errorf("There was an error")
					}
					return []byte("e0037393-0596-4e41-9f37-459fd262623c-00d219d5-456f-4158-8635-35f36522f299"), nil
				})
				// if error != nil {
				// 	json.NewEncoder(w).Encode(Exception{Message: error.Error()})
				// 	return
				// }
				if token.Valid {
					context.Set(r, "decoded", token.Claims)
					next(w, r)
				} else {
					json.NewEncoder(w).Encode(Exception{Message: "Invalid authorization token"})
				}
			} else {
				json.NewEncoder(w).Encode(Exception{Message: "Invalid token"})
			}
		} else {
			json.NewEncoder(w).Encode(Exception{Message: "An authorization header is required"})
		}
	})
}

func UserData(w http.ResponseWriter, r *http.Request) {
	decoded := context.Get(r, "decoded")
	var user User
	mapstructure.Decode(decoded.(jwt.MapClaims), &user)
	json.NewEncoder(w).Encode(user)
}

func main() {
	router := mux.NewRouter()
	fmt.Println("Starting the application...")
	router.HandleFunc("/token-auth", CreateTokenAuth).Methods("POST")
	router.HandleFunc("/user", RequireTokenAuth(UserData)).Methods("GET")
	log.Fatal(http.ListenAndServe(":3000", router))
}
