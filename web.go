package web

import (
	"encoding/json"
	"errors"
	"github.com/dgrijalva/jwt-go"
	"golang.org/x/crypto/bcrypt"
	"net/http"
)

type Token struct {
	Value interface{}
	jwt.StandardClaims
}
func HashPassword(password string) string {
	hashed, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return ""
	}
	return string(hashed)
}

func VerifyPassword(hashedPassword, password string) bool {
	if err := bcrypt.CompareHashAndPassword([]byte(hashedPassword), []byte(password)); err != nil {
		return false
	}
	return true
}

func GenerateJwtToken(key string, data interface{}) (string, error) {
	token := jwt.NewWithClaims(jwt.GetSigningMethod("HS256"), &Token{Value: data})
	return token.SignedString([]byte(key))
}

func ParseJwtToken(tokenString, key string) (interface{}, error) {
	tk := &Token{}
	token, err := jwt.ParseWithClaims(tokenString, tk, func(token *jwt.Token) (interface{}, error) {
		signingMethod := jwt.GetSigningMethod("HS256")
		if token.Method != signingMethod {
			return nil, errors.New("invalid signing method")
		}
		return []byte(key), nil
	})
	if err != nil {
		return nil, errors.New("malformed token")
	}
	if !token.Valid {
		return nil, errors.New("malformed or invalid token")
	}
	return tk.Value, nil
}

func BadRequest(w http.ResponseWriter, message interface{}) {
	w.WriteHeader(http.StatusBadRequest)
	w.Header().Add("Content-Type", "application/json")
	data, _ := json.Marshal(message)
	w.Write(data)
}

func OK(w http.ResponseWriter, data interface{}, contentType string) {
	w.WriteHeader(http.StatusOK)
	w.Header().Add("Content-Type", contentType)
	d, _ := json.Marshal(data)
	w.Write(d)
}