package auth

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"golang.org/x/crypto/bcrypt"
)

func HashPassword(password string) (string, error) {
	byte_pw := []byte(password)

	byte_hashed_password, err := bcrypt.GenerateFromPassword(byte_pw, bcrypt.DefaultCost)

	hashed_password := string(byte_hashed_password)

	return hashed_password, err
}

func CheckPasswordHash(password, hash string) error {

	byte_hashed := []byte(hash)
	byte_pw := []byte(password)

	err := bcrypt.CompareHashAndPassword(byte_hashed, byte_pw)

	return err
}

func MakeJWT(userID uuid.UUID, tokenSecret string, expiresIn time.Duration) (string, error) {
	claims := jwt.RegisteredClaims{
		Issuer:    "chirpy",
		IssuedAt:  jwt.NewNumericDate(time.Now()),
		ExpiresAt: jwt.NewNumericDate(time.Now().Add(expiresIn)),
		Subject:   userID.String(),
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	completedToken, err := token.SignedString([]byte(tokenSecret))

	if err != nil {
		return "", err
	}

	return completedToken, nil
}

func ValidateJWT(tokenString, tokenSecret string) (uuid.UUID, error) {
	token, err := jwt.ParseWithClaims(tokenString, &jwt.RegisteredClaims{}, func(token *jwt.Token) (interface{}, error) {
		return []byte(tokenSecret), nil
	},
	)

	if err != nil {
		return uuid.UUID{}, err
	}

	if claims, ok := token.Claims.(*jwt.RegisteredClaims); ok && token.Valid {
		return uuid.Parse(claims.Subject)
	}
	return uuid.Nil, err
}

func GetBearerToken(headers http.Header) (string, error) {
	auth_header := headers.Get("Authorization")

	if !strings.HasPrefix(auth_header, "Bearer ") {
		return "", fmt.Errorf("invalid authorization header format")
	}

	token := strings.TrimPrefix(auth_header, "Bearer ")

	if token == "" {
		return "", fmt.Errorf("authorization header is empty")
	}

	return token, nil
}

func MakeRefreshToken() (string, error) {
	b := make([]byte, 32)
	_, err := rand.Read(b)

	if err != nil {
		return "", err
	}

	hex_str := hex.EncodeToString(b)

	return hex_str, nil
}

func GetAPIKey(headers http.Header) (string, error) {
	auth_header := headers.Get("Authorization")

	if !strings.HasPrefix(auth_header, "ApiKey ") {
		return "", fmt.Errorf("invalid authorization header format")
	}

	apiKey := strings.TrimPrefix(auth_header, "ApiKey ")

	if apiKey == "" {
		return "", fmt.Errorf("authorization header is empty")
	}

	return apiKey, nil
}
