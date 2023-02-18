// Package auth provides authentication utilities using JWT
package auth

import (
	"errors"
	"fmt"

	"time"

	"github.com/golang-jwt/jwt/v4"
	"golang.org/x/crypto/bcrypt"
)

type JWT struct {
	secret []byte
}

type MapClaims jwt.MapClaims

// SetSecret sets the secret key for generating and validating JWT tokens.
func (j *JWT) SetSecret(s string) {
	j.secret = []byte(s)
}

// GenerateToken generates a JWT token and returns the token and any errors.
//
//   - minutesToExpire: The number of minutes before the token expires.
//
// The token is signed using the secret key.
//
// Error can be nil.
func (j JWT) GenerateToken(minutesToExpire int, customClaims MapClaims) (string, error) {
	if minutesToExpire < 0 {
		return "", errors.New("minutesToExpire is negative")
	}

	claims := jwt.MapClaims{
		"exp": jwt.NewNumericDate(time.Now().Add(time.Duration(minutesToExpire) * time.Minute)),
		"iss": "github.com/joevtap",
		"iat": jwt.NewNumericDate(time.Now()),
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)

	for key, value := range customClaims {
		token.Claims.(jwt.MapClaims)[key] = value
	}

	return token.SignedString(j.secret)
}

// The same as GenerateToken but with a default expiration time of 15 minutes.
//
// Args can be used to override the default expiration time.
//
//   - args[0]: The number of minutes before the token expires.
func (j JWT) GenerateRefreshToken(customClaims MapClaims, args ...int) (string, error) {
	minutesToExpire := 15

	if len(args) > 0 {
		minutesToExpire = args[0]
	}

	return j.GenerateToken(minutesToExpire, customClaims)
}

// ParseToken parses a JWT token and returns the token and any errors.
//
// The token is verified using the secret key.
//
// Error can be nil.
func (j JWT) ParseToken(signedString string) (*jwt.Token, error) {
	return jwt.Parse(signedString, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}

		return j.secret, nil
	})
}

// GetTokenClaims returns the claims of a JWT token.
func (JWT) GetTokenClaims(token *jwt.Token) MapClaims {
	mapClaims := make(MapClaims)

	for key, value := range token.Claims.(jwt.MapClaims) {
		mapClaims[key] = value
	}

	return mapClaims
}

// IsTokenExpiring returns true if the token is expiring in the next minutesLeft minutes.
func (j JWT) IsTokenExpiring(token *jwt.Token, minutesLeft int) bool {
	claims := j.GetTokenClaims(token)
	expirationTime := claims["exp"]

	return time.Until(time.Unix(int64(expirationTime.(float64)), 0)).Minutes() <= float64(minutesLeft)
}

// HashAndSaltPassword hashes and salts a password.
//
// It returns the hash in string format.
func (JWT) HashAndSaltPassword(password string) string {
	hash, _ := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	return string(hash)
}

// PasswordMatch returns true if the password matches the hash.
func (JWT) PasswordMatch(password string, hash string) bool {
	err := bcrypt.CompareHashAndPassword([]byte(hash), []byte(password))
	return err == nil
}
