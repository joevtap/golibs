// Package authutils provides authentication utilities for apps using golang-jwt/v4
package authutils

import (
	"errors"
	"fmt"

	"time"

	"github.com/golang-jwt/jwt/v4"
)

// GetSignedJWT creates a JWT token with the provided customClaims and returns a string signed using HMAC SHA-256
//   - ttl: Time To Live in minutes
//   - secret: Signing secret key
//   - customClaims
func GetSignedJWT(ttl int, secret string, customClaims jwt.MapClaims) (string, error) {
	if ttl <= 0 {
		return "", errors.New("minutesToExpire is negative")
	}

	claims := jwt.MapClaims{
		"exp": jwt.NewNumericDate(time.Now().Add(time.Duration(ttl) * time.Minute)),
		"iat": jwt.NewNumericDate(time.Now()),
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)

	for key, value := range customClaims {
		token.Claims.(jwt.MapClaims)[key] = value
	}

	return token.SignedString([]byte(secret))
}

// ParseToken parses and validates a signed string and returns it's token object
//   - signedString
//   - secret: Signing secret key used to generate the signedString
//
// It always returns an error, which is nil when the parsing is successful
func ParseToken(signedString, secret string) (*jwt.Token, error) {
	return jwt.Parse(signedString, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}

		return []byte(secret), nil
	})
}

// GetTokenClaims returns token's associated claims
func GetTokenClaims(token *jwt.Token) jwt.MapClaims {
	mapClaims := make(jwt.MapClaims)

	for key, value := range token.Claims.(jwt.MapClaims) {
		mapClaims[key] = value
	}

	return mapClaims
}

// IsTokenExpiring returns true if the provided token is expiring in the next timeLeft minutes
func IsTokenExpiring(token *jwt.Token, timeLeft int) bool {
	claims := GetTokenClaims(token)
	expirationTime := claims["exp"]

	return time.Until(time.Unix(int64(expirationTime.(float64)), 0)).Minutes() <= float64(timeLeft)
}
