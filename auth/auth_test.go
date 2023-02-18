package auth

import (
	"testing"

	"github.com/golang-jwt/jwt/v4"
)

var (
	mockJWT = JWT{}
)

func TestSetSecret(t *testing.T) {
	mockJWT.SetSecret("secret")

	if mockJWT.secret == nil {
		t.Error("secret not set")
	}
}

func TestGenerateToken(t *testing.T) {
	t.Run("should generate token without custom claims", func(t *testing.T) {
		token, err := mockJWT.GenerateToken(1, MapClaims{})

		if err != nil {
			t.Error("failed to generate token", token)
		}
	})

	t.Run("should generate token with custom claims", func(t *testing.T) {
		token, err := mockJWT.GenerateToken(1, MapClaims{"teste": "teste"})

		if err != nil {
			t.Error("failed to generate token", token)
		}

	})

	t.Run("should fail to generate token with negative ttl", func(t *testing.T) {
		token, err := mockJWT.GenerateToken(-1, MapClaims{})

		if err == nil {
			t.Error("generated token with negative ttl", token)
		}
	})

	t.Run("should not fail to generate token with zero value ttl", func(t *testing.T) {
		token, err := mockJWT.GenerateToken(0, MapClaims{})

		if err != nil {
			t.Error("failed to generate token", token)
		}
	})
}

func TestGenerateRefreshToken(t *testing.T) {
	t.Run("should generate token with no ttl provided", func(t *testing.T) {
		token, err := mockJWT.GenerateRefreshToken(MapClaims{})
		if err != nil {
			t.Error("failed to generate token", token)
		}
	})

	t.Run("should generate token with the provided ttl", func(t *testing.T) {
		ttl := 5

		token, err := mockJWT.GenerateRefreshToken(MapClaims{}, ttl)
		if err != nil {
			t.Error("failed to generate token", token)
		}

		parsedToken, err := mockJWT.ParseToken(token)
		if err != nil {
			t.Error("failed to verify ttl of token", token)
		}

		got := mockJWT.IsTokenExpiring(parsedToken, ttl)
		expected := true

		if got != expected {
			t.Error("token does not have the provided ttl", token)
		}
	})

	t.Run("should fail to generate refresh token with negative ttl", func(t *testing.T) {
		ttl := -5

		token, err := mockJWT.GenerateRefreshToken(MapClaims{}, ttl)
		if err == nil {
			t.Error("generated token with negative ttl", token)
		}
	})
}

func TestParseToken(t *testing.T) {
	t.Run("should parse a valid token in singned string format", func(t *testing.T) {
		signedString, _ := mockJWT.GenerateToken(1, MapClaims{})
		token, err := mockJWT.ParseToken(signedString)
		if err != nil {
			t.Error("failed to parse token", token)
		}
	})

	t.Run("should fail to parse a invalid token", func(t *testing.T) {
		token, err := mockJWT.ParseToken("invalidToken")
		if err == nil {
			t.Error("parsed invalid token", token)
		}
	})

	t.Run("should fail to parse token with wrong signing method", func(t *testing.T) {
		signedWithWrongMethod := "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJEaW5vQ2hpZXNhLmdpdGh1Yi5pbyIsInN1YiI6ImF1ZHJleSIsImF1ZCI6ImFsbWEiLCJpYXQiOjE2NzY2OTEyMjUsImV4cCI6MTY3NjY5MTgyNX0.P-S2M5QpS-7yV_vNMH_ACp9NyG9WnpX7UmHEgYxS4vpwtCrXPbR37sZS9aE_WFREsOrplbvanoaL22tsrcY3Xn9YlfmB44g_LpRx_4X2EvDR152_QiKw5ZtvvQ9cZ5B9xdhXg8L3pTnvt-KTqyKxdaJM72IjT_QjwzowwRv_5ZqUXd9t7kPwBAUEI7keMNHfsUW5H0CSrq-V3pD8DLXvdyBu_TLoULNz13H1dSHIZ5_Wbhr8fHl7wNkUVRAv63uasJP6RdzNx8-XqcpxbP9o53dIBnQAdfQmEbFLT3th4lWzBV7aTyZ2UBr_ZRb8U5p-8NxNNAz01NlOvvR5txILQg"

		token, err := mockJWT.ParseToken(signedWithWrongMethod)
		if err == nil {
			t.Error("parsed token with wrong signing method", token)
		}
	})
}

func SetupToken() (*jwt.Token, error) {
	tokenString, _ := mockJWT.GenerateToken(1, MapClaims{"teste": true})
	return mockJWT.ParseToken(tokenString)
}

func TestGetTokenClaims(t *testing.T) {
	token, _ := SetupToken()
	mapClaims := mockJWT.GetTokenClaims(token)

	if mapClaims["teste"] != true {
		t.Error("failed to get token claims", mapClaims)
	}
}

func TestIsTokenExpiring(t *testing.T) {
	token, _ := SetupToken()

	got := mockJWT.IsTokenExpiring(token, 1)
	expected := true

	if got != expected {
		t.Error("returned false instead of true for token expiring")
	}
}

func TestHashAndSaltPassword(t *testing.T) {
	hash := mockJWT.HashAndSaltPassword("123")

	if !mockJWT.PasswordMatch("123", hash) || hash == "123" {
		t.Error("failed to hash and salt password")
	}
}

func TestPasswordMatch(t *testing.T) {
	hash := mockJWT.HashAndSaltPassword("123")

	if !mockJWT.PasswordMatch("123", hash) || mockJWT.PasswordMatch("wrong", hash) {
		t.Error("failed to hash and salt password")
	}
}
