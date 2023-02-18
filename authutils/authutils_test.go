package authutils

import (
	"testing"

	"github.com/golang-jwt/jwt/v4"
)

var (
	secret = "secret"
	ttl    = 1
	claims = jwt.MapClaims{"test": "test"}
)

var signedString, _ = GetSignedJWT(ttl, secret, claims)

func TestGetSignedJWT(t *testing.T) {
	t.Run("should generate token", func(t *testing.T) {
		_, err := GetSignedJWT(ttl, secret, claims)
		if err != nil {
			t.Error("failed to generate token", err)
		}
	})

	t.Run("should generate token without claims", func(t *testing.T) {
		_, err := GetSignedJWT(ttl, secret, jwt.MapClaims{})
		if err != nil {
			t.Error("failed to generate token", err)
		}
	})

	t.Run("should only generate token with positive and nonzero ttl", func(t *testing.T) {
		var err error

		_, err = GetSignedJWT(-ttl, secret, jwt.MapClaims{})
		if err == nil {
			t.Error(err)
		}

		_, err = GetSignedJWT(0, secret, jwt.MapClaims{})
		if err == nil {
			t.Error(err)
		}
	})
}

func TestParseToken(t *testing.T) {
	t.Run("should parse a signed string as a token", func(t *testing.T) {
		_, err := ParseToken(signedString, secret)
		if err != nil {
			t.Error(err)
		}
	})

	t.Run("should only parse valid signed strings", func(t *testing.T) {
		_, err := ParseToken("invalid", secret)
		if err == nil {
			t.Error(err)
		}
	})

	t.Run("should error when secret key is wrong", func(t *testing.T) {
		_, err := ParseToken(signedString, "invalid")
		if err == nil {
			t.Error(err)
		}
	})

	t.Run("should error when using wrong signing method", func(t *testing.T) {
		_, err := ParseToken("eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.e30.IR0tmJYE-4-Q3DwhFnba4nIBX7-6kkgwhE1CpiY9o5AN7EMXlAuNtZV9a9uh_MZbHTzLD1kgSgMcYsVhIiKOrN9a83c1VWh2itGKEB2BMz3g02hlZvTvFhrVHAz0khyUR-KMBVmpeXKNsFDPb0E_J0bTnKgCQm9a48m5D8Jl8EmrMP4NHAedycvFOFu3KEZ1K_Hn6OueJtFziSKkIeB_hOV4sC2X6F8wjVc59kVWk54pAVSHgyDfOzK0dXj4bHwvxltJMVZ6tIJMC-KAIADE57cdahbDdz4e5Sjs1P-B1rA2NBGyRzyL7r85wKLiOs7y8eQ_M_GiFyU_V0jJq_ctCw", secret)
		if err == nil {
			t.Fail()
		}
	})
}

func TestGetTokenClaims(t *testing.T) {
	token, err := ParseToken(signedString, secret)
	if err != nil {
		t.Error(err)
	}

	if GetTokenClaims(token)["test"] != claims["test"] {
		t.Error("failed to get token claims")
	}
}

func TestIsTokenExpiring(t *testing.T) {
	token, err := ParseToken(signedString, secret)
	if err != nil {
		t.Error(err)
	}

	if !IsTokenExpiring(token, ttl) {
		t.Error("returned false when it should return true for token expiring")
	}
}
