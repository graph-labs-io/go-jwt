package jwt

import (
	"errors"
	"time"

	"github.com/dgrijalva/jwt-go"
	"github.com/google/uuid"

	_ "github.com/joho/godotenv/autoload"
)

type tokenClaims struct {
	Key        string
	TokenId    string
	InstanceId string
	Premium    bool
	jwt.StandardClaims
}

func GenerateToken(key string, instanceId string, isPremium bool, jwtKey string) (string, string, error) {
	tokenId := uuid.New().String()

	claims := tokenClaims{
		key,
		tokenId,
		instanceId,
		isPremium,
		jwt.StandardClaims{
			ExpiresAt: time.Now().Add(time.Hour * 5 * 24).Unix(),
			IssuedAt:  time.Now().Unix(),
		},
	}

	jsonWebToken := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	signedString, jwtSignErr := jsonWebToken.SignedString([]byte(jwtKey))
	if jwtSignErr != nil {
		return "", "", jwtSignErr
	}

	return signedString, tokenId, nil
}

func VerifyTokenSignature(tokenString string, jwtKey string) (tokenClaims, error) {
	parsedToken, jwtParseErr := jwt.ParseWithClaims(tokenString, &tokenClaims{}, func(token *jwt.Token) (interface{}, error) {
		return []byte(jwtKey), nil
	})

	if jwtParseErr != nil {
		return tokenClaims{}, jwtParseErr
	}

	if claims, ok := parsedToken.Claims.(*tokenClaims); ok && parsedToken.Valid {
		return *claims, nil
	} else {
		return tokenClaims{}, errors.New("invalid token")
	}
}

type TokenClaimsMismatch []TokenClaimComparison
type TokenClaimComparison struct {
	Claim    string
	Received string
	Expected string
}

type UserJwtRecord struct {
	Key        string `json:"key"`
	TokenId    string `json:"tokenId"`
	InstanceId string `json:"instanceId"`
}

func VerifyTokenClaims(recievedTokenClaims tokenClaims, currentJwtRecord UserJwtRecord, requestInstanceId string) (bool, TokenClaimsMismatch) {
	if recievedTokenClaims.TokenId == currentJwtRecord.TokenId && currentJwtRecord.InstanceId == requestInstanceId {
		return true, TokenClaimsMismatch{}
	} else {
		mismatch := TokenClaimsMismatch{}

		if recievedTokenClaims.TokenId != currentJwtRecord.TokenId {
			mismatch = append(mismatch, TokenClaimComparison{
				"TokenId",
				recievedTokenClaims.TokenId,
				currentJwtRecord.TokenId,
			})
		}

		if requestInstanceId != currentJwtRecord.InstanceId {
			mismatch = append(mismatch, TokenClaimComparison{
				"InstanceId",
				requestInstanceId,
				currentJwtRecord.InstanceId,
			})
		}

		return false, mismatch
	}
}
