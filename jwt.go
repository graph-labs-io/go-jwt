package jwt

import (
	"errors"
	"os"
	"time"

	"github.com/dgrijalva/jwt-go"
	"github.com/google/uuid"

	_ "github.com/joho/godotenv/autoload"
)

type tokenClaims struct {
	Key        string
	Ip         string
	TokenId    string
	InstanceId string
	jwt.StandardClaims
}

func GenerateToken(key string, ip string, instanceId string) (string, string, error) {
	tokenId := uuid.New().String()

	claims := tokenClaims{
		key,
		ip,
		tokenId,
		instanceId,
		jwt.StandardClaims{
			ExpiresAt: time.Now().Add(time.Minute * 15).Unix(),
			IssuedAt:  time.Now().Unix(),
		},
	}

	jsonWebToken := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	signedString, jwtSignErr := jsonWebToken.SignedString([]byte(os.Getenv("JWT_KEY")))
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
	Ip         string `json:"ip"`
	Key        string `json:"key"`
	TokenId    string `json:"tokenId"`
	InstanceId string `json:"instanceId"`
}

func VerifyTokenClaims(recievedTokenClaims tokenClaims, currentJwtRecord UserJwtRecord, requestIp string, requestInstanceId string) (bool, TokenClaimsMismatch) {
	if recievedTokenClaims.TokenId == currentJwtRecord.TokenId && currentJwtRecord.InstanceId == requestInstanceId && currentJwtRecord.Ip == requestIp {
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

		if requestIp != currentJwtRecord.Ip {
			mismatch = append(mismatch, TokenClaimComparison{
				"Ip",
				requestIp,
				currentJwtRecord.Ip,
			})
		}

		return false, mismatch
	}
}
