package zcj_rsa

import (
	"fmt"
	"github.com/golang-jwt/jwt"
	"time"
)

const EXPIRSTIME = 5    // 有效期时间 单位为分钟

type token struct {
	jwt.StandardClaims
}
var rsa *signData

// 创建jwt token
func CreateToken(issuer, aud string) (string, error) {
	nowTime := time.Now()
	tk := token{}
	tk.Issuer = issuer  //  签发人
	tk.Audience = aud   //
	tk.ExpiresAt = nowTime.Add(EXPIRSTIME*time.Minute).Unix()     // 定义有效期
	tk.IssuedAt = nowTime.Unix()  // 签发时间
	//jwt.SigningMethodHS256
	jwtTk := jwt.NewWithClaims(jwt.GetSigningMethod("RS256"), tk) // 得到jwt TOKEN
	// 使用rsa进行加密
	rsa = RsaInit(false, -1, "", "")
	err := rsa.creatKey()
	if err != nil {
		return "", err
	}
	privateKey, err := rsa.GetPrivateKey()
	if err != nil {
		return "", err
	}
	signKey, err := jwt.ParseRSAPrivateKeyFromPEM([]byte(privateKey))
	return jwtTk.SignedString(signKey)
}

func ParseToken(th string) (*token, error) {
	tk := &token{}
	jwtTk, err := jwt.ParseWithClaims(th, tk, func(tk1 *jwt.Token) (interface{}, error) {
		jwtToken := tk1.Claims.(*token)

		if jwtToken.Issuer == "" {
			return "", fmt.Errorf("issuer field not exist in jwt payload")
		}
		pubKey, err := rsa.GetPublicKey()
		if err != nil {
			return "", err
		}
		return pubKey, nil
	})

	if ve, ok := err.(*jwt.ValidationError); ok {
		return tk,fmt.Errorf("inner: %v\n metaToken:%v", ve, th)
	}

	if err != nil {
		return nil, err
	}
	if !jwtTk.Valid {
		return nil, fmt.Errorf("invalid token")
	}
	return tk, nil
}
