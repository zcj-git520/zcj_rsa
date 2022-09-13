package zcj_rsa

import (
	"fmt"
	"testing"
)

// 创建rsa保存在文件
func TestRsaFile(t *testing.T) {
	rsa := RsaInit(true, 1, "./", "./")
	err := rsa.creatKey()
	if err != nil {
		t.Errorf("公私钥创建失败: %v", err)
	}
	// 加密
	cipherText, err := rsa.RSAEncryption("zcj")
	if err != nil {
		t.Errorf("加密失败：%v", err)
	}
	// 解密
	planinText, err := rsa.RSADecryption(cipherText)
	if err != nil {
		t.Errorf("解密失败：%v", err)
	}
	fmt.Printf("密文：%v \n", cipherText)
	fmt.Printf("原码：%v \n", planinText)
}

// 保存rsa在内存
func TestRsa(t *testing.T) {
	rsa := RsaInit(false, 1, "", "")
	err := rsa.creatKey()
	if err != nil {
		t.Errorf("公私钥创建失败: %v", err)
	}
	// 加密
	cipherText, err := rsa.RSAEncryption("zcj")
	if err != nil {
		t.Errorf("加密失败：%v", err)
	}
	// 解密
	planinText, err := rsa.RSADecryption(cipherText)
	if err != nil {
		t.Errorf("解密失败：%v", err)
	}
	fmt.Printf("密文：%v \n", cipherText)
	fmt.Printf("原码：%v \n", planinText)
}

// test jwt
func TestJet(t *testing.T)  {
	jwtStr, err := CreateToken("zcj", "ss")
	if err != nil {
		t.Errorf(err.Error())
	}
	tk, err := ParseToken(jwtStr)
	if err != nil {
		t.Errorf(err.Error())
	}
	fmt.Errorf(tk.Issuer)

}