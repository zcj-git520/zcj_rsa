package zcj_rsa

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"os"
	"path"
	"time"
)

const (
	BITS  = 2048        // 证书大小
	SAVEKEYPATH = "./"  // 默认保存公私钥的路径
)

type signData struct {
	publicKey  		string    // 公钥
	privateKey 		string    // 私钥
	generateTime    time.Time // 生成时间
	isCreate        bool      // 是否创建公私钥
	Timeout         int       // 证书超时时间 单位时间为分钟 <= 0 表示永久有效
	SaveMode        bool      // true 保存为文件，False保存在内存中
	PublicKeyPath   string    // 保存公钥的路径
	PrivateKeyPath  string    // 保存私钥的路径
}

// 创建公私钥对
func (s *signData)creatKey() error {
	if s.isEffectiveKey(){
		return fmt.Errorf("公私钥已存在")
	}
	// 创建私钥
	prvKey, err := rsa.GenerateKey(rand.Reader, BITS)
	if err != nil {
		return err
	}
	//通过x509标准将得到的ras私钥序列化为ASN.1 的 DER编码字符串
	x509PrivateKey := x509.MarshalPKCS1PrivateKey(prvKey)
	privateKeyBlock := &pem.Block{
		Type:"RSA Private key",
		Bytes: x509PrivateKey,
	}
	//处理公钥,公钥包含在私钥中
	pubKey := prvKey.PublicKey
	//通过x509标准将得到的ras公钥序列化为ASN.1 的 DER编码字符串
	x509PublicKey, err := x509.MarshalPKIXPublicKey(&pubKey)
	if err != nil {
		return err
	}
	publicKeyBlock := &pem.Block{
		Type:"RSA Public key",
		Bytes: x509PublicKey,
	}
	if s.SaveMode{
		publicFile, err := os.Create(path.Join(s.PublicKeyPath, "public.pem"))
		if err!=nil{
			return err
		}
		privateKeyFile, err := os.Create(path.Join(s.PrivateKeyPath, "privateKey.pem"))
		if err!=nil{
			return err
		}
		defer publicFile.Close()
		defer privateKeyFile.Close()
		//保存到文件
		err = pem.Encode(privateKeyFile,privateKeyBlock)
		if err!=nil{
			return err
		}
		err = pem.Encode(publicFile,publicKeyBlock)
		if err!=nil{
			return err
		}
	}else{
		s.publicKey = string(pem.EncodeToMemory(publicKeyBlock))
		s.privateKey = string(pem.EncodeToMemory(privateKeyBlock))
	}
	s.generateTime = time.Now()
	s.isCreate = true
	return nil
}

// 判断公私钥是否有效
func (s *signData)isEffectiveKey()bool{
	if s.isCreate{
		if s.Timeout <= 0{
			//log.Info("公私钥创建，且永久有效")
			return true
		}
		duration := time.Now().Sub(s.generateTime).Minutes()
		if int(duration) <= s.Timeout{
			//log.Info("公私钥创建，且在有效期")
			return true
		}
	}
	return false
}

// 使用私钥进行解密
func (s *signData)RSADecryption(cipherText string)(string, error){
	// 保存在内存中进行判断
	if !s.SaveMode && !s.isEffectiveKey(){
		return "", fmt.Errorf("公私钥未创建")
	}
	cipherBuf, err := base64.StdEncoding.DecodeString(cipherText)
	if err != nil {
		return "", err
	}
	var buf []byte
	if s.SaveMode{
		file,err:=os.Open(path.Join(s.PrivateKeyPath, "privateKey.pem"))
		if err!=nil{
			panic(err)
		}
		defer file.Close()
		//读取文件的内容
		info, _ := file.Stat()
		buf =make([]byte,info.Size())
		file.Read(buf)
	}else{
		buf = []byte(s.privateKey)
	}
	block, _ := pem.Decode(buf)
	if block == nil{
		return "", fmt.Errorf("pem decode fild")
	}
	privateKey, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		return "", err
	}
	plainText, err := rsa.DecryptPKCS1v15(rand.Reader, privateKey, cipherBuf)
	if err != nil {
		return "", err
	}
	return string(plainText), err
}

// 使用公钥加密
func (s *signData)RSAEncryption(plainText string)(string, error){
	// 保存在内存中进行判断
	if !s.SaveMode && !s.isEffectiveKey(){
		return "", fmt.Errorf("公私钥未创建")
	}
	var buf []byte
	if s.SaveMode{
		file,err:=os.Open(path.Join(s.PrivateKeyPath, "public.pem"))
		if err!=nil{
			panic(err)
		}
		defer file.Close()
		//读取文件的内容
		info, _ := file.Stat()
		buf =make([]byte,info.Size())
		file.Read(buf)
	}else{
		buf = []byte(s.publicKey)
	}
	block, _ := pem.Decode(buf)
	if block == nil{
		return "", fmt.Errorf("pem decode fild")
	}
	//x509解码
	publicKeyInterface, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err!=nil{
		return "", nil
	}
	//类型断言
	publicKey:=publicKeyInterface.(*rsa.PublicKey)
	//对明文进行加密
	cipherText, err := rsa.EncryptPKCS1v15(rand.Reader, publicKey, []byte(plainText))
	if err!=nil{
		return "", nil
	}
	strCipher := base64.StdEncoding.EncodeToString(cipherText)
	return strCipher, nil

}

func RsaInit(saveMode bool, timeOut int, publicKeyPath, privateKeyPath string) *signData {
	if publicKeyPath == ""{
		publicKeyPath = SAVEKEYPATH
	}
	if privateKeyPath == ""{
		privateKeyPath = SAVEKEYPATH
	}
	return &signData{
		isCreate:		false,
		Timeout:        timeOut,
		SaveMode:       saveMode,
		PublicKeyPath:  publicKeyPath,
		PrivateKeyPath: privateKeyPath,
	}
}



