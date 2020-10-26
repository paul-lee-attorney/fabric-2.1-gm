/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package utils

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/md5"
	"crypto/rand"
	"crypto/x509"
	"encoding/asn1"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"strings"

	"github.com/paul-lee-attorney/gm/sm4"
	"github.com/paul-lee-attorney/gm/sm3"
)

// struct to hold info required for PKCS#8
type pkcs8Info struct {
	Version             int
	PrivateKeyAlgorithm []asn1.ObjectIdentifier
	PrivateKey          []byte
}

type ecPrivateKey struct {
	Version       int
	PrivateKey    []byte
	NamedCurveOID asn1.ObjectIdentifier `asn1:"optional,explicit,tag:0"`
	PublicKey     asn1.BitString        `asn1:"optional,explicit,tag:1"`
}

var (
	oidNamedCurveP224 = asn1.ObjectIdentifier{1, 3, 132, 0, 33}
	oidNamedCurveP256 = asn1.ObjectIdentifier{1, 2, 840, 10045, 3, 1, 7}
	oidNamedCurveP384 = asn1.ObjectIdentifier{1, 3, 132, 0, 34}
	oidNamedCurveP521 = asn1.ObjectIdentifier{1, 3, 132, 0, 35}

	// 加入SM2推荐曲线的oid
	oidSM2P256V1 = asn1.ObjectIdentifier{1, 2, 156, 10197, 1, 301}
	// oidSignatureSM3WithSM2 = asn1.ObjectIdentifier{1, 2, 156, 10197, 1, 501}
)

var oidPublicKeyECDSA = asn1.ObjectIdentifier{1, 2, 840, 10045, 2, 1}

func oidFromNamedCurve(curve elliptic.Curve) (asn1.ObjectIdentifier, bool) {
	switch curve {
	case elliptic.P224():
		return oidNamedCurveP224, true
	case elliptic.P256():
		return oidNamedCurveP256, true
	case elliptic.P384():
		return oidNamedCurveP384, true
	case elliptic.P521():
		return oidNamedCurveP521, true
	case sm2.GetSm2P256V1():
		return oidSM2P256V1, true
	}
	return nil, false
}

// PrivateKeyToDER marshals a private key to der
func PrivateKeyToDER(privateKey *ecdsa.PrivateKey) ([]byte, error) {
	if privateKey == nil {
		return nil, errors.New("Invalid ecdsa private key. It must be different from nil.")
	}

	return x509.MarshalECPrivateKey(privateKey)
}

// PrivateKeyToPEM converts the private key to PEM format.
// EC private keys are converted to PKCS#8 format.
func PrivateKeyToPEM(privateKey interface{}, pwd []byte) ([]byte, error) {
	// Validate inputs
	if len(pwd) != 0 {
		return PrivateKeyToEncryptedPEM(privateKey, pwd)
	}
	if privateKey == nil {
		return nil, errors.New("Invalid key. It must be different from nil.")
	}

	switch k := privateKey.(type) {
	case *ecdsa.PrivateKey:
		if k == nil {
			return nil, errors.New("Invalid ecdsa private key. It must be different from nil.")
		}

		// get the oid for the curve
		oidNamedCurve, ok := oidFromNamedCurve(k.Curve)
		if !ok {
			return nil, errors.New("unknown elliptic curve")
		}

		// based on https://golang.org/src/crypto/x509/sec1.go
		privateKeyBytes := k.D.Bytes()
		paddedPrivateKey := make([]byte, (k.Curve.Params().N.BitLen()+7)/8)
		copy(paddedPrivateKey[len(paddedPrivateKey)-len(privateKeyBytes):], privateKeyBytes)
		// omit NamedCurveOID for compatibility as it's optional
		asn1Bytes, err := asn1.Marshal(ecPrivateKey{
			Version:    1,
			PrivateKey: paddedPrivateKey,
			PublicKey:  asn1.BitString{Bytes: elliptic.Marshal(k.Curve, k.X, k.Y)},
		})

		if err != nil {
			return nil, fmt.Errorf("error marshaling EC key to asn1 [%s]", err)
		}

		var pkcs8Key pkcs8Info
		pkcs8Key.Version = 0
		pkcs8Key.PrivateKeyAlgorithm = make([]asn1.ObjectIdentifier, 2)
		pkcs8Key.PrivateKeyAlgorithm[0] = oidPublicKeyECDSA
		pkcs8Key.PrivateKeyAlgorithm[1] = oidNamedCurve
		pkcs8Key.PrivateKey = asn1Bytes

		pkcs8Bytes, err := asn1.Marshal(pkcs8Key)
		if err != nil {
			return nil, fmt.Errorf("error marshaling EC key to asn1 [%s]", err)
		}
		return pem.EncodeToMemory(
			&pem.Block{
				Type:  "PRIVATE KEY",
				Bytes: pkcs8Bytes,
			},
		), nil

	case *sm2.PrivateKey:
		if k == nil {
			return nil, errors.New("Invalid ecdsa private key. It must be different from nil.")
		}

		// get the oid for the curve
		oidNamedCurve, ok := oidFromNamedCurve(k.Curve)
		if !ok {
			return nil, errors.New("unknown elliptic curve")
		}

		// based on https://golang.org/src/crypto/x509/sec1.go
		privateKeyBytes := k.D.Bytes()
		paddedPrivateKey := make([]byte, (k.Curve.Params().N.BitLen()+7)/8)
		copy(paddedPrivateKey[len(paddedPrivateKey)-len(privateKeyBytes):], privateKeyBytes)
		// omit NamedCurveOID for compatibility as it's optional
		asn1Bytes, err := asn1.Marshal(ecPrivateKey{
			Version:    1,
			PrivateKey: paddedPrivateKey,
			PublicKey:  asn1.BitString{Bytes: elliptic.Marshal(k.Curve, k.X, k.Y)},
		})

		if err != nil {
			return nil, fmt.Errorf("error marshaling EC key to asn1 [%s]", err)
		}

		var pkcs8Key pkcs8Info
		pkcs8Key.Version = 0
		pkcs8Key.PrivateKeyAlgorithm = make([]asn1.ObjectIdentifier, 2)
		pkcs8Key.PrivateKeyAlgorithm[0] = oidPublicKeyECDSA
		pkcs8Key.PrivateKeyAlgorithm[1] = oidNamedCurve
		pkcs8Key.PrivateKey = asn1Bytes

		pkcs8Bytes, err := asn1.Marshal(pkcs8Key)
		if err != nil {
			return nil, fmt.Errorf("error marshaling EC key to asn1 [%s]", err)
		}
		return pem.EncodeToMemory(
			&pem.Block{
				Type:  "PRIVATE KEY",
				Bytes: pkcs8Bytes,
			},
		), nil
	default:
		return nil, errors.New("Invalid key type. It must be *ecdsa.PrivateKey")
	}
}

// PrivateKeyToEncryptedPEM converts a private key to an encrypted PEM
func PrivateKeyToEncryptedPEM(privateKey interface{}, pwd []byte) ([]byte, error) {
	if privateKey == nil {
		return nil, errors.New("Invalid private key. It must be different from nil.")
	}

	switch k := privateKey.(type) {
	case *ecdsa.PrivateKey:
		if k == nil {
			return nil, errors.New("Invalid ecdsa private key. It must be different from nil.")
		}
		raw, err := x509.MarshalECPrivateKey(k)

		if err != nil {
			return nil, err
		}

		block, err := x509.EncryptPEMBlock(
			rand.Reader,
			"PRIVATE KEY",
			raw,
			pwd,
			x509.PEMCipherAES256)

		if err != nil {
			return nil, err
		}

		return pem.EncodeToMemory(block), nil

	default:
		return nil, errors.New("Invalid key type. It must be *ecdsa.PrivateKey")
	}
}

// DERToPrivateKey unmarshals a der to private key
func DERToPrivateKey(der []byte) (key interface{}, err error) {

	if key, err = x509.ParsePKCS1PrivateKey(der); err == nil {
		return key, nil
	}

	if key, err = x509.ParsePKCS8PrivateKey(der); err == nil {
		switch key.(type) {
		case *ecdsa.PrivateKey:
			return
		default:
			return nil, errors.New("Found unknown private key type in PKCS#8 wrapping")
		}
	}

	if key, err = x509.ParseECPrivateKey(der); err == nil {
		return
	}

	return nil, errors.New("Invalid key type. The DER must contain an ecdsa.PrivateKey")
}

// PEMtoPrivateKey unmarshals a pem to private key
func PEMtoPrivateKey(raw []byte, pwd []byte) (interface{}, error) {
	if len(raw) == 0 {
		return nil, errors.New("Invalid PEM. It must be different from nil.")
	}
	block, _ := pem.Decode(raw)
	if block == nil {
		return nil, fmt.Errorf("Failed decoding PEM. Block must be different from nil. [% x]", raw)
	}

	// TODO: derive from header the type of the key

	if x509.IsEncryptedPEMBlock(block) {
		if len(pwd) == 0 {
			return nil, errors.New("Encrypted Key. Need a password")
		}

		decrypted, err := x509.DecryptPEMBlock(block, pwd)
		if err != nil {
			return nil, fmt.Errorf("Failed PEM decryption [%s]", err)
		}

		key, err := DERToPrivateKey(decrypted)
		if err != nil {
			return nil, err
		}
		return key, err
	}

	cert, err := DERToPrivateKey(block.Bytes)
	if err != nil {
		return nil, err
	}
	return cert, err
}

// PEMtoAES extracts from the PEM an AES/SM4 key
func PEMtoAES(raw []byte, pwd []byte) ([]byte, error) {
	if len(raw) == 0 {
		return nil, errors.New("Invalid PEM. It must be different from nil.")
	}
	block, _ := pem.Decode(raw)
	if block == nil {
		return nil, fmt.Errorf("Failed decoding PEM. Block must be different from nil. [% x]", raw)
	}

	if x509.IsEncryptedPEMBlock(block) {
		if len(pwd) == 0 {
			return nil, errors.New("Encrypted Key. Password must be different from nil")
		}

		// 判断加密算法是否为SM4
		dek, _ := block.Headers["DEK-Info"]

		// 剥离出算法标识和向量初始值
		idx := strings.Index(dek, ",")
		if idx == -1 {
			return nil, errors.New("x509: malformed DEK-Info header")
		}

		mode, hexIV := dek[:idx], dek[idx+1:]
		if mode == "SM4-CBC" { // SM4加密
			// 将向量初始值从ASCII编码恢复
			iv, err := hex.DecodeString(hexIV)
			if err != nil {
				return nil, err
			}

			// 根据OpenSSL源代码，向量初始值的前八位为“盐”, 用MD5取哈希摘要
			key := deriveKey(pwd, iv[:8])

			// 创建SM4密文实例
			sm4Block, err := sm4.NewCipher(key)

			// 创建目标明文字节数组
			data := make([]byte, len(block.Bytes))

			// 调用SM4密文的解密方法，解密至data
			sm4Block.Decrypt(data, block.Bytes)

			return data, nil

		} else {
			decrypted, err := x509.DecryptPEMBlock(block, pwd)
			if err != nil {
				return nil, fmt.Errorf("Failed PEM decryption. [%s]", err)
			}
			return decrypted, nil
		}
	}

	return block.Bytes, nil
}

// deriveKey 为秘钥派生函数，参考Openssl和go标准库，用SM3为哈希函数
// 将密码加盐取SM3哈希后，将哈希值前16位取出作为SM4秘钥使用。
func deriveKey(password, salt []byte) []byte {
	hash := sm3.New() // SM4 秘钥长度为128位，16字节，而SM3只能生成256位哈希值
	out := make([]byte, 16)

	hash.Reset()
	hash.Write(password)
	hash.Write(salt)
	digest := hash.Sum(nil)

	copy(out, digest[:16]) // 截取SM3前16字节为SM4秘钥

	return out
}

// AEStoPEM encapsulates an AES key in the PEM format
func AEStoPEM(raw []byte) []byte {
	return pem.EncodeToMemory(&pem.Block{Type: "AES PRIVATE KEY", Bytes: raw})
}

// SM4toPEM encapsulates an SM4 key in the PEM format
func SM4toPEM(raw []byte) []byte {
	return pem.EncodeToMemory(&pem.Block{Type: "SM4 PRIVATE KEY", Bytes: raw})
}

// AEStoEncryptedPEM encapsulates an AES key in the encrypted PEM format
// ********需要后续对 x509 国密改造 ********
func AEStoEncryptedPEM(raw []byte, pwd []byte) ([]byte, error) {
	if len(raw) == 0 {
		return nil, errors.New("Invalid aes key. It must be different from nil")
	}
	if len(pwd) == 0 {
		return AEStoPEM(raw), nil
	}

	block, err := x509.EncryptPEMBlock(
		rand.Reader,
		"AES PRIVATE KEY",
		raw,
		pwd,
		x509.PEMCipherAES256)

	if err != nil {
		return nil, err
	}

	return pem.EncodeToMemory(block), nil
}

// SM4toEncryptedPEM encapsulates an SM4 key in the encrypted PEM format
// ******** 需要后续对 x509 国密改造 ********
func SM4toEncryptedPEM(raw []byte, pwd []byte) ([]byte, error) {

	if len(raw) == 0 {
		return nil, errors.New("Invalid SM4 key. It must be different from nil")
	}
	if len(pwd) == 0 {
		return SM4toPEM(raw), nil
	}

	// SM4的秘钥长度16字节，128位
	blockSize := 16

	// 按秘钥长度创设初始向量iv切片
	iv := make([]byte, blockSize)
	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		return nil, errors.New("x509: cannot generate IV: " + err.Error())
	}

	// The salt is the first 8 bytes of the initialization vector,
	// matching the key derivation in DecryptPEMBlock.
	key := deriveKey(pwd, iv[:8])

	//计算输入消息需要填充的字节长度
	pad := blockSize - len(raw)%blockSize

	//创设目标字节切片
	encrypted := make([]byte, len(raw), len(raw)+pad)

	//将输入消息拷贝到目标数组
	copy(encrypted, raw)

	//以填充字节长度为内容填充目标字节切片
	for i := 0; i < pad; i++ {
		encrypted = append(encrypted, byte(pad))
	}

	//sm4CBCEncryptBlocks为SM4算法CBC模式加密函数
	sm4CBCEncryptBlocks(key, encrypted, encrypted, iv)

	block := &pem.Block{
		Type: "SM4 PRIVATE KEY",
		Headers: map[string]string{
			"Proc-Type": "4,ENCRYPTED",
			"DEK-Info":  "SM4-CBC" + "," + hex.EncodeToString(iv),
		},
		Bytes: encrypted,
	}

	return pem.EncodeToMemory(block), nil
}

// sm4CBCEncryptBlocks 为SM4算法CBC模式加密函数。
sm4CBCEncryptBlocks(key, dst, src, iv []byte) {
	sm4Block, err := sm4.NewCipher(key)
	if err != nil {
		return nil, err
	}

	// go语言函数中对切片参数为指针引用，函数中直接修改切片内容，
	// 因此，需要将iv拷贝副本，否则将改变iv参数的原值.
	ivTemp := make([]byte, 16)
	copy(ivTemp, iv)

	for len(src) > 0 {
		// Write the xor to dst, then encrypt in place.
		dst[:16] = src[:16] ^ ivTemp
		sm4Block.Encrypt(dst[:16], dst[:16])

		// Move to the next block with this block as the next iv.
		ivTemp = dst[:16]
		src = src[16:]
		dst = dst[16:]
	}
}

// PublicKeyToPEM marshals a public key to the pem format
func PublicKeyToPEM(publicKey interface{}, pwd []byte) ([]byte, error) {
	if len(pwd) != 0 {
		return PublicKeyToEncryptedPEM(publicKey, pwd)
	}

	if publicKey == nil {
		return nil, errors.New("Invalid public key. It must be different from nil.")
	}

	switch k := publicKey.(type) {
	case *ecdsa.PublicKey:
		if k == nil {
			return nil, errors.New("Invalid ecdsa public key. It must be different from nil.")
		}
		PubASN1, err := x509.MarshalPKIXPublicKey(k)
		if err != nil {
			return nil, err
		}

		return pem.EncodeToMemory(
			&pem.Block{
				Type:  "PUBLIC KEY",
				Bytes: PubASN1,
			},
		), nil

	default:
		return nil, errors.New("Invalid key type. It must be *ecdsa.PublicKey")
	}
}

// PublicKeyToDER marshals a public key to the der format
func PublicKeyToDER(publicKey interface{}) ([]byte, error) {
	if publicKey == nil {
		return nil, errors.New("Invalid public key. It must be different from nil.")
	}

	switch k := publicKey.(type) {
	case *ecdsa.PublicKey:
		if k == nil {
			return nil, errors.New("Invalid ecdsa public key. It must be different from nil.")
		}
		PubASN1, err := x509.MarshalPKIXPublicKey(k)
		if err != nil {
			return nil, err
		}

		return PubASN1, nil

	default:
		return nil, errors.New("Invalid key type. It must be *ecdsa.PublicKey")
	}
}

// PublicKeyToEncryptedPEM converts a public key to encrypted pem
func PublicKeyToEncryptedPEM(publicKey interface{}, pwd []byte) ([]byte, error) {
	if publicKey == nil {
		return nil, errors.New("Invalid public key. It must be different from nil.")
	}
	if len(pwd) == 0 {
		return nil, errors.New("Invalid password. It must be different from nil.")
	}

	switch k := publicKey.(type) {
	case *ecdsa.PublicKey:
		if k == nil {
			return nil, errors.New("Invalid ecdsa public key. It must be different from nil.")
		}
		raw, err := x509.MarshalPKIXPublicKey(k)
		if err != nil {
			return nil, err
		}

		block, err := x509.EncryptPEMBlock(
			rand.Reader,
			"PUBLIC KEY",
			raw,
			pwd,
			x509.PEMCipherAES256)

		if err != nil {
			return nil, err
		}

		return pem.EncodeToMemory(block), nil

	default:
		return nil, errors.New("Invalid key type. It must be *ecdsa.PublicKey")
	}
}

// PEMtoPublicKey unmarshals a pem to public key
func PEMtoPublicKey(raw []byte, pwd []byte) (interface{}, error) {
	if len(raw) == 0 {
		return nil, errors.New("Invalid PEM. It must be different from nil.")
	}
	block, _ := pem.Decode(raw)
	if block == nil {
		return nil, fmt.Errorf("Failed decoding. Block must be different from nil. [% x]", raw)
	}

	// TODO: derive from header the type of the key
	if x509.IsEncryptedPEMBlock(block) {
		if len(pwd) == 0 {
			return nil, errors.New("Encrypted Key. Password must be different from nil")
		}

		decrypted, err := x509.DecryptPEMBlock(block, pwd)
		if err != nil {
			return nil, fmt.Errorf("Failed PEM decryption. [%s]", err)
		}

		key, err := DERToPublicKey(decrypted)
		if err != nil {
			return nil, err
		}
		return key, err
	}

	cert, err := DERToPublicKey(block.Bytes)
	if err != nil {
		return nil, err
	}
	return cert, err
}

// DERToPublicKey unmarshals a der to public key
func DERToPublicKey(raw []byte) (pub interface{}, err error) {
	if len(raw) == 0 {
		return nil, errors.New("Invalid DER. It must be different from nil.")
	}

	key, err := x509.ParsePKIXPublicKey(raw)

	return key, err
}
