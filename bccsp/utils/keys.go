/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package utils

import (
	"crypto/cipher"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"math/big"
	"strings"

	"github.com/paul-lee-attorney/gm/sm2"
	"github.com/paul-lee-attorney/gm/sm3"
	"github.com/paul-lee-attorney/gm/sm4"
)

// struct to hold info required for PKCS#8
type pkcs8Info struct {
	Version             int
	PrivateKeyAlgorithm []asn1.ObjectIdentifier
	PrivateKey          []byte
}

// pkcs8 reflects an ASN.1, PKCS#8 PrivateKey. See
// ftp://ftp.rsasecurity.com/pub/pkcs/pkcs-8/pkcs-8v1_2.asn
// and RFC 5208.
type pkcs8 struct {
	Version    int
	Algo       pkix.AlgorithmIdentifier
	PrivateKey []byte
	// optional attributes omitted.
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

		pkcs8Bytes, err := x509.MarshalPKCS8PrivateKey(k)
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

		pkcs8Bytes, err := MarshalPKCS8SM2PrivateKey(k)
		if err != nil {
			return nil, fmt.Errorf("error marshaling EC key to asn1 [%s]", err)
		}
		return pem.EncodeToMemory(
			&pem.Block{
				Type:  "SM2 PRIVATE KEY",
				Bytes: pkcs8Bytes,
			},
		), nil
	default:
		return nil, errors.New("Invalid key type. It must be *ecdsa.PrivateKey")
	}
}

// PrivateKeyToEncryptedPEM converts a private key into an encrypted PEM
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

	case *sm2.PrivateKey:
		if k == nil {
			return nil, errors.New("Invalid ecdsa private key. It must be different from nil")
		}

		raw, err := MarshalSM2PrivateKey(k)
		if err != nil {
			return nil, err
		}

		blockType := "SM2 PRIVATE KEY"

		block, err := SM4EncryptPEMBlock(blockType, raw, pwd)
		if err != nil {
			return nil, err
		}

		return block, nil

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

// MarshalSM2PrivateKey converts a SM2 private key to SEC 1, ASN.1 DER form.
func MarshalSM2PrivateKey(key *sm2.PrivateKey) ([]byte, error) {
	privateKeyBytes := key.D.Bytes()
	paddedPrivateKey := make([]byte, sm2.KeyBytes)
	copy(paddedPrivateKey[len(paddedPrivateKey)-len(privateKeyBytes):], privateKeyBytes)

	return asn1.Marshal(ecPrivateKey{
		Version:       1,
		PrivateKey:    paddedPrivateKey,
		NamedCurveOID: oidSM2P256V1,
		PublicKey:     asn1.BitString{Bytes: elliptic.Marshal(key.Curve, key.X, key.Y)},
	})
}

// ParseSM2PrivateKey parses a SM2 in form of SEC 1, ASN.1 DER back to object.
// 解析依照ASN.1规范的椭圆曲线私钥结构定义的SM2.
// ref: crypto/x509/sec1.go ---- ParseECPrivateKey()
func ParseSM2PrivateKey(der []byte) (key *sm2.PrivateKey, err error) {
	var privKey ecPrivateKey
	if _, err := asn1.Unmarshal(der, &privKey); err != nil {
		return nil, errors.New("failed to parse EC private key: " + err.Error())
	}
	if privKey.Version != 1 {
		return nil, fmt.Errorf("unknown EC private key version %d", privKey.Version)
	}
	if !privKey.NamedCurveOID.Equal(oidSM2P256V1) {
		return nil, fmt.Errorf("the oid does not equal to SM2 EC ")
	}

	curve := sm2.GetSm2P256V1()
	k := new(big.Int).SetBytes(privKey.PrivateKey)
	curveOrder := curve.Params().N
	if k.Cmp(curveOrder) >= 0 {
		return nil, errors.New("invalid elliptic curve private key value")
	}
	priv := new(sm2.PrivateKey)
	priv.Curve = curve
	priv.D = k

	privateKey := make([]byte, (curveOrder.BitLen()+7)/8)

	// Some private keys have leading zero padding. This is invalid
	// according to [SEC1], but this code will ignore it.
	for len(privKey.PrivateKey) > len(privateKey) {
		if privKey.PrivateKey[0] != 0 {
			return nil, errors.New("x509: invalid private key length")
		}
		privKey.PrivateKey = privKey.PrivateKey[1:]
	}

	// Some private keys remove all leading zeros, this is also invalid
	// according to [SEC1] but since OpenSSL used to do this, we ignore
	// this too.
	copy(privateKey[len(privateKey)-len(privKey.PrivateKey):], privKey.PrivateKey)
	priv.X, priv.Y = curve.ScalarBaseMult(privateKey)

	return priv, nil
}

// MarshalPKCS8SM2PrivateKey convert SM2 private key into PKCS#8 []byte
// ref: crypto/x509/pkcs8.go ---- MarshalPKCS8PrivateKey()
func MarshalPKCS8SM2PrivateKey(key *sm2.PrivateKey) ([]byte, error) {

	var privKey pkcs8

	privKey.Version = 0

	oidBytes, err := asn1.Marshal(oidSM2P256V1)
	if err != nil {
		return nil, errors.New("failed to marshal curve OID: " + err.Error())
	}

	privKey.Algo = pkix.AlgorithmIdentifier{
		Algorithm: oidPublicKeyECDSA,
		Parameters: asn1.RawValue{
			FullBytes: oidBytes,
		},
	}

	if privKey.PrivateKey, err = MarshalSM2PrivateKey(key); err != nil {
		return nil, errors.New("failed to marshal EC private key while building PKCS#8: " + err.Error())
	}

	return asn1.Marshal(privKey)
}

// ParsePKCS8SM2PrivateKey 解析PKCS8格式的采用DER规则编码的SM2私钥.
func ParsePKCS8SM2PrivateKey(der []byte) (*sm2.PrivateKey, error) {

	var privKey pkcs8

	if _, err := asn1.Unmarshal(der, &privKey); err != nil {
		return nil, err
	}

	if !privKey.Algo.Algorithm.Equal(oidPublicKeyECDSA) {
		return nil, fmt.Errorf("PKCS#8 wrapping algorithm is note ECDSA: %v", privKey.Algo.Algorithm)
	}

	bytes := privKey.Algo.Parameters.FullBytes
	namedCurveOID := new(asn1.ObjectIdentifier)
	if _, err := asn1.Unmarshal(bytes, namedCurveOID); err != nil {
		namedCurveOID = nil
	}

	if !namedCurveOID.Equal(oidSM2P256V1) {
		return nil, fmt.Errorf("PKCS#8 wrapped Curve is note the SM2 EC ")
	}

	key, err := ParseSM2PrivateKey(privKey.PrivateKey)
	if err != nil {
		return nil, err
	}

	return key, nil
}

// PEMtoPrivateKey unmarshals a pem to private key
func PEMtoPrivateKey(raw []byte, pwd []byte) (interface{}, error) {
	if len(raw) == 0 {
		return nil, errors.New("Invalid PEM. It must be different from nil")
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

		if block.Type == "SM2 PRIVATE KEY" {
			decrypted, err := SM4DecryptPEMBlock(block, pwd)
			if err != nil {
				return nil, fmt.Errorf("Failed PEM decryption [%s]", err)
			}

			key, err := ParseSM2PrivateKey(decrypted)
			if err != nil {
				return nil, err
			}
			return key, err
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

	if block.Type == "SM2 PRIVATE KEY" {
		cert, err := ParsePKCS8SM2PrivateKey(block.Bytes)
		if err != nil {
			return nil, err
		}
		return cert, err
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
		return nil, errors.New("Invalid PEM. It must be different from nil")
	}
	block, _ := pem.Decode(raw)
	if block == nil {
		return nil, fmt.Errorf("Failed decoding PEM. Block must be different from nil. [% x]", raw)
	}

	if x509.IsEncryptedPEMBlock(block) {
		if len(pwd) == 0 {
			return nil, errors.New("Encrypted Key. Password must be different from nil")
		}

		if block.Type == "SM4 PRIVATE KEY" {
			decrypted, err := SM4DecryptPEMBlock(block, pwd)
			if err != nil {
				return nil, fmt.Errorf("Failed PEM decryption. [%s]", err)
			}
			return decrypted, nil
		}

		decrypted, err := x509.DecryptPEMBlock(block, pwd)
		if err != nil {
			return nil, fmt.Errorf("Failed PEM decryption. [%s]", err)
		}
		return decrypted, nil
	}

	return block.Bytes, nil
}

// AEStoPEM encapsulates an AES key in the PEM format
func AEStoPEM(raw []byte) []byte {
	return pem.EncodeToMemory(&pem.Block{Type: "AES PRIVATE KEY", Bytes: raw})
}

// AEStoEncryptedPEM encapsulates an AES key in the encrypted PEM format
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

// SM4EncryptPEMBlock encrypt raw message into PEM format via SM4. refer: x509.EncryptPEMBlock()
// 将输入消息用SM4加密并转化为PEM格式的函数。
func SM4EncryptPEMBlock(blockType string, raw []byte, pwd []byte) ([]byte, error) {

	if len(raw) == 0 || raw == nil {
		return nil, errors.New("Invalid SM4 key. It must be different from nil")
	}
	if len(pwd) == 0 || pwd == nil {
		return pem.EncodeToMemory(&pem.Block{Type: blockType, Bytes: raw}), nil
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

	sm4Block, err := sm4.NewCipher(key)
	if err != nil {
		return nil, err
	}

	enc := cipher.NewCBCEncrypter(sm4Block, iv)
	enc.CryptBlocks(encrypted, encrypted)

	block := &pem.Block{
		Type: blockType,
		Headers: map[string]string{
			"Proc-Type": "4,ENCRYPTED",
			"DEK-Info":  "SM4-CBC" + "," + hex.EncodeToString(iv),
		},
		Bytes: encrypted,
	}

	return pem.EncodeToMemory(block), nil
}

// SM4DecryptPEMBlock decrypt PEM block via SM4.
// 将输入消息用SM4加密并转化为PEM格式的函数。
func SM4DecryptPEMBlock(block *pem.Block, pwd []byte) ([]byte, error) {

	// 读取加密密码算法信息
	dek, _ := block.Headers["DEK-Info"]

	// 获取标识符","的位置
	idx := strings.Index(dek, ",")
	if idx == -1 {
		return nil, errors.New("x509: malformed DEK-Info header")
	}

	// 获取CBC加密的初始向量值iv
	hexIV := dek[idx+1:]
	iv, err := hex.DecodeString(hexIV)
	if err != nil {
		return nil, err
	}

	// 根据OpenSSL源代码，向量初始值的前八位为“盐”，利用SM3取哈希值
	// 截取哈希值前16字节，进而获得SM4加密秘钥
	key := deriveKey(pwd, iv[:8])

	// 创建SM4密文实例
	sm4Block, err := sm4.NewCipher(key)

	// 按照Block密文长度，创建目标明文字节数组
	data := make([]byte, len(block.Bytes))

	// SM4实际上实现了cipher.Block接口，因此，可直接利用标准包cipher创设CBCDecrypter接口实例
	dec := cipher.NewCBCDecrypter(sm4Block, iv)
	dec.CryptBlocks(data, block.Bytes)

	return data, nil
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

// PublicKeyToPEM marshals a public key to the pem format
func PublicKeyToPEM(publicKey interface{}, pwd []byte) ([]byte, error) {
	if len(pwd) != 0 {
		return PublicKeyToEncryptedPEM(publicKey, pwd)
	}

	if publicKey == nil {
		return nil, errors.New("Invalid public key. It must be different from nil")
	}

	switch k := publicKey.(type) {
	case *ecdsa.PublicKey:
		if k == nil {
			return nil, errors.New("Invalid ecdsa public key. It must be different from nil")
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

	case *sm2.PublicKey:
		if k == nil {
			return nil, errors.New("Invalid SM2 public key. It must be different from nil")
		}

		PubASN1, err := MarshalPKIXSM2PublicKey(k)
		if err != nil {
			return nil, err
		}

		return pem.EncodeToMemory(
			&pem.Block{
				Type:  "SM2 PUBLIC KEY",
				Bytes: PubASN1,
			},
		), nil

	default:
		return nil, errors.New("Invalid key type. It must be *ecdsa.PublicKey")
	}
}

// pkixPublicKey reflects a PKIX public key structure. See SubjectPublicKeyInfo
// in RFC 3280.
type pkixPublicKey struct {
	Algo      pkix.AlgorithmIdentifier
	BitString asn1.BitString
}

// MarshalPKIXSM2PublicKey converts a SM2 public key to PKIX, ASN.1 DER form.
// 将SM2公钥转换成符合PKIX, ASN.1 DER编码规则的形式.
func MarshalPKIXSM2PublicKey(pub *sm2.PublicKey) ([]byte, error) {

	var publicKeyBytes []byte
	var publicKeyAlgorithm pkix.AlgorithmIdentifier

	publicKeyBytes = pub.GetUnCompressBytes()

	publicKeyAlgorithm.Algorithm = oidPublicKeyECDSA

	paramBytes, err := asn1.Marshal(oidSM2P256V1)
	if err != nil {
		return nil, err
	}

	publicKeyAlgorithm.Parameters.FullBytes = paramBytes

	pkix := pkixPublicKey{
		Algo: publicKeyAlgorithm,
		BitString: asn1.BitString{
			Bytes:     publicKeyBytes,
			BitLength: 8 * len(publicKeyBytes),
		},
	}

	ret, _ := asn1.Marshal(pkix)
	return ret, nil
}

type publicKeyInfo struct {
	Raw       asn1.RawContent
	Algorithm pkix.AlgorithmIdentifier
	PublicKey asn1.BitString
}

// UnmarshalPKIXSM2PublicKey parse a DER-encoded ASN.1 data into SM2 public key object.
// 将符合PKIX, ASN.1 DER编码规则的SM2公钥反序列化为对象.
func UnmarshalPKIXSM2PublicKey(der []byte) (*sm2.PublicKey, error) {

	var pki publicKeyInfo

	if rest, err := asn1.Unmarshal(der, &pki); len(rest) != 0 || err != nil {
		return nil, errors.New("failed to parse SM2 public key")
	}

	// 校验算法是否属于ECDSA
	if algo := pki.Algorithm.Algorithm; !algo.Equal(oidPublicKeyECDSA) {
		return nil, errors.New("the algorithm does not belong to ECDSA ")
	}

	paramsData := pki.Algorithm.Parameters.FullBytes
	namedCurveOID := new(asn1.ObjectIdentifier)
	rest, err := asn1.Unmarshal(paramsData, namedCurveOID)
	if err != nil {
		return nil, err
	}
	if len(rest) != 0 {
		return nil, errors.New("x509: trailing data after SM2 parameters")
	}
	// 校验基础曲线是否为SM2推荐曲线
	if !namedCurveOID.Equal(oidSM2P256V1) {
		return nil, errors.New("x509: CurveOID is not the OID of SM2P256")
	}

	// 初始化并获得SM2曲线
	namedCurve := sm2.GetSm2P256V1()

	// 编码时没有对BitString移位，所以不必右对齐进行调整
	publicKeyBytes := pki.PublicKey.RightAlign()

	// 反序列化SM2曲线和公钥
	x, y := elliptic.Unmarshal(namedCurve, publicKeyBytes)
	if x == nil {
		return nil, errors.New("x509: failed to unmarshal elliptic curve point")
	}
	pub := &sm2.PublicKey{
		Curve: namedCurve,
		X:     x,
		Y:     y,
	}
	return pub, nil
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
		return nil, errors.New("Invalid public key. It must be different from nil")
	}
	if len(pwd) == 0 {
		return nil, errors.New("Invalid password. It must be different from nil")
	}

	switch k := publicKey.(type) {
	case *ecdsa.PublicKey:
		if k == nil {
			return nil, errors.New("Invalid ecdsa public key. It must be different from nil")
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

	case *sm2.PublicKey:
		if k == nil {
			return nil, errors.New("Invalid ecdsa public key. It must be different from nil")
		}
		raw, err := MarshalPKIXSM2PublicKey(k)
		if err != nil {
			return nil, err
		}

		blockType := "MS2 PUBLIC KEY"

		block, err := SM4EncryptPEMBlock(blockType, raw, pwd)
		if err != nil {
			return nil, err
		}

		return block, nil

	default:
		return nil, errors.New("Invalid key type. It must be *ecdsa.PublicKey")
	}
}

// PEMtoPublicKey unmarshals a pem to public key
func PEMtoPublicKey(raw []byte, pwd []byte) (interface{}, error) {
	if len(raw) == 0 {
		return nil, errors.New("invalid PEM. It must be different from nil")
	}
	block, _ := pem.Decode(raw)
	if block == nil {
		return nil, fmt.Errorf("Failed decoding. Block must be different from nil. [% x]", raw)
	}

	// TODO: derive from header the type of the key
	if x509.IsEncryptedPEMBlock(block) {
		if len(pwd) == 0 {
			return nil, errors.New("encrypted Key. Password must be different from nil")
		}

		if block.Type == "SM2 PUBLIC KEY" {
			decrypted, err := SM4DecryptPEMBlock(block, pwd)
			if err != nil {
				return nil, fmt.Errorf("Failed PEM decryption. [%s]", err)
			}
			key, err := UnmarshalPKIXSM2PublicKey(decrypted)
			if err != nil {
				return nil, err
			}
			return key, err
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

	if block.Type == "SM2 PUBLIC KEY" {
		cert, err := UnmarshalPKIXSM2PublicKey(block.Bytes)
		if err != nil {
			return nil, err
		}
		return cert, err
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

	if key, err := x509.ParsePKIXPublicKey(raw); err == nil {
		switch key.(type) {
		case *ecdsa.PublicKey:
			return key, nil
		default:
			return nil, errors.New("Found unknown public key type in PKIX wrapping")
		}
		return key, nil
	}

	// adding SM2 public key parse function herein
	if key, err := UnmarshalPKIXSM2PublicKey(raw); err == nil {
		return key, nil
	}

	return nil, errors.New("Invalid key type. The DER must contain an ecdsa.PublicKey or sm2.PublicKey")

}
