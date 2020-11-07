/*
Copyright Paul Lee. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package gm

import (
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
)

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
	// 加入SM2推荐曲线的oid
	oidSM2P256V1 = asn1.ObjectIdentifier{1, 2, 156, 10197, 1, 301}
	// ECDSA算法的oid
	oidPublicKeyECDSA = asn1.ObjectIdentifier{1, 2, 840, 10045, 2, 1}
)

// sm2PrivateKeyToPEM converts sm2 private key to PEM format.
// EC private keys are converted to PKCS#8 format.
func sm2PrivateKeyToPEM(privateKey interface{}, pwd []byte) ([]byte, error) {
	// Validate inputs
	if len(pwd) != 0 {
		return sm2PrivateKeyToEncryptedPEM(privateKey, pwd)
	}
	if privateKey == nil {
		return nil, errors.New("Invalid key. It must be different from nil.")
	}

	switch k := privateKey.(type) {
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
		return nil, errors.New("Invalid key type. It must be *sm2.PrivateKey")
	}
}

// sm2PrivateKeyToEncryptedPEM converts a private key into an encrypted PEM
func sm2PrivateKeyToEncryptedPEM(privateKey interface{}, pwd []byte) ([]byte, error) {
	if privateKey == nil {
		return nil, errors.New("Invalid private key. It must be different from nil.")
	}

	switch k := privateKey.(type) {
	case *sm2.PrivateKey:
		if k == nil {
			return nil, errors.New("Invalid ecdsa private key. It must be different from nil")
		}

		raw, err := MarshalSM2Privatekey(k)
		if err != nil {
			return nil, err
		}

		blockType := "SM2 PRIVATE KEY"

		block, err := sm4EncryptPEMBlock(blockType, raw, pwd)
		if err != nil {
			return nil, err
		}

		return block, nil

	default:
		return nil, errors.New("Invalid key type. It must be *sm2.PrivateKey")
	}
}

// pemToSM2PrivateKey unmarshals a pem to SM2 private key
func pemToSM2PrivateKey(raw []byte, pwd []byte) (interface{}, error) {
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

		decrypted, err := sm4DecryptPEMBlock(block, pwd)
		if err != nil {
			return nil, fmt.Errorf("Failed PEM decryption [%s]", err)
		}

		key, err := ParseSM2PrivateKey(decrypted)
		if err != nil {
			return nil, err
		}

		return key, err
	}

	cert, err := ParsePKCS8SM2PrivateKey(block.Bytes)
	if err != nil {
		return nil, err
	}
	return cert, err
}

// MarshalSM2Privatekey converts a SM2 private key to SEC 1, ASN.1 DER form.
func MarshalSM2Privatekey(key *sm2.PrivateKey) ([]byte, error) {

	if key == nil {
		return nil, errors.New("x509: input materials for sm2 private key marshalling shall not be nil")
	}

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

	if privKey.PrivateKey, err = MarshalSM2Privatekey(key); err != nil {
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

// SM4toPEM encapsulates a SM4 key in the PEM format
func SM4toPEM(raw []byte) []byte {
	return pem.EncodeToMemory(&pem.Block{Type: "SM4 PRIVATE KEY", Bytes: raw})
}

// PEMtoSM4 extracts from the PEM an SM4 private key
func PEMtoSM4(raw []byte, pwd []byte) ([]byte, error) {
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

		decrypted, err := sm4DecryptPEMBlock(block, pwd)
		if err != nil {
			return nil, fmt.Errorf("Failed PEM decryption. [%s]", err)
		}
		return decrypted, nil
	}

	return block.Bytes, nil
}

// SM4toEncryptedPEM encapsulates a SM4 key in the encrypted PEM format
func SM4toEncryptedPEM(raw []byte, pwd []byte) ([]byte, error) {
	if len(raw) == 0 {
		return nil, errors.New("Invalid aes key. It must be different from nil")
	}
	if len(pwd) == 0 {
		return SM4toPEM(raw), nil
	}

	blockType := "SM4 PRIVATE KEY"

	pem, err := sm4EncryptPEMBlock(blockType, raw, pwd)

	if err != nil {
		return nil, err
	}

	return pem, nil
}

// sm4EncryptPEMBlock encrypt raw message into PEM format via SM4. refer: x509.EncryptPEMBlock()
// 将输入消息用SM4加密并转化为PEM格式的函数。
func sm4EncryptPEMBlock(blockType string, raw []byte, pwd []byte) ([]byte, error) {

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

	encrypted, err := SM4CBCPKCS7EncryptWithIV(iv, key, raw)
	if err != nil {
		return nil, err
	}

	block := &pem.Block{
		Type: blockType,
		Headers: map[string]string{
			"Proc-Type": "4,ENCRYPTED",
			"DEK-Info":  "SM4CBCPKCS7" + "," + hex.EncodeToString(iv),
		},
		Bytes: encrypted,
	}

	return pem.EncodeToMemory(block), nil
}

// sm4DecryptPEMBlock decrypt PEM block via SM4.
// 将输入消息用SM4加密并转化为PEM格式的函数, 其中密文格式采用CBC模式，PKCS7规范填充尾部字节。
func sm4DecryptPEMBlock(block *pem.Block, pwd []byte) ([]byte, error) {

	if len(pwd) == 0 || pwd == nil {
		return nil, errors.New("password shall not be nil")
	}

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

	data, err := SM4CBCPKCS7Decrypt(key, block.Bytes)
	if err != nil {
		return nil, err
	}

	return data, nil
}

// deriveKey 为秘钥派生函数，参考Openssl和go标准库，用SM3为哈希函数
// 将密码加盐（初始向量前8字节）取SM3哈希后，将哈希值前16位取出作为SM4秘钥使用。
// 不同于SM2国标派生函数的32位计数器加盐，与Fabric内置算法保持一致。
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

// pemToSM2PublicKey unmarshals a pem to public key
func pemToSM2PublicKey(raw []byte, pwd []byte) (interface{}, error) {
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

		decrypted, err := sm4DecryptPEMBlock(block, pwd)
		if err != nil {
			return nil, fmt.Errorf("Failed PEM decryption. [%s]", err)
		}
		key, err := ParsePKIXSM2PublicKey(decrypted)
		if err != nil {
			return nil, err
		}
		return key, err
	}

	cert, err := ParsePKIXSM2PublicKey(block.Bytes)
	if err != nil {
		return nil, err
	}
	return cert, err
}

// sm2PublicKeyToPEM marshals a public key to the pem format
func sm2PublicKeyToPEM(publicKey interface{}, pwd []byte) ([]byte, error) {
	if len(pwd) != 0 {
		return sm2PublicKeyToEncryptedPEM(publicKey, pwd)
	}

	if publicKey == nil {
		return nil, errors.New("Invalid public key. It must be different from nil")
	}

	switch k := publicKey.(type) {
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

// sm2PublicKeyToEncryptedPEM converts a public key to encrypted pem
func sm2PublicKeyToEncryptedPEM(publicKey interface{}, pwd []byte) ([]byte, error) {
	if publicKey == nil {
		return nil, errors.New("Invalid public key. It must be different from nil")
	}
	if len(pwd) == 0 {
		return nil, errors.New("Invalid password. It must be different from nil")
	}

	switch k := publicKey.(type) {
	case *sm2.PublicKey:
		if k == nil {
			return nil, errors.New("Invalid ecdsa public key. It must be different from nil")
		}
		raw, err := MarshalPKIXSM2PublicKey(k)
		if err != nil {
			return nil, err
		}

		blockType := "MS2 PUBLIC KEY"

		block, err := sm4EncryptPEMBlock(blockType, raw, pwd)
		if err != nil {
			return nil, err
		}

		return block, nil

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

	if pub == nil {
		return nil, errors.New("input sm2 public key shall not be nil")
	}

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

// ParsePKIXSM2PublicKey parse a DER-encoded ASN.1 data into SM2 public key object.
// 将符合PKIX, ASN.1 DER编码规则的SM2公钥反序列化为对象.
func ParsePKIXSM2PublicKey(der []byte) (*sm2.PublicKey, error) {

	if len(der) == 0 || der == nil {
		return nil, errors.New("x509: raw materials of SM2 public key shall not be nil")
	}

	var pki publicKeyInfo

	if rest, err := asn1.Unmarshal(der, &pki); err != nil {
		return nil, err
	} else if len(rest) != 0 {
		return nil, errors.New("x509: trailing data after ASN.1 of public-key")
	}

	// 校验算法是否属于ECDSA
	if algo := pki.Algorithm.Algorithm; !algo.Equal(oidPublicKeyECDSA) {
		return nil, errors.New("the algorithm does not belong to ECDSA ")
	}

	paramsData := pki.Algorithm.Parameters.FullBytes
	namedCurveOID := new(asn1.ObjectIdentifier)
	if rest, err := asn1.Unmarshal(paramsData, namedCurveOID); err != nil {
		return nil, err
	} else if len(rest) != 0 {
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
