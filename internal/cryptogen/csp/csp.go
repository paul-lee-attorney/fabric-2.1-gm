/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/
package csp

import (
	"crypto"
	"crypto/rand"
	"encoding/pem"
	"io"
	"io/ioutil"
	"os"
	"path/filepath"
	"strings"

	"github.com/paul-lee-attorney/fabric-2.1-gm/bccsp/gm"
	"github.com/paul-lee-attorney/gm/sm2"
	"github.com/pkg/errors"
)

// LoadPrivateKey loads a private key from a file in keystorePath.  It looks
// for a file ending in "_sk" and expects a PEM-encoded PKCS8 EC private key.
func LoadPrivateKey(keystorePath string) (*sm2.PrivateKey, error) {
	var priv *sm2.PrivateKey
	// var priv *ecdsa.PrivateKey

	walkFunc := func(path string, info os.FileInfo, pathErr error) error {

		if !strings.HasSuffix(path, "_sk") {
			return nil
		}

		rawKey, err := ioutil.ReadFile(path)
		if err != nil {
			return err
		}

		priv, err = parsePrivateKeyPEM(rawKey)
		if err != nil {
			return errors.WithMessage(err, path)
		}

		return nil
	}

	err := filepath.Walk(keystorePath, walkFunc)
	if err != nil {
		return nil, err
	}

	return priv, err
}

// 将PEM-PKCS8格式的SM2私钥解析为
func parsePrivateKeyPEM(rawKey []byte) (*sm2.PrivateKey, error) {
	block, _ := pem.Decode(rawKey)
	if block == nil {
		return nil, errors.New("bytes are not PEM encoded")
	}

	// key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	key, err := gm.ParsePKCS8SM2PrivateKey(block.Bytes)
	if err != nil {
		return nil, errors.WithMessage(err, "pem bytes are not PKCS8 encoded ")
	}

	// priv, ok := key.(*sm2.PrivateKey)
	// if !ok {
	// 	return nil, errors.New("pem bytes do not contain an EC private key")
	// }

	return key, nil
}

// GeneratePrivateKey creates an SM2 private key using  SM2P256V1 curve and stores
// it in keystorePath.
func GeneratePrivateKey(keystorePath string) (*sm2.PrivateKey, error) {

	// priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	priv, err := sm2.GenerateKey(rand.Reader)
	if err != nil {
		return nil, errors.WithMessage(err, "failed to generate private key")
	}

	// pkcs8Encoded, err := x509.MarshalPKCS8PrivateKey(priv)
	pkcs8Encoded, err := gm.MarshalPKCS8SM2PrivateKey(priv)
	if err != nil {
		return nil, errors.WithMessage(err, "failed to marshal private key")
	}

	pemEncoded := pem.EncodeToMemory(&pem.Block{Type: "SM2 PRIVATE KEY", Bytes: pkcs8Encoded})

	keyFile := filepath.Join(keystorePath, "priv_sk")
	err = ioutil.WriteFile(keyFile, pemEncoded, 0600)
	if err != nil {
		return nil, errors.WithMessagef(err, "failed to save private key to file %s", keyFile)
	}

	return priv, err
}

/**
SM2 signer implements the crypto.Signer interface for SM2 keys.  The
Sign method ensures signatures are created with Low S values since Fabric
normalizes all signatures to Low S.
See https://github.com/bitcoin/bips/blob/master/bip-0146.mediawiki#low_s
for more detail.

将所有ECDSA相关内容替换为SM2, 适用曲线为SM2国标的推荐曲线

*/

// type ECDSASigner struct {
// 	PrivateKey *ecdsa.PrivateKey
// }

// SM2Signer 实现 crypto.Signer 接口
type SM2Signer struct {
	PrivateKey *sm2.PrivateKey
}

// Public returns the *sm2.PublicKey associated with PrivateKey.
// func (e *ECDSASigner) Public() crypto.PublicKey {
// 	return &e.PrivateKey.PublicKey
// }
func (s *SM2Signer) Public() crypto.PublicKey {
	return &s.PrivateKey.PublicKey
}

// Sign signs the digest and ensures that signatures use the Low S value.
// func (e *ECDSASigner) Sign(rand io.Reader, digest []byte, opts crypto.SignerOpts) ([]byte, error) {
// 	r, s, err := ecdsa.Sign(rand, e.PrivateKey, digest)
// 	if err != nil {
// 		return nil, err
// 	}

// 	// ensure Low S signatures
// 	sig := toLowS(
// 		e.PrivateKey.PublicKey,
// 		ECDSASignature{
// 			R: r,
// 			S: s,
// 		},
// 	)

// 	// return marshaled aignature
// 	return asn1.Marshal(sig)
// }

// Sign returns SM2 signature in form of DER marshalized via ASN1
func (s *SM2Signer) Sign(rand io.Reader, msg []byte, opts crypto.SignerOpts) ([]byte, error) {

	return sm2.Sign(s.PrivateKey, nil, msg)
}

/**
When using ECDSA, both (r,s) and (r, -s mod n) are valid signatures.  In order
to protect against signature malleability attacks, Fabric normalizes all
signatures to a canonical form where s is at most half the order of the curve.
In order to make signatures compliant with what Fabric expects, toLowS creates
signatures in this canonical form.
*/
// func toLowS(key ecdsa.PublicKey, sig ECDSASignature) ECDSASignature {
// 	// calculate half order of the curve
// 	halfOrder := new(big.Int).Div(key.Curve.Params().N, big.NewInt(2))
// 	// check if s is greater than half order of curve
// 	if sig.S.Cmp(halfOrder) == 1 {
// 		// Set s to N - s so that s will be less than or equal to half order
// 		sig.S.Sub(key.Params().N, sig.S)
// 	}
// 	return sig
// }

// type ECDSASignature struct {
// 	R, S *big.Int
// }
