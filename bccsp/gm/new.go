/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package gm

import (
	"hash"
	"reflect"

	"github.com/paul-lee-attorney/fabric-2.1-gm/bccsp"
	"github.com/paul-lee-attorney/gm/sm2"
	"github.com/paul-lee-attorney/gm/sm3"
	"github.com/pkg/errors"
)

type config struct {
	ellipticCurve sm2.P256V1Curve  // 椭圆曲线配置
	hashFunction  func() hash.Hash // 哈希函数配置
}

// NewDefaultSecurityLevel returns a new instance of the GM-based BCCSP
func NewDefaultSecurityLevel(keyStorePath string) (bccsp.BCCSP, error) {
	ks := &fileBasedKeyStore{}
	if err := ks.Init(nil, keyStorePath, false); err != nil {
		return nil, errors.Wrapf(err, "Failed initializing key store at [%v]", keyStorePath)
	}

	return NewWithParams(ks)
}

// NewDefaultSecurityLevelWithKeystore returns a new instance of the GM-based BCCSP
func NewDefaultSecurityLevelWithKeystore(keyStore bccsp.KeyStore) (bccsp.BCCSP, error) {
	return NewWithParams(keyStore)
}

// NewWithParams returns a new instance of the GM-based BCCSP
func NewWithParams(keyStore bccsp.KeyStore) (bccsp.BCCSP, error) {
	// Init config 在没有设置秘钥派生函数的情况下，conf应该没有被调用
	conf := &config{}
	conf.ellipticCurve = sm2.GetSm2P256V1() //将SM2推荐椭圆曲线实例赋值给配置
	conf.hashFunction = sm3.New             // 将SM3哈希摘要实例初始化函数赋值给配置

	gmbccsp, err := New(keyStore)
	if err != nil {
		return nil, err
	}

	// Notice that errors are ignored here because some test will fail if one
	// of the following call fails.

	// Set the Encryptors
	gmbccsp.AddWrapper(reflect.TypeOf(&sm4PrivateKey{}), &sm4cbcpkcs7Encryptor{}) // sm4 encryptor

	// Set the Decryptors
	gmbccsp.AddWrapper(reflect.TypeOf(&sm4PrivateKey{}), &sm4cbcpkcs7Decryptor{}) // 	sm4 decryptor

	// Set the Signers
	gmbccsp.AddWrapper(reflect.TypeOf(&sm2PrivateKey{}), &sm2Signer{}) // sm2 signor

	// Set the Verifiers
	gmbccsp.AddWrapper(reflect.TypeOf(&sm2PrivateKey{}), &sm2PrivateKeyVerifier{})  // sm2 Private Key Verifier
	gmbccsp.AddWrapper(reflect.TypeOf(&sm2PublicKey{}), &sm2PublicKeyKeyVerifier{}) // sm2 Public Key Verifier

	// Set the Hashers
	gmbccsp.AddWrapper(reflect.TypeOf(&bccsp.SM3Opts{}), &hasher{hash: conf.hashFunction}) // SM3 hasher

	// Set the key generators
	gmbccsp.AddWrapper(reflect.TypeOf(&bccsp.SM2KeyGenOpts{}), &sm2KeyGenerator{curve: conf.ellipticCurve}) // sm2 key generator
	gmbccsp.AddWrapper(reflect.TypeOf(&bccsp.SM4KeyGenOpts{}), &sm4KeyGenerator{length: 16})                // sm4 key generator

	// Set the key deriver
	gmbccsp.AddWrapper(reflect.TypeOf(&sm2PrivateKey{}), &sm2PrivateKeyKeyDeriver{}) //sm2 private key deriver
	gmbccsp.AddWrapper(reflect.TypeOf(&sm2PublicKey{}), &sm2PublicKeyKeyDeriver{})   //sm2 public key deriver
	gmbccsp.AddWrapper(reflect.TypeOf(&sm4PrivateKey{}), &sm4PrivateKeyKeyDeriver{}) //sm4 key deriver

	// Set the key importers
	gmbccsp.AddWrapper(reflect.TypeOf(&bccsp.X509PublicKeyImportOpts{}), &x509PublicKeyImportOptsKeyImporter{bccsp: gmbccsp})
	gmbccsp.AddWrapper(reflect.TypeOf(&bccsp.SM4ImportKeyOpts{}), &sm4ImportKeyOptsKeyImporter{})                 // sm4 key importor
	gmbccsp.AddWrapper(reflect.TypeOf(&bccsp.SM2PrivateKeyImportOpts{}), &sm2PrivateKeyImportOptsKeyImporter{})   // sm2 private key importor
	gmbccsp.AddWrapper(reflect.TypeOf(&bccsp.SM2GoPublicKeyImportOpts{}), &sm2GoPublicKeyImportOptsKeyImporter{}) // sm2 public key importor

	return gmbccsp, nil
}
