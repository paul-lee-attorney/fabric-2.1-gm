/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package signer

import (
	"crypto/ecdsa"
	"crypto/rand"
	"encoding/asn1"
	"encoding/pem"
	"io/ioutil"
	"math/big"

	"github.com/hyperledger/fabric-protos-go/msp"
	"github.com/hyperledger/fabric/protoutil"
	"github.com/paul-lee-attorney/fabric-2.1-gm/bccsp/gm"
	"github.com/paul-lee-attorney/fabric-2.1-gm/bccsp/utils"
	"github.com/paul-lee-attorney/gm/sm2"
	"github.com/pkg/errors"
)

// Config holds the configuration for
// creation of a Signer
// 考虑到国密改造的目的性，命令行工具默认为全部适用国密算法，不再考虑其他兼容性。
type Config struct {
	MSPID        string
	IdentityPath string
	KeyPath      string
}

// Signer signs messages.
// TODO: Ideally we'd use an MSP to be agnostic, but since it's impossible to
// initialize an MSP without a CA cert that signs the signing identity,
// this will do for now.
type Signer struct {
	// key     *ecdsa.PrivateKey
	key     *sm2.PrivateKey
	Creator []byte
}

func (si *Signer) Serialize() ([]byte, error) {
	return si.Creator, nil
}

// NewSigner creates a new Signer out of the given configuration
func NewSigner(conf Config) (*Signer, error) {
	sId, err := serializeIdentity(conf.IdentityPath, conf.MSPID)
	if err != nil {
		return nil, errors.WithStack(err)
	}
	key, err := loadPrivateKey(conf.KeyPath)
	if err != nil {
		return nil, errors.WithStack(err)
	}
	return &Signer{
		Creator: sId,
		key:     key,
	}, nil
}

func serializeIdentity(clientCert string, mspID string) ([]byte, error) {
	b, err := ioutil.ReadFile(clientCert)
	if err != nil {
		return nil, errors.WithStack(err)
	}
	sId := &msp.SerializedIdentity{
		Mspid:   mspID,
		IdBytes: b,
	}
	return protoutil.MarshalOrPanic(sId), nil
}

func (si *Signer) Sign(msg []byte) ([]byte, error) {

	// digest := util.ComputeSHA256(msg)
	// return signECDSA(si.key, digest)

	// SM2算法内建了哈希预处理，因此，签字之前不需要事先经哈希处理
	return sm2.Sign(si.key, nil, msg)
}

func loadPrivateKey(file string) (*sm2.PrivateKey, error) {
	b, err := ioutil.ReadFile(file)
	if err != nil {
		return nil, errors.WithStack(err)
	}
	bl, _ := pem.Decode(b)
	if bl == nil {
		return nil, errors.Errorf("failed to decode PEM block from %s", file)
	}
	key, err := parsePrivateKey(bl.Bytes)
	if err != nil {
		return nil, err
	}
	return key, nil
}

// Based on crypto/tls/tls.go but modified for Fabric:
func parsePrivateKey(der []byte) (*sm2.PrivateKey, error) {
	// OpenSSL 1.0.0 generates PKCS#8 keys.
	if key, err := gm.ParsePKCS8SM2PrivateKey(der); err == nil {
		// switch key := key.(type) {
		// // Fabric only supports ECDSA at the moment.
		// case *ecdsa.PrivateKey:
		return key, nil
		// default:
		// 	return nil, errors.Errorf("found unknown private key type (%T) in PKCS#8 wrapping", key)
		// }
	}

	// OpenSSL ecparam generates SEC1 EC private keys for ECDSA.
	key, err := gm.ParseSM2PrivateKey(der)
	if err != nil {
		return nil, errors.Errorf("failed to parse private key: %v", err)
	}

	return key, nil
}

// 改造后，该私有函数将不被调用
func signECDSA(k *ecdsa.PrivateKey, digest []byte) (signature []byte, err error) {
	r, s, err := ecdsa.Sign(rand.Reader, k, digest)
	if err != nil {
		return nil, err
	}

	s, err = utils.ToLowS(&k.PublicKey, s)
	if err != nil {
		return nil, err
	}

	return marshalECDSASignature(r, s)
}

// 改造后，该私有函数将不被调用
func marshalECDSASignature(r, s *big.Int) ([]byte, error) {
	return asn1.Marshal(ECDSASignature{r, s})
}

// 改造后，该类别将不被调用
type ECDSASignature struct {
	R, S *big.Int
}
