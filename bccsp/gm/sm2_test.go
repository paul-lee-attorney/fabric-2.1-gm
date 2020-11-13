/*
Copyright Paul Lee based on IBM's works. 2020 All Rights Reserved.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

		 http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package gm

import (
	"crypto/elliptic"
	"crypto/rand"
	"math/big"
	"testing"

	"github.com/paul-lee-attorney/gm/gmx509"
	"github.com/paul-lee-attorney/gm/sm2"
	"github.com/paul-lee-attorney/gm/sm3"
	"github.com/stretchr/testify/assert"
)

func TestVerifySM2(t *testing.T) {
	t.Parallel()

	// Generate a key
	sk, err := sm2.GenerateKey(rand.Reader)
	assert.NoError(t, err)

	msg := []byte("hello world")
	sigma, err := signSM2(sk, msg, nil)
	assert.NoError(t, err)

	valid, err := verifySM2(&sk.PublicKey, sigma, msg, nil)
	assert.NoError(t, err)
	assert.True(t, valid)

	_, err = verifySM2(&sk.PublicKey, nil, msg, nil)
	assert.Error(t, err)

	_, err = verifySM2(&sk.PublicKey, nil, msg, nil)
	assert.Error(t, err)

	// 测试SM2签字
	R, S, err := sm2.UnmarshalSign(sigma)
	assert.NoError(t, err)
	S.Add(sm2.GetSm2P256V1().Params().N, big.NewInt(1))
	sigmaWrongS, err := sm2.MarshalSign(R, S)
	assert.NoError(t, err)
	_, err = verifySM2(&sk.PublicKey, sigmaWrongS, msg, nil)
	assert.Error(t, err)
}

func TestSM2SignerSign(t *testing.T) {
	t.Parallel()

	signer := &sm2Signer{}
	verifierPrivateKey := &sm2PrivateKeyVerifier{}
	verifierPublicKey := &sm2PublicKeyKeyVerifier{}

	// Generate a key
	sk, err := sm2.GenerateKey(rand.Reader)
	assert.NoError(t, err)
	k := &sm2PrivateKey{sk}
	pk, err := k.PublicKey()
	assert.NoError(t, err)

	// Sign
	msg := []byte("Hello World")
	sigma, err := signer.Sign(k, msg, nil)
	assert.NoError(t, err)
	assert.NotNil(t, sigma)

	// Verify
	valid, err := verifySM2(&sk.PublicKey, sigma, msg, nil)
	assert.NoError(t, err)
	assert.True(t, valid)

	valid, err = verifierPrivateKey.Verify(k, sigma, msg, nil)
	assert.NoError(t, err)
	assert.True(t, valid)

	valid, err = verifierPublicKey.Verify(pk, sigma, msg, nil)
	assert.NoError(t, err)
	assert.True(t, valid)
}

func TestSM2PrivateKey(t *testing.T) {
	t.Parallel()

	sk, err := sm2.GenerateKey(rand.Reader)
	assert.NoError(t, err)
	k := &sm2PrivateKey{sk}

	assert.False(t, k.Symmetric())
	assert.True(t, k.Private())

	_, err = k.Bytes()
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "Not supported.")

	k.privKey = nil
	ski := k.SKI()
	assert.Nil(t, ski)

	k.privKey = sk
	ski = k.SKI()
	raw := elliptic.Marshal(k.privKey.Curve, k.privKey.PublicKey.X, k.privKey.PublicKey.Y)
	hash := sm3.New()
	hash.Write(raw)
	ski2 := hash.Sum(nil)
	assert.Equal(t, ski2, ski, "SKI is not computed in the right way.")

	pk, err := k.PublicKey()
	assert.NoError(t, err)
	assert.NotNil(t, pk)
	sm2PK, ok := pk.(*sm2PublicKey)
	assert.True(t, ok)
	assert.Equal(t, &sk.PublicKey, sm2PK.pubKey)
}

func TestSM2PublicKey(t *testing.T) {
	t.Parallel()

	sk, err := sm2.GenerateKey(rand.Reader)
	assert.NoError(t, err)
	k := &sm2PublicKey{&sk.PublicKey}

	assert.False(t, k.Symmetric())
	assert.False(t, k.Private())

	k.pubKey = nil
	ski := k.SKI()
	assert.Nil(t, ski)

	k.pubKey = &sk.PublicKey
	ski = k.SKI()
	raw := elliptic.Marshal(k.pubKey.Curve, k.pubKey.X, k.pubKey.Y)
	hash := sm3.New()
	hash.Write(raw)
	ski2 := hash.Sum(nil)
	assert.Equal(t, ski, ski2, "SKI is not computed in the right way.")

	pk, err := k.PublicKey()
	assert.NoError(t, err)
	assert.Equal(t, k, pk)

	bytes, err := k.Bytes()
	assert.NoError(t, err)
	bytes2, err := gmx509.MarshalPKIXSM2PublicKey(k.pubKey)
	assert.NoError(t, err)
	assert.Equal(t, bytes2, bytes, "bytes are not computed in the right way.")

}
