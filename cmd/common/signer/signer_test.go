/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package signer

import (
	"crypto/rand"
	"encoding/pem"
	"io/ioutil"
	"os"
	"path/filepath"
	"testing"

	"github.com/paul-lee-attorney/gm/gmx509"
	"github.com/paul-lee-attorney/gm/sm2"
	"github.com/stretchr/testify/assert"
)

func TestSigner(t *testing.T) {
	conf := Config{
		MSPID:        "SampleOrg",
		IdentityPath: filepath.Join("testdata", "signer", "cert.pem"),
		KeyPath:      filepath.Join("testdata", "signer", "8150cb2d09628ccc89727611ebb736189f6482747eff9b8aaaa27e9a382d2e93_sk"),
	}

	signer, err := NewSigner(conf)
	assert.NoError(t, err)

	msg := []byte("foo")
	sig, err := signer.Sign(msg)
	assert.NoError(t, err)

	// r, s, err := utils.UnmarshalECDSASignature(sig)
	r, s, err := sm2.UnmarshalSign(sig)
	// ecdsa.Verify(&signer.key.PublicKey, util.ComputeSHA256(msg), r, s)
	result, err := sm2.VerifyByRS(&signer.key.PublicKey, nil, msg, r, s)
	assert.NoError(t, err)
	assert.True(t, result)
}

func TestSignerDifferentFormats(t *testing.T) {
	// 	key := `-----BEGIN SM2 PRIVATE KEY-----
	// MHcCAQEEIOwCtOQIkowasuWoDQpXHgC547VHq+aBFaSyPOoV8mnGoAoGCCqGSM49
	// AwEHoUQDQgAEEsrroAkPez9reWvJukufUqyfouJjakrKuhNBYuclkldqsLZ/TO+w
	// ZsQXrlIqlmNalfYPX+NDDELqlpXQBeEqnA==
	// -----END SM2 PRIVATE KEY-----`

	key, err := sm2.GenerateKey(rand.Reader)

	privKeyPem, err := gmx509.SM2PrivateKeyToPEM(key, nil)

	pemBlock, _ := pem.Decode([]byte(privKeyPem))
	assert.NotNil(t, pemBlock)

	ecPK, err := gmx509.ParseSM2PrivateKey(pemBlock.Bytes)
	assert.NoError(t, err)

	ec1, err := gmx509.MarshalSM2PrivateKey(ecPK)
	assert.NoError(t, err)

	pkcs8, err := gmx509.MarshalPKCS8SM2PrivateKey(ecPK)
	assert.NoError(t, err)

	for _, testCase := range []struct {
		description string
		keyBytes    []byte
	}{
		{
			description: "SM2P256V1",
			keyBytes:    pem.EncodeToMemory(&pem.Block{Type: "SM2 Private Key", Bytes: ec1}),
		},
		{
			description: "PKCS8",
			keyBytes:    pem.EncodeToMemory(&pem.Block{Type: "Private Key", Bytes: pkcs8}),
		},
	} {
		t.Run(testCase.description, func(t *testing.T) {
			tmpFile, err := ioutil.TempFile("", "key")
			assert.NoError(t, err)

			defer os.Remove(tmpFile.Name())

			err = ioutil.WriteFile(tmpFile.Name(), []byte(testCase.keyBytes), 0600)
			assert.NoError(t, err)

			signer, err := NewSigner(Config{
				MSPID:        "MSPID",
				IdentityPath: filepath.Join("testdata", "signer", "cert.pem"),
				KeyPath:      tmpFile.Name(),
			})

			assert.NoError(t, err)
			assert.NotNil(t, signer)
		})
	}
}

func TestSignerBadConfig(t *testing.T) {
	conf := Config{
		MSPID:        "SampleOrg",
		IdentityPath: filepath.Join("testdata", "signer", "non_existent_cert"),
	}

	signer, err := NewSigner(conf)
	assert.EqualError(t, err, "open testdata/signer/non_existent_cert: no such file or directory")
	assert.Nil(t, signer)

	conf = Config{
		MSPID:        "SampleOrg",
		IdentityPath: filepath.Join("testdata", "signer", "cert.pem"),
		KeyPath:      filepath.Join("testdata", "signer", "non_existent_cert"),
	}

	signer, err = NewSigner(conf)
	assert.EqualError(t, err, "open testdata/signer/non_existent_cert: no such file or directory")
	assert.Nil(t, signer)

	conf = Config{
		MSPID:        "SampleOrg",
		IdentityPath: filepath.Join("testdata", "signer", "cert.pem"),
		KeyPath:      filepath.Join("testdata", "signer", "broken_private_key"),
	}

	signer, err = NewSigner(conf)
	assert.EqualError(t, err, "failed to decode PEM block from testdata/signer/broken_private_key")
	assert.Nil(t, signer)

	conf = Config{
		MSPID:        "SampleOrg",
		IdentityPath: filepath.Join("testdata", "signer", "cert.pem"),
		KeyPath:      filepath.Join("testdata", "signer", "empty_private_key"),
	}

	signer, err = NewSigner(conf)
	assert.EqualError(t, err, "failed to parse private key: x509: failed to parse EC private key: asn1: syntax error: sequence truncated")
	assert.Nil(t, signer)
}
