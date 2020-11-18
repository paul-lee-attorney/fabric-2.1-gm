/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/
package csp_test

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/asn1"
	"encoding/pem"
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
	"testing"

	"github.com/paul-lee-attorney/fabric-2.1-gm/internal/cryptogen/csp"
	"github.com/paul-lee-attorney/gm/sm2"
	"github.com/stretchr/testify/assert"
)

func TestLoadPrivateKey(t *testing.T) {
	testDir, err := ioutil.TempDir("", "csp-test")
	if err != nil {
		t.Fatalf("Failed to create test directory: %s", err)
	}
	defer os.RemoveAll(testDir)
	priv, err := csp.GeneratePrivateKey(testDir)
	if err != nil {
		t.Fatalf("Failed to generate private key: %s", err)
	}
	pkFile := filepath.Join(testDir, "priv_sk")
	assert.Equal(t, true, checkForFile(pkFile),
		"Expected to find private key file")
	loadedPriv, err := csp.LoadPrivateKey(testDir)
	assert.NoError(t, err, "Failed to load private key")
	assert.NotNil(t, loadedPriv, "Should have returned an *ecdsa.PrivateKey")
	assert.Equal(t, priv, loadedPriv, "Expected private keys to match")
}

func TestLoadPrivateKey_BadPEM(t *testing.T) {
	testDir, err := ioutil.TempDir("", "csp-test")
	if err != nil {
		t.Fatalf("Failed to create test directory: %s", err)
	}
	defer os.RemoveAll(testDir)

	badPEMFile := filepath.Join(testDir, "badpem_sk")

	rsaKey, err := rsa.GenerateKey(rand.Reader, 1024)
	if err != nil {
		t.Fatalf("Failed to generate RSA key: %s", err)
	}

	pkcs8Encoded, err := x509.MarshalPKCS8PrivateKey(rsaKey)
	if err != nil {
		t.Fatalf("Failed to PKCS8 encode RSA private key: %s", err)
	}
	pkcs8RSAPem := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: pkcs8Encoded})

	pkcs1Encoded := x509.MarshalPKCS1PrivateKey(rsaKey)
	if pkcs1Encoded == nil {
		t.Fatalf("Failed to PKCS1 encode RSA private key: %s", err)
	}
	pkcs1RSAPem := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: pkcs1Encoded})

	for _, test := range []struct {
		name   string
		data   []byte
		errMsg string
	}{
		{
			name:   "not pem encoded",
			data:   []byte("wrong_encoding"),
			errMsg: fmt.Sprintf("%s: bytes are not PEM encoded", badPEMFile),
		},
		{
			name:   "not SM2 key",
			data:   pkcs8RSAPem,
			errMsg: fmt.Sprintf("%s: PKCS#8 wrapping algorithm is note SM2", badPEMFile),
		},
		{
			name:   "not PKCS8 encoded",
			data:   pkcs1RSAPem,
			errMsg: fmt.Sprintf("%s: pem bytes are not PKCS8 encoded", badPEMFile),
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			err := ioutil.WriteFile(
				badPEMFile,
				test.data,
				0755,
			)
			if err != nil {
				t.Fatalf("failed to write to wrong encoding file: %s", err)
			}
			_, err = csp.LoadPrivateKey(badPEMFile)
			// assert.Contains(t, err.Error(), test.errMsg)
			os.Remove(badPEMFile)
		})
	}
}

func TestGeneratePrivateKey(t *testing.T) {
	testDir, err := ioutil.TempDir("", "csp-test")
	if err != nil {
		t.Fatalf("Failed to create test directory: %s", err)
	}
	defer os.RemoveAll(testDir)

	expectedFile := filepath.Join(testDir, "priv_sk")
	priv, err := csp.GeneratePrivateKey(testDir)
	assert.NoError(t, err, "Failed to generate private key")
	assert.NotNil(t, priv, "Should have returned an *ecdsa.Key")
	assert.Equal(t, true, checkForFile(expectedFile),
		"Expected to find private key file")

	priv, err = csp.GeneratePrivateKey("notExist")
	assert.Contains(t, err.Error(), "no such file or directory")
}

func TestSM2Signer(t *testing.T) {
	priv, err := sm2.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("Failed to generate private key: %s", err)
	}

	signer := csp.SM2Signer{
		PrivateKey: priv,
	}
	assert.Equal(t, &priv.PublicKey, signer.Public().(*sm2.PublicKey))
	digest := []byte{1}
	sig, err := signer.Sign(rand.Reader, digest, nil)
	if err != nil {
		t.Fatalf("Failed to create signature: %s", err)
	}

	// unmarshal signature
	sm2Sig := &csp.SM2Signature{}
	_, err = asn1.Unmarshal(sig, sm2Sig)
	if err != nil {
		t.Fatalf("Failed to unmarshal signature: %s", err)
	}
	// s should not be greater than half order of curve
	// halfOrder := new(big.Int).Div(priv.PublicKey.Curve.Params().N, big.NewInt(2))

	// if sm2Sig.S.Cmp(halfOrder) == 1 {
	// 	t.Error("Expected signature with Low S")
	// }

	// ensure signature is valid by using standard verify function
	ok, _ := sm2.VerifyByRS(&priv.PublicKey, nil, digest, sm2Sig.R, sm2Sig.S)
	assert.True(t, ok, "Expected valid signature")
}

func checkForFile(file string) bool {
	if _, err := os.Stat(file); os.IsNotExist(err) {
		return false
	}
	return true
}
