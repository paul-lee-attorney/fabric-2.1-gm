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
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"errors"
	"reflect"
	"testing"

	mocks2 "github.com/paul-lee-attorney/fabric-2.1-gm/bccsp/mocks"
	"github.com/paul-lee-attorney/fabric-2.1-gm/bccsp/sw/mocks"
	"github.com/paul-lee-attorney/gm/gmx509"
	"github.com/paul-lee-attorney/gm/sm2"
	"github.com/stretchr/testify/assert"
)

func TestKeyImport(t *testing.T) {
	t.Parallel()

	expectedRaw := []byte{1, 2, 3}
	expectedOpts := &mocks2.KeyDerivOpts{EphemeralValue: true}
	expectetValue := &mocks2.MockKey{BytesValue: []byte{1, 2, 3, 4, 5}}
	expectedErr := errors.New("Expected Error")

	keyImporters := make(map[reflect.Type]KeyImporter)
	keyImporters[reflect.TypeOf(&mocks2.KeyDerivOpts{})] = &mocks.KeyImporter{
		RawArg:  expectedRaw,
		OptsArg: expectedOpts,
		Value:   expectetValue,
		Err:     expectedErr,
	}
	csp := CSP{KeyImporters: keyImporters}
	value, err := csp.KeyImport(expectedRaw, expectedOpts)
	assert.Nil(t, value)
	assert.Contains(t, err.Error(), expectedErr.Error())

	keyImporters = make(map[reflect.Type]KeyImporter)
	keyImporters[reflect.TypeOf(&mocks2.KeyDerivOpts{})] = &mocks.KeyImporter{
		RawArg:  expectedRaw,
		OptsArg: expectedOpts,
		Value:   expectetValue,
		Err:     nil,
	}
	csp = CSP{KeyImporters: keyImporters}
	value, err = csp.KeyImport(expectedRaw, expectedOpts)
	assert.Equal(t, expectetValue, value)
	assert.Nil(t, err)
}

func TestSM4ImportKeyOptsKeyImporter(t *testing.T) {
	t.Parallel()

	ki := sm4ImportKeyOptsKeyImporter{}

	_, err := ki.KeyImport("Hello World", &mocks2.KeyImportOpts{})
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "Invalid raw material. Expected byte array.")

	_, err = ki.KeyImport(nil, &mocks2.KeyImportOpts{})
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "Invalid raw material. Expected byte array.")

	_, err = ki.KeyImport([]byte(nil), &mocks2.KeyImportOpts{})
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "Invalid raw material. It must not be nil.")

	_, err = ki.KeyImport([]byte{0}, &mocks2.KeyImportOpts{})
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "Invalid Key Length [")

	// 测试SM4随机秘钥，成功导入
	kg := &sm4KeyGenerator{length: 16}

	k, err := kg.KeyGen(nil)
	assert.NoError(t, err)

	kk := k.(*sm4PrivateKey)

	kk.exportable = true
	kRaw, err := kk.Bytes()
	assert.NoError(t, err)

	_, err = ki.KeyImport(kRaw, &mocks2.KeyImportOpts{})
	assert.NoError(t, err)
}

func TestSM2PKIXPublicKeyImportOptsKeyImporter(t *testing.T) {
	t.Parallel()

	ki := sm2PKIXPublicKeyImportOptsKeyImporter{}

	_, err := ki.KeyImport("Hello World", &mocks2.KeyImportOpts{})
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "Invalid raw material. Expected byte array.")

	_, err = ki.KeyImport(nil, &mocks2.KeyImportOpts{})
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "Invalid raw material. Expected byte array.")

	_, err = ki.KeyImport([]byte(nil), &mocks2.KeyImportOpts{})
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "Invalid raw. It must not be nil.")

	_, err = ki.KeyImport([]byte{0}, &mocks2.KeyImportOpts{})
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "Failed converting PKIX to SM2 public key [")

	k, err := rsa.GenerateKey(rand.Reader, 512)
	assert.NoError(t, err)
	raw, err := x509.MarshalPKIXPublicKey(&k.PublicKey)
	assert.NoError(t, err)
	_, err = ki.KeyImport(raw, &mocks2.KeyImportOpts{})
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "Failed converting PKIX to SM2 public key [")

	// 测试SM2公钥导入
	kSM2, err := sm2.GenerateKey(rand.Reader)
	assert.NoError(t, err)

	raw, err = gmx509.MarshalPKIXSM2PublicKey(&kSM2.PublicKey)
	assert.NoError(t, err)
	_, err = ki.KeyImport(raw, &mocks2.KeyImportOpts{})
	assert.NoError(t, err)

}

func TestSM2PrivateKeyImportOptsKeyImporter(t *testing.T) {
	t.Parallel()

	ki := sm2PrivateKeyImportOptsKeyImporter{}

	_, err := ki.KeyImport("Hello World", &mocks2.KeyImportOpts{})
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "Invalid raw material. Expected byte array.")

	_, err = ki.KeyImport(nil, &mocks2.KeyImportOpts{})
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "Invalid raw material. Expected byte array.")

	_, err = ki.KeyImport([]byte(nil), &mocks2.KeyImportOpts{})
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "Invalid raw. It must not be nil.")

	_, err = ki.KeyImport([]byte{0}, &mocks2.KeyImportOpts{})
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "Failed converting PKIX to SM2 public key")

	k, err := rsa.GenerateKey(rand.Reader, 512)
	assert.NoError(t, err)
	raw := x509.MarshalPKCS1PrivateKey(k)
	_, err = ki.KeyImport(raw, &mocks2.KeyImportOpts{})
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "Failed converting PKIX to SM2 public key")

	//SM2私钥测试
	kSM2, err := sm2.GenerateKey(rand.Reader)
	assert.NoError(t, err)

	raw, err = gmx509.MarshalPKCS8SM2PrivateKey(kSM2)
	assert.NoError(t, err)
	_, err = ki.KeyImport(raw, &mocks2.KeyImportOpts{})
	assert.NoError(t, err)
}

func TestSM2GoPublicKeyImportOptsKeyImporter(t *testing.T) {
	t.Parallel()

	ki := sm2GoPublicKeyImportOptsKeyImporter{}

	_, err := ki.KeyImport("Hello World", &mocks2.KeyImportOpts{})
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "Invalid raw material. Expected *sm2.PublicKey.")

	_, err = ki.KeyImport(nil, &mocks2.KeyImportOpts{})
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "Invalid raw material. Expected *sm2.PublicKey.")

	//SM2公钥测试
	kSM2, err := sm2.GenerateKey(rand.Reader)
	assert.NoError(t, err)

	_, err = ki.KeyImport(&kSM2.PublicKey, &mocks2.KeyImportOpts{})
	assert.NoError(t, err)

}

func TestX509PublicKeyImportOptsKeyImporter(t *testing.T) {
	t.Parallel()

	ki := x509PublicKeyImportOptsKeyImporter{}

	_, err := ki.KeyImport("Hello World", &mocks2.KeyImportOpts{})
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "Invalid raw material. Expected *x509.Certificate.")

	_, err = ki.KeyImport(nil, &mocks2.KeyImportOpts{})
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "Invalid raw material. Expected *x509.Certificate.")

	cert := &x509.Certificate{}
	cert.PublicKey = "Hello world"
	_, err = ki.KeyImport(cert, &mocks2.KeyImportOpts{})
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "Certificate's public key type not recognized. Supported keys: [SM2]")
}
