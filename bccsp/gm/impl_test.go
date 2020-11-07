/*
Copyright Paul Lee based on IBM's works. 2020 All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package gm

import (
	"bytes"
	"crypto/rand"
	"fmt"
	"hash"
	"io/ioutil"
	"math/big"
	"os"
	"reflect"
	"testing"

	"github.com/paul-lee-attorney/fabric-2.1-gm/bccsp"
	"github.com/paul-lee-attorney/fabric-2.1-gm/bccsp/sw/mocks"
	"github.com/paul-lee-attorney/gm/sm2"
	"github.com/paul-lee-attorney/gm/sm3"
	"github.com/stretchr/testify/assert"
)

var (
	currentTestConfig testConfig
	tempDir           string
)

type testConfig struct {
	securityLevel int
	hashFamily    string
}

func (tc testConfig) Provider(t *testing.T) (bccsp.BCCSP, bccsp.KeyStore, func()) {
	td, err := ioutil.TempDir(tempDir, "test")
	assert.NoError(t, err)
	ks, err := NewFileBasedKeyStore(nil, td, false)
	assert.NoError(t, err)
	p, err := NewWithParams(ks)
	assert.NoError(t, err)
	return p, ks, func() { os.RemoveAll(td) }
}

func TestMain(m *testing.M) {
	code := -1
	defer func() {
		os.Exit(code)
	}()
	tests := testConfig{256, "SM3"}

	var err error
	tempDir, err = ioutil.TempDir("", "bccsp-gm")
	if err != nil {
		fmt.Printf("Failed to create temporary directory: %s\n\n", err)
		return
	}
	defer os.RemoveAll(tempDir)

	currentTestConfig = tests
	code = m.Run()
	if code != 0 {
		fmt.Printf("Failed testing")
		return
	}
}

func TestInvalidNewParameter(t *testing.T) {
	t.Parallel()
	_, _, cleanup := currentTestConfig.Provider(t)
	defer cleanup()

	r, err := NewWithParams(nil)
	if err == nil {
		t.Fatal("Error should be different from nil in this case")
	}
	if r != nil {
		t.Fatal("Return value should be equal to nil in this case")
	}

	r, err = NewDefaultSecurityLevel("")
	if err == nil {
		t.Fatal("Error should be different from nil in this case")
	}
	if r != nil {
		t.Fatal("Return value should be equal to nil in this case")
	}
}

func TestInvalidSKI(t *testing.T) {
	t.Parallel()
	provider, _, cleanup := currentTestConfig.Provider(t)
	defer cleanup()

	k, err := provider.GetKey(nil)
	if err == nil {
		t.Fatal("Error should be different from nil in this case")
	}
	if k != nil {
		t.Fatal("Return value should be equal to nil in this case")
	}

	k, err = provider.GetKey([]byte{0, 1, 2, 3, 4, 5, 6})
	if err == nil {
		t.Fatal("Error should be different from nil in this case")
	}
	if k != nil {
		t.Fatal("Return value should be equal to nil in this case")
	}
}

func TestKeyGenSM2Opts(t *testing.T) {
	t.Parallel()
	provider, _, cleanup := currentTestConfig.Provider(t)
	defer cleanup()

	// Curve P256
	k, err := provider.KeyGen(&bccsp.SM2KeyGenOpts{Temporary: false})
	if err != nil {
		t.Fatalf("Failed generating SM2 P256 key [%s]", err)
	}
	if k == nil {
		t.Fatal("Failed generating SM2 P256 key. Key must be different from nil")
	}
	if !k.Private() {
		t.Fatal("Failed generating SM2 P256 key. Key should be private")
	}
	if k.Symmetric() {
		t.Fatal("Failed generating SM2 P256 key. Key should be asymmetric")
	}

	sm2Key := k.(*sm2PrivateKey).privKey
	if !sm2.GetSm2P256V1().IsOnCurve(sm2Key.X, sm2Key.Y) {
		t.Fatal("P256 generated key in invalid. The public key must be on the P256 curve.")
	}
	if sm2.GetSm2P256V1() != sm2Key.Curve {
		t.Fatal("P256 generated key in invalid. The curve must be P256.")
	}
	if sm2Key.D.Cmp(big.NewInt(0)) == 0 {
		t.Fatal("P256 generated key in invalid. Private key must be different from 0.")
	}
}

func TestKeyGenSM4Opts(t *testing.T) {
	t.Parallel()
	provider, _, cleanup := currentTestConfig.Provider(t)
	defer cleanup()

	// SM4 128
	k, err := provider.KeyGen(&bccsp.SM4KeyGenOpts{Temporary: false})
	if err != nil {
		t.Fatalf("Failed generating SM4 128 key [%s]", err)
	}
	if k == nil {
		t.Fatal("Failed generating SM4 128 key. Key must be different from nil")
	}
	if !k.Private() {
		t.Fatal("Failed generating SM4 128 key. Key should be private")
	}
	if !k.Symmetric() {
		t.Fatal("Failed generating SM4 128 key. Key should be symmetric")
	}

	sm4Key := k.(*sm4PrivateKey).privKey
	if len(sm4Key) != 16 {
		t.Fatal("SM4 Key generated key in invalid. The key must have length 16.")
	}

}

func TestSM2KeyGenEphemeral(t *testing.T) {
	t.Parallel()
	provider, _, cleanup := currentTestConfig.Provider(t)
	defer cleanup()

	k, err := provider.KeyGen(&bccsp.SM2KeyGenOpts{Temporary: true})
	if err != nil {
		t.Fatalf("Failed generating SM2 key [%s]", err)
	}
	if k == nil {
		t.Fatal("Failed generating SM2 key. Key must be different from nil")
	}
	if !k.Private() {
		t.Fatal("Failed generating SM2 key. Key should be private")
	}
	if k.Symmetric() {
		t.Fatal("Failed generating SM2 key. Key should be asymmetric")
	}
	raw, err := k.Bytes()
	if err == nil {
		t.Fatal("Failed marshalling to bytes. Marshalling must fail.")
	}
	if len(raw) != 0 {
		t.Fatal("Failed marshalling to bytes. Output should be 0 bytes")
	}
	pk, err := k.PublicKey()
	if err != nil {
		t.Fatalf("Failed getting corresponding public key [%s]", err)
	}
	if pk == nil {
		t.Fatal("Public key must be different from nil.")
	}
}

func TestSM2PrivateKeySKI(t *testing.T) {
	t.Parallel()
	provider, _, cleanup := currentTestConfig.Provider(t)
	defer cleanup()

	k, err := provider.KeyGen(&bccsp.SM2KeyGenOpts{Temporary: false})
	if err != nil {
		t.Fatalf("Failed generating SM2 key [%s]", err)
	}

	ski := k.SKI()
	if len(ski) == 0 {
		t.Fatal("SKI not valid. Zero length.")
	}
}

func TestSM2KeyGenNonEphemeral(t *testing.T) {
	t.Parallel()
	provider, _, cleanup := currentTestConfig.Provider(t)
	defer cleanup()

	k, err := provider.KeyGen(&bccsp.SM2KeyGenOpts{Temporary: false})
	if err != nil {
		t.Fatalf("Failed generating SM2 key [%s]", err)
	}
	if k == nil {
		t.Fatal("Failed generating SM2 key. Key must be different from nil")
	}
	if !k.Private() {
		t.Fatal("Failed generating SM2 key. Key should be private")
	}
	if k.Symmetric() {
		t.Fatal("Failed generating SM2 key. Key should be asymmetric")
	}
}

func TestSM2GetKeyBySKI(t *testing.T) {
	t.Parallel()
	provider, _, cleanup := currentTestConfig.Provider(t)
	defer cleanup()

	k, err := provider.KeyGen(&bccsp.SM2KeyGenOpts{Temporary: false})
	if err != nil {
		t.Fatalf("Failed generating SM2 key [%s]", err)
	}

	k2, err := provider.GetKey(k.SKI())
	if err != nil {
		t.Fatalf("Failed getting SM2 key [%s]", err)
	}
	if k2 == nil {
		t.Fatal("Failed getting SM2 key. Key must be different from nil")
	}
	if !k2.Private() {
		t.Fatal("Failed getting SM2 key. Key should be private")
	}
	if k2.Symmetric() {
		t.Fatal("Failed getting SM2 key. Key should be asymmetric")
	}

	// Check that the SKIs are the same
	if !bytes.Equal(k.SKI(), k2.SKI()) {
		t.Fatalf("SKIs are different [%x]!=[%x]", k.SKI(), k2.SKI())
	}
}

func TestSM2PublicKeyFromPrivateKey(t *testing.T) {
	t.Parallel()
	provider, _, cleanup := currentTestConfig.Provider(t)
	defer cleanup()

	k, err := provider.KeyGen(&bccsp.SM2KeyGenOpts{Temporary: false})
	if err != nil {
		t.Fatalf("Failed generating SM2 key [%s]", err)
	}

	pk, err := k.PublicKey()
	if err != nil {
		t.Fatalf("Failed getting public key from private SM2 key [%s]", err)
	}
	if pk == nil {
		t.Fatal("Failed getting public key from private SM2 key. Key must be different from nil")
	}
	if pk.Private() {
		t.Fatal("Failed generating SM2 key. Key should be public")
	}
	if pk.Symmetric() {
		t.Fatal("Failed generating SM2 key. Key should be asymmetric")
	}
}

func TestSM2PublicKeyBytes(t *testing.T) {
	t.Parallel()
	provider, _, cleanup := currentTestConfig.Provider(t)
	defer cleanup()

	k, err := provider.KeyGen(&bccsp.SM2KeyGenOpts{Temporary: false})
	if err != nil {
		t.Fatalf("Failed generating SM2 key [%s]", err)
	}

	pk, err := k.PublicKey()
	if err != nil {
		t.Fatalf("Failed getting public key from private SM2 key [%s]", err)
	}

	raw, err := pk.Bytes()
	if err != nil {
		t.Fatalf("Failed marshalling SM2 public key [%s]", err)
	}
	if len(raw) == 0 {
		t.Fatal("Failed marshalling SM2 public key. Zero length")
	}
}

func TestSM2PublicKeySKI(t *testing.T) {
	t.Parallel()
	provider, _, cleanup := currentTestConfig.Provider(t)
	defer cleanup()

	k, err := provider.KeyGen(&bccsp.SM2KeyGenOpts{Temporary: false})
	if err != nil {
		t.Fatalf("Failed generating SM2 key [%s]", err)
	}

	pk, err := k.PublicKey()
	if err != nil {
		t.Fatalf("Failed getting public key from private SM2 key [%s]", err)
	}

	ski := pk.SKI()
	if len(ski) == 0 {
		t.Fatal("SKI not valid. Zero length.")
	}
}

func TestSM2Sign(t *testing.T) {
	t.Parallel()
	provider, _, cleanup := currentTestConfig.Provider(t)
	defer cleanup()

	k, err := provider.KeyGen(&bccsp.SM2KeyGenOpts{Temporary: false})
	if err != nil {
		t.Fatalf("Failed generating SM2 key [%s]", err)
	}

	msg := []byte("Hello World")

	digest, err := provider.Hash(msg, &bccsp.SM3Opts{})
	if err != nil {
		t.Fatalf("Failed computing HASH [%s]", err)
	}

	signature, err := provider.Sign(k, digest, nil)
	if err != nil {
		t.Fatalf("Failed generating SM2 signature [%s]", err)
	}
	if len(signature) == 0 {
		t.Fatal("Failed generating SM2 key. Signature must be different from nil")
	}
}

func TestSM2Verify(t *testing.T) {
	t.Parallel()
	provider, ks, cleanup := currentTestConfig.Provider(t)
	defer cleanup()

	k, err := provider.KeyGen(&bccsp.SM2KeyGenOpts{Temporary: false})
	if err != nil {
		t.Fatalf("Failed generating SM2 key [%s]", err)
	}

	msg := []byte("Hello World")

	digest, err := provider.Hash(msg, &bccsp.SM3Opts{})
	if err != nil {
		t.Fatalf("Failed computing HASH [%s]", err)
	}

	signature, err := provider.Sign(k, digest, nil)
	if err != nil {
		t.Fatalf("Failed generating SM2 signature [%s]", err)
	}

	valid, err := provider.Verify(k, signature, digest, nil)
	if err != nil {
		t.Fatalf("Failed verifying SM2 signature [%s]", err)
	}
	if !valid {
		t.Fatal("Failed verifying SM2 signature. Signature not valid.")
	}

	pk, err := k.PublicKey()
	if err != nil {
		t.Fatalf("Failed getting corresponding public key [%s]", err)
	}

	valid, err = provider.Verify(pk, signature, digest, nil)
	if err != nil {
		t.Fatalf("Failed verifying SM2 signature [%s]", err)
	}
	if !valid {
		t.Fatal("Failed verifying SM2 signature. Signature not valid.")
	}

	// Store public key
	err = ks.StoreKey(pk)
	if err != nil {
		t.Fatalf("Failed storing corresponding public key [%s]", err)
	}

	pk2, err := ks.GetKey(pk.SKI())
	if err != nil {
		t.Fatalf("Failed retrieving corresponding public key [%s]", err)
	}

	valid, err = provider.Verify(pk2, signature, digest, nil)
	if err != nil {
		t.Fatalf("Failed verifying SM2 signature [%s]", err)
	}
	if !valid {
		t.Fatal("Failed verifying SM2 signature. Signature not valid.")
	}
}

func TestSM2KeyImportFromExportedKey(t *testing.T) {
	t.Parallel()
	provider, _, cleanup := currentTestConfig.Provider(t)
	defer cleanup()

	// Generate an SM2 key
	k, err := provider.KeyGen(&bccsp.SM2KeyGenOpts{Temporary: false})
	if err != nil {
		t.Fatalf("Failed generating SM2 key [%s]", err)
	}

	// Export the public key
	pk, err := k.PublicKey()
	if err != nil {
		t.Fatalf("Failed getting SM2 public key [%s]", err)
	}

	pkRaw, err := pk.Bytes()
	if err != nil {
		t.Fatalf("Failed getting SM2 raw public key [%s]", err)
	}

	// Import the exported public key
	pk2, err := provider.KeyImport(pkRaw, &bccsp.SM2PKIXPublicKeyImportOpts{Temporary: false})
	if err != nil {
		t.Fatalf("Failed importing SM2 public key [%s]", err)
	}
	if pk2 == nil {
		t.Fatal("Failed importing SM2 public key. Return BCCSP key cannot be nil.")
	}

	// Sign and verify with the imported public key
	msg := []byte("Hello World")

	digest, err := provider.Hash(msg, &bccsp.SM3Opts{})
	if err != nil {
		t.Fatalf("Failed computing HASH [%s]", err)
	}

	signature, err := provider.Sign(k, digest, nil)
	if err != nil {
		t.Fatalf("Failed generating SM2 signature [%s]", err)
	}

	valid, err := provider.Verify(pk2, signature, digest, nil)
	if err != nil {
		t.Fatalf("Failed verifying SM2 signature [%s]", err)
	}
	if !valid {
		t.Fatal("Failed verifying SM2 signature. Signature not valid.")
	}
}

func TestSM2KeyImportFromSM2PublicKey(t *testing.T) {
	t.Parallel()
	provider, _, cleanup := currentTestConfig.Provider(t)
	defer cleanup()

	// Generate an SM2 key
	k, err := provider.KeyGen(&bccsp.SM2KeyGenOpts{Temporary: false})
	if err != nil {
		t.Fatalf("Failed generating SM2 key [%s]", err)
	}

	// Export the public key
	pk, err := k.PublicKey()
	if err != nil {
		t.Fatalf("Failed getting SM2 public key [%s]", err)
	}

	pkRaw, err := pk.Bytes()
	if err != nil {
		t.Fatalf("Failed getting SM2 raw public key [%s]", err)
	}

	pub, err := ParsePKIXSM2PublicKey(pkRaw)
	if err != nil {
		t.Fatalf("Failed converting raw to sm2.PublicKey [%s]", err)
	}

	// Import the sm2.PublicKey
	pk2, err := provider.KeyImport(pub, &bccsp.SM2GoPublicKeyImportOpts{Temporary: false})
	if err != nil {
		t.Fatalf("Failed importing SM2 public key [%s]", err)
	}
	if pk2 == nil {
		t.Fatal("Failed importing SM2 public key. Return BCCSP key cannot be nil.")
	}

	// Sign and verify with the imported public key
	msg := []byte("Hello World")

	digest, err := provider.Hash(msg, &bccsp.SM3Opts{})
	if err != nil {
		t.Fatalf("Failed computing HASH [%s]", err)
	}

	signature, err := provider.Sign(k, digest, nil)
	if err != nil {
		t.Fatalf("Failed generating SM2 signature [%s]", err)
	}

	valid, err := provider.Verify(pk2, signature, digest, nil)
	if err != nil {
		t.Fatalf("Failed verifying SM2 signature [%s]", err)
	}
	if !valid {
		t.Fatal("Failed verifying SM2 signature. Signature not valid.")
	}
}

func TestSM2KeyImportFromSM2PrivateKey(t *testing.T) {
	t.Parallel()
	provider, _, cleanup := currentTestConfig.Provider(t)
	defer cleanup()

	// Generate an SM2 key, default is P256
	key, err := sm2.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("Failed generating SM2 key [%s]", err)
	}

	// Import the sm2.PrivateKey
	priv, err := MarshalSM2Privatekey(key)
	if err != nil {
		t.Fatalf("Failed converting raw to sm2.PrivateKey [%s]", err)
	}

	sk, err := provider.KeyImport(priv, &bccsp.SM2PrivateKeyImportOpts{Temporary: false})
	if err != nil {
		t.Fatalf("Failed importing SM2 private key [%s]", err)
	}
	if sk == nil {
		t.Fatal("Failed importing SM2 private key. Return BCCSP key cannot be nil.")
	}

	// Import the sm2.PublicKey
	pub, err := MarshalPKIXSM2PublicKey(&key.PublicKey)
	if err != nil {
		t.Fatalf("Failed converting raw to sm2.PublicKey [%s]", err)
	}

	pk, err := provider.KeyImport(pub, &bccsp.SM2PKIXPublicKeyImportOpts{Temporary: false})

	if err != nil {
		t.Fatalf("Failed importing SM2 public key [%s]", err)
	}
	if pk == nil {
		t.Fatal("Failed importing SM2 public key. Return BCCSP key cannot be nil.")
	}

	// Sign and verify with the imported public key
	msg := []byte("Hello World")

	digest, err := provider.Hash(msg, &bccsp.SM3Opts{})
	if err != nil {
		t.Fatalf("Failed computing HASH [%s]", err)
	}

	signature, err := provider.Sign(sk, digest, nil)
	if err != nil {
		t.Fatalf("Failed generating SM2 signature [%s]", err)
	}

	valid, err := provider.Verify(pk, signature, digest, nil)
	if err != nil {
		t.Fatalf("Failed verifying SM2 signature [%s]", err)
	}
	if !valid {
		t.Fatal("Failed verifying SM2 signature. Signature not valid.")
	}
}

func TestSM4KeyGen(t *testing.T) {
	t.Parallel()
	provider, _, cleanup := currentTestConfig.Provider(t)
	defer cleanup()

	k, err := provider.KeyGen(&bccsp.SM4KeyGenOpts{Temporary: false})
	if err != nil {
		t.Fatalf("Failed generating SM4 key [%s]", err)
	}
	if k == nil {
		t.Fatal("Failed generating SM4 key. Key must be different from nil")
	}
	if !k.Private() {
		t.Fatal("Failed generating SM4 key. Key should be private")
	}
	if !k.Symmetric() {
		t.Fatal("Failed generating SM4 key. Key should be symmetric")
	}

	pk, err := k.PublicKey()
	if err == nil {
		t.Fatal("Error should be different from nil in this case")
	}
	if pk != nil {
		t.Fatal("Return value should be equal to nil in this case")
	}
}

func TestSM4Encrypt(t *testing.T) {
	t.Parallel()
	provider, _, cleanup := currentTestConfig.Provider(t)
	defer cleanup()

	k, err := provider.KeyGen(&bccsp.SM4KeyGenOpts{Temporary: false})
	if err != nil {
		t.Fatalf("Failed generating SM4 key [%s]", err)
	}

	ct, err := provider.Encrypt(k, []byte("Hello World"), &bccsp.SM4CBCPKCS7ModeOpts{})
	if err != nil {
		t.Fatalf("Failed encrypting [%s]", err)
	}
	if len(ct) == 0 {
		t.Fatal("Failed encrypting. Nil ciphertext")
	}
}

func TestSM4Decrypt(t *testing.T) {
	t.Parallel()
	provider, _, cleanup := currentTestConfig.Provider(t)
	defer cleanup()

	k, err := provider.KeyGen(&bccsp.SM4KeyGenOpts{Temporary: false})
	if err != nil {
		t.Fatalf("Failed generating SM4 key [%s]", err)
	}

	msg := []byte("Hello World")

	ct, err := provider.Encrypt(k, msg, &bccsp.SM4CBCPKCS7ModeOpts{})
	if err != nil {
		t.Fatalf("Failed encrypting [%s]", err)
	}

	pt, err := provider.Decrypt(k, ct, bccsp.SM4CBCPKCS7ModeOpts{})
	if err != nil {
		t.Fatalf("Failed decrypting [%s]", err)
	}
	if len(ct) == 0 {
		t.Fatal("Failed decrypting. Nil plaintext")
	}

	if !bytes.Equal(msg, pt) {
		t.Fatalf("Failed decrypting. Decrypted plaintext is different from the original. [%x][%x]", msg, pt)
	}
}

func TestSM4KeyImport(t *testing.T) {
	t.Parallel()
	provider, _, cleanup := currentTestConfig.Provider(t)
	defer cleanup()

	raw, err := getRandomBytes(16)
	if err != nil {
		t.Fatalf("Failed generating SM4 key [%s]", err)
	}

	k, err := provider.KeyImport(raw, &bccsp.SM4ImportKeyOpts{Temporary: false})
	if err != nil {
		t.Fatalf("Failed importing SM4 key [%s]", err)
	}
	if k == nil {
		t.Fatal("Failed importing SM4 key. Imported Key must be different from nil")
	}
	if !k.Private() {
		t.Fatal("Failed HMACing SM4 key. Imported Key should be private")
	}
	if !k.Symmetric() {
		t.Fatal("Failed HMACing SM4 key. Imported Key should be asymmetric")
	}
	raw, err = k.Bytes()
	if err == nil {
		t.Fatal("Failed marshalling to bytes. Marshalling must fail.")
	}
	if len(raw) != 0 {
		t.Fatal("Failed marshalling to bytes. Output should be 0 bytes")
	}

	msg := []byte("Hello World")

	ct, err := provider.Encrypt(k, msg, &bccsp.SM4CBCPKCS7ModeOpts{})
	if err != nil {
		t.Fatalf("Failed encrypting [%s]", err)
	}

	pt, err := provider.Decrypt(k, ct, bccsp.SM4CBCPKCS7ModeOpts{})
	if err != nil {
		t.Fatalf("Failed decrypting [%s]", err)
	}
	if len(ct) == 0 {
		t.Fatal("Failed decrypting. Nil plaintext")
	}

	if !bytes.Equal(msg, pt) {
		t.Fatalf("Failed decrypting. Decrypted plaintext is different from the original. [%x][%x]", msg, pt)
	}
}

func TestSM4KeyImportBadPaths(t *testing.T) {
	t.Parallel()
	provider, _, cleanup := currentTestConfig.Provider(t)
	defer cleanup()

	_, err := provider.KeyImport(nil, &bccsp.SM4ImportKeyOpts{Temporary: false})
	if err == nil {
		t.Fatal("Failed importing key. Must fail on importing nil key")
	}

	_, err = provider.KeyImport([]byte{1}, &bccsp.SM4ImportKeyOpts{Temporary: false})
	if err == nil {
		t.Fatal("Failed importing key. Must fail on importing a key with an invalid length")
	}
}

func TestSM4KeyGenSKI(t *testing.T) {
	t.Parallel()
	provider, _, cleanup := currentTestConfig.Provider(t)
	defer cleanup()

	k, err := provider.KeyGen(&bccsp.SM4KeyGenOpts{Temporary: false})
	if err != nil {
		t.Fatalf("Failed generating SM4 key [%s]", err)
	}

	k2, err := provider.GetKey(k.SKI())
	if err != nil {
		t.Fatalf("Failed getting SM4 key [%s]", err)
	}
	if k2 == nil {
		t.Fatal("Failed getting SM4 key. Key must be different from nil")
	}
	if !k2.Private() {
		t.Fatal("Failed getting SM4 key. Key should be private")
	}
	if !k2.Symmetric() {
		t.Fatal("Failed getting SM4 key. Key should be symmetric")
	}

	// Check that the SKIs are the same
	if !bytes.Equal(k.SKI(), k2.SKI()) {
		t.Fatalf("SKIs are different [%x]!=[%x]", k.SKI(), k2.SKI())
	}
}

func TestSHA(t *testing.T) {
	t.Parallel()
	provider, _, cleanup := currentTestConfig.Provider(t)
	defer cleanup()

	for i := 1; i < 100; i++ {
		b, err := getRandomBytes(i)
		if err != nil {
			t.Fatalf("Failed getting random bytes [%s]", err)
		}

		h1, err := provider.Hash(b, &bccsp.SM3Opts{})
		if err != nil {
			t.Fatalf("Failed computing SHA [%s]", err)
		}

		var h hash.Hash
		h = sm3.New()
		h.Write(b)
		h2 := h.Sum(nil)
		if !bytes.Equal(h1, h2) {
			t.Fatalf("Discrempancy found in HASH result [%x], [%x]!=[%x]", b, h1, h2)
		}
	}
}

func TestAddWrapper(t *testing.T) {
	t.Parallel()
	p, _, cleanup := currentTestConfig.Provider(t)
	defer cleanup()

	gmcsp, ok := p.(*CSP)
	assert.True(t, ok)

	tester := func(o interface{}, getter func(t reflect.Type) (interface{}, bool)) {
		tt := reflect.TypeOf(o)
		err := gmcsp.AddWrapper(tt, o)
		assert.NoError(t, err)
		o2, ok := getter(tt)
		assert.True(t, ok)
		assert.Equal(t, o, o2)
	}

	tester(&mocks.KeyGenerator{}, func(t reflect.Type) (interface{}, bool) { o, ok := gmcsp.KeyGenerators[t]; return o, ok })
	tester(&mocks.KeyDeriver{}, func(t reflect.Type) (interface{}, bool) { o, ok := gmcsp.KeyDerivers[t]; return o, ok })
	tester(&mocks.KeyImporter{}, func(t reflect.Type) (interface{}, bool) { o, ok := gmcsp.KeyImporters[t]; return o, ok })
	tester(&mocks.Encryptor{}, func(t reflect.Type) (interface{}, bool) { o, ok := gmcsp.Encryptors[t]; return o, ok })
	tester(&mocks.Decryptor{}, func(t reflect.Type) (interface{}, bool) { o, ok := gmcsp.Decryptors[t]; return o, ok })
	tester(&mocks.Signer{}, func(t reflect.Type) (interface{}, bool) { o, ok := gmcsp.Signers[t]; return o, ok })
	tester(&mocks.Verifier{}, func(t reflect.Type) (interface{}, bool) { o, ok := gmcsp.Verifiers[t]; return o, ok })
	tester(&mocks.Hasher{}, func(t reflect.Type) (interface{}, bool) { o, ok := gmcsp.Hashers[t]; return o, ok })

	// Add invalid wrapper
	err := gmcsp.AddWrapper(reflect.TypeOf(cleanup), cleanup)
	assert.Error(t, err)
	assert.Equal(t, err.Error(), "wrapper type not valid, must be on of: KeyGenerator, KeyDeriver, KeyImporter, Encryptor, Decryptor, Signer, Verifier, Hasher")
}
