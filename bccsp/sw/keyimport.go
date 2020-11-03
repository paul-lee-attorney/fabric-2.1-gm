/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package sw

import (
	"crypto/ecdsa"
	"crypto/x509"
	"errors"
	"fmt"
	"reflect"

	"github.com/paul-lee-attorney/fabric-2.1-gm/bccsp"
	"github.com/paul-lee-attorney/fabric-2.1-gm/bccsp/utils"
	"github.com/paul-lee-attorney/gm/sm2"
)

type aes256ImportKeyOptsKeyImporter struct{}

func (*aes256ImportKeyOptsKeyImporter) KeyImport(raw interface{}, opts bccsp.KeyImportOpts) (bccsp.Key, error) {
	aesRaw, ok := raw.([]byte)
	if !ok {
		return nil, errors.New("Invalid raw material. Expected byte array.")
	}

	if aesRaw == nil {
		return nil, errors.New("Invalid raw material. It must not be nil.")
	}

	if len(aesRaw) != 32 {
		return nil, fmt.Errorf("Invalid Key Length [%d]. Must be 32 bytes", len(aesRaw))
	}

	return &aesPrivateKey{aesRaw, false}, nil
}

type sm4ImportKeyOptsKeyImporter struct{}

func (*sm4ImportKeyOptsKeyImporter) KeyImport(raw interface{}, opts bccsp.KeyImportOpts) (bccsp.Key, error) {
	sm4Raw, ok := raw.([]byte)
	if !ok {
		return nil, errors.New("invalid raw material, expected byte array")
	}

	if sm4Raw == nil {
		return nil, errors.New("invalid raw material, it must not be nil")
	}

	if len(sm4Raw) != 16 {
		return nil, fmt.Errorf("invalid Key Length [%d], must be 16 bytes", len(sm4Raw))
	}

	return &sm4PrivateKey{sm4Raw, false}, nil
}

type hmacImportKeyOptsKeyImporter struct{}

func (*hmacImportKeyOptsKeyImporter) KeyImport(raw interface{}, opts bccsp.KeyImportOpts) (bccsp.Key, error) {
	aesRaw, ok := raw.([]byte)
	if !ok {
		return nil, errors.New("Invalid raw material. Expected byte array.")
	}

	if len(aesRaw) == 0 {
		return nil, errors.New("Invalid raw material. It must not be nil.")
	}

	return &aesPrivateKey{aesRaw, false}, nil
}

type ecdsaPKIXPublicKeyImportOptsKeyImporter struct{}

func (*ecdsaPKIXPublicKeyImportOptsKeyImporter) KeyImport(raw interface{}, opts bccsp.KeyImportOpts) (bccsp.Key, error) {
	der, ok := raw.([]byte)
	if !ok {
		return nil, errors.New("Invalid raw material. Expected byte array.")
	}

	if len(der) == 0 {
		return nil, errors.New("Invalid raw. It must not be nil.")
	}

	lowLevelKey, err := utils.DERToPublicKey(der)
	if err != nil {
		return nil, fmt.Errorf("Failed converting PKIX to ECDSA public key [%s]", err)
	}

	ecdsaPK, ok := lowLevelKey.(*ecdsa.PublicKey)
	if !ok {
		return nil, errors.New("Failed casting to ECDSA public key. Invalid raw material.")
	}

	return &ecdsaPublicKey{ecdsaPK}, nil
}

type sm2PKIXPublicKeyImportOptsKeyImporter struct{}

func (*sm2PKIXPublicKeyImportOptsKeyImporter) KeyImport(raw interface{}, opts bccsp.KeyImportOpts) (bccsp.Key, error) {
	der, ok := raw.([]byte)
	if !ok {
		return nil, errors.New("Invalid raw material. Expected byte array.")
	}

	if len(der) == 0 {
		return nil, errors.New("Invalid raw. It must not be nil.")
	}

	sm2PK, err := utils.UnmarshalPKIXSM2PublicKey(der)
	if err != nil {
		return nil, fmt.Errorf("Failed converting PKIX to SM2 public key [%s]", err)
	}

	return &sm2PublicKey{sm2PK}, nil
}

type ecdsaPrivateKeyImportOptsKeyImporter struct{}

func (*ecdsaPrivateKeyImportOptsKeyImporter) KeyImport(raw interface{}, opts bccsp.KeyImportOpts) (bccsp.Key, error) {
	der, ok := raw.([]byte)
	if !ok {
		return nil, errors.New("[ECDSADERPrivateKeyImportOpts] Invalid raw material. Expected byte array.")
	}

	if len(der) == 0 {
		return nil, errors.New("[ECDSADERPrivateKeyImportOpts] Invalid raw. It must not be nil.")
	}

	lowLevelKey, err := utils.DERToPrivateKey(der)
	if err != nil {
		return nil, fmt.Errorf("Failed converting PKIX to ECDSA public key [%s]", err)
	}

	ecdsaSK, ok := lowLevelKey.(*ecdsa.PrivateKey)
	if !ok {
		return nil, errors.New("Failed casting to ECDSA private key. Invalid raw material.")
	}

	return &ecdsaPrivateKey{ecdsaSK}, nil
}

type sm2PrivateKeyImportOptsKeyImporter struct{}

func (*sm2PrivateKeyImportOptsKeyImporter) KeyImport(raw interface{}, opts bccsp.KeyImportOpts) (bccsp.Key, error) {
	der, ok := raw.([]byte)
	if !ok {
		return nil, errors.New("Invalid raw material for SM2 private key import,expected byte array")
	}

	if len(der) == 0 {
		return nil, errors.New("invalid raw, it must not be nil")
	}

	sm2Priv, err := utils.ParsePKCS8SM2PrivateKey(der)
	if err != nil {
		return nil, fmt.Errorf("Failed converting PKIX to SM2 public key [%s]", err)
	}

	return &sm2PrivateKey{sm2Priv}, nil
}

type ecdsaGoPublicKeyImportOptsKeyImporter struct{}

func (*ecdsaGoPublicKeyImportOptsKeyImporter) KeyImport(raw interface{}, opts bccsp.KeyImportOpts) (bccsp.Key, error) {
	lowLevelKey, ok := raw.(*ecdsa.PublicKey)
	if !ok {
		return nil, errors.New("Invalid raw material. Expected *ecdsa.PublicKey.")
	}

	return &ecdsaPublicKey{lowLevelKey}, nil
}

type sm2GoPublicKeyImportOptsKeyImporter struct{}

func (*sm2GoPublicKeyImportOptsKeyImporter) KeyImport(raw interface{}, opts bccsp.KeyImportOpts) (bccsp.Key, error) {
	lowLevelKey, ok := raw.(*sm2.PublicKey)
	if !ok {
		return nil, errors.New("invalid raw material. Expected *ecdsa.PublicKey")
	}

	return &sm2PublicKey{lowLevelKey}, nil
}

type x509PublicKeyImportOptsKeyImporter struct {
	bccsp *CSP
}

func (ki *x509PublicKeyImportOptsKeyImporter) KeyImport(raw interface{}, opts bccsp.KeyImportOpts) (bccsp.Key, error) {
	x509Cert, ok := raw.(*x509.Certificate)
	if !ok {
		return nil, errors.New("Invalid raw material. Expected *x509.Certificate")
	}

	pk := x509Cert.PublicKey

	switch pk.(type) {
	case *ecdsa.PublicKey:
		return ki.bccsp.KeyImporters[reflect.TypeOf(&bccsp.ECDSAGoPublicKeyImportOpts{})].KeyImport(
			pk,
			&bccsp.ECDSAGoPublicKeyImportOpts{Temporary: opts.Ephemeral()})
	case *sm2.PublicKey:
		return ki.bccsp.KeyImporters[reflect.TypeOf(&bccsp.SM2GoPublicKeyImportOpts{})].KeyImport(
			pk,
			&bccsp.SM2GoPublicKeyImportOpts{Temporary: opts.Ephemeral()})
	default:
		return nil, errors.New("Certificate's public key type not recognized. Supported keys: [ECDSA]")
	}
}
