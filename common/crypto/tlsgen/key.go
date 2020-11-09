/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package tlsgen

import (
	"crypto"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net"
	"time"

	"github.com/paul-lee-attorney/fabric-2.1-gm/bccsp/gm"
	"github.com/paul-lee-attorney/gm/sm2"

	sm2cert "github.com/paul-lee-attorney/gm/sm2/cert"

	"github.com/pkg/errors"
)

func newPrivKey() (*sm2.PrivateKey, []byte, error) {
	privateKey, err := sm2.GenerateKey(rand.Reader)
	if err != nil {
		return nil, nil, err
	}
	privBytes, err := gm.MarshalPKCS8SM2PrivateKey(privateKey)
	if err != nil {
		return nil, nil, err
	}
	return privateKey, privBytes, nil
}

func newCertTemplate() (x509.Certificate, error) {
	sn, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return x509.Certificate{}, err
	}
	return x509.Certificate{
		Subject:      pkix.Name{SerialNumber: sn.String()},
		NotBefore:    time.Now().Add(time.Hour * (-24)),
		NotAfter:     time.Now().Add(time.Hour * 24),
		KeyUsage:     x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		SerialNumber: sn,
	}, nil
}

func newCertKeyPair(isCA bool, isServer bool, host string, certSigner crypto.Signer, parent *x509.Certificate) (*CertKeyPair, error) {
	privateKey, privBytes, err := newPrivKey()
	if err != nil {
		return nil, err
	}

	template, err := newCertTemplate()
	if err != nil {
		return nil, err
	}

	tenYearsFromNow := time.Now().Add(time.Hour * 24 * 365 * 10)
	if isCA {
		template.NotAfter = tenYearsFromNow
		template.IsCA = true
		template.KeyUsage |= x509.KeyUsageCertSign | x509.KeyUsageCRLSign
		template.ExtKeyUsage = []x509.ExtKeyUsage{
			x509.ExtKeyUsageClientAuth,
			x509.ExtKeyUsageServerAuth,
		}
		template.BasicConstraintsValid = true
	} else {
		template.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}
	}
	if isServer {
		template.NotAfter = tenYearsFromNow
		template.ExtKeyUsage = append(template.ExtKeyUsage, x509.ExtKeyUsageServerAuth)
		if ip := net.ParseIP(host); ip != nil {
			template.IPAddresses = append(template.IPAddresses, ip)
		} else {
			template.DNSNames = append(template.DNSNames, host)
		}
	}
	// If no parent cert, it's a self signed cert
	if parent == nil || certSigner == nil {
		parent = &template
		certSigner = privateKey
	}

	// rawBytes, err := x509.CreateCertificate(rand.Reader, &template, parent, &privateKey.PublicKey, certSigner)
	rawBytes, err := sm2cert.CreateCertificate(rand.Reader, &template, parent, &privateKey.PublicKey, certSigner)
	if err != nil {
		return nil, err
	}
	pubKey := encodePEM("SM2 CERTIFICATE", rawBytes)

	block, _ := pem.Decode(pubKey)
	if block == nil { // Never comes unless x509 or pem has bug
		return nil, errors.Errorf("%s: wrong PEM encoding", pubKey)
	}

	// cert, err := x509.ParseCertificate(block.Bytes)
	cert, err := sm2cert.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, err
	}
	privKey := encodePEM("SM2 PRIVATE KEY", privBytes)
	return &CertKeyPair{
		Key:     privKey,
		Cert:    pubKey,
		Signer:  privateKey,
		TLSCert: cert,
	}, nil
}

func encodePEM(keyType string, data []byte) []byte {
	return pem.EncodeToMemory(&pem.Block{Type: keyType, Bytes: data})
}
