/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package tlsgen

import (
	"crypto/x509"
	"encoding/pem"
	"testing"

	"github.com/paul-lee-attorney/gm/gmtls"
	"github.com/stretchr/testify/assert"
)

func TestLoadCert(t *testing.T) {
	pair, err := newCertKeyPair(false, false, "", nil, nil)
	assert.NoError(t, err)
	assert.NotNil(t, pair)
	tlsCertPair, err := gmtls.X509KeyPair(pair.Cert, pair.Key)
	assert.NoError(t, err)
	assert.NotNil(t, tlsCertPair)
	block, _ := pem.Decode(pair.Cert)
	cert, err := x509.ParseCertificate(block.Bytes)
	assert.NoError(t, err)
	assert.NotNil(t, cert)
}
