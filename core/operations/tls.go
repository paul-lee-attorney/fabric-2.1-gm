/*
Copyright IBM Corp All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package operations

import (
	"crypto/tls"
	"io/ioutil"

	"github.com/paul-lee-attorney/fabric-2.1-gm/internal/pkg/comm"
	"github.com/paul-lee-attorney/gm/gmtls"
	"github.com/paul-lee-attorney/gm/gmx509"
)

type TLS struct {
	Enabled            bool
	CertFile           string
	KeyFile            string
	ClientCertRequired bool
	ClientCACertFiles  []string
}

func (t TLS) Config() (*gmtls.Config, error) {
	var tlsConfig *gmtls.Config

	if t.Enabled {
		cert, err := gmtls.LoadX509KeyPair(t.CertFile, t.KeyFile)
		if err != nil {
			return nil, err
		}
		caCertPool := gmx509.NewCertPool()
		for _, caPath := range t.ClientCACertFiles {
			caPem, err := ioutil.ReadFile(caPath)
			if err != nil {
				return nil, err
			}
			caCertPool.AppendCertsFromPEM(caPem)
		}
		tlsConfig = &gmtls.Config{
			Certificates: []tls.Certificate{cert},
			CipherSuites: comm.DefaultTLSCipherSuites,
			ClientCAs:    caCertPool,
		}
		if t.ClientCertRequired {
			tlsConfig.ClientAuth = tls.RequireAndVerifyClientCert
		} else {
			tlsConfig.ClientAuth = tls.VerifyClientCertIfGiven
		}
	}

	return tlsConfig, nil
}
