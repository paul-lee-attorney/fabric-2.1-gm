/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package util

import (
	"crypto/tls"
	"fmt"
	"net"
	"strconv"
	"time"

	"github.com/paul-lee-attorney/fabric-2.1-gm/common/crypto/tlsgen"
	"github.com/paul-lee-attorney/fabric-2.1-gm/gossip/api"
	"github.com/paul-lee-attorney/fabric-2.1-gm/gossip/common"
	"github.com/paul-lee-attorney/fabric-2.1-gm/internal/pkg/comm"
	"github.com/paul-lee-attorney/gm/gmtls"
	"github.com/paul-lee-attorney/gm/gmx509"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
)

// CA that generates TLS key-pairs
var ca = createCAOrPanic()

func createCAOrPanic() tlsgen.CA {
	ca, err := tlsgen.NewCA()
	if err != nil {
		panic(fmt.Sprintf("failed creating CA: %+v", err))
	}
	return ca
}

// CreateGRPCLayer returns a new gRPC server with associated port, TLS certificates, SecureDialOpts and DialOption
func CreateGRPCLayer() (port int, gRPCServer *comm.GRPCServer, certs *common.TLSCertificates,
	secureDialOpts api.PeerSecureDialOpts, dialOpts []grpc.DialOption) {

	serverKeyPair, err := ca.NewServerCertKeyPair("127.0.0.1")
	if err != nil {
		panic(err)
	}
	clientKeyPair, err := ca.NewClientCertKeyPair()
	if err != nil {
		panic(err)
	}

	tlsServerCert, err := gmtls.X509KeyPair(serverKeyPair.Cert, serverKeyPair.Key)
	if err != nil {
		panic(err)
	}
	tlsClientCert, err := gmtls.X509KeyPair(clientKeyPair.Cert, clientKeyPair.Key)
	if err != nil {
		panic(err)
	}

	tlsConf := &gmtls.Config{
		Certificates: []tls.Certificate{tlsClientCert},
		ClientAuth:   tls.RequestClientCert,
		RootCAs:      gmx509.NewCertPool(),
	}

	tlsConf.RootCAs.AppendCertsFromPEM(ca.CertBytes())

	ta := credentials.NewTLS(tlsConf)
	dialOpts = append(dialOpts, grpc.WithTransportCredentials(ta))

	secureDialOpts = func() []grpc.DialOption {
		return dialOpts
	}

	certs = &common.TLSCertificates{}
	certs.TLSServerCert.Store(&tlsServerCert)
	certs.TLSClientCert.Store(&tlsClientCert)

	srvConfig := comm.ServerConfig{
		ConnectionTimeout: time.Second,
		SecOpts: comm.SecureOptions{
			Key:         serverKeyPair.Key,
			Certificate: serverKeyPair.Cert,
			UseTLS:      true,
		},
	}
	gRPCServer, err = comm.NewGRPCServer("127.0.0.1:", srvConfig)
	if err != nil {
		panic(err)
	}

	_, portString, err := net.SplitHostPort(gRPCServer.Address())
	if err != nil {
		panic(err)
	}
	portInt, err := strconv.Atoi(portString)
	if err != nil {
		panic(err)
	}

	return portInt, gRPCServer, certs, secureDialOpts, dialOpts
}
