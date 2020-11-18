/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package extcc_test

import (
	"net"
	"time"

	"github.com/paul-lee-attorney/fabric-2.1-gm/core/chaincode/extcc"
	"github.com/paul-lee-attorney/fabric-2.1-gm/core/chaincode/extcc/mock"
	"github.com/paul-lee-attorney/fabric-2.1-gm/core/container/ccintf"
	"github.com/paul-lee-attorney/fabric-2.1-gm/internal/pkg/comm"

	"google.golang.org/grpc"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

var _ = Describe("Extcc", func() {
	var (
		i        *extcc.ExternalChaincodeRuntime
		shandler *mock.StreamHandler
	)

	BeforeEach(func() {
		shandler = &mock.StreamHandler{}
		i = &extcc.ExternalChaincodeRuntime{}
	})

	Context("Run", func() {
		When("chaincode is running", func() {
			var (
				cclist net.Listener
				ccserv *grpc.Server
			)
			BeforeEach(func() {
				var err error
				cclist, err = net.Listen("tcp", "127.0.0.1:0")
				Expect(err).To(BeNil())
				Expect(cclist).To(Not(BeNil()))
				ccserv = grpc.NewServer([]grpc.ServerOption{}...)
				go ccserv.Serve(cclist)
			})

			AfterEach(func() {
				if ccserv != nil {
					ccserv.Stop()
				}
				if cclist != nil {
					cclist.Close()
				}
			})

			It("runs to completion", func() {
				ccinfo := &ccintf.ChaincodeServerInfo{
					Address: cclist.Addr().String(),
					ClientConfig: comm.ClientConfig{
						KaOpts:  comm.DefaultKeepaliveOptions,
						Timeout: 10 * time.Second,
					},
				}
				err := i.Stream("ccid", ccinfo, shandler)
				Expect(err).To(BeNil())
				Expect(shandler.HandleChaincodeStreamCallCount()).To(Equal(1))

				streamArg := shandler.HandleChaincodeStreamArgsForCall(0)
				Expect(streamArg).To(Not(BeNil()))
			})
		})
		Context("chaincode info incorrect", func() {
			var (
				ccinfo *ccintf.ChaincodeServerInfo
			)
			BeforeEach(func() {
				ccinfo = &ccintf.ChaincodeServerInfo{
					Address: "ccaddress:12345",
					ClientConfig: comm.ClientConfig{
						SecOpts: comm.SecureOptions{
							UseTLS:            true,
							RequireClientCert: true,
							Certificate:       []byte("fake-cert"),
							Key:               []byte("fake-key"),
							ServerRootCAs:     [][]byte{[]byte("fake-root-cert")},
						},
						Timeout: 10 * time.Second,
					},
				}
			})
			When("address is bad", func() {
				BeforeEach(func() {
					ccinfo.ClientConfig.SecOpts.UseTLS = false
					ccinfo.Address = "<badaddress>"
				})
				It("returns an error", func() {
					err := i.Stream("ccid", ccinfo, shandler)
					Expect(err).To(MatchError(ContainSubstring("error creating grpc connection to <badaddress>")))
				})
			})
			When("unspecified client spec", func() {
				BeforeEach(func() {
					ccinfo.ClientConfig.SecOpts.Key = nil
				})
				It("returns an error", func() {
					err := i.Stream("ccid", ccinfo, shandler)
					Expect(err).To(MatchError(ContainSubstring("both Key and Certificate are required when using mutual TLS")))
				})
			})
		})
	})
})
