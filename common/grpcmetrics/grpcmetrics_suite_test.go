/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package grpcmetrics_test

import (
	"testing"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	"github.com/paul-lee-attorney/fabric-2.1-gm/common/grpcmetrics/testpb"
)

//go:generate protoc --proto_path=testpb --go_out=plugins=grpc,paths=source_relative:testpb testpb/echo.proto

func TestGrpcmetrics(t *testing.T) {
	RegisterFailHandler(Fail)
	RunSpecs(t, "Grpcmetrics Suite")
}

//go:generate counterfeiter -o fakes/echo_service.go --fake-name EchoServiceServer . echoServiceServer

type echoServiceServer interface {
	testpb.EchoServiceServer
}
