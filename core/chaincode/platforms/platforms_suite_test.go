/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package platforms_test

import (
	"testing"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	"github.com/paul-lee-attorney/fabric-2.1-gm/core/chaincode/platforms"
)

//go:generate counterfeiter -o mock/platform.go --fake-name Platform . platform
type platform interface {
	platforms.Platform
}

//go:generate counterfeiter -o mock/package_writer.go --fake-name PackageWriter . packageWriter
type packageWriter interface {
	platforms.PackageWriter
}

func TestPlatforms(t *testing.T) {
	RegisterFailHandler(Fail)
	RunSpecs(t, "Platforms Suite")
}
