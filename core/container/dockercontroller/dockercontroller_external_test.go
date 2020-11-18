/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package dockercontroller_test

import (
	"github.com/paul-lee-attorney/fabric-2.1-gm/core/container/dockercontroller"
)

//go:generate counterfeiter -o mock/platform_builder.go --fake-name PlatformBuilder . platformBuilder
type platformBuilder interface {
	dockercontroller.PlatformBuilder
}
