/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package ordererext_test

import (
	"github.com/paul-lee-attorney/fabric-2.1-gm/common/tools/protolator"
	"github.com/paul-lee-attorney/fabric-2.1-gm/common/tools/protolator/protoext/ordererext"
)

// ensure structs implement expected interfaces
var (
	_ protolator.DynamicMapFieldProto       = &ordererext.DynamicOrdererGroup{}
	_ protolator.DecoratedProto             = &ordererext.DynamicOrdererGroup{}
	_ protolator.VariablyOpaqueFieldProto   = &ordererext.ConsensusType{}
	_ protolator.DecoratedProto             = &ordererext.ConsensusType{}
	_ protolator.DynamicMapFieldProto       = &ordererext.DynamicOrdererOrgGroup{}
	_ protolator.DecoratedProto             = &ordererext.DynamicOrdererOrgGroup{}
	_ protolator.StaticallyOpaqueFieldProto = &ordererext.DynamicOrdererConfigValue{}
	_ protolator.DecoratedProto             = &ordererext.DynamicOrdererConfigValue{}
	_ protolator.StaticallyOpaqueFieldProto = &ordererext.DynamicOrdererOrgConfigValue{}
	_ protolator.DecoratedProto             = &ordererext.DynamicOrdererOrgConfigValue{}
)
