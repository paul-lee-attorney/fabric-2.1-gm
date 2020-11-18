/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package rwsetext_test

import (
	"github.com/paul-lee-attorney/fabric-2.1-gm/common/tools/protolator"
	"github.com/paul-lee-attorney/fabric-2.1-gm/common/tools/protolator/protoext/ledger/rwsetext"
)

// ensure structs implement expected interfaces
var (
	_ protolator.DynamicSliceFieldProto     = &rwsetext.TxReadWriteSet{}
	_ protolator.DecoratedProto             = &rwsetext.TxReadWriteSet{}
	_ protolator.StaticallyOpaqueFieldProto = &rwsetext.DynamicNsReadWriteSet{}
	_ protolator.DecoratedProto             = &rwsetext.DynamicNsReadWriteSet{}
	_ protolator.StaticallyOpaqueFieldProto = &rwsetext.DynamicCollectionHashedReadWriteSet{}
	_ protolator.DecoratedProto             = &rwsetext.DynamicCollectionHashedReadWriteSet{}
)
