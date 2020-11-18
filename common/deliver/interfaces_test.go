/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package deliver_test

import (
	"github.com/paul-lee-attorney/fabric-2.1-gm/common/ledger/blockledger"
)

//go:generate counterfeiter -o mock/block_reader.go -fake-name BlockReader . blockledgerReader
type blockledgerReader interface {
	blockledger.Reader
}

//go:generate counterfeiter -o mock/block_iterator.go -fake-name BlockIterator . blockledgerIterator
type blockledgerIterator interface {
	blockledger.Iterator
}
