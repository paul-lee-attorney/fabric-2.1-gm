/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package txvalidator

import (
	"github.com/paul-lee-attorney/fabric-2.1-gm/common/channelconfig"
	"github.com/paul-lee-attorney/fabric-2.1-gm/core/ledger"
)

//go:generate mockery -dir . -name ApplicationCapabilities -case underscore -output mocks

type ApplicationCapabilities interface {
	channelconfig.ApplicationCapabilities
}

//go:generate mockery -dir . -name QueryExecutor -case underscore -output mocks

type QueryExecutor interface {
	ledger.QueryExecutor
}
