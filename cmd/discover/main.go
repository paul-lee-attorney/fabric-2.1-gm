/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package main

import (
	"os"

	"github.com/paul-lee-attorney/fabric-2.1-gm/bccsp/factory"
	"github.com/paul-lee-attorney/fabric-2.1-gm/cmd/common"
	discovery "github.com/paul-lee-attorney/fabric-2.1-gm/discovery/cmd"
)

func main() {
	factory.InitFactories(nil)
	cli := common.NewCLI("discover", "Command line client for fabric discovery service")
	discovery.AddCommands(cli)
	cli.Run(os.Args[1:])
}
