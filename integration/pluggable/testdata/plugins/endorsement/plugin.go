/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package main

import (
	endorsement "github.com/paul-lee-attorney/fabric-2.1-gm/core/handlers/endorsement/api"
	"github.com/paul-lee-attorney/fabric-2.1-gm/core/handlers/endorsement/builtin"
	"github.com/paul-lee-attorney/fabric-2.1-gm/integration/pluggable"
)

// go build -buildmode=plugin -o plugin.so

// NewPluginFactory is the function ran by the plugin infrastructure to create an endorsement plugin factory.
func NewPluginFactory() endorsement.PluginFactory {
	pluggable.PublishEndorsementPluginActivation()
	return &builtin.DefaultEndorsementFactory{}
}
