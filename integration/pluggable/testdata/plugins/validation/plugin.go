/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package main

import (
	validation "github.com/paul-lee-attorney/fabric-2.1-gm/core/handlers/validation/api"
	"github.com/paul-lee-attorney/fabric-2.1-gm/core/handlers/validation/builtin"
	"github.com/paul-lee-attorney/fabric-2.1-gm/integration/pluggable"
)

// go build -buildmode=plugin -o plugin.so

// NewPluginFactory is the function ran by the plugin infrastructure to create a validation plugin factory.
func NewPluginFactory() validation.PluginFactory {
	pluggable.PublishValidationPluginActivation()
	return &builtin.DefaultValidationFactory{}
}
