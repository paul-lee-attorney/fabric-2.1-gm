/*
Copyright IBM Corp, SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package library

import (
	"github.com/paul-lee-attorney/fabric-2.1-gm/core/handlers/auth"
	"github.com/paul-lee-attorney/fabric-2.1-gm/core/handlers/auth/filter"
	"github.com/paul-lee-attorney/fabric-2.1-gm/core/handlers/decoration"
	"github.com/paul-lee-attorney/fabric-2.1-gm/core/handlers/decoration/decorator"
	endorsement "github.com/paul-lee-attorney/fabric-2.1-gm/core/handlers/endorsement/api"
	"github.com/paul-lee-attorney/fabric-2.1-gm/core/handlers/endorsement/builtin"
	validation "github.com/paul-lee-attorney/fabric-2.1-gm/core/handlers/validation/api"
	. "github.com/paul-lee-attorney/fabric-2.1-gm/core/handlers/validation/builtin"
)

// HandlerLibrary is used to assert
// how to create the various handlers
type HandlerLibrary struct {
}

// DefaultAuth creates a default auth.Filter
// that doesn't do any access control checks - simply
// forwards the request further.
// It needs to be initialized via a call to Init()
// and be passed a peer.EndorserServer
func (r *HandlerLibrary) DefaultAuth() auth.Filter {
	return filter.NewFilter()
}

// ExpirationCheck is an auth filter which blocks requests
// from identities with expired x509 certificates
func (r *HandlerLibrary) ExpirationCheck() auth.Filter {
	return filter.NewExpirationCheckFilter()
}

// DefaultDecorator creates a default decorator
// that doesn't do anything with the input, simply
// returns the input as output.
func (r *HandlerLibrary) DefaultDecorator() decoration.Decorator {
	return decorator.NewDecorator()
}

func (r *HandlerLibrary) DefaultEndorsement() endorsement.PluginFactory {
	return &builtin.DefaultEndorsementFactory{}
}

func (r *HandlerLibrary) DefaultValidation() validation.PluginFactory {
	return &DefaultValidationFactory{}
}
