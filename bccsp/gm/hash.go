/*
Copyright IBM Corp. 2017 All Rights Reserved.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

		 http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package gm

import (
	"errors"
	"hash"

	"github.com/paul-lee-attorney/fabric-2.1-gm/bccsp"
	"github.com/paul-lee-attorney/gm/sm3"
)

type hasher struct{}

func (c *hasher) Hash(msg []byte, opts bccsp.HashOpts) ([]byte, error) {

	if len(msg) == 0 || msg == nil {
		return nil, errors.New("input message shall not be nil")
	}

	h := sm3.New()
	h.Write(msg)
	return h.Sum(nil), nil
}

func (c *hasher) GetHash(opts bccsp.HashOpts) (hash.Hash, error) {
	return sm3.New(), nil
}
