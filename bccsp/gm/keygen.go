/*
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
	"crypto/rand"
	"fmt"

	"github.com/paul-lee-attorney/fabric-2.1-gm/bccsp"
	"github.com/paul-lee-attorney/fabric-2.1-gm/bccsp/sw"
	"github.com/paul-lee-attorney/gm/sm2"
)

type sm2KeyGenerator struct {
	curve sm2.P256V1Curve
}

func (kg *sm2KeyGenerator) KeyGen(opts bccsp.KeyGenOpts) (bccsp.Key, error) {

	privKey, err := sm2.GenerateKey(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("Failed generating SM2 key for [%v]: [%s]", kg.curve, err)
	}

	return &sm2PrivateKey{privKey}, nil
}

type sm4KeyGenerator struct {
	length int
}

func (kg *sm4KeyGenerator) KeyGen(opts bccsp.KeyGenOpts) (bccsp.Key, error) {
	lowLevelKey, err := sw.GetRandomBytes(int(kg.length))
	if err != nil {
		return nil, fmt.Errorf("Failed generating AES %d key [%s]", kg.length, err)
	}

	return &sm4PrivateKey{lowLevelKey, false}, nil
}
