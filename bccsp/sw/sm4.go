/*
Copyright Suzhou Tongji Fintech Research Institute 2017 All Rights Reserved.

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

package sw

import (
	"errors"

	"github.com/paul-lee-attorney/fabric-2.1-gm/bccsp"
	"github.com/paul-lee-attorney/gm/sm4"
)

// SM4Encrypt encrypt the srouce message into cypher message of the same length
func SM4Encrypt(key, src []byte) ([]byte, error) {
	dst := make([]byte, len(src))
	c, err := sm4.NewCipher(key)
	if err != nil {
		return nil, errors.New("Error incurred upon new cipher stage")
	}
	c.Encrypt(dst, src)
	return dst, nil
}

// SM4Decrypt decrypt the cypher message into plain text with the private key
func SM4Decrypt(key, src []byte) ([]byte, error) {
	dst := make([]byte, len(src))
	c, err := sm4.NewCipher(key)
	if err != nil {
		return nil, errors.New("Error incurred upon new cipher stage")
	}
	c.Decrypt(dst, src)
	return dst, nil
}

type sm4Encryptor struct{}

// Implement method of Encrypt for the interface of Encryptor
func (*sm4Encryptor) Encrypt(k bccsp.Key, plaintext []byte, opts bccsp.EncrypterOpts) (ciphertext []byte, err error) {
	return SM4Encrypt(k.(*sm4PrivateKey).privKey, plaintext)
}

type sm4Decryptor struct{}

// Implement method of Decrypt for the interface of Decryptor
func (*sm4Decryptor) Decrypt(k bccsp.Key, ciphertext []byte, opts bccsp.DecrypterOpts) (plaintext []byte, err error) {
	return SM4Decrypt(k.(*sm4PrivateKey).privKey, ciphertext)
}
