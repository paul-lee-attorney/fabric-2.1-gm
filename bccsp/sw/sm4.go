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
	"crypto/rand"
	"errors"
	"fmt"

	"github.com/tjfoc/gmsm/sm4"
	"github.com/tjfoc/hyperledger-fabric-gm/bccsp"
)

// GetRandomBytes returns len random looking bytes
func GetRandomBytes(len int) ([]byte, error) {
	if len < 0 {
		return nil, errors.New("Len must be larger than 0")
	}

	buffer := make([]byte, len)

	n, err := rand.Read(buffer)
	if err != nil {
		return nil, err
	}
	if n != len {
		return nil, fmt.Errorf("Buffer not filled. Requested [%d], got [%d]", len, n)
	}

	return buffer, nil
}

// SM4Encrypt encrypt the srouce message into cypher message of the same length
func SM4Encrypt(key, src []byte) ([]byte, error) {
	dst := make([]byte, len(src))
	sm4.EncryptBlock(key, dst, src)
	return dst, nil
}

// SM4Decrypt decrypt the cypher message into plain text with the private key
func SM4Decrypt(key, src []byte) ([]byte, error) {
	dst := make([]byte, len(src))
	sm4.DecryptBlock(key, dst, src)
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
