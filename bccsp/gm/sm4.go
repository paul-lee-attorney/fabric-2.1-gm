/*
Copyright IBM Corp. 2016 All Rights Reserved.

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
	"bytes"
	"crypto/cipher"
	"crypto/rand"
	"errors"
	"fmt"
	"io"

	"github.com/paul-lee-attorney/fabric-2.1-gm/bccsp"
	"github.com/paul-lee-attorney/gm/sm4"
)

// sm4 分组长度16字节128位
const sm4BlockSize = 16

// 按pkcs7规则填充尾部字节
func pkcs7Padding(src []byte) []byte {
	padding := sm4BlockSize - len(src)%sm4BlockSize
	padtext := bytes.Repeat([]byte{byte(padding)}, padding)
	return append(src, padtext...)
}

// 按pkcs7规则截去尾部填充字节
func pkcs7UnPadding(src []byte) ([]byte, error) {
	length := len(src)
	unpadding := int(src[length-1])

	if unpadding > sm4BlockSize || unpadding == 0 {
		return nil, errors.New("Invalid pkcs7 padding (unpadding > sm4BlockSize || unpadding == 0)")
	}

	pad := src[len(src)-unpadding:]
	for i := 0; i < unpadding; i++ {
		if pad[i] != byte(unpadding) {
			return nil, errors.New("Invalid pkcs7 padding (pad[i] != unpadding)")
		}
	}

	return src[:(length - unpadding)], nil
}

// CBC模式加密
func sm4CBCEncrypt(key, s []byte) ([]byte, error) {
	return sm4CBCEncryptWithRand(rand.Reader, key, s)
}

// 引入随机数为"初始向量"并以CBC模式加盐加密
func sm4CBCEncryptWithRand(prng io.Reader, key, s []byte) ([]byte, error) {
	if len(s)%sm4BlockSize != 0 {
		return nil, errors.New("Invalid plaintext. It must be a multiple of the block size")
	}

	block, err := sm4.NewCipher(key)
	if err != nil {
		return nil, err
	}

	ciphertext := make([]byte, sm4BlockSize+len(s))
	iv := ciphertext[:sm4BlockSize]
	if _, err := io.ReadFull(prng, iv); err != nil {
		return nil, err
	}

	mode := cipher.NewCBCEncrypter(block, iv)
	mode.CryptBlocks(ciphertext[sm4BlockSize:], s)

	return ciphertext, nil
}

// 以给定的初始向量以CBC模式加盐加密
func sm4CBCEncryptWithIV(IV []byte, key, s []byte) ([]byte, error) {
	if len(s)%sm4BlockSize != 0 {
		return nil, errors.New("Invalid plaintext. It must be a multiple of the block size")
	}

	if len(IV) != sm4BlockSize {
		return nil, errors.New("Invalid IV. It must have length the block size")
	}

	block, err := sm4.NewCipher(key)
	if err != nil {
		return nil, err
	}

	ciphertext := make([]byte, sm4BlockSize+len(s))
	copy(ciphertext[:sm4BlockSize], IV)

	mode := cipher.NewCBCEncrypter(block, IV)
	mode.CryptBlocks(ciphertext[sm4BlockSize:], s)

	return ciphertext, nil
}

// 以输入消息头部信息为初始向量CBC模式加密
func sm4CBCDecrypt(key, src []byte) ([]byte, error) {
	block, err := sm4.NewCipher(key)
	if err != nil {
		return nil, err
	}

	if len(src) < sm4BlockSize {
		return nil, errors.New("Invalid ciphertext. It must be a multiple of the block size")
	}
	iv := src[:sm4BlockSize]
	src = src[sm4BlockSize:]

	if len(src)%sm4BlockSize != 0 {
		return nil, errors.New("Invalid ciphertext. It must be a multiple of the block size")
	}

	mode := cipher.NewCBCDecrypter(block, iv)

	mode.CryptBlocks(src, src)

	return src, nil
}

// SM4CBCPKCS7Encrypt combines CBC encryption and PKCS7 padding
func SM4CBCPKCS7Encrypt(key, src []byte) ([]byte, error) {
	// First pad
	tmp := pkcs7Padding(src)

	// Then encrypt
	return sm4CBCEncrypt(key, tmp)
}

// SM4CBCPKCS7EncryptWithRand combines CBC encryption and PKCS7 padding using as prng the passed to the function
func SM4CBCPKCS7EncryptWithRand(prng io.Reader, key, src []byte) ([]byte, error) {
	// First pad
	tmp := pkcs7Padding(src)

	// Then encrypt
	return sm4CBCEncryptWithRand(prng, key, tmp)
}

// SM4CBCPKCS7EncryptWithIV combines CBC encryption and PKCS7 padding, the IV used is the one passed to the function
func SM4CBCPKCS7EncryptWithIV(IV []byte, key, src []byte) ([]byte, error) {
	// First pad
	tmp := pkcs7Padding(src)

	// Then encrypt
	return sm4CBCEncryptWithIV(IV, key, tmp)
}

// SM4CBCPKCS7Decrypt combines CBC decryption and PKCS7 unpadding
func SM4CBCPKCS7Decrypt(key, src []byte) ([]byte, error) {
	// First decrypt
	pt, err := sm4CBCDecrypt(key, src)
	if err == nil {
		return pkcs7UnPadding(pt)
	}
	return nil, err
}

type sm4cbcpkcs7Encryptor struct{}

func (e *sm4cbcpkcs7Encryptor) Encrypt(k bccsp.Key, plaintext []byte, opts bccsp.EncrypterOpts) ([]byte, error) {
	switch o := opts.(type) {
	case *bccsp.SM4CBCPKCS7ModeOpts:
		// SM4 in CBC mode with PKCS7 padding

		if len(o.IV) != 0 && o.PRNG != nil {
			return nil, errors.New("Invalid options. Either IV or PRNG should be different from nil, or both nil.")
		}

		if len(o.IV) != 0 {
			// Encrypt with the passed IV
			return SM4CBCPKCS7EncryptWithIV(o.IV, k.(*sm4PrivateKey).privKey, plaintext)
		} else if o.PRNG != nil {
			// Encrypt with PRNG
			return SM4CBCPKCS7EncryptWithRand(o.PRNG, k.(*sm4PrivateKey).privKey, plaintext)
		}
		// SM4 in CBC mode with PKCS7 padding
		return SM4CBCPKCS7Encrypt(k.(*sm4PrivateKey).privKey, plaintext)
	case bccsp.SM4CBCPKCS7ModeOpts:
		return e.Encrypt(k, plaintext, &o)
	default:
		return nil, fmt.Errorf("Mode not recognized [%s]", opts)
	}
}

type sm4cbcpkcs7Decryptor struct{}

func (*sm4cbcpkcs7Decryptor) Decrypt(k bccsp.Key, ciphertext []byte, opts bccsp.DecrypterOpts) ([]byte, error) {
	// check for mode
	switch opts.(type) {
	case *bccsp.SM4CBCPKCS7ModeOpts, bccsp.SM4CBCPKCS7ModeOpts:
		// SM4 in CBC mode with PKCS7 padding
		return SM4CBCPKCS7Decrypt(k.(*sm4PrivateKey).privKey, ciphertext)
	default:
		return nil, fmt.Errorf("Mode not recognized [%s]", opts)
	}
}

// getRandomBytes returns len random looking bytes
func getRandomBytes(len int) ([]byte, error) {
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
