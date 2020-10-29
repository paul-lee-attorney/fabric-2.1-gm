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
	"github.com/paul-lee-attorney/fabric-2.1-gm/bccsp"
	"github.com/paul-lee-attorney/gm/sm2"
)

// signSM2 为基于SM2私钥生成数字签名的函数。其中:
// opts 参数为go标准库中的哈希算法代码，在本函数中没有实际使用。
func signSM2(k *sm2.PrivateKey, digest []byte, opts bccsp.SignerOpts) (signature []byte, err error) {
	// sm2.Sign() 第2个输入参数为userID，若为nil则导入SM2的默认用户识别码
	// 返回为符合ASN.1标准的DER编码字节数组
	signature, err = sm2.Sign(k, nil, digest)
	return
}

// verifySM2 为SM2算法验签函数。其中：
// opts 在go标准库中代表哈希算法代码，在本函数中没有使用。
func verifySM2(k *sm2.PublicKey, signature, digest []byte, opts bccsp.SignerOpts) (valid bool, err error) {
	// sm2.Sign() 第2个输入参数为userID，若为nil则导入SM2的默认用户识别码。
	// 返回为数字签名校验结果。验签失败，valid值为false, 不会返回错误。
	valid = sm2.Verify(k, nil, digest, signature)
	return valid, nil
}

type sm2Signer struct{}

func (s *sm2Signer) Sign(k bccsp.Key, digest []byte, opts bccsp.SignerOpts) (signature []byte, err error) {
	return signSM2(k.(*sm2PrivateKey).privKey, digest, opts)
}

type sm2PrivateKeyVerifier struct{}

func (v *sm2PrivateKeyVerifier) Verify(k bccsp.Key, signature, digest []byte, opts bccsp.SignerOpts) (valid bool, err error) {
	return verifySM2(k.(*sm2PrivateKey).PublicKey, signature, digest, opts)
}

type sm2PublicKeyKeyVerifier struct{}

func (v *sm2PublicKeyKeyVerifier) Verify(k bccsp.Key, signature, digest []byte, opts bccsp.SignerOpts) (valid bool, err error) {
	return verifySM2(k.(*sm2PublicKey).pubKey, signature, digest, opts)
}
