/*
Copyright Paul Lee 2020 All Rights Reserved.

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

package bccsp

// 国密商密系列算法选项类别

const (
	// SM2 国密商密第2号, 中国官方采用的一种“椭圆曲线加密算法”。
	// SM2 No.2 National Cryptographic Algorithm for Commercial Purpose of China,
	// which is a special ECDSA adopted by Chinese authority.
	SM2 = "SM2"

	// SM2ReRand SM2 key re-randomization
	SM2ReRand = "SM2_RERAND"

	// SM3 国密商密第3号, 中国官方采用的一种杂凑加密算法。
	// SM3 No.3 National Cryptographic Algorithm for commercial purpose of China,
	// which is a special hash algorithm adopted by Chinese government.
	SM3 = "SM3"

	// SM4 国密商密第4号, 中国官方采用的一种分组密码算法。
	// SM4 No.4 National Encryption Algorithm for Commercial Purpose of China,
	// which is a block cipher algorithm adopted by Chinese government.
	SM4 = "SM4"
)

/************************************
 ****	        SM2                ****
 ************************************
 */

// SM2KeyGenOpts contains options for SM2 key generation.
type SM2KeyGenOpts struct {
	Temporary bool
}

// Algorithm returns the key generation algorithm identifier (to be used).
func (opts *SM2KeyGenOpts) Algorithm() string {
	return SM2
}

// Ephemeral returns true if the key to generate has to be ephemeral,
// false otherwise.
func (opts *SM2KeyGenOpts) Ephemeral() bool {
	return opts.Temporary
}

// SM2PKIXPublicKeyImportOpts contains options for SM2 public key importation in PKIX format
type SM2PKIXPublicKeyImportOpts struct {
	Temporary bool
}

// Algorithm returns the key importation algorithm identifier (to be used).
func (opts *SM2PKIXPublicKeyImportOpts) Algorithm() string {
	return SM2
}

// Ephemeral returns true if the key to generate has to be ephemeral,
// false otherwise.
func (opts *SM2PKIXPublicKeyImportOpts) Ephemeral() bool {
	return opts.Temporary
}

// SM2PrivateKeyImportOpts contains options for SM2 secret key importation.
type SM2PrivateKeyImportOpts struct {
	Temporary bool
}

// Algorithm returns the key importation algorithm identifier (to be used).
func (opts *SM2PrivateKeyImportOpts) Algorithm() string {
	return SM2
}

// Ephemeral returns true if the key to generate has to be ephemeral,
// false otherwise.
func (opts *SM2PrivateKeyImportOpts) Ephemeral() bool {
	return opts.Temporary
}

// SM2GoPublicKeyImportOpts contains options for SM2 key importation from SM2.PublicKey
type SM2GoPublicKeyImportOpts struct {
	Temporary bool
}

// Algorithm returns the key importation algorithm identifier (to be used).
func (opts *SM2GoPublicKeyImportOpts) Algorithm() string {
	return SM2
}

// Ephemeral returns true if the key to generate has to be ephemeral,
// false otherwise.
func (opts *SM2GoPublicKeyImportOpts) Ephemeral() bool {
	return opts.Temporary
}

// SM2ReRandKeyOpts contains options for SM2 key re-randomization.
type SM2ReRandKeyOpts struct {
	Temporary bool
	Expansion []byte
}

// Algorithm returns the key derivation algorithm identifier (to be used).
func (opts *SM2ReRandKeyOpts) Algorithm() string {
	return SM2ReRand
}

// Ephemeral returns true if the key to generate has to be ephemeral,
// false otherwise.
func (opts *SM2ReRandKeyOpts) Ephemeral() bool {
	return opts.Temporary
}

// ExpansionValue returns the re-randomization factor
func (opts *SM2ReRandKeyOpts) ExpansionValue() []byte {
	return opts.Expansion
}

/************************************
 ****	        SM3                ****
 ************************************
 */

// SM3Opts contains options relating to SM3.
type SM3Opts struct {
}

// Algorithm returns the hash algorithm identifier (to be used).
func (opts *SM3Opts) Algorithm() string {
	return SM3
}

/************************************
 ****	        SM4                ****
 ************************************
 */

// SM4KeyGenOpts contains options for SM4 key generation at default security level
type SM4KeyGenOpts struct {
	Temporary bool
}

// Algorithm returns the key generation algorithm identifier (to be used).
func (opts *SM4KeyGenOpts) Algorithm() string {
	return SM4
}

// Ephemeral returns true if the key to generate has to be ephemeral,
// false otherwise.
func (opts *SM4KeyGenOpts) Ephemeral() bool {
	return opts.Temporary
}

// SM4ImportKeyOpts contains options for importing SM4 keys.
type SM4ImportKeyOpts struct {
	Temporary bool
}

// Algorithm returns the key importation algorithm identifier (to be used).
func (opts *SM4ImportKeyOpts) Algorithm() string {
	return SM4
}

// Ephemeral returns true if the key generated has to be ephemeral,
// false otherwise.
func (opts *SM4ImportKeyOpts) Ephemeral() bool {
	return opts.Temporary
}
