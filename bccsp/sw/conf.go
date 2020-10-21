/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package sw

import (
	"crypto/elliptic"
	"crypto/sha256"
	"crypto/sha512"
	"fmt"
	"hash"

	"github.com/paul-lee-attorney/gm/sm2"
	"github.com/paul-lee-attorney/gm/sm3"
	"golang.org/x/crypto/sha3"
)

type config struct {
	ellipticCurve elliptic.Curve   // 椭圆曲线配置
	hashFunction  func() hash.Hash // 哈希函数配置
	aesBitLength  int              // AES随机秘钥的字节长度， SM4直接在new.go中赋值(16字节)
}

// setSecurityLevel 为设置安全等级的方法。
func (conf *config) setSecurityLevel(securityLevel int, hashFamily string) (err error) {
	switch hashFamily {
	case "SHA2":
		err = conf.setSecurityLevelSHA2(securityLevel)
	case "SHA3":
		err = conf.setSecurityLevelSHA3(securityLevel)
	case "SM3":
		err = conf.setSecurityLevelSM3(securityLevel) // SM3 security level setting
	default:
		err = fmt.Errorf("Hash Family not supported [%s]", hashFamily)
	}
	return
}

func (conf *config) setSecurityLevelSHA2(level int) (err error) {
	switch level {
	case 256:
		conf.ellipticCurve = elliptic.P256()
		conf.hashFunction = sha256.New
		conf.aesBitLength = 32
	case 384:
		conf.ellipticCurve = elliptic.P384()
		conf.hashFunction = sha512.New384
		conf.aesBitLength = 32
	default:
		err = fmt.Errorf("Security level not supported [%d]", level)
	}
	return
}

func (conf *config) setSecurityLevelSHA3(level int) (err error) {
	switch level {
	case 256:
		conf.ellipticCurve = elliptic.P256()
		conf.hashFunction = sha3.New256
		conf.aesBitLength = 32
	case 384:
		conf.ellipticCurve = elliptic.P384()
		conf.hashFunction = sha3.New384
		conf.aesBitLength = 32
	default:
		err = fmt.Errorf("Security level not supported [%d]", level)
	}
	return
}

// SM3 security level setting
func (conf *config) setSecurityLevelSM3(level int) (err error) {
	if level == 256 {
		conf.ellipticCurve = sm2.GetSm2P256V1() //将SM2推荐椭圆曲线实例赋值给配置
		conf.hashFunction = sm3.New             // 将SM3哈希摘要实例初始化函数赋值给配置
		conf.aesBitLength = 16                  // SM4为128位秘钥，即16字节
	} else {
		err = fmt.Errorf("Security level not supported [%d]", level)
	}
	return
}
