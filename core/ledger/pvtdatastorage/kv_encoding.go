/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package pvtdatastorage

import (
	"bytes"
	"encoding/binary"
	"math"

	"github.com/golang/protobuf/proto"
	"github.com/hyperledger/fabric-protos-go/ledger/rwset"
	"github.com/paul-lee-attorney/fabric-2.1-gm/core/ledger/kvledger/txmgmt/version"
	"github.com/pkg/errors"
	"github.com/willf/bitset"
)

var (
	pendingCommitKey               = []byte{0}
	lastCommittedBlkkey            = []byte{1}
	pvtDataKeyPrefix               = []byte{2}
	expiryKeyPrefix                = []byte{3}
	eligibleMissingDataKeyPrefix   = []byte{4}
	ineligibleMissingDataKeyPrefix = []byte{5}
	collElgKeyPrefix               = []byte{6}
	lastUpdatedOldBlocksKey        = []byte{7}

	nilByte    = byte(0)
	emptyValue = []byte{}
)

func getDataKeysForRangeScanByBlockNum(blockNum uint64) (startKey, endKey []byte) {
	startKey = append(pvtDataKeyPrefix, version.NewHeight(blockNum, 0).ToBytes()...)
	endKey = append(pvtDataKeyPrefix, version.NewHeight(blockNum+1, 0).ToBytes()...)
	return
}

func getExpiryKeysForRangeScan(minBlkNum, maxBlkNum uint64) (startKey, endKey []byte) {
	startKey = append(expiryKeyPrefix, version.NewHeight(minBlkNum, 0).ToBytes()...)
	endKey = append(expiryKeyPrefix, version.NewHeight(maxBlkNum+1, 0).ToBytes()...)
	return
}

func encodeLastCommittedBlockVal(blockNum uint64) []byte {
	return proto.EncodeVarint(blockNum)
}

func decodeLastCommittedBlockVal(blockNumBytes []byte) uint64 {
	s, _ := proto.DecodeVarint(blockNumBytes)
	return s
}

func encodeDataKey(key *dataKey) []byte {
	dataKeyBytes := append(pvtDataKeyPrefix, version.NewHeight(key.blkNum, key.txNum).ToBytes()...)
	dataKeyBytes = append(dataKeyBytes, []byte(key.ns)...)
	dataKeyBytes = append(dataKeyBytes, nilByte)
	return append(dataKeyBytes, []byte(key.coll)...)
}

func encodeDataValue(collData *rwset.CollectionPvtReadWriteSet) ([]byte, error) {
	return proto.Marshal(collData)
}

func encodeExpiryKey(expiryKey *expiryKey) []byte {
	// reusing version encoding scheme here
	return append(expiryKeyPrefix, version.NewHeight(expiryKey.expiringBlk, expiryKey.committingBlk).ToBytes()...)
}

func encodeExpiryValue(expiryData *ExpiryData) ([]byte, error) {
	return proto.Marshal(expiryData)
}

func decodeExpiryKey(expiryKeyBytes []byte) (*expiryKey, error) {
	height, _, err := version.NewHeightFromBytes(expiryKeyBytes[1:])
	if err != nil {
		return nil, err
	}
	return &expiryKey{expiringBlk: height.BlockNum, committingBlk: height.TxNum}, nil
}

func decodeExpiryValue(expiryValueBytes []byte) (*ExpiryData, error) {
	expiryData := &ExpiryData{}
	err := proto.Unmarshal(expiryValueBytes, expiryData)
	return expiryData, err
}

func decodeDatakey(datakeyBytes []byte) (*dataKey, error) {
	v, n, err := version.NewHeightFromBytes(datakeyBytes[1:])
	if err != nil {
		return nil, err
	}
	blkNum := v.BlockNum
	tranNum := v.TxNum
	remainingBytes := datakeyBytes[n+1:]
	nilByteIndex := bytes.IndexByte(remainingBytes, nilByte)
	ns := string(remainingBytes[:nilByteIndex])
	coll := string(remainingBytes[nilByteIndex+1:])
	return &dataKey{nsCollBlk{ns, coll, blkNum}, tranNum}, nil
}

func decodeDataValue(datavalueBytes []byte) (*rwset.CollectionPvtReadWriteSet, error) {
	collPvtdata := &rwset.CollectionPvtReadWriteSet{}
	err := proto.Unmarshal(datavalueBytes, collPvtdata)
	return collPvtdata, err
}

func encodeMissingDataKey(key *missingDataKey) []byte {
	if key.isEligible {
		// When missing pvtData reconciler asks for missing data info,
		// it is necessary to pass the missing pvtdata info associated with
		// the most recent block so that missing pvtdata in the state db can
		// be fixed sooner to reduce the "private data matching public hash version
		// is not available" error during endorserments. In order to give priority
		// to missing pvtData in the most recent block, we use reverse order
		// preserving encoding for the missing data key. This simplifies the
		// implementation of GetMissingPvtDataInfoForMostRecentBlocks().
		keyBytes := append(eligibleMissingDataKeyPrefix, encodeReverseOrderVarUint64(key.blkNum)...)
		keyBytes = append(keyBytes, []byte(key.ns)...)
		keyBytes = append(keyBytes, nilByte)
		return append(keyBytes, []byte(key.coll)...)
	}

	keyBytes := append(ineligibleMissingDataKeyPrefix, []byte(key.ns)...)
	keyBytes = append(keyBytes, nilByte)
	keyBytes = append(keyBytes, []byte(key.coll)...)
	keyBytes = append(keyBytes, nilByte)
	return append(keyBytes, []byte(encodeReverseOrderVarUint64(key.blkNum))...)
}

func decodeMissingDataKey(keyBytes []byte) *missingDataKey {
	key := &missingDataKey{nsCollBlk: nsCollBlk{}}
	if keyBytes[0] == eligibleMissingDataKeyPrefix[0] {
		blkNum, numBytesConsumed := decodeReverseOrderVarUint64(keyBytes[1:])

		splittedKey := bytes.Split(keyBytes[numBytesConsumed+1:], []byte{nilByte})
		key.ns = string(splittedKey[0])
		key.coll = string(splittedKey[1])
		key.blkNum = blkNum
		key.isEligible = true
		return key
	}

	splittedKey := bytes.SplitN(keyBytes[1:], []byte{nilByte}, 3) //encoded bytes for blknum may contain empty bytes
	key.ns = string(splittedKey[0])
	key.coll = string(splittedKey[1])
	key.blkNum, _ = decodeReverseOrderVarUint64(splittedKey[2])
	key.isEligible = false
	return key
}

func encodeMissingDataValue(bitmap *bitset.BitSet) ([]byte, error) {
	return bitmap.MarshalBinary()
}

func decodeMissingDataValue(bitmapBytes []byte) (*bitset.BitSet, error) {
	bitmap := &bitset.BitSet{}
	if err := bitmap.UnmarshalBinary(bitmapBytes); err != nil {
		return nil, err
	}
	return bitmap, nil
}

func encodeCollElgKey(blkNum uint64) []byte {
	return append(collElgKeyPrefix, encodeReverseOrderVarUint64(blkNum)...)
}

func decodeCollElgKey(b []byte) uint64 {
	blkNum, _ := decodeReverseOrderVarUint64(b[1:])
	return blkNum
}

func encodeCollElgVal(m *CollElgInfo) ([]byte, error) {
	return proto.Marshal(m)
}

func decodeCollElgVal(b []byte) (*CollElgInfo, error) {
	m := &CollElgInfo{}
	if err := proto.Unmarshal(b, m); err != nil {
		return nil, errors.WithStack(err)
	}
	return m, nil
}

func createRangeScanKeysForEligibleMissingDataEntries(blkNum uint64) (startKey, endKey []byte) {
	startKey = append(eligibleMissingDataKeyPrefix, encodeReverseOrderVarUint64(blkNum)...)
	endKey = append(eligibleMissingDataKeyPrefix, encodeReverseOrderVarUint64(0)...)

	return startKey, endKey
}

func createRangeScanKeysForIneligibleMissingData(maxBlkNum uint64, ns, coll string) (startKey, endKey []byte) {
	startKey = encodeMissingDataKey(
		&missingDataKey{
			nsCollBlk:  nsCollBlk{ns: ns, coll: coll, blkNum: maxBlkNum},
			isEligible: false,
		},
	)
	endKey = encodeMissingDataKey(
		&missingDataKey{
			nsCollBlk:  nsCollBlk{ns: ns, coll: coll, blkNum: 0},
			isEligible: false,
		},
	)
	return
}

func createRangeScanKeysForCollElg() (startKey, endKey []byte) {
	return encodeCollElgKey(math.MaxUint64),
		encodeCollElgKey(0)
}

func datakeyRange(blockNum uint64) (startKey, endKey []byte) {
	startKey = append(pvtDataKeyPrefix, version.NewHeight(blockNum, 0).ToBytes()...)
	endKey = append(pvtDataKeyPrefix, version.NewHeight(blockNum, math.MaxUint64).ToBytes()...)
	return
}

func eligibleMissingdatakeyRange(blkNum uint64) (startKey, endKey []byte) {
	startKey = append(eligibleMissingDataKeyPrefix, encodeReverseOrderVarUint64(blkNum)...)
	endKey = append(eligibleMissingDataKeyPrefix, encodeReverseOrderVarUint64(blkNum-1)...)
	return
}

// encodeReverseOrderVarUint64 returns a byte-representation for a uint64 number such that
// the number is first subtracted from MaxUint64 and then all the leading 0xff bytes
// are trimmed and replaced by the number of such trimmed bytes. This helps in reducing the size.
// In the byte order comparison this encoding ensures that EncodeReverseOrderVarUint64(A) > EncodeReverseOrderVarUint64(B),
// If B > A
func encodeReverseOrderVarUint64(number uint64) []byte {
	bytes := make([]byte, 8)
	binary.BigEndian.PutUint64(bytes, math.MaxUint64-number)
	numFFBytes := 0
	for _, b := range bytes {
		if b != 0xff {
			break
		}
		numFFBytes++
	}
	size := 8 - numFFBytes
	encodedBytes := make([]byte, size+1)
	encodedBytes[0] = proto.EncodeVarint(uint64(numFFBytes))[0]
	copy(encodedBytes[1:], bytes[numFFBytes:])
	return encodedBytes
}

// decodeReverseOrderVarUint64 decodes the number from the bytes obtained from function 'EncodeReverseOrderVarUint64'.
// Also, returns the number of bytes that are consumed in the process
func decodeReverseOrderVarUint64(bytes []byte) (uint64, int) {
	s, _ := proto.DecodeVarint(bytes)
	numFFBytes := int(s)
	decodedBytes := make([]byte, 8)
	realBytesNum := 8 - numFFBytes
	copy(decodedBytes[numFFBytes:], bytes[1:realBytesNum+1])
	numBytesConsumed := realBytesNum + 1
	for i := 0; i < numFFBytes; i++ {
		decodedBytes[i] = 0xff
	}
	return (math.MaxUint64 - binary.BigEndian.Uint64(decodedBytes)), numBytesConsumed
}
