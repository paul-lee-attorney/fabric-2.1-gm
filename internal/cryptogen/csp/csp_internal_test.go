/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/
package csp

// func TestToLowS(t *testing.T) {
// 	curve := elliptic.P256()
// 	halfOrder := new(big.Int).Div(curve.Params().N, big.NewInt(2))

// 	for _, test := range []struct {
// 		name        string
// 		sig         SM2Signature
// 		expectedSig SM2Signature
// 	}{
// 		{
// 			name: "HighS",
// 			sig: SM2Signature{
// 				R: big.NewInt(1),
// 				// set S to halfOrder + 1
// 				S: new(big.Int).Add(halfOrder, big.NewInt(1)),
// 			},
// 			// expected signature should be (sig.R, -sig.S mod N)
// 			expectedSig: SM2Signature{
// 				R: big.NewInt(1),
// 				S: new(big.Int).Mod(new(big.Int).Neg(new(big.Int).Add(halfOrder, big.NewInt(1))), curve.Params().N),
// 			},
// 		},
// 		{
// 			name: "LowS",
// 			sig: SM2Signature{
// 				R: big.NewInt(1),
// 				// set S to halfOrder - 1
// 				S: new(big.Int).Sub(halfOrder, big.NewInt(1)),
// 			},
// 			// expected signature should be sig
// 			expectedSig: SM2Signature{
// 				R: big.NewInt(1),
// 				S: new(big.Int).Sub(halfOrder, big.NewInt(1)),
// 			},
// 		},
// 		{
// 			name: "HalfOrder",
// 			sig: SM2Signature{
// 				R: big.NewInt(1),
// 				// set S to halfOrder
// 				S: halfOrder,
// 			},
// 			// expected signature should be sig
// 			expectedSig: SM2Signature{
// 				R: big.NewInt(1),
// 				S: halfOrder,
// 			},
// 		},
// 	} {
// 		t.Run(test.name, func(t *testing.T) {
// 			curve := elliptic.P256()
// 			key := ecdsa.PublicKey{
// 				Curve: curve,
// 			}
// 			assert.Equal(t, test.expectedSig, toLowS(key, test.sig))
// 		})
// 	}
// }
