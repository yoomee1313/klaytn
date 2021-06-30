// Copyright 2019 The klaytn Authors
// This file is part of the klaytn library.
//
// The klaytn library is free software: you can redistribute it and/or modify
// it under the terms of the GNU Lesser General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// The klaytn library is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU Lesser General Public License for more details.
//
// You should have received a copy of the GNU Lesser General Public License
// along with the klaytn library. If not, see <http://www.gnu.org/licenses/>.

package accountkey

import (
	"crypto/ecdsa"
	"encoding/json"
	"testing"

	"github.com/klaytn/klaytn/common"
	"github.com/klaytn/klaytn/crypto"
	"github.com/klaytn/klaytn/params"
	"github.com/klaytn/klaytn/rlp"
	"github.com/stretchr/testify/assert"
)

func TestAccountKeySerialization(t *testing.T) {
	var keys = []struct {
		Name string
		k    AccountKey
	}{
		{"Nil", genAccountKeyNil()},
		{"Legacy", genAccountKeyLegacy()},
		{"Public", genAccountKeyPublic()},
		{"Fail", genAccountKeyFail()},
		{"WeightedMultisig", genAccountKeyWeightedMultisig()},
		{"RoleBased", genAccountKeyRoleBased()},
	}

	var testcases = []struct {
		Name string
		fn   func(t *testing.T, k AccountKey)
	}{
		{"RLP", testAccountKeyRLP},
		{"JSON", testAccountKeyJSON},
	}
	for _, test := range testcases {
		for _, key := range keys {
			Name := test.Name + "/" + key.Name
			t.Run(Name, func(t *testing.T) {
				test.fn(t, key.k)
			})
		}
	}
}

func testAccountKeyRLP(t *testing.T, k AccountKey) {
	enc := NewAccountKeySerializerWithAccountKey(k)

	b, err := rlp.EncodeToBytes(enc)
	if err != nil {
		t.Fatal(err)
	}

	dec := NewAccountKeySerializer()

	if err := rlp.DecodeBytes(b, &dec); err != nil {
		t.Fatal(err)
	}

	switch k.Type() {
	case AccountKeyTypeFail:
		if k.Equal(dec.key) {
			t.Errorf("AlwaysFail key returns true! k != dec.key\nk=%v\ndec.key=%v", k, dec.key)
		}
	default:
		if !k.Equal(dec.key) {
			t.Errorf("AlwaysFail key returns true! k != dec.key\nk=%v\ndec.key=%v", k, dec.key)
		}
	}
}

func testAccountKeyJSON(t *testing.T, k AccountKey) {
	enc := NewAccountKeySerializerWithAccountKey(k)

	b, err := json.Marshal(enc)
	if err != nil {
		t.Fatal(err)
	}

	dec := NewAccountKeySerializer()

	if err := json.Unmarshal(b, &dec); err != nil {
		t.Fatal(err)
	}

	switch k.Type() {
	case AccountKeyTypeFail:
		if k.Equal(dec.key) {
			t.Errorf("AlwaysFail key returns true! k != dec.key\nk=%v\ndec.key=%v", k, dec.key)
		}
	default:
		if !k.Equal(dec.key) {
			t.Errorf("AlwaysFail key returns true! k != dec.key\nk=%v\ndec.key=%v", k, dec.key)
		}
	}
}

func genAccountKeyNil() AccountKey {
	return NewAccountKeyNil()
}

func genAccountKeyLegacy() AccountKey {
	return NewAccountKeyLegacy()
}

func genAccountKeyPublic() AccountKey {
	k, _ := crypto.GenerateKey()
	return NewAccountKeyPublicWithValue(&k.PublicKey)
}

func genAccountKeyFail() AccountKey {
	return NewAccountKeyFail()
}

func genAccountKeyWeightedMultisig() AccountKey {
	threshold := uint(3)
	numKeys := 4
	keys := make(WeightedPublicKeys, numKeys)

	for i := 0; i < numKeys; i++ {
		k, _ := crypto.GenerateKey()
		keys[i] = NewWeightedPublicKey(1, (*PublicKeySerializable)(&k.PublicKey))
	}

	return NewAccountKeyWeightedMultiSigWithValues(threshold, keys)
}

func genAccountKeyRoleBased() AccountKey {
	k1, err := crypto.HexToECDSA("98275a145bc1726eb0445433088f5f882f8a4a9499135239cfb4040e78991dab")
	if err != nil {
		panic(err)
	}
	txKey := NewAccountKeyPublicWithValue(&k1.PublicKey)

	k2, err := crypto.HexToECDSA("c64f2cd1196e2a1791365b00c4bc07ab8f047b73152e4617c6ed06ac221a4b0c")
	if err != nil {
		panic(err)
	}
	threshold := uint(2)
	keys := WeightedPublicKeys{
		NewWeightedPublicKey(1, (*PublicKeySerializable)(&k1.PublicKey)),
		NewWeightedPublicKey(1, (*PublicKeySerializable)(&k2.PublicKey)),
	}
	updateKey := NewAccountKeyWeightedMultiSigWithValues(threshold, keys)

	k3, err := crypto.HexToECDSA("ed580f5bd71a2ee4dae5cb43e331b7d0318596e561e6add7844271ed94156b20")
	if err != nil {
		panic(err)
	}
	feeKey := NewAccountKeyPublicWithValue(&k3.PublicKey)

	return NewAccountKeyRoleBasedWithValues(AccountKeyRoleBased{txKey, updateKey, feeKey})
}

func TestAccountKeyWeightedMultiSig_Validate(t *testing.T) {
	// generate multiSigAccount. weights: [1,1,1,1,1,1,1,1,1,1], threshold: 3
	keys := make(WeightedPublicKeys, 6)
	for i := 0; i < 6; i++ {
		k, _ := crypto.GenerateKey()
		keys[i] = NewWeightedPublicKey(1, (*PublicKeySerializable)(&k.PublicKey))
	}
	m := NewAccountKeyWeightedMultiSigWithValues(uint(3), keys)

	// generate test data
	testData := []struct {
		recoveredKeys []*ecdsa.PublicKey
		beforeIsValid bool // expectIsValid before istanbul compatible change
		afterIsValid  bool // expectIsValid values after istanbul compatible change
	}{
		// 1. after istanbul compatible change, validation failed because sigNum exceeds keyNum
		{append(getValidKeys(m, 6), getAnonymousPubKeys(2)...), true, false},
		{append(getValidKeys(m, 6), getAnonymousPubKeys(4)...), true, false},
		{append(getValidKeys(m, 6), getValidKeys(m, 2)...), true, false},
		{append(getValidKeys(m, 6), getValidKeys(m, 4)...), true, false},
		{append(getValidKeys(m, 2), getValidKeys(m, 6)...), true, false},
		{append(getValidKeys(m, 1), getValidKeys(m, 6)...), true, false},
		// 2. after istanbul compatible change, validation failed because invalidSig is included
		{append(getValidKeys(m, 3), getAnonymousPubKeys(1)...), true, false},
		{append(getValidKeys(m, 3), append(getValidKeys(m, 2), getAnonymousPubKeys(1)...)...), true, false},
		{append(getValidKeys(m, 5), getAnonymousPubKeys(1)...), true, false},
		// 3. validation failed because couldn't reach to the threshold
		{getValidKeys(m, 1), false, false},
		{getValidKeys(m, 2), false, false},
		// 4. result is same between before and after istanbul compatible change
		{getValidKeys(m, 3), true, true},
		{getValidKeys(m, 4), true, true},
		{getValidKeys(m, 6), true, true},
	}

	// do test
	for i, tc := range testData {
		isValid, _ := m.Validate(0, tc.recoveredKeys, common.Address{}, false)
		assert.Equal(t, tc.beforeIsValid, isValid, "test", i)

		isValid, _ = m.Validate(0, tc.recoveredKeys, common.Address{}, true)
		assert.Equal(t, tc.afterIsValid, isValid, "test", i)
	}
}

func TestAccountKeyWeightedMultiSig_SigValidationGas(t *testing.T) {
	// generate multiSigAccount
	keys := make(WeightedPublicKeys, 10)
	for i := 0; i < 10; i++ {
		k, _ := crypto.GenerateKey()
		keys[i] = NewWeightedPublicKey(1, (*PublicKeySerializable)(&k.PublicKey))
	}
	m := NewAccountKeyWeightedMultiSigWithValues(uint(3), keys)

	// generate test data
	testData := []struct {
		recoveredKeys []*ecdsa.PublicKey
		beforeGas     int // expectGas before istanbul compatible change
		afterGas      int // expectGas after istanbul compatible change
	}{
		// 1. Without duplication
		{getValidKeys(m, 3), 10, 3},
		{getValidKeys(m, 4), 10, 4},
		{getValidKeys(m, 10), 10, 10},
		// 2. With duplication
		{append(getValidKeys(m, 3), getValidKeys(m, 1)...), 10, 3},
		{append(getValidKeys(m, 3), getValidKeys(m, 3)...), 10, 3},
		{append(getValidKeys(m, 6), getValidKeys(m, 2)...), 10, 6},
	}

	// do test
	for _, tc := range testData {
		isValid, validSigNum := m.Validate(0, tc.recoveredKeys, common.Address{}, false)
		assert.Equal(t, true, isValid)
		gas, err := m.SigValidationGas(0, 0, validSigNum, false)
		assert.NoError(t, err)
		assert.Equal(t, uint64(tc.beforeGas-1)*params.TxValidationGasPerKey, gas)

		isValid, validSigNum = m.Validate(0, tc.recoveredKeys, common.Address{}, true)
		assert.Equal(t, true, isValid)
		gas, err = m.SigValidationGas(0, 0, validSigNum, true)
		assert.NoError(t, err)
		assert.Equal(t, uint64(tc.afterGas-1)*params.TxValidationGasPerKey, gas)
	}
}

// getAnonymousKeys returns 'num' number of anonymousKeys which are not belongs to the multiSigAccount
func getAnonymousPubKeys(num int) []*ecdsa.PublicKey {
	var pubKeys []*ecdsa.PublicKey
	for i := 0; i < num; i++ {
		k, _ := crypto.GenerateKey()
		pubKeys = append(pubKeys, &k.PublicKey)
	}
	return pubKeys
}

// getValidKeys returns multiSigAccount[0:num] keys
func getValidKeys(multiSigAccount AccountKey, num int) []*ecdsa.PublicKey {
	var pubKeys []*ecdsa.PublicKey
	for i := 0; i < num; i++ {
		key := multiSigAccount.(*AccountKeyWeightedMultiSig).Keys[i].Key
		pubKeys = append(pubKeys, &ecdsa.PublicKey{Curve: key.Curve, X: key.X, Y: key.Y})
	}
	return pubKeys
}
