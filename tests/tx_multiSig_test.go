package tests

import (
	"crypto/ecdsa"
	"fmt"
	"math/big"
	"math/rand"
	"testing"

	"github.com/klaytn/klaytn/blockchain/types"
	"github.com/klaytn/klaytn/common"
	"github.com/klaytn/klaytn/common/profile"
	"github.com/klaytn/klaytn/crypto"
	"github.com/klaytn/klaytn/params"

	"github.com/stretchr/testify/assert"
)

type testFunction func(int, *TestAccountType, *TestAccountType, *TestAccountType, *BCData)

// TestMultiSigGasCost checks the multiSig transaction gas cost.
func TestMultiSigGasCost(t *testing.T) {
	multiSigTest(t, func(keyNum int, multiSigAccount, contractAddr, payer *TestAccountType, bcData *BCData) {
		// Run valueTransfer transaction
		for sigNum := 1; sigNum <= keyNum; sigNum++ {
			expectGas := 21000 + (uint64(sigNum)-1)*params.TxValidationGasPerKey
			customPrvKeys := multiSigAccount.GetTxKeys()[0:sigNum]

			receipt, _, err := applyTransaction(t, bcData, genTxWithCustomSig(t, multiSigAccount, &TestAccountType{Addr: to}, nil, customPrvKeys, bcData, genValueTransfer))
			assert.Equal(t, nil, err)
			assert.Equal(t, expectGas, receipt.GasUsed)
			t.Log(fmt.Sprintf("valueTransfer tx(%d key, %d validSig): (usedGas %d, expectGas %d).. test passed", keyNum, sigNum, receipt.GasUsed, expectGas))
		}

		// Run feeDelegatedSmartContractExecution transaction
		for sigNum := 1; sigNum <= keyNum; sigNum++ {
			expectGas := 76444 + (uint64(sigNum)-1)*params.TxValidationGasPerKey
			customPrvKeys := multiSigAccount.GetTxKeys()[0:sigNum]

			receipt, _, err := applyTransaction(t, bcData, genTxWithCustomSig(t, multiSigAccount, contractAddr, payer, customPrvKeys, bcData, genFeeDelegatedSmartContractExecution))
			assert.Equal(t, nil, err)
			assert.Equal(t, expectGas, receipt.GasUsed)
			t.Log(fmt.Sprintf("feeDelegatedSCExecution tx(%d key, %d validSig): (usedGas %d, expectGas %d).. test passed", keyNum, sigNum, receipt.GasUsed, expectGas))
		}
	})
}

// TestSigNumValidation tests one of the validation logic of the multiSig tx
// validation logic: multiSig tx which has more signatures than key number is invalid
func TestSigNumValidation(t *testing.T) {
	multiSigTest(t, func(keyNum int, multiSigAccount, contractAddr, payer *TestAccountType, bcData *BCData) {
		// pass the test when key number is 10
		if keyNum == 10 {
			return
		}

		// Run valueTransfer transaction
		for sigNum := 1; sigNum <= 10-keyNum; sigNum++ {
			customPrvKeys := append(multiSigAccount.GetTxKeys()[0:keyNum], multiSigAccount.GetTxKeys()[0:sigNum]...)

			_, _, err := applyTransaction(t, bcData, genTxWithCustomSig(t, multiSigAccount, &TestAccountType{Addr: to}, nil, customPrvKeys, bcData, genValueTransfer))
			assert.Equal(t, types.ErrInvalidSigSender, err)
			t.Log(fmt.Sprintf("valueTransfer tx(%d key, %d validSig): InvalidSigSender error returned.. test passed", keyNum, len(customPrvKeys)))
		}
		// Run feeDelegatedSmartContractExecution transaction
		for sigNum := 1; sigNum <= 10-keyNum; sigNum++ {
			customPrvKeys := append(multiSigAccount.GetTxKeys()[0:keyNum], multiSigAccount.GetTxKeys()[0:sigNum]...)

			_, _, err := applyTransaction(t, bcData, genTxWithCustomSig(t, multiSigAccount, contractAddr, payer, customPrvKeys, bcData, genFeeDelegatedSmartContractExecution))
			assert.Equal(t, types.ErrInvalidSigSender, err)
			t.Log(fmt.Sprintf("feeDelegatedSCExecution tx(%d key, %d validSig): InvalidSigSender error returned.. test passed", keyNum, len(customPrvKeys)))
		}
	})
}

// TestInvalidSigValidation tests one of the validation logic of the multiSig tx
// validation logic: multiSig tx which has one or more invalid signatures is invalid
func TestInvalidSigValidation(t *testing.T) {
	multiSigTest(t, func(keyNum int, multiSigAccount, contractAddr, payer *TestAccountType, bcData *BCData) {
		// pass the test when key number is 1 or 10
		if keyNum == 1 || keyNum == 10 {
			return
		}

		// generateInvalidSig generates randomly generated keys which will be invalid keys for a multiSigAccount
		generateInvalidKey := func(num int) []*ecdsa.PrivateKey {
			var invalidSigs []*ecdsa.PrivateKey
			for i := 0; i < num; i++ {
				key, _ := crypto.GenerateKey()
				invalidSigs = append(invalidSigs, key)
			}
			return invalidSigs
		}

		// Run valueTransfer transaction
		for invalidSigNum := 1; invalidSigNum <= keyNum; invalidSigNum++ {
			customPrvKeys := append(generateInvalidKey(invalidSigNum), multiSigAccount.GetTxKeys()[rand.Intn(keyNum)])

			_, _, err := applyTransaction(t, bcData, genTxWithCustomSig(t, multiSigAccount, &TestAccountType{Addr: to}, nil, customPrvKeys, bcData, genValueTransfer))
			assert.Equal(t, types.ErrInvalidSigSender, err)
			t.Log(fmt.Sprintf("valueTransfer tx(%d key, %d validSig, %d invalidSig): InvalidSigSender error returned.. test passed",
				keyNum, len(customPrvKeys)-invalidSigNum, invalidSigNum))
		}

		// Run feeDelegatedSmartContractExecution transaction
		for invalidSigNum := 1; invalidSigNum <= keyNum; invalidSigNum++ {
			customPrvKeys := append(generateInvalidKey(invalidSigNum), multiSigAccount.GetTxKeys()[rand.Intn(keyNum)])

			_, _, err := applyTransaction(t, bcData, genTxWithCustomSig(t, multiSigAccount, contractAddr, payer, customPrvKeys, bcData, genFeeDelegatedSmartContractExecution))
			assert.Equal(t, types.ErrInvalidSigSender, err)
			t.Log(fmt.Sprintf("feeDelegatedSCExecution tx(%d key, %d validSig, %d invalidSig): InvalidSigSender error returned.. test passed",
				keyNum, len(customPrvKeys)-invalidSigNum, invalidSigNum))
		}
	})
}

// transaction generation functions
func genValueTransferTxWithAmount(t *testing.T, amount *big.Int, from, to *TestAccountType, bcData *BCData) *types.Transaction {
	// set signer and gasPrice
	signer := types.NewEIP155Signer(bcData.bc.Config().ChainID)
	gasPrice := new(big.Int).SetUint64(bcData.bc.Config().UnitPrice)

	values := map[types.TxValueKeyType]interface{}{
		types.TxValueKeyNonce:    from.GetNonce(),
		types.TxValueKeyFrom:     from.GetAddr(),
		types.TxValueKeyTo:       to.GetAddr(),
		types.TxValueKeyAmount:   new(big.Int).Mul(amount, new(big.Int).SetUint64(params.KLAY)),
		types.TxValueKeyGasLimit: gasLimit,
		types.TxValueKeyGasPrice: gasPrice,
	}
	tx, err := types.NewTransactionWithMap(types.TxTypeValueTransfer, values)
	assert.Equal(t, nil, err)

	err = tx.SignWithKeys(signer, from.GetTxKeys())
	assert.Equal(t, nil, err)

	return tx
}

func genAccountUpdateTx(t *testing.T, from *TestAccountType, bcData *BCData) *types.Transaction {
	// set signer and gasPrice
	signer := types.NewEIP155Signer(bcData.bc.Config().ChainID)
	gasPrice := new(big.Int).SetUint64(bcData.bc.Config().UnitPrice)

	values := map[types.TxValueKeyType]interface{}{
		types.TxValueKeyNonce:      from.GetNonce(),
		types.TxValueKeyFrom:       from.GetAddr(),
		types.TxValueKeyGasLimit:   gasLimit,
		types.TxValueKeyGasPrice:   gasPrice,
		types.TxValueKeyAccountKey: from.GetAccKey(),
	}

	tx, err := types.NewTransactionWithMap(types.TxTypeAccountUpdate, values)
	assert.Equal(t, nil, err)

	err = tx.SignWithKeys(signer, from.GetTxKeys())
	assert.Equal(t, nil, err)

	return tx
}

func genTxWithCustomSig(t *testing.T, from, to, payer *TestAccountType, customPrvKeys []*ecdsa.PrivateKey, bcData *BCData, genTxFunc genTransaction) *types.Transaction {
	signer := types.NewEIP155Signer(bcData.bc.Config().ChainID)
	gasPrice := new(big.Int).SetUint64(bcData.bc.Config().UnitPrice)

	// backup multiSigAccount's keys
	originMultiSigKey := from.Keys

	// generate transaction with custom keys
	from.Keys = customPrvKeys
	tx, _ := genTxFunc(t, signer, from, to, payer, gasPrice)

	// restore multiSigAccount's keys
	from.Keys = originMultiSigKey

	return tx
}

func multiSigTest(t *testing.T, testF testFunction) {
	var (
		feePayerAccount  *TestAccountType   // feePayerAccount is used in feePayerSmartContractExecution transaction test as a feePayer
		multiSigAccounts []*TestAccountType // multiSigAccounts are used in valueTransfer and feePayerSmartContactExecution transaction test as a sender
		reservoirAccount *TestAccountType   // reservoirAccount is not used in test, instead it gives klays to feePayerAccount and multiSigAccount
		txs              types.Transactions
		prof             = profile.NewProfiler()
	)

	// 1.1. initialize blockchain
	bcData, err := NewBCData(10, 4, istanbulCompatibleBlock(big.NewInt(0)))
	defer bcData.Shutdown()
	assert.Equal(t, nil, err)

	// 1.2. set accountMap
	accountMap := NewAccountMap()
	assert.Equal(t, nil, accountMap.Initialize(bcData))

	// 1.3. set reservoirAccount
	reservoirAccount = &TestAccountType{
		Addr:  *bcData.addrs[1],
		Keys:  []*ecdsa.PrivateKey{bcData.privKeys[1]},
		Nonce: uint64(0),
	}

	// 1.4. Set signer, gasPrice
	signer := types.NewEIP155Signer(bcData.bc.Config().ChainID)
	gasPrice := new(big.Int).SetUint64(bcData.bc.Config().UnitPrice)

	// 2.1. generate feePayerAccount and multiSigAccounts
	prvKey, err := crypto.GenerateKey()
	assert.Equal(t, nil, err)
	feePayerAccount = &TestAccountType{
		Addr:  crypto.PubkeyToAddress(prvKey.PublicKey),
		Keys:  []*ecdsa.PrivateKey{prvKey},
		Nonce: uint64(0),
	}
	{
		txs = append(txs, genValueTransferTxWithAmount(t, big.NewInt(30000), reservoirAccount, feePayerAccount, bcData))
		reservoirAccount.AddNonce()
	}

	var weights []uint
	var prvKeysECDSA []*ecdsa.PrivateKey
	var prvKeysString []string

	for keyNum := 1; keyNum < 11; keyNum++ {
		// prepare a new key
		prvKey, _ := crypto.GenerateKey()
		weights = append(weights, 1)
		prvKeysECDSA = append(prvKeysECDSA, prvKey)
		prvKeysString = append(prvKeysString, common.Bytes2Hex(crypto.FromECDSA(prvKey)))

		// generate multiSigAccount
		acc, err := createMultisigAccount(uint(1), weights, prvKeysString, crypto.PubkeyToAddress(prvKey.PublicKey))
		assert.Equal(t, nil, err)
		acc.Keys = []*ecdsa.PrivateKey{prvKey}

		// generate a value transfer tx which charges klay to the multiSigAccount
		txs = append(txs, genValueTransferTxWithAmount(t, big.NewInt(3000), reservoirAccount, acc, bcData))
		reservoirAccount.AddNonce()

		// append new multiSigAccount to the multiSigAccounts slice
		multiSigAccounts = append(multiSigAccounts, acc)
	}

	assert.Equal(t, nil, bcData.GenABlockWithTransactions(accountMap, txs, prof))
	txs = nil

	// 2.2. generate accountUpdate transactions
	for keyNum := 1; keyNum < 11; keyNum++ {
		// generate an account update tx
		txs = append(txs, genAccountUpdateTx(t, multiSigAccounts[keyNum-1], bcData))
		multiSigAccounts[keyNum-1].AddNonce()
	}
	assert.Equal(t, nil, bcData.GenABlockWithTransactions(accountMap, txs, prof))
	txs = nil

	// 2.3. generate transaction which deploys test contract
	tx, _ := genSmartContractDeploy(t, signer, &TestAccountType{Addr: *bcData.addrs[2], Keys: []*ecdsa.PrivateKey{bcData.privKeys[2]}}, nil, nil, gasPrice)
	// currently, accountMap validation only works at valueTransferTx
	// it should check an error when accountMap validation is fixed
	_ = bcData.GenABlockWithTransactions(accountMap, types.Transactions{tx}, prof)
	contractAddr := &TestAccountType{Addr: bcData.bc.GetReceiptByTxHash(tx.Hash()).ContractAddress}

	// 3. test part
	for keyNum := 1; keyNum < 11; keyNum++ {
		multiSigAccounts[keyNum-1].Keys = prvKeysECDSA[0:keyNum]
		testF(keyNum, multiSigAccounts[keyNum-1], contractAddr, feePayerAccount, bcData)
	}
}
