// Modifications Copyright 2018 The klaytn Authors
// Copyright 2015 The go-ethereum Authors
// This file is part of go-ethereum.
//
// The go-ethereum library is free software: you can redistribute it and/or modify
// it under the terms of the GNU Lesser General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// The go-ethereum library is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU Lesser General Public License for more details.
//
// You should have received a copy of the GNU Lesser General Public License
// along with the go-ethereum library. If not, see <http://www.gnu.org/licenses/>.
//
// This file is derived from eth/api.go (2018/06/04).
// Modified and improved for the klaytn development.

package cn

import (
	"bytes"
	"compress/gzip"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"github.com/klaytn/klaytn/blockchain"
	"github.com/klaytn/klaytn/blockchain/state"
	"github.com/klaytn/klaytn/blockchain/types"
	"github.com/klaytn/klaytn/common"
	"github.com/klaytn/klaytn/common/hexutil"
	"github.com/klaytn/klaytn/kerrors"
	"github.com/klaytn/klaytn/networks/rpc"
	"github.com/klaytn/klaytn/params"
	"github.com/klaytn/klaytn/rlp"
	"github.com/klaytn/klaytn/storage/statedb"
	"github.com/klaytn/klaytn/work"
)

// PublicKlayAPI provides an API to access Klaytn CN-related
// information.
type PublicKlayAPI struct {
	cn *CN
}

// NewPublicKlayAPI creates a new Klaytn protocol API for full nodes.
func NewPublicKlayAPI(e *CN) *PublicKlayAPI {
	return &PublicKlayAPI{e}
}

// Rewardbase is the address that consensus rewards will be send to
func (api *PublicKlayAPI) Rewardbase() (common.Address, error) {
	return api.cn.Rewardbase()
}

// PrivateAdminAPI is the collection of CN full node-related APIs
// exposed over the private admin endpoint.
type PrivateAdminAPI struct {
	cn *CN
}

// NewPrivateAdminAPI creates a new API definition for the full node private
// admin methods of the CN service.
func NewPrivateAdminAPI(cn *CN) *PrivateAdminAPI {
	return &PrivateAdminAPI{cn: cn}
}

// ExportChain exports the current blockchain into a local file.
func (api *PrivateAdminAPI) ExportChain(file string) (bool, error) {
	if _, err := os.Stat(file); err == nil {
		// File already exists. Allowing overwrite could be a DoS vecotor,
		// since the 'file' may point to arbitrary paths on the drive
		return false, errors.New("location would overwrite an existing file")
	}

	// Make sure we can create the file to export into
	out, err := os.OpenFile(file, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, os.ModePerm)
	if err != nil {
		return false, err
	}
	defer out.Close()

	var writer io.Writer = out
	if strings.HasSuffix(file, ".gz") {
		writer = gzip.NewWriter(writer)
		defer writer.(*gzip.Writer).Close()
	}

	// Export the blockchain
	if err := api.cn.BlockChain().Export(writer); err != nil {
		return false, err
	}
	return true, nil
}

func hasAllBlocks(chain work.BlockChain, bs []*types.Block) bool {
	for _, b := range bs {
		if !chain.HasBlock(b.Hash(), b.NumberU64()) {
			return false
		}
	}

	return true
}

// ImportChain imports a blockchain from a local file.
func (api *PrivateAdminAPI) ImportChain(file string) (bool, error) {
	// Make sure the can access the file to import
	in, err := os.Open(file)
	if err != nil {
		return false, err
	}
	defer in.Close()

	var reader io.Reader = in
	if strings.HasSuffix(file, ".gz") {
		if reader, err = gzip.NewReader(reader); err != nil {
			return false, err
		}
	}
	stream := rlp.NewStream(reader, 0)

	return api.importChain(stream)
}

func (api *PrivateAdminAPI) ImportChainFromString(blockRlp string) (bool, error) {
	// Run actual the import in pre-configured batches
	stream := rlp.NewStream(bytes.NewReader(common.FromHex(blockRlp)), 0)

	return api.importChain(stream)
}

func (api *PrivateAdminAPI) importChain(stream *rlp.Stream) (bool, error) {
	blocks, index := make([]*types.Block, 0, 2500), 0
	for batch := 0; ; batch++ {
		// Load a batch of blocks from the input file
		for len(blocks) < cap(blocks) {
			block := new(types.Block)
			if err := stream.Decode(block); err == io.EOF {
				break
			} else if err != nil {
				return false, fmt.Errorf("block %d: failed to parse: %v", index, err)
			}
			blocks = append(blocks, block)
			index++
		}
		if len(blocks) == 0 {
			break
		}

		if hasAllBlocks(api.cn.BlockChain(), blocks) {
			blocks = blocks[:0]
			continue
		}
		// Import the batch and reset the buffer
		if _, err := api.cn.BlockChain().InsertChain(blocks); err != nil {
			return false, fmt.Errorf("batch %d: failed to insert: %v", batch, err)
		}
		blocks = blocks[:0]
	}
	return true, nil
}

// StartStateMigration starts state migration.
func (api *PrivateAdminAPI) StartStateMigration() error {
	return api.cn.blockchain.PrepareStateMigration()
}

// StopStateMigration stops state migration and removes stateMigrationDB.
func (api *PrivateAdminAPI) StopStateMigration() error {
	return api.cn.BlockChain().StopStateMigration()
}

// StateMigrationStatus returns the status information of state trie migration.
func (api *PrivateAdminAPI) StateMigrationStatus() map[string]interface{} {
	isMigration, blkNum, read, committed, pending, progress, err := api.cn.BlockChain().StateMigrationStatus()

	errStr := "null"
	if err != nil {
		errStr = err.Error()
	}

	return map[string]interface{}{
		"isMigration":          isMigration,
		"migrationBlockNumber": blkNum,
		"read":                 read,
		"committed":            committed,
		"pending":              pending,
		"progress":             progress,
		"err":                  errStr,
	}
}

func (api *PrivateAdminAPI) SaveTrieNodeCacheToDisk() error {
	return api.cn.BlockChain().SaveTrieNodeCacheToDisk()
}

// PublicDebugAPI is the collection of Klaytn full node APIs exposed
// over the public debugging endpoint.
type PublicDebugAPI struct {
	cn *CN
}

// NewPublicDebugAPI creates a new API definition for the full node-
// related public debug methods of the Klaytn service.
func NewPublicDebugAPI(cn *CN) *PublicDebugAPI {
	return &PublicDebugAPI{cn: cn}
}

// =DumpBlock retrieves the entire state of the database at a given block.
func (api *PublicDebugAPI) DumpBlock(blockNr rpc.BlockNumber) (state.Dump, error) {
	if blockNr == rpc.PendingBlockNumber {
		return state.Dump{}, kerrors.ErrPendingBlockNotSupported
	}
	var block *types.Block
	if blockNr == rpc.LatestBlockNumber {
		block = api.cn.blockchain.CurrentBlock()
	} else {
		block = api.cn.blockchain.GetBlockByNumber(uint64(blockNr))
	}
	if block == nil {
		return state.Dump{}, fmt.Errorf("block #%d not found", blockNr)
	}
	stateDb, err := api.cn.BlockChain().StateAtWithPersistent(block.Root())
	if err != nil {
		return state.Dump{}, err
	}
	return stateDb.RawDump(), nil
}

type Trie struct {
	Type   string `json:"type"`
	Hash   string `json:"hash"`
	Parent string `json:"parent"`
	Path   string `json:"path"`
}

type DumpStateTrieResult struct {
	Root  string `json:"root"`
	Tries []Trie `json:"tries"`
}

// DumpStateTrie retrieves all state/storage tries of the given state root.
func (api *PublicDebugAPI) DumpStateTrie(blockNr uint64) (DumpStateTrieResult, error) {
	block := api.cn.blockchain.GetBlockByNumber(uint64(blockNr))
	if block == nil {
		return DumpStateTrieResult{}, fmt.Errorf("block #%d not found", blockNr)
	}

	result := DumpStateTrieResult{
		Root:  block.Root().String(),
		Tries: make([]Trie, 0),
	}

	db := state.NewDatabaseWithExistingCache(api.cn.chainDB, api.cn.blockchain.StateCache().TrieDB().TrieNodeCache())
	stateDB, err := state.New(block.Root(), db)
	if err != nil {
		return DumpStateTrieResult{}, err
	}
	it := state.NewNodeIterator(stateDB)
	for it.Next() {
		t := Trie{
			it.Type,
			it.Hash.String(),
			it.Parent.String(),
			statedb.HexPathToString(it.Path),
		}

		result.Tries = append(result.Tries, t)
	}
	return result, nil
}

// StartWarmUp retrieves all state/storage tries of the latest committed state root and caches the tries.
func (api *PublicDebugAPI) StartWarmUp() error {
	return api.cn.blockchain.StartWarmUp()
}

// StartContractWarmUp retrieves a storage trie of the latest state root and caches the trie
// corresponding to the given contract address.
func (api *PublicDebugAPI) StartContractWarmUp(contractAddr common.Address) error {
	return api.cn.blockchain.StartContractWarmUp(contractAddr)
}

// StopWarmUp stops the warming up process.
func (api *PublicDebugAPI) StopWarmUp() error {
	return api.cn.blockchain.StopWarmUp()
}

// StartCollectingTrieStats  collects state/storage trie statistics and print in the log.
func (api *PublicDebugAPI) StartCollectingTrieStats(contractAddr common.Address) error {
	return api.cn.blockchain.StartCollectingTrieStats(contractAddr)
}

// PrivateDebugAPI is the collection of CN full node APIs exposed over
// the private debugging endpoint.
type PrivateDebugAPI struct {
	config *params.ChainConfig
	cn     *CN
}

// NewPrivateDebugAPI creates a new API definition for the full node-related
// private debug methods of the CN service.
func NewPrivateDebugAPI(config *params.ChainConfig, cn *CN) *PrivateDebugAPI {
	return &PrivateDebugAPI{config: config, cn: cn}
}

// Preimage is a debug API function that returns the preimage for a sha3 hash, if known.
func (api *PrivateDebugAPI) Preimage(ctx context.Context, hash common.Hash) (hexutil.Bytes, error) {
	if preimage := api.cn.ChainDB().ReadPreimage(hash); preimage != nil {
		return preimage, nil
	}
	return nil, errors.New("unknown preimage")
}

// GetBadBLocks returns a list of the last 'bad blocks' that the client has seen on the network
// and returns them as a JSON list of block-hashes
func (api *PrivateDebugAPI) GetBadBlocks(ctx context.Context) ([]blockchain.BadBlockArgs, error) {
	return api.cn.BlockChain().BadBlocks()
}

// StorageRangeResult is the result of a debug_storageRangeAt API call.
type StorageRangeResult struct {
	Storage storageMap   `json:"storage"`
	NextKey *common.Hash `json:"nextKey"` // nil if Storage includes the last key in the statedb.
}

type storageMap map[common.Hash]storageEntry

type storageEntry struct {
	Key   *common.Hash `json:"key"`
	Value common.Hash  `json:"value"`
}

// StorageRangeAt returns the storage at the given block height and transaction index.
//func (api *PrivateDebugAPI) StorageRangeAt(ctx context.Context, blockHash common.Hash, txIndex int, contractAddress common.Address, keyStart hexutil.Bytes, maxResult int) (StorageRangeResult, error) {
//	_, _, statedb, err := api.computeTxEnv(blockHash, txIndex, 0)
//	if err != nil {
//		return StorageRangeResult{}, err
//	}
//	st := statedb.StorageTrie(contractAddress)
//	if st == nil {
//		return StorageRangeResult{}, fmt.Errorf("account %x doesn't exist", contractAddress)
//	}
//	return storageRangeAt(st, keyStart, maxResult)
//}

func storageRangeAt(st state.Trie, start []byte, maxResult int) (StorageRangeResult, error) {
	it := statedb.NewIterator(st.NodeIterator(start))
	result := StorageRangeResult{Storage: storageMap{}}
	for i := 0; i < maxResult && it.Next(); i++ {
		_, content, _, err := rlp.Split(it.Value)
		if err != nil {
			return StorageRangeResult{}, err
		}
		e := storageEntry{Value: common.BytesToHash(content)}
		if preimage := st.GetKey(it.Key); preimage != nil {
			preimage := common.BytesToHash(preimage)
			e.Key = &preimage
		}
		result.Storage[common.BytesToHash(it.Key)] = e
	}
	// Add the 'next key' so clients can continue downloading.
	if it.Next() {
		next := common.BytesToHash(it.Key)
		result.NextKey = &next
	}
	return result, nil
}

// GetModifiedAccountsByNumber returns all accounts that have changed between the
// two blocks specified. A change is defined as a difference in nonce, balance,
// code hash, or storage hash.
//
// With one parameter, returns the list of accounts modified in the specified block.
func (api *PrivateDebugAPI) GetModifiedAccountsByNumber(startNum uint64, endNum *uint64) ([]common.Address, error) {
	startBlock, endBlock, err := api.getStartAndEndBlock(startNum, endNum)
	if err != nil {
		return nil, err
	}
	return api.getModifiedAccounts(startBlock, endBlock)
}

// GetModifiedAccountsByHash returns all accounts that have changed between the
// two blocks specified. A change is defined as a difference in nonce, balance,
// code hash, or storage hash.
//
// With one parameter, returns the list of accounts modified in the specified block.
func (api *PrivateDebugAPI) GetModifiedAccountsByHash(startHash common.Hash, endHash *common.Hash) ([]common.Address, error) {
	var startBlock, endBlock *types.Block
	startBlock = api.cn.blockchain.GetBlockByHash(startHash)
	if startBlock == nil {
		return nil, fmt.Errorf("start block %x not found", startHash)
	}

	if endHash == nil {
		endBlock = startBlock
		startBlock = api.cn.blockchain.GetBlockByHash(startBlock.ParentHash())
		if startBlock == nil {
			return nil, fmt.Errorf("block %x has no parent", startHash)
		}
	} else {
		endBlock = api.cn.blockchain.GetBlockByHash(*endHash)
		if endBlock == nil {
			return nil, fmt.Errorf("end block %x not found", *endHash)
		}
	}
	return api.getModifiedAccounts(startBlock, endBlock)
}

func (api *PrivateDebugAPI) getModifiedAccounts(startBlock, endBlock *types.Block) ([]common.Address, error) {
	trieDB := api.cn.blockchain.StateCache().TrieDB()

	oldTrie, err := statedb.NewSecureTrie(startBlock.Root(), trieDB)
	if err != nil {
		return nil, err
	}
	newTrie, err := statedb.NewSecureTrie(endBlock.Root(), trieDB)
	if err != nil {
		return nil, err
	}

	diff, _ := statedb.NewDifferenceIterator(oldTrie.NodeIterator([]byte{}), newTrie.NodeIterator([]byte{}))
	iter := statedb.NewIterator(diff)

	var dirty []common.Address
	for iter.Next() {
		key := newTrie.GetKey(iter.Key)
		if key == nil {
			return nil, fmt.Errorf("no preimage found for hash %x", iter.Key)
		}
		dirty = append(dirty, common.BytesToAddress(key))
	}
	return dirty, nil
}

// getStartAndEndBlock returns start and end block based on the given startNum and endNum.
func (api *PrivateDebugAPI) getStartAndEndBlock(startNum uint64, endNum *uint64) (*types.Block, *types.Block, error) {
	var startBlock, endBlock *types.Block

	startBlock = api.cn.blockchain.GetBlockByNumber(startNum)
	if startBlock == nil {
		return nil, nil, fmt.Errorf("start block number %d not found", startNum)
	}

	if endNum == nil {
		endBlock = startBlock
		startBlock = api.cn.blockchain.GetBlockByHash(startBlock.ParentHash())
		if startBlock == nil {
			return nil, nil, fmt.Errorf("block number %d has no parent", startNum)
		}
	} else {
		endBlock = api.cn.blockchain.GetBlockByNumber(*endNum)
		if endBlock == nil {
			return nil, nil, fmt.Errorf("end block number %d not found", *endNum)
		}
	}

	if startBlock.Number().Uint64() >= endBlock.Number().Uint64() {
		return nil, nil, fmt.Errorf("start block height (%d) must be less than end block height (%d)", startBlock.Number().Uint64(), endBlock.Number().Uint64())
	}

	return startBlock, endBlock, nil
}

// GetModifiedStorageNodesByNumber returns the number of storage nodes of a contract account
// that have been changed between the two blocks specified.
//
// With the first two parameters, it returns the number of storage trie nodes modified in the specified block.
func (api *PrivateDebugAPI) GetModifiedStorageNodesByNumber(contractAddr common.Address, startNum uint64, endNum *uint64, printDetail *bool) (int, error) {
	startBlock, endBlock, err := api.getStartAndEndBlock(startNum, endNum)
	if err != nil {
		return 0, err
	}
	return api.getModifiedStorageNodes(contractAddr, startBlock, endBlock, printDetail)
}

func (api *PrivateDebugAPI) getModifiedStorageNodes(contractAddr common.Address, startBlock, endBlock *types.Block, printDetail *bool) (int, error) {
	startBlockRoot, err := api.cn.blockchain.GetContractStorageRoot(startBlock, api.cn.blockchain.StateCache(), contractAddr)
	if err != nil {
		return 0, err
	}
	endBlockRoot, err := api.cn.blockchain.GetContractStorageRoot(endBlock, api.cn.blockchain.StateCache(), contractAddr)
	if err != nil {
		return 0, err
	}

	trieDB := api.cn.blockchain.StateCache().TrieDB()
	oldTrie, err := statedb.NewSecureTrie(startBlockRoot, trieDB)
	if err != nil {
		return 0, err
	}
	newTrie, err := statedb.NewSecureTrie(endBlockRoot, trieDB)
	if err != nil {
		return 0, err
	}

	diff, _ := statedb.NewDifferenceIterator(oldTrie.NodeIterator([]byte{}), newTrie.NodeIterator([]byte{}))
	iter := statedb.NewIterator(diff)

	logger.Info("Start collecting the modified storage nodes", "contractAddr", contractAddr.String(),
		"startBlock", startBlock.NumberU64(), "endBlock", endBlock.NumberU64())
	start := time.Now()
	numModifiedNodes := 0
	for iter.Next() {
		numModifiedNodes++
		if printDetail != nil && *printDetail {
			logger.Info("modified storage trie nodes", "contractAddr", contractAddr.String(),
				"nodeHash", common.BytesToHash(iter.Key).String())
		}
	}
	logger.Info("Finished collecting the modified storage nodes", "contractAddr", contractAddr.String(),
		"startBlock", startBlock.NumberU64(), "endBlock", endBlock.NumberU64(), "numModifiedNodes", numModifiedNodes, "elapsed", time.Since(start))
	return numModifiedNodes, nil
}
