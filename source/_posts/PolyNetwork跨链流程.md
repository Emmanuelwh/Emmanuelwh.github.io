---
title: PolyNetwork跨链流程
date: 2023-12-16 11:42:01
tags: 跨链桥
categories: 
  - [跨链桥]
  - [智能合约]
  - [以太坊]
description: 摘要：Poly Network跨链流程
---

# Poly Network跨链流程

### 源链

用户发起跨链交易，调用逻辑合约中的lock()函数

eth_contracts\contracts\core\lock_proxy\LockProxy.sol

```solidity
    /* @notice                  This function is meant to be invoked by the user,
    *                           a certin amount teokens will be locked in the proxy contract the invoker/msg.sender immediately.
    *                           Then the same amount of tokens will be unloked from target chain proxy contract at the target chain with chainId later.
    *  @param fromAssetHash     The asset address in current chain, uniformly named as `fromAssetHash`
    *  @param toChainId         The target chain id
    *                           
    *  @param toAddress         The address in bytes format to receive same amount of tokens in target chain 
    *  @param amount            The amount of tokens to be crossed from ethereum to the chain with chainId
    */
    function lock(address fromAssetHash, uint64 toChainId, bytes memory toAddress, uint256 amount) public payable returns (bool) {
        require(amount != 0, "amount cannot be zero!");
        
        //将代币合约地址锁到代理合约之中
        require(_transferToContract(fromAssetHash, amount), "transfer asset from fromAddress to lock_proxy contract  failed!");
        
        bytes memory toAssetHash = assetHashMap[fromAssetHash][toChainId];
        require(toAssetHash.length != 0, "empty illegal toAssetHash");

        TxArgs memory txArgs = TxArgs({
            toAssetHash: toAssetHash,
            toAddress: toAddress,
            amount: amount
        });
        bytes memory txData = _serializeTxArgs(txArgs);
        
        IEthCrossChainManagerProxy eccmp = IEthCrossChainManagerProxy(managerProxyContract);
        address eccmAddr = eccmp.getEthCrossChainManager();
        IEthCrossChainManager eccm = IEthCrossChainManager(eccmAddr);
        
        bytes memory toProxyHash = proxyHashMap[toChainId];
        require(toProxyHash.length != 0, "empty illegal toProxyHash");
        require(eccm.crossChain(toChainId, toProxyHash, "unlock", txData), "EthCrossChainManager crossChain executed error!");

        emit LockEvent(fromAssetHash, _msgSender(), toChainId, toAssetHash, toAddress, amount);
        
        return true;

    }
```

lock()函数中会调用CCM跨链管理合约中的crossChain()函数，并emit对应LockEvent。

eth_contracts\contracts\core\cross_chain_manager\logic\EthCrossChainManager.sol

```solidity
    function crossChain(uint64 toChainId, bytes calldata toContract, bytes calldata method, bytes calldata txData) whenNotPaused external returns (bool) {
        // Only allow whitelist contract to call
        require(whiteListFromContract[msg.sender],"Invalid from contract");
        
        // Load Ethereum cross chain data contract
        IEthCrossChainData eccd = IEthCrossChainData(EthCrossChainDataAddress);
        
        // To help differentiate two txs, the ethTxHashIndex is increasing automatically
        uint256 txHashIndex = eccd.getEthTxHashIndex();
        
        // Convert the uint256 into bytes
        bytes memory paramTxHash = Utils.uint256ToBytes(txHashIndex);
        
        // Construct the makeTxParam, and put the hash info storage, to help provide proof of tx existence
        bytes memory rawParam = abi.encodePacked(ZeroCopySink.WriteVarBytes(paramTxHash),
            ZeroCopySink.WriteVarBytes(abi.encodePacked(sha256(abi.encodePacked(address(this), paramTxHash)))),
            ZeroCopySink.WriteVarBytes(Utils.addressToBytes(msg.sender)),
            ZeroCopySink.WriteUint64(toChainId),
            ZeroCopySink.WriteVarBytes(toContract),
            ZeroCopySink.WriteVarBytes(method),
            ZeroCopySink.WriteVarBytes(txData)
        );
        
        // Must save it in the storage to be included in the proof to be verified.
        require(eccd.putEthTxHash(keccak256(rawParam)), "Save ethTxHash by index to Data contract failed!");
        
        // Fire the cross chain event denoting there is a cross chain request from Ethereum network to other public chains through Poly chain network
        emit CrossChainEvent(tx.origin, paramTxHash, msg.sender, toChainId, toContract, rawParam);
        return true;
    }
```

crossChain()函数构造对应的跨链函数的交易信息，并且emit对应的跨链事件。

### Relayer

#### Txlisten 

**从源链获取跨链交易消息的数据，并将其放入消息队列中**

对应的abi接口将监听对应的跨链事件,将对应的跨链事件存储到对应的迭代器中。

eth_contracts\go_abi\eccm_abi\eccm_abi.go

```go
// FilterCrossChainEvent is a free log retrieval operation binding the contract event 0x6ad3bf15c1988bc04bc153490cab16db8efb9a3990215bf1c64ea6e28be88483.
//
// Solidity: event CrossChainEvent(address indexed sender, bytes txId, address proxyOrAssetContract, uint64 toChainId, bytes toContract, bytes rawdata)
func (_EthCrossChainManager *EthCrossChainManagerFilterer) FilterCrossChainEvent(opts *bind.FilterOpts, sender []common.Address) (*EthCrossChainManagerCrossChainEventIterator, error) {

	var senderRule []interface{}
	for _, senderItem := range sender {
		senderRule = append(senderRule, senderItem)
	}

	logs, sub, err := _EthCrossChainManager.contract.FilterLogs(opts, "CrossChainEvent", senderRule)
	if err != nil {
		return nil, err
	}
	return &EthCrossChainManagerCrossChainEventIterator{contract: _EthCrossChainManager.contract, event: "CrossChainEvent", logs: logs, sub: sub}, nil
}
```

relayer中的scan()函数将查找在区块中的跨链交易，构造交易数据，并且调用compose()函数进一步构造交易数据

poly-relayer/relayer/eth/listener.go

```go
func (l *Listener) Scan(height uint64) (txs []*msg.Tx, err error) {
	ccm, err := eccm_abi.NewEthCrossChainManager(l.ccm, l.sdk.Node())
	if err != nil {
		return nil, err
	}
	opt := &bind.FilterOpts{
		Start:   height,
		End:     &height,
		Context: context.Background(),
	}
	events, err := ccm.FilterCrossChainEvent(opt, nil)
	if err != nil {
		return nil, err
	}

	if events == nil {
		return
	}

	txs = []*msg.Tx{}
	for events.Next() {
		ev := events.Event
		param := &ccom.MakeTxParam{}
		err = param.Deserialization(pcom.NewZeroCopySource([]byte(ev.Rawdata)))
		if err != nil {
			return
		}
		tx := &msg.Tx{
			TxType:     msg.SRC,
			TxId:       msg.EncodeTxId(ev.TxId),
			SrcHash:    ev.Raw.TxHash.String(),
			DstChainId: ev.ToChainId,
			SrcHeight:  height,
			SrcParam:   hex.EncodeToString(ev.Rawdata),
			SrcChainId: l.config.ChainId,
			SrcProxy:   ev.ProxyOrAssetContract.String(),
			DstProxy:   common.BytesToAddress(ev.ToContract).String(),
			SrcAddress: ev.Sender.String(),
		}
		l.Compose(tx)
		txs = append(txs, tx)
	}
    
// FilterCrossChainEvent is a free log retrieval operation binding the contract event 0x6ad3bf15c1988bc04bc153490cab16db8efb9a3990215bf1c64ea6e28be88483.
//
// Solidity: event CrossChainEvent(address indexed sender, bytes txId, address proxyOrAssetContract, uint64 toChainId, bytes toContract, bytes rawdata)
func (_EthCrossChainManager *EthCrossChainManagerFilterer) FilterCrossChainEvent(opts *bind.FilterOpts, sender []common.Address) (*EthCrossChainManagerCrossChainEventIterator, error) {

	var senderRule []interface{}
	for _, senderItem := range sender {
		senderRule = append(senderRule, senderItem)
	}

	logs, sub, err := _EthCrossChainManager.contract.FilterLogs(opts, "CrossChainEvent", senderRule)
	if err != nil {
		return nil, err
	}
	return &EthCrossChainManagerCrossChainEventIterator{contract: _EthCrossChainManager.contract, event: "CrossChainEvent", logs: logs, sub: sub}, nil
}
```

compose()函数对构造跨链交易的参数进行检查，构造一些数据，调用GetProof()得到对应的交易证明

poly-relayer/relayer/eth/listener.go

```go
func (l *Listener) Compose(tx *msg.Tx) (err error) {
	if len(tx.SrcProofHex) > 0 && tx.Param != nil { // Already fetched the proof
		log.Info("Proof already fetched for tx", "hash", tx.SrcHash)
		tx.SrcProof, _ = hex.DecodeString(tx.SrcProofHex)
		return
	}

	if tx.SrcHeight == 0 || len(tx.TxId) == 0 {
		return fmt.Errorf("tx missing attributes src height %v, txid %s", tx.SrcHeight, tx.TxId)
	}
	if len(tx.SrcParam) == 0 {
		return fmt.Errorf("src param is missing")
	}
	event, err := hex.DecodeString(tx.SrcParam)
	if err != nil {
		return fmt.Errorf("%s submitter decode src param error %v event %s", l.name, err, tx.SrcParam)
	}
	txId, err := hex.DecodeString(tx.TxId)
	if err != nil {
		return fmt.Errorf("%s failed to decode src txid %s, err %v", l.name, tx.TxId, err)
	}
	param := &ccom.MakeTxParam{}
	err = param.Deserialization(pcom.NewZeroCopySource(event))
	if err != nil {
		return
	}
	tx.Param = param
	tx.SrcEvent = event
	tx.SrcProofHeight, tx.SrcProof, err = l.GetProof(txId, tx.SrcHeight)
	return
}
```

getproof()通过对应rpc接口获取以太坊上对应的交易证明

poly-relayer/relayer/eth/listener.go

```go
func (l *Listener) getProof(txId []byte, txHeight uint64) (height uint64, proof []byte, err error) {
	id := msg.EncodeTxId(txId)
	bytes, err := ceth.MappingKeyAt(id, "01")
	if err != nil {
		err = fmt.Errorf("%s scan event mapping key error %v", l.name, err)
		return
	}
	proofKey := hexutil.Encode(bytes)
	height, err = l.GetProofHeight(txHeight)
	if err != nil {
		err = fmt.Errorf("%s can height get proof height error %v", l.name, err)
		return
	}
	if txHeight > height {
		err = fmt.Errorf("%w Proof not ready tx height %v proof height %v", msg.ERR_PROOF_UNAVAILABLE, txHeight, height)
		// We dont return here, still fetch the proof with tx height
		height = txHeight
	}
	ethProof, e := l.sdk.Node().GetProof(l.ccd.String(), proofKey, height)
	if e != nil {
		return height, nil, e
	}
	proof, e = json.Marshal(ethProof)
	if e != nil {
		return height, nil, e
	}
	return
}
```

```go
func (c *Client) GetProof(addr string, key string, height uint64) (proof *ETHProof, err error) {
	heightHex := hexutil.EncodeBig(big.NewInt(int64(height)))
	proof = &ETHProof{}
	err = c.Rpc.CallContext(context.Background(), &proof, "eth_getProof", addr, []string{key}, heightHex)
	return
}
```

在构造完对应的跨链交易结构之后，relayer构造一个Redis数据库，存储消息队列，将对应的跨链交易存到对应的队列中。

poly-relayer/bus/sort.go

```go
type SortedTxBus interface {
	Push(context.Context, *msg.Tx, uint64) error
	Range(context.Context, uint64, int64) ([]*msg.Tx, error)
	Pop(context.Context) (*msg.Tx, uint64, error)
	Len(context.Context) (uint64, error)
	Topic() string
}

func (b *RedisSortedTxBus) Push(ctx context.Context, msg *msg.Tx, height uint64) (err error) {
	_, err = b.db.ZAdd(ctx, b.Key.Key(),
		&redis.Z{
			Score:  float64(height),
			Member: msg.Encode(),
		},
	).Result()
	return
}
func (b *RedisSortedTxBus) Pop(ctx context.Context) (tx *msg.Tx, score uint64, err error) {
	res, err := b.db.BZPopMin(ctx, 0, b.Key.Key()).Result()
	if err != nil {
		return
	}
	if res == nil {
		return
	}
	score = uint64(res.Score)
	tx = new(msg.Tx)
	err = tx.Decode(res.Member.(string))
	return
}
```

#### Txcommit

遍历对应的跨链交易信息队列，将跨链交易提交给Poly Chain。

relayer随后启动poly submitter worker，调用pop()函数将对应的跨链交易信息从队列中取出，随后调用对应的submit()函数，将对应的跨链交易信息传递到poly chain上。

poly-relayer/relayer/poly/poly.go

```go

func (s *Submitter) Start(ctx context.Context, wg *sync.WaitGroup, mq bus.SortedTxBus, composer msg.SrcComposer) error {
	s.composer = composer
	s.Context = ctx
	s.wg = wg

	if s.config.Procs == 0 {
		s.config.Procs = 1
	}
	for i := 0; i < s.config.Procs; i++ {
		log.Info("Starting poly submitter worker", "index", i, "procs", s.config.Procs, "chain", s.name, "topic", mq.Topic())
		go s.consume(mq)
	}
	return nil
}

func (s *Submitter) consume(mq bus.SortedTxBus) error {
	s.wg.Add(1)
	defer s.wg.Done()
	ticker := time.NewTicker(300 * time.Millisecond)
	defer ticker.Stop()

	height := s.ReadyBlock()
	for {
		select {
		case <-s.Done():
			log.Info("Submitter is exiting now", "chain", s.name)
			return nil
		default:
		}

		select {
		case <-ticker.C:
			h := s.ReadyBlock()
			if h > 0 && height != h {
				height = h
				log.Info("Current ready block height", "chain", s.name, "height", height)
			}
		default:
		}

		tx, block, err := mq.Pop(s.Context)
		if err != nil {
			log.Error("Bus pop error", "err", err)
			continue
		}
		if tx == nil {
			time.Sleep(200 * time.Millisecond)
			continue
		}

		if block <= height {
			log.Info("Processing src tx", "src_hash", tx.SrcHash, "src_chain", tx.SrcChainId, "dst_chain", tx.DstChainId)
			err = s.submit(tx)
			if err == nil {
				log.Info("Submitted src tx to poly", "src_hash", tx.SrcHash, "poly_hash", tx.PolyHash)
				continue
			}

			if errors.Is(err, msg.ERR_Tx_VERIFYMERKLEPROOF) {
				log.Warn("src tx submit to poly verifyMerkleProof failed, clear src proof", "chain", s.name, "src hash", tx.SrcHash, "err", err)
				tx.SrcProofHex = ""
				tx.SrcProof = []byte{}
			}

			if strings.Contains(err.Error(), "side chain") && strings.Contains(err.Error(), "not registered") {
				log.Warn("Submit src tx to poly error", "chain", s.name, "err", err, "proof_height", tx.SrcProofHeight)
				continue
			}

			block = height + 10
			tx.Attempts++
			log.Error("Submit src tx to poly error", "chain", s.name, "err", err, "proof_height", tx.SrcProofHeight, "next_try", block)
			bus.SafeCall(s.Context, tx, "push back to tx bus", func() error { return mq.Push(context.Background(), tx, block) })
		} else {
			bus.SafeCall(s.Context, tx, "push back to tx bus", func() error { return mq.Push(context.Background(), tx, block) })
			time.Sleep(200 * time.Millisecond)
		}
	}
}
```

submit()函数的实现

首先对一些交易参数进行检查，判断是否有效，是否为空，以及交易调用的方法是否为AllowMethod。

随后调用poly-go-sdk中的CrossChain API将对应的交易信息和交易证明传递给Poly。

```go
func (s *Submitter) submit(tx *msg.Tx) error {
	err := s.composer.Compose(tx)
	if err != nil {
		if strings.Contains(err.Error(), "missing trie node") {
			return msg.ERR_PROOF_UNAVAILABLE
		}
		return err
	}
	if tx.Param == nil || tx.SrcChainId == 0 {
		return fmt.Errorf("%s submitter src tx %s param is missing or src chain id not specified", s.name, tx.SrcHash)
	}

	if !config.CONFIG.AllowMethod(tx.Param.Method) {
		log.Error("Invalid src tx method", "src_hash", tx.SrcHash, "chain", s.name, "method", tx.Param.Method)
		return nil
	}

	if tx.SrcStateRoot == nil {
		tx.SrcStateRoot = []byte{}
	}

	var account []byte
	switch tx.SrcChainId {
	case base.NEO, base.ONT:
		account = s.signer.Address[:]
		if len(tx.SrcStateRoot) == 0 || len(tx.SrcProof) == 0 {
			return fmt.Errorf("%s submitter src tx src state root(%x) or src proof(%x) missing for chain %d with tx %s", s.name, tx.SrcStateRoot, tx.SrcProof, tx.SrcChainId, tx.SrcHash)
		}
	default:
		// For other chains, reversed?
		account = common.Hex2Bytes(s.signer.Address.ToHexString())

		// Check done tx existence
		data, _ := s.sdk.Node().GetDoneTx(tx.SrcChainId, tx.Param.CrossChainID)
		if len(data) != 0 {
			log.Info("Tx already imported", "src_hash", tx.SrcHash)
			return nil
		}
	}

	t, err := s.sdk.Node().Native.Ccm.ImportOuterTransfer(
		tx.SrcChainId,
		tx.SrcEvent,
		uint32(tx.SrcProofHeight),
		tx.SrcProof,
		account,
		tx.SrcStateRoot,
		s.signer,
	)
	if err != nil {
		if strings.Contains(err.Error(), "tx already done") {
			log.Info("Tx already imported", "src_hash", tx.SrcHash, "chain", tx.SrcChainId)
			return nil
		} else if strings.Contains(err.Error(), "verifyMerkleProof error") {
			log.Error("Tx verifyMerkleProof err", "src_hash", tx.SrcHash, "chain", tx.SrcChainId, "err", err)
			return msg.ERR_Tx_VERIFYMERKLEPROOF
		}
		return fmt.Errorf("Failed to import tx to poly, %v tx src hash %s", err, tx.SrcHash)
	}
	tx.PolyHash = t.ToHexString()
	return nil
}
```

### Poly Chain

```go
type ChainHandler interface {
    MakeDepositProposal(service *native.NativeService) (*MakeTxParam, error)
}
```

该函数用来验证跨链交易的合法性，并将合法交易存储到Poly Chain中。

```go
func (this *ETHHandler) MakeDepositProposal(service *native.NativeService) (*scom.MakeTxParam, error) {
	params := new(scom.EntranceParam)
	//parse the EntranceParam from native service data
	if err := params.Deserialization(common.NewZeroCopySource(service.GetInput())); err != nil {
		return nil, fmt.Errorf("eth MakeDepositProposal, contract params deserialize error: %s", err)
	}
	//get registered side chain information from poly chain
	sideChain, err := side_chain_manager.GetSideChain(service, params.SourceChainID)
	if err != nil {
		return nil, fmt.Errorf("eth MakeDepositProposal, side_chain_manager.GetSideChain error: %v", err)
	}
	//Verify the merkle proof and return the parsed txParam from Extra field after
	value, err := verifyFromEthTx(service, params.Proof, params.Extra, params.SourceChainID, params.Height, sideChain)
	if err != nil {
		return nil, fmt.Errorf("eth MakeDepositProposal, verifyFromEthTx error: %s", err)
	}
	//Look for this tx on relay chain to make sure this tx hasn't been executed yet
	if err := scom.CheckDoneTx(service, value.CrossChainID, params.SourceChainID); err != nil {
		return nil, fmt.Errorf("eth MakeDepositProposal, check done transaction error:%s", err)
	}
	if err := scom.PutDoneTx(service, value.CrossChainID, params.SourceChainID); err != nil {
		return nil, fmt.Errorf("eth MakeDepositProposal, PutDoneTx error:%s", err)
	}
	return value, nil
}
```

根据ChainID得到对应的侧链信息，进行merkle proof的验证，返回对应解析过的txParam

txParam用于验证这个交易是否已经执行了

```go
type MakeTxParam struct {
    TxHash              []byte
    CrossChainID        []byte
    FromContractAddress []byte
    ToChainID           uint64
    ToContractAddress   []byte
    Method              string
    Args                []byte
}
```

**MakeDepositProposal **  中主要有两个函数 **verifyFromTx**  和  **verifyMerkleProof**   

| Method            | Description                                                  |
| ----------------- | ------------------------------------------------------------ |
| verifyFromTx      | 该方法用于从Poly Chain存储的数据库中获取同步的区块头，然后调用函数verifyMerkleProof验证跨链交易的合法性 |
| verifyMerkleProof | 该方法用于验证交易提交的Merkle证明是否与存储在Poly中的区块头一致 |

```go
/*  
 *  @param native       Native Service that carries values of information of cross-chain events     
 *  @param proof        The proof submitted by the current cross-chain transaction      
 *  @param extra        The cross-chain message which is used to construct MakeTxParam 
 *  @param fromChainID  Source chain id
 *  @param height       The block height corresponding to the current transaction event
 *  @param sideChain    Source chain information that contains the ccm contract address
*/
func verifyFromEthTx(native *native.NativeService, proof, extra []byte, fromChainID uint64, height uint32, sideChain *cmanager.SideChain) (*scom.MakeTxParam, error)
```

```go
/*  
 *  @param ethProof      The proof submitted by the current cross-chain transaction 
 *  @param blockData     The block header stored in poly chain corresponding to the current transaction event      
 *  @param contractAddr  The ccm contract address
*/
func VerifyMerkleProof(ethProof *ETHProof, blockData *eth.Header, contractAddr []byte) ([]byte, error)
```

验证通过之后，检验对应的交易信息是否已经存储在relayer chain中，若无，则将其存入relayer chain的数据库中。

### Relayer

#### Polylisten

relayer通过调用ScanDst()函数，通过对应的rpc接口，获取对应的跨链事件，进一步构造对应的跨链交易信息，并通过调用对应的GetProof()函数获取对应的merkle proof。

poly-relayer/relayer/poly/listener.go

```go
func (l *Listener) ScanDst(height uint64) (txs []*msg.Tx, err error) {
	txs, err = l.Scan(height)
	if err != nil { return }
	sub := &Submitter{sdk:l.sdk}
	for _, tx := range txs {
		tx.MerkleValue, _, _, err = sub.GetProof(tx.PolyHeight, tx.PolyKey)
		if err != nil { return }
	}
	return
}

func (l *Listener) Scan(height uint64) (txs []*msg.Tx, err error) {
	events, err := l.sdk.Node().GetSmartContractEventByBlock(uint32(height))
	if err != nil {
		return nil, err
	}

	for _, event := range events {
		for _, notify := range event.Notify {
			if notify.ContractAddress == poly.CCM_ADDRESS {
				states := notify.States.([]interface{})
				if len(states) < 6 {
					continue
				}
				method, _ := states[0].(string)
				if method != "makeProof" {
					continue
				}

				dstChain := uint64(states[2].(float64))
				if dstChain == 0 {
					log.Error("Invalid dst chain id in poly tx", "hash", event.TxHash)
					continue
				}

				tx := new(msg.Tx)
				tx.DstChainId = dstChain
				tx.PolyKey = states[5].(string)
				tx.PolyHeight = uint32(height)
				tx.PolyHash = event.TxHash
				tx.TxType = msg.POLY
				tx.TxId = states[3].(string)
				tx.SrcChainId = uint64(states[1].(float64))
				switch tx.SrcChainId {
				case base.NEO, base.NEO3, base.ONT:
					tx.TxId = util.ReverseHex(tx.TxId)
				}
				txs = append(txs, tx)
			}
		}
	}

	return
}
```

通过对应的poly-go-sdk中的API接口，获取对应的交易证明

poly-relayer/relayer/poly/compose.go

```go

func (s *Submitter) GetProof(height uint32, key string) (param *ccom.ToMerkleValue, auditPath string, evt *scom.SmartContactEvent, err error) {
	return s.getProof(s.sdk.Node(), height, key)
}

func (s *Submitter) getProof(node *poly.Client, height uint32, key string) (param *ccom.ToMerkleValue, auditPath string, evt *scom.SmartContactEvent, err error) {
	proof, err := node.GetCrossStatesProof(height, key)
	if err != nil {
		err = fmt.Errorf("GetProof: GetCrossStatesProof key %s, error %v", key, err)
		return
	}
	auditPath = proof.AuditPath
	path, err := hex.DecodeString(proof.AuditPath)
	if err != nil {
		return
	}
	value, _, _, _ := msg.ParseAuditPath(path)
	param = new(ccom.ToMerkleValue)
	err = param.Deserialization(pcom.NewZeroCopySource(value))
	if err != nil {
		err = fmt.Errorf("GetPolyParams: param.Deserialization error %v", err)
	}
	return
}
```

之后的过程，与前一个relayer类似，将对应的跨链消息以队列的形式存入到Redis数据库中。

#### PolyCommit

realyer调用start()函数启动对应的submitter，循环从队列中Pop出对应的跨链消息。

poly-relayer/relayer/eth/eth.go

```go
func (s *Submitter) run(account accounts.Account, mq bus.TxBus, delay bus.DelayedTxBus, compose msg.PolyComposer) error {
	s.wg.Add(1)
	defer s.wg.Done()
	for {
		select {
		case <-s.Done():
			log.Info("Submitter is exiting now", "chain", s.name)
			return nil
		default:
		}
		tx, err := mq.Pop(s.Context)
		if err != nil {
			log.Error("Bus pop error", "err", err)
			continue
		}
		if tx == nil {
			log.Warn("Bus pop nil?", "chain", s.name)
			time.Sleep(time.Second)
			continue
		}
		log.Info("Processing poly tx", "poly_hash", tx.PolyHash, "account", account.Address)
		tx.DstSender = &account
		err = s.ProcessTx(tx, compose)
		if err == nil {
			err = s.SubmitTx(tx)
		}
		if err != nil {
			log.Error("Process poly tx error", "chain", s.name, "poly_hash", tx.PolyHash, "err", err)
			log.Json(log.ERROR, tx)
			if errors.Is(err, msg.ERR_INVALID_TX) || errors.Is(err, msg.ERR_TX_BYPASS) {
				log.Error("Skipped poly tx for error", "poly_hash", tx.PolyHash, "err", err)
				continue
			}
			tx.Attempts++
			// TODO: retry with increased gas price?
			if errors.Is(err, msg.ERR_TX_EXEC_FAILURE) || errors.Is(err, msg.ERR_TX_EXEC_ALWAYS_FAIL) {
				tsp := time.Now().Unix() + 60*3
				bus.SafeCall(s.Context, tx, "push to delay queue", func() error { return delay.Delay(context.Background(), tx, tsp) })
			} else if errors.Is(err, msg.ERR_FEE_CHECK_FAILURE) {
				tsp := time.Now().Unix() + 10
				bus.SafeCall(s.Context, tx, "push to delay queue", func() error { return delay.Delay(context.Background(), tx, tsp) })
			} else if errors.Is(err, msg.ERR_PAID_FEE_TOO_LOW) {
				tsp := time.Now().Unix() + 60*10
				bus.SafeCall(s.Context, tx, "push to delay queue", func() error { return delay.Delay(context.Background(), tx, tsp) })
			} else {
				tsp := time.Now().Unix() + 1
				bus.SafeCall(s.Context, tx, "push to delay queue", func() error { return delay.Delay(context.Background(), tx, tsp) })
				if errors.Is(err, msg.ERR_LOW_BALANCE) {
					log.Info("Low wallet balance detected", "chain", s.name, "account", account.Address)
					s.WaitForBalance(account.Address)
				}
			}
		} else {
			log.Info("Submitted poly tx", "poly_hash", tx.PolyHash, "chain", s.name, "dst_hash", tx.DstHash)

			// Retry to verify a successful submit
			tsp := int64(0)
			switch s.config.ChainId {
			case base.MATIC, base.PLT:
				tsp = time.Now().Unix() + 60*3
			case base.ARBITRUM, base.OPTIMISM:
				tsp = time.Now().Unix() + 60*25
			case base.BSC, base.HECO, base.OK, base.KCC, base.BYTOM, base.HSC, base.MILKO:
				tsp = time.Now().Unix() + 60*4
			case base.ETH:
				tsp = time.Now().Unix() + 60*6
			default:
				tsp = time.Now().Unix() + 60*3
			}
			if tsp > 0 && tx.DstHash != "" {
				bus.SafeCall(s.Context, tx, "push to delay queue", func() error { return delay.Delay(context.Background(), tx, tsp) })
			}
		}
	}
}
```

relayer随后调用ProcessTx()函数，对对应的跨链函数进行处理，这里会检验对应的跨链交易是否已经传递给了目标链，随后会构造调用以太坊上'verifyHeaderAndExecuteTx'函数的数据，将其存储到对应的tx数据之中。

poly-relayer/relayer/eth/eth.go

```go
func (s *Submitter) processPolyTx(tx *msg.Tx) (err error) {
	ccd, err := eccd_abi.NewEthCrossChainData(s.ccd, s.sdk.Node())
	if err != nil {
		return
	}
	txId := [32]byte{}
	copy(txId[:], tx.MerkleValue.TxHash[:32])
	exist, err := ccd.CheckIfFromChainTxExist(nil, tx.SrcChainId, txId)
	if err != nil {
		return err
	}

	if exist {
		log.Info("ProcessPolyTx dst tx already relayed, tx id occupied", "chain", s.name, "poly_hash", tx.PolyHash)
		tx.DstHash = ""
		return nil
	}

	proof, err := hex.DecodeString(tx.AnchorProof)
	if err != nil {
		return fmt.Errorf("%s processPolyTx decode anchor proof hex error %v", s.name, err)
	}

	var anchor []byte
	if tx.AnchorHeader != nil {
		anchor = tx.AnchorHeader.GetMessage()
	}
	path, err := hex.DecodeString(tx.AuditPath)
	if err != nil {
		return fmt.Errorf("%s failed to decode audit path %v", s.name, err)
	}
	tx.DstData, err = s.abi.Pack("verifyHeaderAndExecuteTx", path, tx.PolyHeader.GetMessage(), proof, anchor, tx.PolySigs)
	if err != nil {
		err = fmt.Errorf("%s processPolyTx pack tx error %v", s.name, err)
		return err
	}
	return
}

func (s *Submitter) ProcessTx(m *msg.Tx, compose msg.PolyComposer) (err error) {
	if m.Type() != msg.POLY {
		return fmt.Errorf("%s desired message is not poly tx %v", m.Type())
	}

	if m.DstChainId != s.config.ChainId {
		return fmt.Errorf("%s message dst chain does not match %v", m.DstChainId)
	}
	m.DstPolyEpochStartHeight, err = s.GetPolyEpochStartHeight()
	if err != nil {
		return fmt.Errorf("%s fetch dst chain poly epoch height error %v", s.name, err)
	}
	m.DstPolyKeepers, err = s.GetPolyKeepers()
	if err != nil {
		return fmt.Errorf("%s fetch dst chain poly keepers error %v", s.name, err)
	}
	err = compose(m)
	if err != nil {
		return
	}
	err = s.processPolyTx(m)
	return
}

// CheckIfFromChainTxExist is a free data retrieval call binding the contract method 0x0586763c.
//
// Solidity: function checkIfFromChainTxExist(uint64 fromChainId, bytes32 fromChainTx) view returns(bool)
func (_EthCrossChainData *EthCrossChainDataCaller) CheckIfFromChainTxExist(opts *bind.CallOpts, fromChainId uint64, fromChainTx [32]byte) (bool, error) {
	var (
		ret0 = new(bool)
	)
	out := ret0
	err := _EthCrossChainData.contract.Call(opts, out, "checkIfFromChainTxExist", fromChainId, fromChainTx)
	return *ret0, err
}
```

relayer将对应的交易数据构造处理后之后，调用对应的SubmitTx()函数，来将对应的交易信息传递给目标链。

poly-relayer/relayer/eth/eth.go

```go

func (s *Submitter) SubmitTx(tx *msg.Tx) (err error) {
	switch v := tx.DstSender.(type) {
	case string:
		for _, a := range s.wallet.Accounts() {
			if util.LowerHex(a.Address.String()) == util.LowerHex(v) {
				tx.DstSender = &a
				break
			}
		}
	}
	err = s.submit(tx)
	if err != nil {
		info := err.Error()
		if strings.Contains(info, "business contract failed") {
			err = fmt.Errorf("%w tx exec error %v", msg.ERR_TX_EXEC_FAILURE, err)
		} else if strings.Contains(info, "higher than max limit") || strings.Contains(info, "max limit is zero or missing") {
			err = fmt.Errorf("%w %v", msg.ERR_PAID_FEE_TOO_LOW, err)
		} else if strings.Contains(info, "always failing") {
			err = fmt.Errorf("%w tx exec error %v", msg.ERR_TX_EXEC_ALWAYS_FAIL, err)
		} else if strings.Contains(info, "insufficient funds") || strings.Contains(info, "exceeds allowance") {
			err = msg.ERR_LOW_BALANCE
		}
	}
	return
}
```

调用submit()函数将，在目标链上发起对应的跨链交易。

poly-relayer/relayer/eth/eth.go

```go
func (s *Submitter) submit(tx *msg.Tx) error {
	if len(tx.DstData) == 0 {
		return nil
	}
	var (
		gasPrice  *big.Int
		gasPriceX *big.Float
		ok        bool
	)
	if tx.DstGasPrice != "" {
		gasPrice, ok = new(big.Int).SetString(tx.DstGasPrice, 10)
		if !ok {
			return fmt.Errorf("%s submit invalid gas price %s", tx.DstGasPrice)
		}
	}
	if tx.DstGasPriceX != "" {
		gasPriceX, ok = new(big.Float).SetString(tx.DstGasPriceX)
		if !ok {
			return fmt.Errorf("%s submit invalid gas priceX %s", tx.DstGasPriceX)
		}
	}
	var (
		err     error
		account accounts.Account
	)
	if tx.DstSender != nil {
		acc := tx.DstSender.(*accounts.Account)
		account = *acc
	} else {
		account, _, _ = s.wallet.Select()
	}

	if tx.CheckFeeOff || tx.CheckFeeStatus != bridge.PAID_LIMIT {
		tx.DstHash, err = s.wallet.SendWithAccount(account, s.ccm, big.NewInt(0), tx.DstGasLimit, gasPrice, gasPriceX, tx.DstData)
	} else {
		maxLimit, _ := big.NewFloat(tx.PaidGas).Int(nil)
		tx.DstHash, err = s.wallet.SendWithMaxLimit(s.sdk.ChainID, account, s.ccm, big.NewInt(0), maxLimit, gasPrice, gasPriceX, tx.DstData)
	}
	return err
}
```

调用SendWithAccount()向以太坊上发送对应的交易

bridge-common/wallet/eth.go

```go
// NOTE: gasPrice, gasPriceX used as gas tip here!
func (w *EthWallet) SendWithAccount(account accounts.Account, addr common.Address, amount *big.Int, gasLimit uint64, gasPrice *big.Int, gasPriceX *big.Float, data []byte) (hash string, err error) {
	if gasPrice == nil || gasPrice.Sign() <= 0 {
		gasPrice, err = w.GasTip()
		if err != nil {
			err = fmt.Errorf("Get gas tip error %v", err)
			return
		}
		if gasPriceX != nil {
			gasPrice, _ = new(big.Float).Mul(new(big.Float).SetInt(gasPrice), gasPriceX).Int(nil)
		}
	}

	gasCap, err := w.GasPrice()
	if err != nil {
		err = fmt.Errorf("Get gas price error %v", err)
		return
	}
	// TODO: Make this configurable
	gasCap = big.NewInt(0).Quo(big.NewInt(0).Mul(gasCap, big.NewInt(30)), big.NewInt(10)) // max gas price

	provider, nonces := w.GetAccount(account)
	nonce, err := nonces.Acquire()
	if err != nil {
		return
	}
	if gasLimit == 0 {
		msg := ethereum.CallMsg{
			From: account.Address, To: &addr, Value: big.NewInt(0), Data: data,
			GasFeeCap: gasCap, GasTipCap: gasPrice,
		}
		gasLimit, err = w.sdk.Node().EstimateGas(context.Background(), msg)
		if err != nil {
			nonces.Update(false)
			if strings.Contains(err.Error(), "has been executed") {
				log.Info("Transaction already executed")
				return "", nil
			}
			return "", fmt.Errorf("Estimate gas limit error %v", err)
		}
	}

	gasLimit = uint64(1.3 * float32(gasLimit))
	limit := GetChainGasLimit(w.chainId, gasLimit)
	if limit < gasLimit {
		nonces.Update(false)
		return "", fmt.Errorf("Send tx estimated gas limit(%v) higher than max %v", gasLimit, limit)
	}
	tx := types.NewTx(&types.DynamicFeeTx{
		Nonce:     nonce,
		GasTipCap: gasPrice,
		GasFeeCap: gasCap,
		Gas:       limit,
		To:        &addr,
		Value:     amount,
		Data:      data,
	})
	// tx := types.NewTransaction(nonce, addr, amount, limit, gasPrice, data)
	tx, err = provider.SignTx(account, tx, big.NewInt(int64(w.chainId)))
	if err != nil {
		nonces.Update(false)
		return "", fmt.Errorf("Sign tx error %v", err)
	}
	log.Info("Compose dst chain tx", "hash", tx.Hash(), "account", account.Address, "nonce", tx.Nonce(), "limit", tx.Gas(), "gasPrice", tx.GasPrice())
	err = w.sdk.Node().SendTransaction(context.Background(), tx)
	//TODO: Check err here before update nonces
	nonces.Update(true)
	return tx.Hash().String(), err
}
```

go-ethereum/ethclient/ethclient.go

```go
func (ec *Client) SendTransaction(ctx context.Context, tx *types.Transaction) error {
	data, err := tx.MarshalBinary()
	if err != nil {
		return err
	}
	return ec.c.CallContext(ctx, nil, "eth_sendRawTransaction", hexutil.Encode(data))
}
```

通过json-rpc接口，发起在以太坊上的函数调用

go-ethereum/rpc/client.go

```go
// CallContext performs a JSON-RPC call with the given arguments. If the context is
// canceled before the call has successfully returned, CallContext returns immediately.
//
// The result must be a pointer so that package json can unmarshal into it. You
// can also pass nil, in which case the result is ignored.
func (c *Client) CallContext(ctx context.Context, result interface{}, method string, args ...interface{}) error {}
```

### 目标链

验证对应的区块头和**Merkle proof** ，验证通过，交易在目标链上执行。

- 中继器调用该函数，一些情况，用户从**Poly**链获取有效的块信息，自行调用该方法
- 该方法获取并处理跨链交易，得到对应交易的**Merkle**根，使用交易参数来验证交易的合法性
- 验证Poly Chain区块头和证明后，检查参数**toContract** 和**toMerkleValue.makeTxParam.method** 是否已经在白名单中
- 然后调用部署在目标链上的业务逻辑合约，通过内部方法**_executeCrossChainTx()**对业务逻辑合约进行处理：
  - 该方法旨在调用目标合约并触发目标链上跨链交易的执行。
  - 首先，您需要确保目标合约正在等待调用合约而不是标准账户地址。
  - 然后构造一个目标业务逻辑契约方法：需要对_method和输入数据格式“(bytes,bytes,uint64)”进行**encodePacked**
  - 然后它会**keccak256**编码的字符串，使用 **bytes4** 获取函数调用的调用数据的前四个字节，指定要调用的函数。

- 调用方法后，需要检查返回值。  只有返回值为真，整个跨链交易才会执行成功

```solidity
/*  
 *  @param proof                  Poly chain transaction Merkle proof
 *  @param rawHeader              The header containing crossStateRoot to verify the above tx Merkle proof
 *  @param headerProof            The header Merkle proof used to verify rawHeader
 *  @param curRawHeader           Any header in current epoch consensus of Poly chain
 *  @param headerSig              The converted signature variable for solidity derived from Poly chain consensus nodes' signature 
 *                                used to verify the validity of curRawHeader
 *  @return                       true or false
*/
function verifyHeaderAndExecuteTx(bytes memory proof, bytes memory rawHeader, bytes memory headerProof, bytes memory curRawHeader,bytes memory headerSig) whenNotPaused public returns (bool){
    ECCUtils.Header memory header = ECCUtils.deserializeHeader(rawHeader);
    // Load ehereum cross chain data contract
    IEthCrossChainData eccd = IEthCrossChainData(EthCrossChainDataAddress);

    // Get stored consensus public key bytes of current Poly chain epoch and deserialize Poly chain consensus public key bytes to address[]
    address[] memory polyChainBKs = ECCUtils.deserializeKeepers(eccd.getCurEpochConPubKeyBytes());

    uint256 curEpochStartHeight = eccd.getCurEpochStartHeight();

    uint n = polyChainBKs.length;
    if (header.height >= curEpochStartHeight) {
        // It's enough to verify rawHeader signature
        require(ECCUtils.verifySig(rawHeader, headerSig, polyChainBKs, n - ( n - 1) / 3), "Verify Poly chain header signature failed!");
    } else {
        // We need to verify the signature of curHeader 
        require(ECCUtils.verifySig(curRawHeader, headerSig, polyChainBKs, n - ( n - 1) / 3), "Verify Poly chain current epoch header signature failed!");

        // Then use curHeader.StateRoot and headerProof to verify rawHeader.CrossStateRoot
        ECCUtils.Header memory curHeader = ECCUtils.deserializeHeader(curRawHeader);
        bytes memory proveValue = ECCUtils.MerkleProve(headerProof, curHeader.blockRoot);
        require(ECCUtils.getHeaderHash(rawHeader) == Utils.bytesToBytes32(proveValue), "verify header proof failed!");
    }

    // Through rawHeader.CrossStatesRoot, the toMerkleValue or cross chain msg can be verified and parsed from proof
    bytes memory toMerkleValueBs = ECCUtils.MerkleProve(proof, header.crossStatesRoot);

    // Parse the toMerkleValue struct and make sure the tx has not been processed, then mark this tx as processed
    ECCUtils.ToMerkleValue memory toMerkleValue = ECCUtils.deserializeMerkleValue(toMerkleValueBs);
    require(!eccd.checkIfFromChainTxExist(toMerkleValue.fromChainID, Utils.bytesToBytes32(toMerkleValue.txHash)), "the transaction has been executed!");
    require(eccd.markFromChainTxExist(toMerkleValue.fromChainID, Utils.bytesToBytes32(toMerkleValue.txHash)), "Save crosschain tx exist failed!");

    // Ethereum ChainId is 2, we need to check the transaction is for Ethereum network
    require(toMerkleValue.makeTxParam.toChainId == chainId, "This Tx is not aiming at this network!");

    // Obtain the target contract, so that Ethereum cross chain manager contract can trigger the executation of cross chain tx on Ethereum side
    address toContract = Utils.bytesToAddress(toMerkleValue.makeTxParam.toContract);

    // only invoke PreWhiteListed Contract and method For Now
    require(whiteListContractMethodMap[toContract][toMerkleValue.makeTxParam.method],"Invalid to contract or method");

    //TODO: check this part to make sure we commit the next line when doing local net UT test
    require(_executeCrossChainTx(toContract, toMerkleValue.makeTxParam.method, toMerkleValue.makeTxParam.args, toMerkleValue.makeTxParam.fromContract, toMerkleValue.fromChainID), "Execute CrossChain Tx failed!");

    // Fire the cross chain event denoting the executation of cross chain tx is successful,
    // and this tx is coming from other public chains to current Ethereum network
    emit VerifyHeaderAndExecuteTxEvent(toMerkleValue.fromChainID, toMerkleValue.makeTxParam.toContract, toMerkleValue.txHash, toMerkleValue.makeTxParam.txHash);

    return true;
}

/* 
 *  @notice                       Dynamically invoke the target contract, trigger execution of cross-chain tx 
                                  on Ethereum side
 *  @param _toContract            the Ethereum Cross Chain Manager contract will invoke the target contract
 *  @param _method                At which method will be invoked within the target contract
 *  @param _args                  The parameter that will be passed into the target contract
 *  @param _fromContractAddr      From chain smart contract address
 *  @param _fromChainId           Indicate from which chain current cross-chain tx comes 
 *  @return                       true or false
*/
function _executeCrossChainTx(address _toContract, bytes memory _method, bytes memory _args, bytes memory _fromContractAddr, uint64 _fromChainId) internal returns (bool){
    // Ensure the target contract gonna be invoked is indeed a contract rather than a normal account address
    require(Utils.isContract(_toContract), "The passed in address is not a contract!");
    bytes memory returnData;
    bool success;

    // The returnData will be bytes32, the last byte must be 01;
    (success, returnData) = _toContract.call(abi.encodePacked(bytes4(keccak256(abi.encodePacked(_method, "(bytes,bytes,uint64)"))), abi.encode(_args, _fromContractAddr, _fromChainId)));

    // Ensure the executation is successful
    require(success == true, "EthCrossChain call business contract failed");

    // Ensure the returned value is true
    require(returnData.length != 0, "No return value from business contract!");
    (bool res,) = ZeroCopySource.NextBool(returnData, 31);
    require(res == true, "EthCrossChain call business contract return is not true");

    return true;
} 
```
