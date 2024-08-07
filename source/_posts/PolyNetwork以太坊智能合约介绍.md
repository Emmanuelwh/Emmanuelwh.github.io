---
title: PolyNetwork以太坊智能合约介绍
date: 2023-12-16 11:34:02
tags: [Defi安全, 跨链桥]
categories: 
  - [以太坊]
  - [智能合约]
  - [跨链桥]
description: 摘要：PolyNetwork跨链桥智能合约介绍（详细注释）
---

## 跨链智能合约介绍（eth-contracts）

代码已经详细注释，参考PolyNetwork官网

跨链合约主要分为分为逻辑(logic)合约，数据(data)合约和代理(proxy)合约

- Cross Chain Manager Contract：CCM合约对应的是`EthCrossChainManager.sol `

- Cross Chain Data Contract：CCD合约对应的是`EthCrossChainData.sol`

- Cross Chain Manager Proxy Contract：CCMP合约对应的是`EthCrossChainManagerProxy.sol`

- Business Logic Contract：主要对应的是`LoxyProxy.sol` 
![在这里插入图片描述](https://gitee.com/Emmanuel_scb/blogimage/raw/master/img/202312161134666.png)


##  跨链智能合约代码具体分析

### Business Logic Contract: 

#### `LockProxy.sol`

代码github位置：polynetwork/eth-contracts/contracts/core/lock_proxy/LockProxy.sol

https://github.com/polynetwork/eth-contracts/blob/master/contracts/core/lock_proxy/LockProxy.sol

```solidity
pragma solidity ^0.5.0;
import "./../../libs/ownership/Ownable.sol";
import "./../../libs/common/ZeroCopySource.sol";
import "./../../libs/common/ZeroCopySink.sol";
import "./../../libs/utils/Utils.sol";
import "./../../libs/token/ERC20/SafeERC20.sol";
import "./../cross_chain_manager/interface/IEthCrossChainManager.sol";
import "./../cross_chain_manager/interface/IEthCrossChainManagerProxy.sol";
contract LockProxy is Ownable {
    using SafeMath for uint;         //包含基本算数运算，以防止溢出
    using SafeERC20 for IERC20;

    struct TxArgs {
        bytes toAssetHash;        //目标链上的资产哈希
        bytes toAddress;         //目标链上接收对应代币的字节格式的地址
        uint256 amount;          //交易数额
    }
    address public managerProxyContract;    //CCMP合约的地址
    mapping(uint64 => bytes) public proxyHashMap;
    //存储链与链之间的CCM合约之间的映射关系
    //以目标链ID（ChainID）为键，CCM合约地址哈希为值。
    mapping(address => mapping(uint64 => bytes)) public assetHashMap;
    //存储链与链之间的资产映射关系.
    //以源链资产哈希（fromAssetHash）和目标链ID（toChainID）为键，目标资产哈希(toAssetHash)为值。
    mapping(address => bool) safeTransfer;

    event SetManagerProxyEvent(address manager);
    event BindProxyEvent(uint64 toChainId, bytes targetProxyHash);
    event BindAssetEvent(address fromAssetHash, uint64 toChainId, bytes targetProxyHash, uint initialAmount);
    event UnlockEvent(address toAssetHash, address toAddress, uint256 amount);
    event LockEvent(address fromAssetHash, address fromAddress, uint64 toChainId, bytes toAssetHash, bytes toAddress, uint256 amount);
    
    modifier onlyManagerContract() {
        IEthCrossChainManagerProxy ieccmp = IEthCrossChainManagerProxy(managerProxyContract);
        require(_msgSender() == ieccmp.getEthCrossChainManager(), "msgSender is not EthCrossChainManagerContract");
        _;
    }
    //getEthCrossChainManager()函数得到跨链管理合约的地址，require()的判断用来确保函数的调用者，是跨链管理合约。
	//Unlock()函数中用到，用来确实对应的资产解锁操作，只能由跨链管理合约发出
    
    function setManagerProxy(address ethCCMProxyAddr) onlyOwner public {
        managerProxyContract = ethCCMProxyAddr;
        emit SetManagerProxyEvent(managerProxyContract);
    }
    //CCMP合约部署之后，将CCMP合约的地址赋值给managerProxyContract
    
    function bindProxyHash(uint64 toChainId, bytes memory targetProxyHash) onlyOwner public returns (bool) {
        proxyHashMap[toChainId] = targetProxyHash;
        emit BindProxyEvent(toChainId, targetProxyHash);
        return true;
    }
    //存储链与链之间的CCM合约之间的映射关系
    //以目标链ID（ChainID）为键，CCM合约哈希为值。
    
    function bindAssetHash(address fromAssetHash, uint64 toChainId, bytes memory toAssetHash) onlyOwner public returns (bool) {
        assetHashMap[fromAssetHash][toChainId] = toAssetHash;
        emit BindAssetEvent(fromAssetHash, toChainId, toAssetHash, getBalanceFor(fromAssetHash));
        return true;
    }
    //存储链与链之间的资产映射关系.
    //以源链资产哈希（fromAssetHash）和目标链ID（toChainID）为键，目标资产哈希(toAssetHash)为值。
    
	//lock()函数应该由用户调用，特定数量的代币将会被锁定，ChainID目标链上的代理合约将会解锁对应的代币
    function lock(address fromAssetHash, uint64 toChainId, bytes memory toAddress, uint256 amount) public payable returns (bool) {
        require(amount != 0, "amount cannot be zero!");     //判断锁定金额不能为0
        
        require(_transferToContract(fromAssetHash, amount), "transfer asset from fromAddress to lock_proxy contract  failed!");
        //将对应amount数量的资产转移到LockProxy合约中
        bytes memory toAssetHash = assetHashMap[fromAssetHash][toChainId]; //得到目标链上的资产哈希
        require(toAssetHash.length != 0, "empty illegal toAssetHash");  
        //require()验证确保目标链上的资产哈希不为0
        TxArgs memory txArgs = TxArgs({
            toAssetHash: toAssetHash,
            toAddress: toAddress,
            amount: amount
        });    //构造对应的交易参数
        bytes memory txData = _serializeTxArgs(txArgs);
        //将对应的交易参数结构体，序列化成为对应的字节数据
        IEthCrossChainManagerProxy eccmp = IEthCrossChainManagerProxy(managerProxyContract);
        address eccmAddr = eccmp.getEthCrossChainManager();
        //得到对应的CCM合约的地址
        IEthCrossChainManager eccm = IEthCrossChainManager(eccmAddr);  //实例化CCM合约
        
        bytes memory toProxyHash = proxyHashMap[toChainId];     //得到bytes形式的CCM合约的地址
        require(toProxyHash.length != 0, "empty illegal toProxyHash");   //确保对应bytes形式的CCM合约地址是合法的
        require(eccm.crossChain(toChainId, toProxyHash, "unlock", txData), "EthCrossChainManager crossChain executed error!");
		//调用对应的CCM跨链管理合约的跨链函数
        emit LockEvent(fromAssetHash, _msgSender(), toChainId, toAssetHash, toAddress, amount);
        //锁定完成，emit对应的LockEvent。
        return true;

    }

    //modifier onlyManagerContract限制该函数只能CCM合约来调用，铸造一定数量的代币到指定的地址
    //输入序列化的对应交易数据，源链合约地址，源链ID
    function unlock(bytes memory argsBs, bytes memory fromContractAddr, uint64 fromChainId) onlyManagerContract public returns (bool) {
        TxArgs memory args = _deserializeTxArgs(argsBs);    //反序列化对应的字节数据为交易参数结构体
        require(fromContractAddr.length != 0, "from proxy contract address cannot be empty");  
        //检查确保源链的CCM合约地址不为空
        require(Utils.equalStorage(proxyHashMap[fromChainId], fromContractAddr), "From Proxy contract address error!");
   //Utils.equalStorage()函数用来比较两个字节是否相等，验证传入源链的CCM合约地址哈希是否和proxyHashMap mapping存储的一样
        require(args.toAssetHash.length != 0, "toAssetHash cannot be empty");
        //确保目标链资产地址哈希不为空
        address toAssetHash = Utils.bytesToAddress(args.toAssetHash);
		//将目标链资产地址哈希，取十六进制字符串的后40位，得到目标链资产地址
		
        require(args.toAddress.length != 0, "toAddress cannot be empty");  //确保目标链上的收款地址不为空
        address toAddress = Utils.bytesToAddress(args.toAddress);
        //与上面类似，将对应的字节哈希，转换为目标链上的收款地址
        
        require(_transferFromContract(toAssetHash, toAddress, args.amount), "transfer asset from lock_proxy contract to toAddress failed!");
        //将对应amount数量的资产从LockProxy合约转移到用户的toAddress中
        emit UnlockEvent(toAssetHash, toAddress, args.amount);
        //完成对应的铸造，emit对应的UnlockEvent事件
        return true;
    }
    
    //得到对应的账户余额
    function getBalanceFor(address fromAssetHash) public view returns (uint256) {
        if (fromAssetHash == address(0)) {
            // return address(this).balance; // this expression would result in error: Failed to decode output: Error: insufficient data for uint256 type
            //如果对应的源链资产哈希为空的话，证明不存在对应的代币代理合约，直接返回当前LockProxy合约的余额。
            address selfAddr = address(this);
            return selfAddr.balance;
        } else {
        	//否则的话，根据资产地址哈希实例化对应的ERC20代币，
            IERC20 erc20Token = IERC20(fromAssetHash);
            return erc20Token.balanceOf(address(this));  //返回当前合约账户的对应的ERC20代币余额
        }
    }
    
    //将用户对应的资产地址哈希，从fromAddress转移到对应的LockProxy合约中
    function _transferToContract(address fromAssetHash, uint256 amount) internal returns (bool) {
        if (fromAssetHash == address(0)) {
            // fromAssetHash === address(0) denotes user choose to lock ether
            // passively check if the received msg.value equals amount
            //当对应的资产地址哈希为空的时候，代表用户转移的不是ERC20代币，是ether。
            require(msg.value != 0, "transferred ether cannot be zero!");
            require(msg.value == amount, "transferred ether is not equal to amount!");
            //检查对应的转移的以太数量是否为对应的amount
        } else {
            // make sure lockproxy contract will decline any received ether
            require(msg.value == 0, "there should be no ether transfer!");  //这里不应该有以太的转移
            // actively transfer amount of asset from msg.sender to lock_proxy contract
            require(_transferERC20ToContract(fromAssetHash, _msgSender(), address(this), amount), "transfer erc20 asset to lock_proxy contract failed!");
            //调用函数_transferERC20ToContract()
        }
        return true;
    }
    function _transferFromContract(address toAssetHash, address toAddress, uint256 amount) internal returns (bool) {
        if (toAssetHash == address(0x0000000000000000000000000000000000000000)) {
            // toAssetHash === address(0) denotes contract needs to unlock ether to toAddress
            // convert toAddress from 'address' type to 'address payable' type, then actively transfer ether
            address(uint160(toAddress)).transfer(amount);
            //toAssetHash资产地址为空，表明合约需要解锁以太到toAddress中
        } else {
            // actively transfer amount of asset from lock_proxy contract to toAddress
            require(_transferERC20FromContract(toAssetHash, toAddress, amount), "transfer erc20 asset from lock_proxy contract to toAddress failed!");
            //调用函数_transferERC20FromContract()
        }
        return true;
    }
    
    //将对应数量的ERC20代币转移到LockProxy合约中
    function _transferERC20ToContract(address fromAssetHash, address fromAddress, address toAddress, uint256 amount) internal returns (bool) {
         IERC20 erc20Token = IERC20(fromAssetHash);
         //根据源链的资产地址哈希，实例化对应的ERC20代币，从用户的账户地址转移amount数量代币到LockProxy合约中
        //  require(erc20Token.transferFrom(fromAddress, toAddress, amount), "trasnfer ERC20 Token failed!");
         erc20Token.safeTransferFrom(fromAddress, toAddress, amount);
         return true;
    }
    
    //转移对应的amount数量的ERC20代币到对应的toAddress账户中
    function _transferERC20FromContract(address toAssetHash, address toAddress, uint256 amount) internal returns (bool) {
         IERC20 erc20Token = IERC20(toAssetHash);
         //根据目标链的资产地址哈希，实例化对应的ERC20代币，从LockProxy合约中转移amount数量代币到toAddress中
        //  require(erc20Token.transfer(toAddress, amount), "trasnfer ERC20 Token failed!");
         erc20Token.safeTransfer(toAddress, amount);
         return true;
    }
    
    function _serializeTxArgs(TxArgs memory args) internal pure returns (bytes memory) {
        bytes memory buff;
        buff = abi.encodePacked(
            ZeroCopySink.WriteVarBytes(args.toAssetHash),
            ZeroCopySink.WriteVarBytes(args.toAddress),
            ZeroCopySink.WriteUint255(args.amount)
            );
        return buff;
    }
	//将对应的交易参数结构体，编码序列化成对应的字节数据
    function _deserializeTxArgs(bytes memory valueBs) internal pure returns (TxArgs memory) {
        TxArgs memory args;
        uint256 off = 0;
        (args.toAssetHash, off) = ZeroCopySource.NextVarBytes(valueBs, off);
        (args.toAddress, off) = ZeroCopySource.NextVarBytes(valueBs, off);
        (args.amount, off) = ZeroCopySource.NextUint255(valueBs, off);
        return args;
    }
    //将对应的字节数据，解码反序列化成对应的交易参数结构体
}
```

### Cross Chain Manager Contract:

#### `EthCrossChainManager.sol`

代码github位置：polynetwork/eth-contracts/contracts/core/cross_chain_manager/logic/EthCrossChainManager.sol

https://github.com/polynetwork/eth-contracts/blob/master/contracts/core/cross_chain_manager/logic/EthCrossChainManager.sol

```solidity
pragma solidity ^0.5.0;
pragma experimental ABIEncoderV2;

import "./../../../libs/math/SafeMath.sol";
import "./../../../libs/common/ZeroCopySource.sol";
import "./../../../libs/common/ZeroCopySink.sol";
import "./../../../libs/utils/Utils.sol";
import "./../upgrade/UpgradableECCM.sol";
import "./../libs/EthCrossChainUtils.sol";
import "./../interface/IEthCrossChainManager.sol";
import "./../interface/IEthCrossChainData.sol";
contract EthCrossChainManager is IEthCrossChainManager, UpgradableECCM {
    using SafeMath for uint256;
    
    address public whiteLister;
    mapping(address => bool) public whiteListFromContract;
    //建立地址的白名单，以对应的地址为键，bool值代表该地址是否在白名单中
    mapping(address => mapping(bytes => bool)) public whiteListContractMethodMap;
    //建立可调用函数的白名单。以调用的合约，调用的函数为键，bool值代表能否调用该函数

    event InitGenesisBlockEvent(uint256 height, bytes rawHeader);
    event ChangeBookKeeperEvent(uint256 height, bytes rawHeader);
    event CrossChainEvent(address indexed sender, bytes txId, address proxyOrAssetContract, uint64 toChainId, bytes toContract, bytes rawdata);
    event VerifyHeaderAndExecuteTxEvent(uint64 fromChainID, bytes toContract, bytes crossChainTxHash, bytes fromChainTxHash);
    
    constructor(
        address _eccd, 
        uint64 _chainId, 
        address[] memory fromContractWhiteList, 
        bytes[] memory contractMethodWhiteList
    ) UpgradableECCM(_eccd,_chainId) public {
        whiteLister = msg.sender;   //将初始合约部署者设置为whiteLister
        for (uint i=0;i<fromContractWhiteList.length;i++) {
            whiteListFromContract[fromContractWhiteList[i]] = true;
        }// 初始部署的时候，建立对应的地址白名单。
        
        for (uint i=0;i<contractMethodWhiteList.length;i++) {
            (address toContract,bytes[] memory methods) = abi.decode(contractMethodWhiteList[i],(address,bytes[]));
            //将对应的字节解码成对应合约中的函数，建立对应的可调用函数的白名单
            for (uint j=0;j<methods.length;j++) {
                whiteListContractMethodMap[toContract][methods[j]] = true;
            }
        }
    }
    
    modifier onlyWhiteLister() {
        require(msg.sender == whiteLister, "Not whiteLister");
        _;
    }
    //modifier onlyWhiteLister用来限制一些函数只有whiteLister能够调用

	//只有whiteLister能够调用该函数
    function setWhiteLister(address newWL) public onlyWhiteLister {
        require(newWL!=address(0), "Can not transfer to address(0)");   //判断对应的地址不为空
        whiteLister = newWL;   //将whiteLister设置为newWL。
    }
    
    //只有whiteLister能够调用该函数
    function setFromContractWhiteList(address[] memory fromContractWhiteList) public onlyWhiteLister {
        for (uint i=0;i<fromContractWhiteList.length;i++) {
            whiteListFromContract[fromContractWhiteList[i]] = true;
        }
        //将一些地址加入地址白名单中
    }
    
     //只有whiteLister能够调用该函数
    function removeFromContractWhiteList(address[] memory fromContractWhiteList) public onlyWhiteLister {
        for (uint i=0;i<fromContractWhiteList.length;i++) {
            whiteListFromContract[fromContractWhiteList[i]] = false;
        }
        //将一些地址从地址白名单之中移除
    }
    
    //只有whiteLister能够调用该函数
    function setContractMethodWhiteList(bytes[] memory contractMethodWhiteList) public onlyWhiteLister {
        for (uint i=0;i<contractMethodWhiteList.length;i++) {
            (address toContract,bytes[] memory methods) = abi.decode(contractMethodWhiteList[i],(address,bytes[]));   //将对应的数据进行解码
            for (uint j=0;j<methods.length;j++) {
                whiteListContractMethodMap[toContract][methods[j]] = true;
            }
            //将一些合约中的可调用函数加入白名单之中
        }
    }
    
    //只有whiteLister能够调用该函数
    function removeContractMethodWhiteList(bytes[] memory contractMethodWhiteList) public onlyWhiteLister {
        for (uint i=0;i<contractMethodWhiteList.length;i++) {
            (address toContract,bytes[] memory methods) = abi.decode(contractMethodWhiteList[i],(address,bytes[]));   //将对应的数据进行解码
            for (uint j=0;j<methods.length;j++) {
                whiteListContractMethodMap[toContract][methods[j]] = false;
            }
            //将一些合约中的可调用函数从白名单中移除
        }
    }

    /* @notice              sync Poly chain genesis block header to smart contrat
    *  @dev                 this function can only be called once, nextbookkeeper of rawHeader can't be empty
    *  @param rawHeader     Poly chain genesis block raw header or raw Header including switching consensus peers info
    */
    //同步Poly Chain的原始区块头到CCD智能合约，该函数只能初始被调用一次，保存共识验证者公钥
    function initGenesisBlock(bytes memory rawHeader, bytes memory pubKeyList) whenNotPaused public returns(bool) {
        IEthCrossChainData eccd = IEthCrossChainData(EthCrossChainDataAddress);
        //实例化CCD合约

        require(eccd.getCurEpochConPubKeyBytes().length == 0, "EthCrossChainData contract has already been initialized!");
        //判断CCD合约之前有无被初始化过，获取存储的共识验证者的公钥所对应的字节，若其长度为0，则说明CCD合约未被初始化
        
        ECCUtils.Header memory header = ECCUtils.deserializeHeader(rawHeader);
        //将字节形式的rawHeader区块头，去序列化为header结构体
        
        (bytes20 nextBookKeeper, address[] memory keepers) = ECCUtils.verifyPubkey(pubKeyList);
        require(header.nextBookkeeper == nextBookKeeper, "NextBookers illegal");
        //从共识验证者的公钥，得到nextBookKeeper，与区块头中保存的nextBookKeeper进行对比，验证对应的公钥是否合法
        //并计算出对应的共识验证者的地址keepers
        
        require(eccd.putCurEpochStartHeight(header.height), "Save Poly chain current epoch start height to Data contract failed!");
        //记录当前epoch区块的起始高度，并要将其保存到CCD合约之中
        require(eccd.putCurEpochConPubKeyBytes(ECCUtils.serializeKeepers(keepers)), "Save Poly chain current epoch book keepers to Data contract failed!");
        //将共识验证者的公钥序列化为bytes形式，并将其保存到CCD合约之中

        emit InitGenesisBlockEvent(header.height, rawHeader);
        //emit对应的事件，包含原始区块头的高度，和原始区块头的信息
        return true;
    }

    //改变CCD合约中保存的区块高度，共识验证者公钥对应的字节，并存储入CCD合约
    function changeBookKeeper(bytes memory rawHeader, bytes memory pubKeyList, bytes memory sigList) whenNotPaused public returns(bool) {
        ECCUtils.Header memory header = ECCUtils.deserializeHeader(rawHeader);
        //将对应的区块头，解码为结构体形式的区块头Header
        IEthCrossChainData eccd = IEthCrossChainData(EthCrossChainDataAddress);
        //实例化对应的CCD合约

        uint64 curEpochStartHeight = eccd.getCurEpochStartHeight();
        require(header.height > curEpochStartHeight, "The height of header is lower than current epoch start height!");
        //调用CCD合约getCurEpochStartHeight()函数，获取之前保存的区块高度
        //require()用来确保传入的区块头对应的高度要高于对应CCD合约中保存的区块头高度

        require(header.nextBookkeeper != bytes20(0), "The nextBookKeeper of header is empty");
        //确保rawHeader是关键区块头，包含切换共识验证者的信息

        address[] memory polyChainBKs = ECCUtils.deserializeKeepers(eccd.getCurEpochConPubKeyBytes());
        //从CCD合约中获取保存的共识验证者公钥的字节，将字节解码为对应的共识验证者的地址
        uint n = polyChainBKs.length;
        //得到对应的共识验证者的数量
        require(ECCUtils.verifySig(rawHeader, sigList, polyChainBKs, n - (n - 1) / 3), "Verify signature failed!");
        //poly chain上的区块是由共识验证者投票决定。
        //调用函数，验证共识验证者的签名，签名者必须大于2/3共识验证者的数目，验证该区块头是否合法
        
        // Convert pubKeyList into ethereum address format and make sure the compound address from the converted ethereum addresses
        // equals passed in header.nextBooker
        (bytes20 nextBookKeeper, address[] memory keepers) = ECCUtils.verifyPubkey(pubKeyList);
        require(header.nextBookkeeper == nextBookKeeper, "NextBookers illegal");
         //从共识验证者的公钥，得到nextBookKeeper，与区块头中保存的nextBookKeeper进行对比，验证对应的公钥是否合法

        require(eccd.putCurEpochStartHeight(header.height), "Save MC LatestHeight to Data contract failed!");
        //将新的当前epoch的区块高度存入CCD合约之中
        require(eccd.putCurEpochConPubKeyBytes(ECCUtils.serializeKeepers(keepers)), "Save Poly chain book keepers bytes to Data contract failed!");
        //将新的共识验证者地址序列化，成对应的字节，并存入CCD合约之中
        
        emit ChangeBookKeeperEvent(header.height, rawHeader);
        //emit对应的事件，表示以太坊上更改了Poly chain上的共识验证者地址
        return true;
    }

    //源链：ERC20代币跨链到其它链上，该函数将tx对应的event发布到区块链上
    //输入的参数：目标链ID，目标链上的智能合约地址，目标链上准备调用的函数方法method，以及交易数据
    function crossChain(uint64 toChainId, bytes calldata toContract, bytes calldata method, bytes calldata txData) whenNotPaused external returns (bool) {
        require(whiteListFromContract[msg.sender],"Invalid from contract");
        //进行判断，只允许白名单中的合约地址能够调用该函数
        IEthCrossChainData eccd = IEthCrossChainData(EthCrossChainDataAddress);
        //实例化对应的CCD合约
        
        uint256 txHashIndex = eccd.getEthTxHashIndex();
        //得到对应跨链交易哈希的index，用来区分两个交易
        
        bytes memory paramTxHash = Utils.uint256ToBytes(txHashIndex);
        //将对应的uint256,转化为bytes形式，用于构造rawParam。

        bytes memory rawParam = abi.encodePacked(ZeroCopySink.WriteVarBytes(paramTxHash),
            ZeroCopySink.WriteVarBytes(abi.encodePacked(sha256(abi.encodePacked(address(this), paramTxHash)))),
            ZeroCopySink.WriteVarBytes(Utils.addressToBytes(msg.sender)),
            ZeroCopySink.WriteUint64(toChainId),
            ZeroCopySink.WriteVarBytes(toContract),
            ZeroCopySink.WriteVarBytes(method),
            ZeroCopySink.WriteVarBytes(txData)
        );
        //构造rawParam交易的数据，并将它的哈希保存，作为交易存在的证明
        
        require(eccd.putEthTxHash(keccak256(rawParam)), "Save ethTxHash by index to Data contract failed!");
        //将对应的交易信息取哈希，将其存入CCD合约中的映射

        emit CrossChainEvent(tx.origin, paramTxHash, msg.sender, toChainId, toContract, rawParam);
        //emit对应的跨链事件，表示以太坊网络通过Poly Chain向其他公共链发送跨链请求
        return true;
    }
    /* @notice              Verify Poly chain header and proof, execute the cross chain tx from Poly chain to Ethereum
    *  @param proof         Poly chain tx merkle proof
    *  @param rawHeader     The header containing crossStateRoot to verify the above tx merkle proof
    *  @param headerProof   The header merkle proof used to verify rawHeader
    *  @param curRawHeader  Any header in current epoch consensus of Poly chain
    *  @param headerSig     The coverted signature veriable for solidity derived from Poly chain consensus nodes' signature
    *                       used to verify the validity of curRawHeader
    *  @return              true or false
    */
    //目标链：验证Poly Chain上的区块头和对应的交易证明，在以太坊上执行来自Poly Chain的跨链交易
    //输入：Poly Chain上的交易证明，包含验证poly chain上交易的crossStateRoot的区块头
    //，，poly chain上的共识验证者的签名
    function verifyHeaderAndExecuteTx(bytes memory proof, bytes memory rawHeader, bytes memory headerProof, bytes memory curRawHeader,bytes memory headerSig) whenNotPaused public returns (bool){
        ECCUtils.Header memory header = ECCUtils.deserializeHeader(rawHeader);
        //将对应的rawHeader解码成对应的Header结构体
     
        IEthCrossChainData eccd = IEthCrossChainData(EthCrossChainDataAddress);
        //实例化对应的CCD合约

        address[] memory polyChainBKs = ECCUtils.deserializeKeepers(eccd.getCurEpochConPubKeyBytes());
		//从CCD合约中获取保存的共识验证者公钥的字节，将字节解码为对应的共识验证者的地址
        uint256 curEpochStartHeight = eccd.getCurEpochStartHeight();
		//从CCD合约中获取保存的区块高度。

        uint n = polyChainBKs.length;     //得到共识验证者的数量
        if (header.height >= curEpochStartHeight) {
        	//如果跨链交易区块高度大于CCD中保存的区块高度，说明两者是在一个epoch中，直接验证交易区块头的签名
            // It's enough to verify rawHeader signature
            require(ECCUtils.verifySig(rawHeader, headerSig, polyChainBKs, n - ( n - 1) / 3), "Verify poly chain header signature failed!");
            //验证包含跨链交易的rawHeader，是否经过了poly chain上的共识验证者签名
            
        } else {
            // We need to verify the signature of curHeader 
            require(ECCUtils.verifySig(curRawHeader, headerSig, polyChainBKs, n - ( n - 1) / 3), "Verify poly chain current epoch header signature failed!");
            //验证poly chain上当前epoch的区块头是否经过了共识验证者的签名

            // Then use curHeader.StateRoot and headerProof to verify rawHeader.CrossStateRoot
            ECCUtils.Header memory curHeader = ECCUtils.deserializeHeader(curRawHeader);
            //解码出poly chain上当前epoch区块头的结构体信息
            bytes memory proveValue = ECCUtils.merkleProve(headerProof, curHeader.blockRoot);
            //通过headerProof,验证rawHeader区块头是否为合法区块头。
            require(ECCUtils.getHeaderHash(rawHeader) == Utils.bytesToBytes32(proveValue), "verify header proof failed!");
        }
        
        // Through rawHeader.CrossStatesRoot, the toMerkleValue or cross chain msg can be verified and parsed from proof
        bytes memory toMerkleValueBs = ECCUtils.merkleProve(proof, header.crossStatesRoot);
        //验证poly chain上包含的跨链交易，根据proof解析出包含的跨链信息toMerkleValueBs
 
        ECCUtils.ToMerkleValue memory toMerkleValue = ECCUtils.deserializeMerkleValue(toMerkleValueBs);
        //解析字节形式的toMerkleValueBs为对应的结构体
        
        require(!eccd.checkIfFromChainTxExist(toMerkleValue.fromChainID, Utils.bytesToBytes32(toMerkleValue.txHash)), "the transaction has been executed!");
        //require()调用CCD合约checkIfFromChainTxExist()函数来，根据chainID和交易哈希判断该交易是否已经处理过
        
        require(eccd.markFromChainTxExist(toMerkleValue.fromChainID, Utils.bytesToBytes32(toMerkleValue.txHash)), "Save crosschain tx exist failed!");
        //require()调用CCD合约markFromChainTxExist()函数，根据chainID和交易哈希标记该交易已经处理

        require(toMerkleValue.makeTxParam.toChainId == chainId, "This Tx is not aiming at this network!");
        //检查交易中保存的toChainID是否为以太坊

        address toContract = Utils.bytesToAddress(toMerkleValue.makeTxParam.toContract);
        //获取目标合约，并将其转换为地址，以便CCM合约触发跨链交易tx在以太坊上执行

        require(whiteListContractMethodMap[toContract][toMerkleValue.makeTxParam.method],"Invalid to contract or method");
        //判断交易调用的合约，和对应的函数是否保存在对应的白名单之中

        require(_executeCrossChainTx(toContract, toMerkleValue.makeTxParam.method, toMerkleValue.makeTxParam.args, toMerkleValue.makeTxParam.fromContract, toMerkleValue.fromChainID), "Execute CrossChain Tx failed!");
        //执行对应的跨链函数

        emit VerifyHeaderAndExecuteTxEvent(toMerkleValue.fromChainID, toMerkleValue.makeTxParam.toContract, toMerkleValue.txHash, toMerkleValue.makeTxParam.txHash);
		//emit 对应事件，表示从其它公链到以太坊这样的跨链交易成功执行
        return true;
    }

    //调用对应的目标合约，触发以太坊上跨链交易的执行
    //输入：调用的合约的地址，调用的函数，输入的参数，源链上智能合约的地址，源链的chainID
    function _executeCrossChainTx(address _toContract, bytes memory _method, bytes memory _args, bytes memory _fromContractAddr, uint64 _fromChainId) internal returns (bool){
        require(Utils.isContract(_toContract), "The passed in address is not a contract!");
        //确保将要调用的_toContract是一个合约，而不是一个账户地址
        bytes memory returnData;
        bool success;

        (success, returnData) = _toContract.call(abi.encodePacked(bytes4(keccak256(abi.encodePacked(_method, "(bytes,bytes,uint64)"))), abi.encode(_args, _fromContractAddr, _fromChainId)));
		//首先将_method和输入参数的格式“(bytes,bytes,uint64)”进行encodePacked编码
		//使用keccak256计算编码字符的哈希，并取前四个字节。
		//将哈希的前四个字节，和encode编码的三个参数，一起进行encodePacked编码，作为一个函数调用
		
        require(success == true, "EthCrossChain call business contract failed");
        //确保对应函数的调用成功执行

        require(returnData.length != 0, "No return value from business contract!");
        (bool res,) = ZeroCopySource.NextBool(returnData, 31);
        require(res == true, "EthCrossChain call business contract return is not true");
        //调用方法后，检查对应的返回值，调用成功，returnData将是bytes32类型，并且最后一个字节为01.
        //只有返回值为真，整个跨链交易才会执行成功
        return true;
    }
}
```

### Cross Chain Manager Proxy Contract:

#### `EthCrossChainManagerProxy.sol`

代码github位置：polynetwork/eth-contracts/contracts/core/cross_chain_manager/upgrade/EthCrossChainManagerProxy.sol

https://github.com/polynetwork/eth-contracts/blob/master/contracts/core/cross_chain_manager/upgrade/EthCrossChainManagerProxy.sol

```solidity
pragma solidity ^0.5.0;
import "./../../../libs/ownership/Ownable.sol";
import "./../../../libs/lifecycle/Pausable.sol";
import "./../interface/IUpgradableECCM.sol";
import "./../interface/IEthCrossChainManagerProxy.sol";

contract EthCrossChainManagerProxy is IEthCrossChainManagerProxy, Ownable, Pausable {
    address private EthCrossChainManagerAddr_;   //对应的跨链管理合约的地址 
    
    constructor(address _ethCrossChainManagerAddr) public {
        EthCrossChainManagerAddr_ = _ethCrossChainManagerAddr;
    }  //constructor()在合约部署的时候，设置跨链管理合约的地址
    
    //调用者账户pause()函数，触发合约到对应的暂停状态
    function pause() onlyOwner public returns (bool) {
        if (paused()) {
            return true;
        }
        _pause();
        return true;
    }
    //调用者账户unpause()函数，恢复合约到对应的正常状态
    function unpause() onlyOwner public returns (bool) {
        if (!paused()) {
            return true;
        }
        _unpause();
        return true;
    }
    //触发对应的跨链管理合约为暂停状态
    function pauseEthCrossChainManager() onlyOwner whenNotPaused public returns (bool) {
        IUpgradableECCM eccm = IUpgradableECCM(EthCrossChainManagerAddr_);
        require(pause(), "pause EthCrossChainManagerProxy contract failed!");
        //将CCMP合约设置为暂停状态
        require(eccm.pause(), "pause EthCrossChainManager contract failed!");
        //将CCM合约设置为暂停状态
    }
    
    //更新跨链管理合约CCM合约的地址
    function upgradeEthCrossChainManager(address _newEthCrossChainManagerAddr) onlyOwner whenPaused public returns (bool) {
        IUpgradableECCM eccm = IUpgradableECCM(EthCrossChainManagerAddr_);
        if (!eccm.paused()) {
            require(eccm.pause(), "Pause old EthCrossChainManager contract failed!");
        }
        //更新CCM合约之前，先将CCM合约的状态设置为暂停状态。
        require(eccm.upgradeToNew(_newEthCrossChainManagerAddr), "EthCrossChainManager upgradeToNew failed!");
        //调用该函数，将对应的modifier中的owner设置为新的跨链管理合约的地址
        IUpgradableECCM neweccm = IUpgradableECCM(_newEthCrossChainManagerAddr);
        require(neweccm.isOwner(), "EthCrossChainManagerProxy is not owner of new EthCrossChainManager contract");
        EthCrossChainManagerAddr_ = _newEthCrossChainManagerAddr;
    }
    
    //将对应的跨链管理合约恢复为正常状态
    function unpauseEthCrossChainManager() onlyOwner whenPaused public returns (bool) {
        IUpgradableECCM eccm = IUpgradableECCM(EthCrossChainManagerAddr_);
        require(eccm.unpause(), "unpause EthCrossChainManager contract failed!");
        //将CCM合约恢复为正常状态
        require(unpause(), "unpause EthCrossChainManagerProxy contract failed!");
        //将CCMP合约恢复为正常状态
    }
    
    //调用该函数获得CCM合约的地址
    function getEthCrossChainManager() whenNotPaused public view returns (address) {
        return EthCrossChainManagerAddr_;
    }
    
    //改变区块链的链ID
    function changeManagerChainID(uint64 _newChainId) onlyOwner whenPaused public {
        IUpgradableECCM eccm = IUpgradableECCM(EthCrossChainManagerAddr_);
        if (!eccm.paused()) {
            require(eccm.pause(), "Pause old EthCrossChainManager contract failed!");
        }
        //在修改链ID之前，将对应的CCM跨链管理合约触发为暂停状态
        require(eccm.setChainId(_newChainId), "set chain ID failed. ");
    }
}
```

### Cross Chain Data Contract:

#### `EthCorssChainData.sol`

代码github位置：polynetwork/eth-contracts/contracts/core/cross_chain_manager/data/EthCrossChainData.sol

https://github.com/polynetwork/eth-contracts/blob/master/contracts/core/cross_chain_manager/data/EthCrossChainData.sol

```solidity
pragma solidity ^0.5.0;
import "./../../../libs/ownership/Ownable.sol";
import "./../../../libs/lifecycle/Pausable.sol";
import "./../interface/IEthCrossChainData.sol";
contract EthCrossChainData is IEthCrossChainData, Ownable, Pausable{
    //该映射存储以太坊发起的跨链交易的哈希值，以自增的index为键，对应的跨链交易哈希为值
    //该映射是为了Poly Chain可以验证来自以太坊的跨链交易请求tx的存在
    mapping(uint256 => bytes32) public EthToPolyTxHashMap;
    
    // uint256 index记录着当前映射mapping的长度
    uint256 public EthToPolyTxHashIndex;
    
    //当Poly Chain更改共识验证者的时候，poly chain的共识验证者的公钥需要转换成bytes形式，
    //以便智能合约将其转换为地址类型，并验证Poly chain账户签名衍生的签名
    bytes public ConKeepersPkBytes;

    //记录着poly chain区块上当前epoch的起始高度
    uint32 public CurEpochStartHeight;
    
    //以链的chainID,对应的跨链交易bytes为键，映射的值--表示该交易是否已经被处理
    mapping(uint64 => mapping(bytes32 => bool)) FromChainTxExist;
    
    // 未用到，未来的潜在使用
    mapping(bytes32 => mapping(bytes32 => bytes)) public ExtraData;
    
    // 存储poly chain区块上当前epoch的起始高度
    function putCurEpochStartHeight(uint32 curEpochStartHeight) public whenNotPaused onlyOwner returns (bool) {
        CurEpochStartHeight = curEpochStartHeight;
        return true;
    }

    // 获得之前存储的poly chain区块上的epoch的起始高度
    function getCurEpochStartHeight() public view returns (uint32) {
        return CurEpochStartHeight;
    }

    //存储共识验证者的公钥对应的字节
    function putCurEpochConPubKeyBytes(bytes memory curEpochPkBytes) public whenNotPaused onlyOwner returns (bool) {
        ConKeepersPkBytes = curEpochPkBytes;
        return true;
    }

    // 获得之前存储的共识验证者的公钥所对应的字节
    function getCurEpochConPubKeyBytes() public view returns (bytes memory) {
        return ConKeepersPkBytes;
    }

    // 标记来自源链chainID,对应的bytes32 tx已经被处理，modifier onlyOwner显示只有对应的owner才能调用该函数
    function markFromChainTxExist(uint64 fromChainId, bytes32 fromChainTx) public whenNotPaused onlyOwner returns (bool) {
        FromChainTxExist[fromChainId][fromChainTx] = true;
        return true;
    }

    //判断来自fromchainID的交易fromchaintx是否已经被处理
    function checkIfFromChainTxExist(uint64 fromChainId, bytes32 fromChainTx) public view returns (bool) {
        return FromChainTxExist[fromChainId][fromChainTx];
    }

    //获取当前记录的跨链请求tx的索引，该txs是记录从以太坊到其它公共链的跨链请求
    //以帮助CCM合约来区分两个跨链tx的请求
    function getEthTxHashIndex() public view returns (uint256) {
        return EthToPolyTxHashIndex;
    }

    //保存以太坊上的跨链交易tx的哈希，将对应记录的index自增1
    function putEthTxHash(bytes32 ethTxHash) public whenNotPaused onlyOwner returns (bool) {
        EthToPolyTxHashMap[EthToPolyTxHashIndex] = ethTxHash;
        EthToPolyTxHashIndex = EthToPolyTxHashIndex + 1;
        return true;
    }

    //根据对应的ethTxHashIndex索引来获得对应的以太坊上的跨链交易的哈希
    function getEthTxHash(uint256 ethTxHashIndex) public view returns (bytes32) {
        return EthToPolyTxHashMap[ethTxHashIndex];
    }

    // extra data的存储函数, 可能未来使用
    function putExtraData(bytes32 key1, bytes32 key2, bytes memory value) public whenNotPaused onlyOwner returns (bool) {
        ExtraData[key1][key2] = value;
        return true;
    }
    // extra data的读取函数，可能未来使用
    function getExtraData(bytes32 key1, bytes32 key2) public view returns (bytes memory) {
        return ExtraData[key1][key2];
    }
    
    //调用pause()函数，触发将对应的合约设置为停止状态
    function pause() onlyOwner whenNotPaused public returns (bool) {
        _pause();
        return true;
    }
    
    //调用unpause()函数，将对应的合约设置为恢复
    function unpause() onlyOwner whenPaused public returns (bool) {
        _unpause();
        return true;
    }
}
```

### 其它关键合约

#### `EthCrossChainUtils.sol`

代码github位置：polynetwork/eth-contracts/contracts/core/cross_chain_manager/libs/EthCrossChainUtils.sol

https://github.com/polynetwork/eth-contracts/blob/master/contracts/core/cross_chain_manager/libs/EthCrossChainUtils.sol

```solidity
pragma solidity ^0.5.0;
import "./../../../libs/common/ZeroCopySource.sol";
import "./../../../libs/common/ZeroCopySink.sol";
import "./../../../libs/utils/Utils.sol";
import "./../../../libs/math/SafeMath.sol";
library ECCUtils {
    using SafeMath for uint256;       //基本的算术运算，防止溢出
    struct Header {
        uint32 version;
        uint64 chainId;
        uint32 timestamp;
        uint32 height;
        uint64 consensusData;
        bytes32 prevBlockHash;
        bytes32 transactionsRoot;
        bytes32 crossStatesRoot;
        bytes32 blockRoot;
        bytes consensusPayload;
        bytes20 nextBookkeeper;
    }       
    struct ToMerkleValue {
        bytes  txHash;  // cross chain txhash
        uint64 fromChainID;
        TxParam makeTxParam;
    }
    struct TxParam {
        bytes txHash; //  source chain txhash
        bytes crossChainId;
        bytes fromContract;
        uint64 toChainId;
        bytes toContract;
        bytes method;
        bytes args;
    }
    uint constant POLYCHAIN_PUBKEY_LEN = 67;
    uint constant POLYCHAIN_SIGNATURE_LEN = 65;

    /* @notice                  Verify Poly chain transaction whether exist or not
    *  @param _auditPath        Poly chain merkle proof
    *  @param _root             Poly chain root
    *  @return                  The verified value included in _auditPath
    */
    //进行merkle proof的验证，验证对应的交易是否合法，proof中包含对应的跨链消息，解码返回
    function merkleProve(bytes memory _auditPath, bytes32 _root) internal pure returns (bytes memory) {
        uint256 off = 0;
        bytes memory value;
        (value, off)  = ZeroCopySource.NextVarBytes(_auditPath, off);
        bytes32 hash = Utils.hashLeaf(value);
        //从_auditPath中读取得到树的根哈希值
        
        uint size = _auditPath.length.sub(off).div(33);
        //得到对应的节点数量，每个节点33个字节，第一个字节代表左右节点，32字节哈希
        bytes32 nodeHash;
        byte pos;
        for (uint i = 0; i < size; i++) {
            (pos, off) = ZeroCopySource.NextByte(_auditPath, off);
            //读取每个节点的第一个字节进行判断
            (nodeHash, off) = ZeroCopySource.NextHash(_auditPath, off);
            //获取每个节点的节点哈希
            if (pos == 0x00) {
                hash = Utils.hashChildren(nodeHash, hash);
            } else if (pos == 0x01) {
                hash = Utils.hashChildren(hash, nodeHash);
            } else {
                revert("merkleProve, NextByte for position info failed");
                节点第一个字节不符合对应格式，报错
            }
            //判断节点为对应的左节点还是右结点，分别计算对应的哈希
        }
        require(hash == _root, "merkleProve, expect root is not equal actual root");
        //将对应根据路径计算出的哈希值，和保存的哈希值进行比较，判断对应根哈希是否正确
        return value;
    }

    /* @notice              calculate next book keeper according to public key list
    *  @param _keyLen       consensus node number
    *  @param _m            minimum signature number
    *  @param _pubKeyList   consensus node public key list
    *  @return              two element: next book keeper, consensus node signer addresses
    */
    //根据共识验证者的公钥来计算出下一代的共识验证者
    //输入：共识验证者的数量，最少的签名数量，共识验证者的公钥
    //输出：bytes下一代共识验证者，以及共识验证者的地址
    function _getBookKeeper(uint _keyLen, uint _m, bytes memory _pubKeyList) internal pure returns (bytes20, address[] memory){
         bytes memory buff;
         buff = ZeroCopySink.WriteUint16(uint16(_keyLen));
         address[] memory keepers = new address[](_keyLen);
         bytes32 hash;
         bytes memory publicKey;
         for(uint i = 0; i < _keyLen; i++){
             publicKey = Utils.slice(_pubKeyList, i*POLYCHAIN_PUBKEY_LEN, POLYCHAIN_PUBKEY_LEN);
             //得到每个共识验证者对应的公钥
             buff =  abi.encodePacked(buff, ZeroCopySink.WriteVarBytes(Utils.compressMCPubKey(publicKey)));
             hash = keccak256(Utils.slice(publicKey, 3, 64));
             keepers[i] = address(uint160(uint256(hash)));
             //将公钥进行哈希，获得共识验证者的地址
         }

         buff = abi.encodePacked(buff, ZeroCopySink.WriteUint16(uint16(_m)));
         bytes20  nextBookKeeper = ripemd160(abi.encodePacked(sha256(buff)));
         return (nextBookKeeper, keepers);
    }

    /* @notice              Verify public key derived from Poly chain
    *  @param _pubKeyList   serialized consensus node public key list
    *  @param _sigList      consensus node signature list
    *  @return              return two element: next book keeper, consensus node signer addresses
    */
    //验证来自poly chain的公钥   输入是序列化的共识验证者公钥
    //返回的是下一代的共识验证者，以及对应共识验证者的地址。
    function verifyPubkey(bytes memory _pubKeyList) internal pure returns (bytes20, address[] memory) {
        require(_pubKeyList.length % POLYCHAIN_PUBKEY_LEN == 0, "_pubKeyList length illegal!");
        //确保公钥长度能够整除单个polychain上的公钥长度，确保公钥长度合法
        uint n = _pubKeyList.length / POLYCHAIN_PUBKEY_LEN;  //得到对应的公钥数量
        require(n >= 1, "too short _pubKeyList!");     //验证确保公钥的数量大于1
        return _getBookKeeper(n, n - (n - 1) / 3, _pubKeyList);
        //调用_getBookKeeper()获得共识验证者的地址
    }

    /* @notice              Verify Poly chain consensus node signature
    *  @param _rawHeader    Poly chain block header raw bytes
    *  @param _sigList      consensus node signature list
    *  @param _keepers      addresses corresponding with Poly chain book keepers' public keys
    *  @param _m            minimum signature number
    *  @return              true or false
    */
    //验证poly chain上的共识验证者的签名，判断某个交易是否经过poly chain的验证
    //输入：poly chain上的区块头数据，共识验证者的签名，共识验证者地址，最少需要有的签名数量
    function verifySig(bytes memory _rawHeader, bytes memory _sigList, address[] memory _keepers, uint _m) internal pure returns (bool){
        bytes32 hash = getHeaderHash(_rawHeader);
		
        uint sigCount = _sigList.length.div(POLYCHAIN_SIGNATURE_LEN);
        address[] memory signers = new address[](sigCount);
        bytes32 r;
        bytes32 s;
        uint8 v;
        for(uint j = 0; j  < sigCount; j++){
            r = Utils.bytesToBytes32(Utils.slice(_sigList, j*POLYCHAIN_SIGNATURE_LEN, 32));
            s =  Utils.bytesToBytes32(Utils.slice(_sigList, j*POLYCHAIN_SIGNATURE_LEN + 32, 32));
            v =  uint8(_sigList[j*POLYCHAIN_SIGNATURE_LEN + 64]) + 27;
            signers[j] =  ecrecover(sha256(abi.encodePacked(hash)), v, r, s);
            if (signers[j] == address(0)) return false;
        }
        //利用共识验证者的签名，调用ecrecover()函数计算出签名者的地址，进行地址的验证
        return Utils.containMAddresses(_keepers, signers, _m);
		//调用Utils中的containMAddresses函数
		//来判断区块头中计算出的签名者公钥，和CCD保存的签名者公钥，是否有_m个签名，验证是否通过
    }

    //将对应的poly chain上的共识验证者的地址，编码为对应的bytes字节形式
    function serializeKeepers(address[] memory keepers) internal pure returns (bytes memory) {
        uint256 keeperLen = keepers.length;
        bytes memory keepersBytes = ZeroCopySink.WriteUint64(uint64(keeperLen));
        for(uint i = 0; i < keeperLen; i++) {
            keepersBytes = abi.encodePacked(keepersBytes, ZeroCopySink.WriteVarBytes(Utils.addressToBytes(keepers[i])));
        }
        return keepersBytes;
    }

    //将poly chain上的字节bytes形式保存的共识验证者地址，解码为address形式
    function deserializeKeepers(bytes memory keepersBytes) internal pure returns (address[] memory) {
        uint256 off = 0;
        uint64 keeperLen;
        (keeperLen, off) = ZeroCopySource.NextUint64(keepersBytes, off);
        address[] memory keepers = new address[](keeperLen);
        bytes memory keeperBytes;
        for(uint i = 0; i < keeperLen; i++) {
            (keeperBytes, off) = ZeroCopySource.NextVarBytes(keepersBytes, off);
            keepers[i] = Utils.bytesToAddress(keeperBytes);
        }
        return keepers;
    }

    //将Poly Chain传递的交易数据进行解码，得到对应的toMerkleValue结构体数据
    function deserializeMerkleValue(bytes memory _valueBs) internal pure returns (ToMerkleValue memory) {
        ToMerkleValue memory toMerkleValue;
        uint256 off = 0;

        (toMerkleValue.txHash, off) = ZeroCopySource.NextVarBytes(_valueBs, off);
        (toMerkleValue.fromChainID, off) = ZeroCopySource.NextUint64(_valueBs, off);

        TxParam memory txParam;

        (txParam.txHash, off) = ZeroCopySource.NextVarBytes(_valueBs, off);
        (txParam.crossChainId, off) = ZeroCopySource.NextVarBytes(_valueBs, off);
        (txParam.fromContract, off) = ZeroCopySource.NextVarBytes(_valueBs, off);
        (txParam.toChainId, off) = ZeroCopySource.NextUint64(_valueBs, off);
        (txParam.toContract, off) = ZeroCopySource.NextVarBytes(_valueBs, off);
        (txParam.method, off) = ZeroCopySource.NextVarBytes(_valueBs, off);
        (txParam.args, off) = ZeroCopySource.NextVarBytes(_valueBs, off);
        
        toMerkleValue.makeTxParam = txParam;

        return toMerkleValue;
    }

    //将对应的bytes形式的rawHeader，解码成对应的Header结构体
    function deserializeHeader(bytes memory _headerBs) internal pure returns (Header memory) {
        Header memory header;
        uint256 off = 0;
        (header.version, off)  = ZeroCopySource.NextUint32(_headerBs, off);
        (header.chainId, off) = ZeroCopySource.NextUint64(_headerBs, off);
        (header.prevBlockHash, off) = ZeroCopySource.NextHash(_headerBs, off);
        (header.transactionsRoot, off) = ZeroCopySource.NextHash(_headerBs, off);
        (header.crossStatesRoot, off) = ZeroCopySource.NextHash(_headerBs, off);
        (header.blockRoot, off) = ZeroCopySource.NextHash(_headerBs, off);
        (header.timestamp, off) = ZeroCopySource.NextUint32(_headerBs, off);
        (header.height, off) = ZeroCopySource.NextUint32(_headerBs, off);
        (header.consensusData, off) = ZeroCopySource.NextUint64(_headerBs, off);
        (header.consensusPayload, off) = ZeroCopySource.NextVarBytes(_headerBs, off);
        (header.nextBookkeeper, off) = ZeroCopySource.NextBytes20(_headerBs, off);
        return header;
    }

    /* @notice            Deserialize Poly chain block header raw bytes
    *  @param rawHeader   Poly chain block header raw bytes
    *  @return            header hash same as Poly chain
    */
    //得到poly chain上的区块头数据的哈希
    function getHeaderHash(bytes memory rawHeader) internal pure returns (bytes32) {
        return sha256(abi.encodePacked(sha256(rawHeader)));
    }
}
```

#### `UpgradableECCM.sol`

代码github位置：polynetwork/eth-contracts/contracts/core/cross_chain_manager/upgrade/UpgradableECCM.sol

https://github.com/polynetwork/eth-contracts/blob/master/contracts/core/cross_chain_manager/upgrade/UpgradableECCM.sol

```solidity
pragma solidity ^0.5.0;

import "./../interface/IEthCrossChainData.sol";
import "./../interface/IUpgradableECCM.sol";
import "./../../../libs/lifecycle/Pausable.sol";
import "./../../../libs/ownership/Ownable.sol";

contract UpgradableECCM is IUpgradableECCM, Ownable, Pausable {
    address public EthCrossChainDataAddress;
    uint64 public chainId;  
    
    constructor (address ethCrossChainDataAddr, uint64 _chainId) Pausable() Ownable()  public {
        EthCrossChainDataAddress = ethCrossChainDataAddr;
        chainId = _chainId;
    }
    //初始化部署时，输入对应的CCD合约的地址，和对应的chainID
    
    function pause() onlyOwner public returns (bool) {
        if (!paused()) {
            _pause();
        }
        IEthCrossChainData eccd = IEthCrossChainData(EthCrossChainDataAddress);
        if (!eccd.paused()) {
            require(eccd.pause(), "pause EthCrossChainData contract failed");
        }
        //将该合约和CCD合约，触发为暂停状态
        return true;
    }
    
    function unpause() onlyOwner public returns (bool) {
        if (paused()) {
            _unpause();
        }
        IEthCrossChainData eccd = IEthCrossChainData(EthCrossChainDataAddress);
        if (eccd.paused()) {
            require(eccd.unpause(), "unpause EthCrossChainData contract failed");
        }
        //将该合约和CCD合约，恢复为正常状态
        return true;
    }

    // modifier onlyOwner限制只有owner，才能将对应的owner更改为新的CCM合约地址
    function upgradeToNew(address newEthCrossChainManagerAddress) whenPaused onlyOwner public returns (bool) {
        IEthCrossChainData eccd = IEthCrossChainData(EthCrossChainDataAddress);
        eccd.transferOwnership(newEthCrossChainManagerAddress);
        //该函数用于将modifier中的owner更改为新的CCM合约地址
        return true;
    }
    
    //更改chainID,modifier onlyOwner限制只有owner才能更改对应的chainID
    function setChainId(uint64 _newChainId) whenPaused onlyOwner public returns (bool) {
        chainId = _newChainId;
        return true;
    }
}
```

##  通用智能合约代码分析

#### `Context.sol`：

提供有关当前执行上下文的信息，包括交易的发送者及交易的数据。

https://github.com/polynetwork/eth-contracts/blob/master/contracts/libs/GSN/Context.sol

#### `Ownable.sol` ：

提供基本访问控制机制的合约模块，如：授权一个账户访问特定的函数功能。

该模块主要通过继承来使用，提供可用的`modifier` onlyOwner，应用于对应的函数，限制特定的owner来调用。

https://github.com/polynetwork/eth-contracts/tree/master/contracts/libs/ownership

```solidity
contract Ownable is Context {
    address private _owner;
    event OwnershipTransferred(address indexed previousOwner, address indexed newOwner);
    //代表合约所有权的转移
    constructor () internal {
        address msgSender = _msgSender();
        _owner = msgSender;
        emit OwnershipTransferred(address(0), msgSender);
    }
    //进行初始化合约，将部署者设置为初始所有者

    function owner() public view returns (address) {
        return _owner;
    }
	//返回当前合约所有者的地址
	
    modifier onlyOwner() {
        require(isOwner(), "Ownable: caller is not the owner");
        _;
    }
    //该modifier用于限制只有所有者账户，才能调用对应的账户

    function isOwner() public view returns (bool) {
        return _msgSender() == _owner;
    }
	//判断调用者是否为当前的所有者

    function renounceOwnership() public onlyOwner {
        emit OwnershipTransferred(_owner, address(0));
        _owner = address(0);
    }
	//该函数用于将合约的所有者去除，恢复初始状态
	
    function transferOwnership(address newOwner) public  onlyOwner {
        _transferOwnership(newOwner);
    }
	//该函数由当前所有者调用，将合约的所有权转移到新账户'newOwner'。
 
    function _transferOwnership(address newOwner) internal {
        require(newOwner != address(0), "Ownable: new owner is the zero address");
        emit OwnershipTransferred(_owner, newOwner);
        _owner = newOwner;
    }
    //将该合约的所有权转移给新账户，emit对应的事件
}
```

#### `Utils.sol`

该函数进行一些bytes ,uint，address之间的转换，以及一些merkle proof和verify sig用到的函数

https://github.com/polynetwork/eth-contracts/blob/master/contracts/libs/utils/Utils.sol

```solidity
pragma solidity ^0.5.0;


library Utils {

    /* @notice      Convert the bytes array to bytes32 type, the bytes array length must be 32
    *  @param _bs   Source bytes array
    *  @return      bytes32
    */
    //将bytes数组转换为bytes32类型，bytes数组长度必须为32
    function bytesToBytes32(bytes memory _bs) internal pure returns (bytes32 value) {
        require(_bs.length == 32, "bytes length is not 32.");
        assembly {
            // load 32 bytes from memory starting from position _bs + 0x20 since the first 0x20 bytes stores _bs length
            value := mload(add(_bs, 0x20))
        }
    }

    /* @notice      Convert bytes to uint256
    *  @param _b    Source bytes should have length of 32
    *  @return      uint256
    */
    //将对应的bytes转换为uint256格式
    function bytesToUint256(bytes memory _bs) internal pure returns (uint256 value) {
        require(_bs.length == 32, "bytes length is not 32.");
        assembly {
            // load 32 bytes from memory starting from position _bs + 32
            value := mload(add(_bs, 0x20))
        }
        require(value <= 0x7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff, "Value exceeds the range");
    }

    /* @notice      Convert uint256 to bytes
    *  @param _b    uint256 that needs to be converted
    *  @return      bytes
    */
   // 将uint256转化为bytes格式
    function uint256ToBytes(uint256 _value) internal pure returns (bytes memory bs) {
        require(_value <= 0x7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff, "Value exceeds the range");
        assembly {
            // Get a location of some free memory and store it in result as
            // Solidity does for memory variables.
            bs := mload(0x40)
            // Put 0x20 at the first word, the length of bytes for uint256 value
            mstore(bs, 0x20)
            //In the next word, put value in bytes format to the next 32 bytes
            mstore(add(bs, 0x20), _value)
            // Update the free-memory pointer by padding our last write location to 32 bytes
            mstore(0x40, add(bs, 0x40))
        }
    }

    /* @notice      Convert bytes to address
    *  @param _bs   Source bytes: bytes length must be 20
    *  @return      Converted address from source bytes
    */
    //将bytes转化为对应的地址
    function bytesToAddress(bytes memory _bs) internal pure returns (address addr)
    {
        require(_bs.length == 20, "bytes length does not match address");
        assembly {
            // for _bs, first word store _bs.length, second word store _bs.value
            // load 32 bytes from mem[_bs+20], convert it into Uint160, meaning we take last 20 bytes as addr (address).
            addr := mload(add(_bs, 0x14))
        }

    }
    
    /* @notice      Convert address to bytes
    *  @param _addr Address need to be converted
    *  @return      Converted bytes from address
    */
    //将地址转化为对应的bytes
    function addressToBytes(address _addr) internal pure returns (bytes memory bs){
        assembly {
            // Get a location of some free memory and store it in result as
            // Solidity does for memory variables.
            bs := mload(0x40)
            // Put 20 (address byte length) at the first word, the length of bytes for uint256 value
            mstore(bs, 0x14)
            // logical shift left _a by 12 bytes, change _a from right-aligned to left-aligned
            mstore(add(bs, 0x20), shl(96, _addr))
            // Update the free-memory pointer by padding our last write location to 32 bytes
            mstore(0x40, add(bs, 0x40))
       }
    }

    /* @notice          Do hash leaf as the multi-chain does
    *  @param _data     Data in bytes format
    *  @return          Hashed value in bytes32 format
    */
    //计算叶子节点的哈希值
    function hashLeaf(bytes memory _data) internal pure returns (bytes32 result)  {
        result = sha256(abi.encodePacked(byte(0x0), _data));
    }

    /* @notice          Do hash children as the multi-chain does
    *  @param _l        Left node
    *  @param _r        Right node
    *  @return          Hashed value in bytes32 format
    */
    //计算左右节点的哈希
    function hashChildren(bytes32 _l, bytes32  _r) internal pure returns (bytes32 result)  {
        result = sha256(abi.encodePacked(bytes1(0x01), _l, _r));
    }

    /* @notice              Compare if two bytes are equal, which are in storage and memory, seperately
                            Refer from https://github.com/summa-tx/bitcoin-spv/blob/master/solidity/contracts/BytesLib.sol#L368
    *  @param _preBytes     The bytes stored in storage
    *  @param _postBytes    The bytes stored in memory
    *  @return              Bool type indicating if they are equal
    */
    //比较两个bytes类型的数据是否相等
    function equalStorage(bytes storage _preBytes, bytes memory _postBytes) internal view returns (bool) {
        bool success = true;

        assembly {
            // we know _preBytes_offset is 0
            let fslot := sload(_preBytes_slot)
            // Arrays of 31 bytes or less have an even value in their slot,
            // while longer arrays have an odd value. The actual length is
            // the slot divided by two for odd values, and the lowest order
            // byte divided by two for even values.
            // If the slot is even, bitwise and the slot with 255 and divide by
            // two to get the length. If the slot is odd, bitwise and the slot
            // with -1 and divide by two.
            let slength := div(and(fslot, sub(mul(0x100, iszero(and(fslot, 1))), 1)), 2)
            let mlength := mload(_postBytes)

            // if lengths don't match the arrays are not equal
            switch eq(slength, mlength)
            case 1 {
                // fslot can contain both the length and contents of the array
                // if slength < 32 bytes so let's prepare for that
                // v. http://solidity.readthedocs.io/en/latest/miscellaneous.html#layout-of-state-variables-in-storage
                // slength != 0
                if iszero(iszero(slength)) {
                    switch lt(slength, 32)
                    case 1 {
                        // blank the last byte which is the length
                        fslot := mul(div(fslot, 0x100), 0x100)

                        if iszero(eq(fslot, mload(add(_postBytes, 0x20)))) {
                            // unsuccess:
                            success := 0
                        }
                    }
                    default {
                        // cb is a circuit breaker in the for loop since there's
                        //  no said feature for inline assembly loops
                        // cb = 1 - don't breaker
                        // cb = 0 - break
                        let cb := 1

                        // get the keccak hash to get the contents of the array
                        mstore(0x0, _preBytes_slot)
                        let sc := keccak256(0x0, 0x20)

                        let mc := add(_postBytes, 0x20)
                        let end := add(mc, mlength)

                        // the next line is the loop condition:
                        // while(uint(mc < end) + cb == 2)
                        for {} eq(add(lt(mc, end), cb), 2) {
                            sc := add(sc, 1)
                            mc := add(mc, 0x20)
                        } {
                            if iszero(eq(sload(sc), mload(mc))) {
                                // unsuccess:
                                success := 0
                                cb := 0
                            }
                        }
                    }
                }
            }
            default {
                // unsuccess:
                success := 0
            }
        }

        return success;
    }

    /* @notice              Slice the _bytes from _start index till the result has length of _length
                            Refer from https://github.com/summa-tx/bitcoin-spv/blob/master/solidity/contracts/BytesLib.sol#L246
    *  @param _bytes        The original bytes needs to be sliced
    *  @param _start        The index of _bytes for the start of sliced bytes
    *  @param _length       The index of _bytes for the end of sliced bytes
    *  @return              The sliced bytes
    */
    //从bytes类型的数据，指定的偏移量分片获得指定长度的bytes数据
    function slice(
        bytes memory _bytes,
        uint _start,
        uint _length
    )
        internal
        pure
        returns (bytes memory)
    {
        require(_bytes.length >= (_start + _length));

        bytes memory tempBytes;

        assembly {
            switch iszero(_length)
            case 0 {
                // Get a location of some free memory and store it in tempBytes as
                // Solidity does for memory variables.
                tempBytes := mload(0x40)

                // The first word of the slice result is potentially a partial
                // word read from the original array. To read it, we calculate
                // the length of that partial word and start copying that many
                // bytes into the array. The first word we copy will start with
                // data we don't care about, but the last `lengthmod` bytes will
                // land at the beginning of the contents of the new array. When
                // we're done copying, we overwrite the full first word with
                // the actual length of the slice.
                // lengthmod <= _length % 32
                let lengthmod := and(_length, 31)

                // The multiplication in the next line is necessary
                // because when slicing multiples of 32 bytes (lengthmod == 0)
                // the following copy loop was copying the origin's length
                // and then ending prematurely not copying everything it should.
                let mc := add(add(tempBytes, lengthmod), mul(0x20, iszero(lengthmod)))
                let end := add(mc, _length)

                for {
                    // The multiplication in the next line has the same exact purpose
                    // as the one above.
                    let cc := add(add(add(_bytes, lengthmod), mul(0x20, iszero(lengthmod))), _start)
                } lt(mc, end) {
                    mc := add(mc, 0x20)
                    cc := add(cc, 0x20)
                } {
                    mstore(mc, mload(cc))
                }

                mstore(tempBytes, _length)

                //update free-memory pointer
                //allocating the array padded to 32 bytes like the compiler does now
                mstore(0x40, and(add(mc, 31), not(31)))
            }
            //if we want a zero-length slice let's just return a zero-length array
            default {
                tempBytes := mload(0x40)

                mstore(0x40, add(tempBytes, 0x20))
            }
        }

        return tempBytes;
    }
    /* @notice              Check if the elements number of _signers within _keepers array is no less than _m
    *  @param _keepers      The array consists of serveral address
    *  @param _signers      Some specific addresses to be looked into
    *  @param _m            The number requirement paramter
    *  @return              True means containment, false meansdo do not contain.
    */
    //用于验证签名，比较两个签名地址数组之中，是否有m个地址相同
    function containMAddresses(address[] memory _keepers, address[] memory _signers, uint _m) internal pure returns (bool){
        uint m = 0;
        for(uint i = 0; i < _signers.length; i++){
            for (uint j = 0; j < _keepers.length; j++) {
                if (_signers[i] == _keepers[j]) {
                    m++;
                    // delete _keepers[j];
                    _keepers[j] = 0x7777777777777777777777777777777777777777;
                }
            }
        }
        return m >= _m;
    }

    /* @notice              TODO
    *  @param key
    *  @return
    */
    //将对应的公钥进行压缩
    function compressMCPubKey(bytes memory key) internal pure returns (bytes memory newkey) {
         require(key.length >= 67, "key lenggh is too short");
         newkey = slice(key, 0, 35);
         if (uint8(key[66]) % 2 == 0){
             newkey[2] = byte(0x02);
         } else {
             newkey[2] = byte(0x03);
         }
         return newkey;
    }
    
    /**
     * @dev Returns true if `account` is a contract.
     *      Refer from https://github.com/OpenZeppelin/openzeppelin-contracts/blob/master/contracts/utils/Address.sol#L18
     *
     * This test is non-exhaustive, and there may be false-negatives: during the
     * execution of a contract's constructor, its address will be reported as
     * not containing a contract.
     *
     * IMPORTANT: It is unsafe to assume that an address for which this
     * function returns false is an externally-owned account (EOA) and not a
     * contract.
     */
     //判断该账户是合约账户还是普通账户
    function isContract(address account) internal view returns (bool) {
        // This method relies in extcodesize, which returns 0 for contracts in
        // construction, since the code is only stored at the end of the
        // constructor execution.

        // According to EIP-1052, 0x0 is the value returned for not-yet created accounts
        // and 0xc5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470 is returned
        // for accounts without code, i.e. `keccak256('')`
        bytes32 codehash;
        bytes32 accountHash = 0xc5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470;
        // solhint-disable-next-line no-inline-assembly
        assembly { codehash := extcodehash(account) }
        return (codehash != 0x0 && codehash != accountHash);
    }
}
```
