---
title: python与智能合约交互（测试链）
date: 2023-12-16 11:03:57
tags: [Solidity, 区块链安全]
categories:
  - [以太坊]
  - [智能合约]
description: 摘要：使用web3.py与测试链上solidity交互
---

# 1. 智能合约
这里用以太坊公链进行说明，以太坊上支持的智能合约主要是由Solidity语言编写，后续介绍都以，以太坊的Goerli测试链为例，进行介绍。
**智能合约** ：是指用特定语言编写，后将其部署到区块链上，实现特定功能的代码。
之前一直研究智能合约的漏洞，而并没有与实际测试链上智能合约进行交互，这次一项目用到这，对web3.py进行了学习。
现在主流智能合约的开发，一般都不太会用web.py，都有封装好的truffle框架，hardhat框架，以及Foundry等。
本文只是对完整web3开发的一个初步了解。
# 2. 测试链和节点数据
这里我们用的以太坊的测试链Goerli，Sepolia也可以用，以及自己通过geth，ganache搭建的私链都可以来测试
先尝试着连接区块链：
- 测试链的话，去infura上申请个节点，会给你个url，相当于可以通过这个节点访问测试链上数据
- 私链的话，直接连接服务器或本机的某个端口就行，一般是7545 or 8545
# 3. web3.py的使用
首先安装web3
```python
pip install web3
```
## 3.1 连接区块链
```python
w3 = Web3(Web3.HTTPProvider(url))
print(w3.is_connected())  ##判断是否连接上
```
## 3.2 部署合约
### 3.2.1 获取abi和bytecode:
web3.py在部署合约之前需要通过对源码进行解析得到其abi和bytecode
**abi**：abi主要包含的合约的函数调用信息，即函数参数，返回值，签名等信息
**bytecode**：bytecode是指源码进行编译得到的二进制代码
python可以通过==solcx==库中的==compile_standard==函数进行合约解析，得到合约的abi和字节码，在创建合约，部署合约时会用到。
### 3.2.2 部署合约：
部署合约则主要通过官方封装的标准函数来实现，web3.py，web3.js的相关函数与geth官方的函数很像。
- 构建部署合约这一交易
```python
Contract = w3.eth.contract(abi = abi, bytecode = bytecode)
nonce = w3.eth.get_transaction_count(Goerli_address)
transaction = Contract.constructor().build_transaction(
    {
        "gasPrice": w3.eth.gas_price,
        "from": Goerli_address,
        "nonce": nonce
    }
)
```
- 签名发布该交易
```python
signed_txn = w3.eth.account.sign_transaction(transaction, private_key = Goerli_privateKey)   
##账户私钥对交易进行验证
tx_hash = w3.eth.send_raw_transaction(signed_txn.rawTransaction)    
tx_receipt = w3.eth.wait_for_transaction_receipt(tx_hash)
##根据交易哈希获取交易凭证，可获取部署合约的地址
```
### 3.2.3 调用合约中的函数
以太坊中调用函数主要是通过call的方式调用函数签名进行实现。
可见毕设之前总结的文章[solidity合约函数调用](https://blog.csdn.net/m0_53689197/article/details/129721360?spm=1001.2014.3001.5502)

这里为了方便起见，我们用函数名直接对函数进行调用
这里以调用**storeUserData**这一函数为例，进行说明：
```python
Contract = w3.eth.contract(address = contract_address, abi = abi) 
nonce = w3.eth.get_transaction_count(call_address)
transaction = Contract.functions.storeUserData(dataHash).build_transaction(
   {
       "gas": 1000000,
       "gasPrice": w3.eth.gas_price,
       "from": call_address,
       "nonce": nonce 
   }
)
## dataHash这里为storeUserData需要传入的参数
signed_txn = w3.eth.account.sign_transaction(transaction, private_key = addressKey)
##签名该函数调用的交易
send_tx = w3.eth.send_raw_transaction(signed_txn.rawTransaction)
tx_receipt = w3.eth.wait_for_transaction_receipt(send_tx)
## 根据交易哈希，获取交易凭证，后对交易凭证进行分析处理
```
### 3.2.4 Event的监听
因为后续实现对函数抛出的event进行实时监听，上述代码中获得了函数调用交易的tx_receipt，即交易凭证，其中就包含了event的log信息。
代码如下：
```python
logs = Contract.events.AccessRequested().process_receipt(tx_receipt)
## AccessRequested()为对应的事件event
```
随后对logs进行处理，即可实现实时监听合约的event抛出了
