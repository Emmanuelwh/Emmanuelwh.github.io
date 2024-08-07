---
title: Defi安全--Cream Finance攻击事件分析
date: 2024-01-21 21:17:15
tags: ['Defi安全', '区块链安全', '安全事件分析']
categories：
  - ['Defi安全']
  - ['安全事件分析']
descriptions: 摘要：Defi安全--Cream Finance攻击事件分析--Phalcon+etherscan
---

## 1、Cream Finance攻击事件相关信息

2021年8月30日，Defi抵押借贷平台Cream Finance在ETH上遭受攻击：

- 攻击合约：[Contract Address 攻击合约 | Etherscan](https://etherscan.io/address/0x38c40427efbaae566407e4cde2a91947df0bd22b)
- 攻击者地址：[Cream Finance Flashloan Attacker | Etherscan](https://etherscan.io/address/0xce1f4b4f17224ec6df16eeb1e3e5321c54ff6ede)
- 攻击交易：[Ethereum Transaction Hash (Txhash) Details | Etherscan](https://etherscan.io/tx/0xa9a1b8ea288eb9ad315088f17f7c7386b9989c95b4d13c81b69d5ddad7ffe61e)
- Phalcon上交易调用序列：[0xa9a1b8ea288eb9ad31 | Phalcon Explorer (blocksec.com)](https://phalcon.blocksec.com/explorer/tx/eth/0xa9a1b8ea288eb9ad315088f17f7c7386b9989c95b4d13c81b69d5ddad7ffe61e)

## 2. Cream Finance攻击流程详解

1. 在Etherscan的攻击交易中，查看对应的input data，发现是存在对应参数的：

![image-20240122101742962](https://gitee.com/Emmanuel_scb/blogimage/raw/master/img/202401221115395.png)

2. 攻击者调用uniswapv2的闪电贷函数，借出500个WETH，随后回调到攻击者的uniswapV2Call函数中，攻击者将WETH对Cream.Finance: crAMP Token合约代币进行相应的授权，并将对应的WETH转账到自己的账户

![image-20240122111058593](https://gitee.com/Emmanuel_scb/blogimage/raw/master/img/202401221115404.png)

3. 攻击者调用crETH的mint函数，实现相应的抵押，这里500WETH，应该是作为msg.value传入的
4. 调用crAMP池中的`borrow()`函数，想要借出19480000AMP，查看具体的函数源码：
   - 调用borrowInternal()函数

```solidity
    function borrow(uint256 borrowAmount) external returns (uint256) {
        return borrowInternal(borrowAmount, false);
    }
    function borrowInternal(uint256 borrowAmount, bool isNative) internal nonReentrant returns (uint256) {
        uint256 error = accrueInterest();
        if (error != uint256(Error.NO_ERROR)) {
            // accrueInterest emits logs on errors, but we still want to log the fact that an attempted borrow failed
            return fail(Error(error), FailureInfo.BORROW_ACCRUE_INTEREST_FAILED);
        }
        // borrowFresh emits borrow-specific logs on errors, so we don't need to
        return borrowFresh(msg.sender, borrowAmount, isNative);
    }
```



















