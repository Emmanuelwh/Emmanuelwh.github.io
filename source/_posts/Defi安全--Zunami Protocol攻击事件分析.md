---
title: Defi安全--Zunami Protocol攻击事件分析
date: 2024-01-12 15:30:12
tags: [Defi安全, 安全事件分析, 区块链安全]
categories:
  - [Defi安全]
  - [安全事件分析]
description: 摘要：Defi安全--Zunami Protocol攻击事件分析--Phalcon+etherscan
---

## 1  Zunami攻击事件相关信息

2023.8.13发生在Ethereum上发生的攻击，存在两个攻击交易，具体信息如下：

- 攻击合约地址：[Contract Address 攻击合约](https://etherscan.io/address/0xa21a2b59d80dc42d332f778cbb9ea127100e5d75#code)
- 攻击者地址：[Zunami Protocol Exploiter](https://etherscan.io/address/0x5f4c21c9bb73c8b4a296cc256c0cde324db146df)
- 攻击交易hash1：[Ethereum Transaction Hash (Txhash) Details | Etherscan](https://etherscan.io/tx/0x0788ba222970c7c68a738b0e08fb197e669e61f9b226ceec4cab9b85abe8cceb)
- 攻击交易hash2：[Ethereum Transaction Hash (Txhash) Details | Etherscan](https://etherscan.io/tx/0x2aec4fdb2a09ad4269a410f2c770737626fb62c54e0fa8ac25e8582d4b690cca)

- phalcon分析调用序列：[0x0788ba222970c7c68a | Phalcon Explorer (blocksec.com)](https://phalcon.blocksec.com/explorer/tx/eth/0x0788ba222970c7c68a738b0e08fb197e669e61f9b226ceec4cab9b85abe8cceb)

## 2  攻击流程详解

### 项目介绍

Zunami是稳定币投资聚合器，用户给定用ETH/USDC/DAI等稳定币投资Zunami协议；

然后Zunami协议会使用用户质押的代币到Curve中高收益的池子进行质押；

那么为了保证更进一步的收益，Zunami还会把Curve的流动性再次质押到StakeDAO和Convex平台中，吃两波流动性奖励。

然后把收到的流动性奖励代币(CRV)经过用户的质押比例返回给用户。

zETH是Zunami协议实现的变基代币(rebase token)，变基代币的逻辑是因为他的代币数量计算是锚定了Zunami所有的资产来计算的，所以可以通过闪电贷对Zunami质押的池子买入卖出就可以影响zETH的数量计算

### 攻击流程

两次攻击交易是单独的，但是基于的漏洞及原理是一致的

以0x0788ba222970c7c68a738b0e08fb197e669e61f9b226ceec4cab9b85abe8cceb攻击交易为例进行分析

![image-20240112153942369](https://gitee.com/Emmanuel_scb/blogimage/raw/master/img/202401121539252.png)

1. 对攻击交易进行调用序列分析，直接调用攻击合约中的函数；先查看了Balancer: Vault账户中USDC的余额
2. 随后攻击者就调用UniswapV3中USDC-USDT对应的闪电贷函数，借出了7 e12wei的USDT；随后查看pair对池子中的USDC和USDT的余额，乐观转账会将对应借贷转给用户。
3. 闪电贷会回调攻击者的`uniswapV3FlashCallback`函数，回调中攻击者调用Balancer: Vault的flashloan函数，这里可以看一下这里的函数源码

```solidity
    function flashLoan(
        IFlashLoanRecipient recipient,
        IERC20[] memory tokens,
        uint256[] memory amounts,
        bytes memory userData
    ) external override nonReentrant whenNotPaused 
```

看了一下源码，其功能无特别之处，就是一个闪电贷函数，不过这个函数可以一次借贷多个代币，用`tokens`和`amounts`表示对应的数组，先后乐观转账，后回调攻击者，在进行还款

3. 在Balancer: Vault的flashloan函数中，会查看对应的余额，进行相应的乐观转账，随后会再次回调到攻击者的`receiveFlashLoan`函数，此时用户已经通过借贷获得了大量的USDT、USDC以及ETH

![image-20240112162057959](https://gitee.com/Emmanuel_scb/blogimage/raw/master/img/202401121621089.png)

4. 随后攻击者给curve finance，sushiswap以及uniswap上很多factory和router合约地址进行相应的代币授权，并调用Curve Finance: Swap用USDC给池子中添加流动性，获得crvFRAX

   ![image-20240112171138441](https://gitee.com/Emmanuel_scb/blogimage/raw/master/img/202401121711714.png)

5. 随后调用Curve.fi Factory Pool中的一些pair对的exchange()函数，DEX智能合约的代币交换功能，可以把vyper代码直接放到GPT中解析，可以理解为就算进行代币的交换，攻击者将对应的crvFRAX兑换为Zunami UZD，将USDC兑换为crvUSD。此时用户拥有UZD和crvUSD

![image-20240112172018837](https://gitee.com/Emmanuel_scb/blogimage/raw/master/img/202401121720061.png)

![image-20240112172948516](https://gitee.com/Emmanuel_scb/blogimage/raw/master/img/202401121729436.png)

6. 攻击再次调用exchange()函数，将所有的crvUSD兑换为对应的UZD，最后攻击者拥有4873316数量的UZD,并且将自身的ETH换成对应的SDT，并且将全部的SDT转到`MIMCurveStakeDao`中（为什么要进行这样一个存款，可能跟攻击行为有关）![image-20240112174205177](https://gitee.com/Emmanuel_scb/blogimage/raw/master/img/202401121927672.png)
7. 随后调用SushiSwap: Router的`swapExactTokensForTokens`函数，进行代币的交换，攻击者首先将自身的WETH兑换为对应的SDT，随后将步骤2中通过闪电贷获得的USDT全部兑换为WETH

8. 攻击者调用UZD合约的cacheAssetPrice()函数,仔细看一下函数源码，获得UZD缓存的资产价格，源码如下：

```solidity
    function cacheAssetPrice() public virtual {
        _blockCached = block.number;
        uint256 currentAssetPrice = assetPrice();
        if (_assetPriceCached < currentAssetPrice) {
            _assetPriceCached = currentAssetPrice;
            emit CachedAssetPrice(_blockCached, _assetPriceCached);
        }
    }
```

8. 可以看出对应的`_assetPriceCached`的价格是由assetPrice()决定的，进一步阅读函数源码

```solidity
    function assetPrice() public view override returns (uint256) {
        return priceOracle.lpPrice();
    }
```

进一步阅读etherscan上源码，可得priceOracle地址为0x2ffCC661011beC72e1A9524E12060983E74D14ce，查看该合约的`lpPrice()`函数。

```solidity
    function lpPrice() external view returns (uint256) {
        return (totalHoldings() * 1e18) / totalSupply();
    }
```

价格取决于`totalHoldings()`函数，`totalSupply()`为ERC标准函数

```solidity
    function totalHoldings() public view returns (uint256) {
        uint256 length = _poolInfo.length;
        uint256 totalHold = 0;
        for (uint256 pid = 0; pid < length; pid++) {
            totalHold += _poolInfo[pid].strategy.totalHoldings();
        }
        return totalHold;
    }
```

这个会取决于每个_poolInfo[pid].strategy的Holdings()函数，这里我们去看`MIMCurveStakeDao`对应的函数，源码如下所示：

```solidity
    function totalHoldings() public view virtual returns (uint256) {
        uint256 crvLpHoldings = (vault.liquidityGauge().balanceOf(address(this)) * getCurvePoolPrice()) /
            CURVE_PRICE_DENOMINATOR;

        uint256 sdtEarned = vault.liquidityGauge().claimable_reward(address(this), address(_config.sdt));
        uint256 amountIn = sdtEarned + _config.sdt.balanceOf(address(this));
        uint256 sdtEarningsInFeeToken = priceTokenByExchange(amountIn, _config.sdtToFeeTokenPath);

        uint256 crvEarned = vault.liquidityGauge().claimable_reward(address(this), address(_config.crv));
        amountIn = crvEarned + _config.crv.balanceOf(address(this));
        uint256 crvEarningsInFeeToken = priceTokenByExchange(amountIn, _config.crvToFeeTokenPath);

        uint256 tokensHoldings = 0;
        for (uint256 i = 0; i < 3; i++) {
            tokensHoldings += _config.tokens[i].balanceOf(address(this)) * decimalsMultipliers[i];
        }

        return
            tokensHoldings +
            crvLpHoldings +
            (sdtEarningsInFeeToken + crvEarningsInFeeToken) *
            decimalsMultipliers[feeTokenId];
    }
    
    function priceTokenByExchange(uint256 amountIn, address[] memory exchangePath)
        internal
        view
        returns (uint256)
    {
        if (amountIn == 0) return 0;
        uint256[] memory amounts = _config.router.getAmountsOut(amountIn, exchangePath);
        return amounts[amounts.length - 1];
    }
```

重点关注sdtEarningsInFeeToken，因为攻击者在此之前，给该合约存入了大量的SDT，仔细看一下`priceTokenByExchange()`函数

![image-20240112201732602](https://gitee.com/Emmanuel_scb/blogimage/raw/master/img/202401122017418.png)

进一步可以去SushiSwap: Router中查看`getAmountsOut()`函数，发现其返回值与amountIn正相关，amountIn的值一定程度上取决于该合约当前的SDT余额，而攻击者在此之前给该地址存入了大量的SDT，最终导致sdtEarningsInFeeToken数量过高，CachedAssetPrice价格过高

![image-20240112203605220](https://gitee.com/Emmanuel_scb/blogimage/raw/master/img/202401122036619.png)

9. 随后攻击者调用SushiSwap: Router的`swapExactTokensForTokens`函数，将SDT转化为WETH，将WETH换成USDT
10. 随后调用UZD合约中的balanceOf函数，发现其依赖于被操纵的cacheAssetPrice价格，具体如下：

```solidity
    function balanceOf(address account) public view virtual override returns (uint256) {
        if (!containRigidAddress(account)) return super.balanceOf(account);

        return _balancesRigid[account];
    }
    
    function balanceOf(address account) public view virtual override returns (uint256) {
        // don't cache price
        return _convertFromNominalCached(_balances[account], Math.Rounding.Down);
    }

    function _convertFromNominalWithCaching(uint256 nominal, Math.Rounding rounding)
        internal
        virtual
        returns (uint256 value)
    {
        if (nominal == type(uint256).max) return type(uint256).max;
        _cacheAssetPriceByBlock();
        return nominal.mulDiv(assetPriceCached(), DEFAULT_DECIMALS_FACTOR, rounding);
    }
```

所以其会错误计算攻击者的UZD余额，这时攻击者进行相应的套利即可

![image-20240112203656910](https://gitee.com/Emmanuel_scb/blogimage/raw/master/img/202401122037904.png)

11. 通过Curve.fi Factory Pool的exchange函数，先将错误余额数量的UZD，一部分兑换为crvFRAX，另一部分兑换为crvUSD。

    移除Curve Finance: Swap中的流动性，攻击者获得对应的FRAX和USDC。

    调用exchange函数，将对应的FRAX和crvUSD兑换城USDC

    并且最后将大部分的USDC全部兑换成USDT，现在攻击者资产为USDT和USDC。

![image-20240112204626131](https://gitee.com/Emmanuel_scb/blogimage/raw/master/img/202401122046516.png)

12. 调用WETH-USDCpair对的闪电贷，获得大量的WETH，攻击者偿还相应数量的USDC，并偿还第2步中Balancer: Vault闪电贷借贷的WETH和USDC，最后偿还第一步中uniswapV3借贷的USDT
13. 最后偿还完闪电贷后，攻击者获得资产USDT和WETH，将其全部提取完成攻击。

再简单看一下另一个攻击交易0x2aec4fdb2a09ad4269a410f2c770737626fb62c54e0fa8ac25e8582d4b690cca

- 也是先调用攻击合约，后进行闪电贷，借出WETH，然后通过curve finance将eth兑换成zETH
- 将ETH兑换成CRV，存入sEthFraxEthCurveConvex合约中，与上述相同，攻击者账户的zETH余额和sEthFraxEthCurveConvex合约中的CRV余额相关，攻击者通过多次在wETH/CRV在池子中兑换CRV，操纵了CRV的价格和漏洞合约的CRV余额，最终导致CachedAssetPrice变大















