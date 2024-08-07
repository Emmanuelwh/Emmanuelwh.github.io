---
title: Defi安全--Orion Protocol攻击事件分析
date: 2024-01-16 11:15:27
tags: ['Defi安全','安全事件分析']
categories:
  - ['Defi安全']
  - ['安全事件分析']
description: 摘要：Defi安全-Orion Protocol攻击事件分析--Phalcon+etherscan
---

## 1. Orion Protocol攻击事件相关信息

2023年2月2日，在ETH和BSC上的Orion Protocol项目被攻击，这里以ETH上攻击为例：

- 攻击合约地址：[Attacker Contract Address | Etherscan](https://etherscan.io/address/0x5061f7e6dfc1a867d945d0ec39ea2a33f772380a)
- 攻击者地址：[Orion Protocol Exploiter 2 | Address](https://etherscan.io/address/0x837962b686fd5a407fb4e5f92e8be86a230484bd)
- 攻击交易：[Ethereum Transaction Hash (Txhash) Details | Etherscan](https://etherscan.io/tx/0xa6f63fcb6bec8818864d96a5b1bb19e8bd85ee37b2cc916412e720988440b2aa)
- Phalcon调用序列分析：[0xa6f63fcb6bec881886 | Phalcon Explorer (blocksec.com)](https://phalcon.blocksec.com/explorer/tx/eth/0xa6f63fcb6bec8818864d96a5b1bb19e8bd85ee37b2cc916412e720988440b2aa)

## 2. Orion Protocol攻击事件分析

### 攻击流程详解

Eth上的攻击交易[Ethereum Transaction Hash (Txhash) Details | Etherscan](https://etherscan.io/tx/0xa6f63fcb6bec8818864d96a5b1bb19e8bd85ee37b2cc916412e720988440b2aa)

从中我们可以看出，input data为单纯的函数签名，没有参数，只是调用了一个攻击函数

![image-20240116111931103](https://gitee.com/Emmanuel_scb/blogimage/raw/master/img/202401161126161.png)

查看对应的phalcon调用序列：

![image-20240116112006459](https://gitee.com/Emmanuel_scb/blogimage/raw/master/img/202401161126931.png)

1. 先进行了一系列基础操作，对Orion Protocol项目合约进行一系列的代币授权approve(）操作，如USDT和USDC等。

![image-20240116112824996](https://gitee.com/Emmanuel_scb/blogimage/raw/master/img/202401161128941.png)

2. 随后我们可以看到攻击者调用了Orion Protocol的`depositAsset`函数，看一下该函数的源码：

```solidity
    function depositAsset(address assetAddress, uint112 amount) external {
        uint256 actualAmount = IERC20(assetAddress).balanceOf(address(this));
        IERC20(assetAddress).safeTransferFrom(
            msg.sender,
            address(this),
            uint256(amount)
        );
        actualAmount = IERC20(assetAddress).balanceOf(address(this)) - actualAmount;
        generalDeposit(assetAddress, uint112(actualAmount));
    }
```

2. 攻击者向orion Protocol合约转入对应数量的USDC，将该合约转账前后的代币余额，作为用户存款的数量，并调用`generateDeposit`函数，这一步USDC的存款是为后续的攻击做准备。
3. 攻击者调用Uniswap V2: USDT的闪电贷函数，借出200多万个USDT

![image-20240116113406567](https://gitee.com/Emmanuel_scb/blogimage/raw/master/img/202401161134520.png)

3. 调用uniswapv2的闪电贷函数，借贷对应的USDT，乐观转账，先将对应的USDT转账给了攻击者，后回调攻击者的`uniswapV2Call`函数
4. 回调函数中，因为攻击者先前存入了USDC，现在攻击者调用了orion Protocol项目ExchangeWithAtomic合约中的一个函数`swapThroughOrionPool`，orion Protocol提供的代币交换函数，代币兑换路径为[USDC,  ATK,  USDT]，其中ATK为攻击者提前创建的恶意代币，将USDC兑换成USDT
5. 随后调用LibPool的doSwapThroughOrionPool的函数，再调用PoolFunctionality 合约中的doSwapThroughOrionPool函数

```solidity
    function swapThroughOrionPool(
        uint112     amount_spend,
        uint112     amount_receive,
        address[]   calldata path,
        bool        is_exact_spend
    ) public payable nonReentrant {
        bool isCheckPosition = LibPool.doSwapThroughOrionPool(
            IPoolFunctionality.SwapData({
                amount_spend: amount_spend,
                amount_receive: amount_receive,
                is_exact_spend: is_exact_spend,
                supportingFee: false,
                path: path,
                orionpool_router: _orionpoolRouter,
                isInContractTrade: false,
                isSentETHEnough: false,
                isFromWallet: false,
                asset_spend: address(0)
            }),
            assetBalances, liabilities);
```

5. 进一步调用PoolFunctionality 合约中的 doSwapThroughOrionPool 函数，仔细看一下函数源码，该函数进一步调用了_doSwapTokens（）函数

6. 上述代码中_doSwapTokens()函数时进行相应的输入，输出代币数量的计算，跟进该函数的实现

```solidity
    function _doSwapTokens(InternalSwapData memory swapData) internal returns (uint256 amountIn, uint256 amountOut) {
        bool isLastWETH = swapData.path[swapData.path.length - 1] == WETH;
        address toAuto = isLastWETH || swapData.curFactoryType == FactoryType.CURVE ? address(this) : swapData.to;
        uint256[] memory amounts;
        if (!swapData.supportingFee) {
            if (swapData.isExactIn) {
                amounts = OrionMultiPoolLibrary.getAmountsOut(
                    swapData.curFactory,
                    swapData.curFactoryType,
                    swapData.amountIn,
                    swapData.path
                );
                require(amounts[amounts.length - 1] >= swapData.amountOut, "PoolFunctionality: IOA");
            } else {
                amounts = OrionMultiPoolLibrary.getAmountsIn(
                    swapData.curFactory,
                    swapData.curFactoryType,
                    swapData.amountOut,
                    swapData.path
                );
                require(amounts[0] <= swapData.amountIn, "PoolFunctionality: EIA");
            }
        } else {
            amounts = new uint256[](1);
            amounts[0] = swapData.amountIn;
        }
        amountIn = amounts[0];

        {
            uint256 curBalance;
            address initialTransferSource = swapData.curFactoryType == FactoryType.CURVE ? address(this)
                : OrionMultiPoolLibrary.pairFor(swapData.curFactory, swapData.path[0], swapData.path[1]);

            if (swapData.supportingFee) curBalance = IERC20(swapData.path[0]).balanceOf(initialTransferSource);

            IPoolSwapCallback(msg.sender).safeAutoTransferFrom(
                swapData.asset_spend,
                swapData.user,
                initialTransferSource,
                amountIn
            );
            if (swapData.supportingFee) amounts[0] = IERC20(swapData.path[0]).balanceOf(initialTransferSource) - curBalance;
        }

        {
            uint256 curBalance = IERC20(swapData.path[swapData.path.length - 1]).balanceOf(toAuto);
            //计算转账前的余额
            if (swapData.curFactoryType == FactoryType.CURVE) {
                _swapCurve(swapData.curFactory, amounts, swapData.path, swapData.supportingFee);
            } else if (swapData.curFactoryType == FactoryType.UNISWAPLIKE) {
            //这里的swap函数完成相应的代币兑换
                _swap(swapData.curFactory, amounts, swapData.path, toAuto, swapData.supportingFee);
            }
            //将账户余额与转账前余额相减，得到新增的金额
            amountOut = IERC20(swapData.path[swapData.path.length - 1]).balanceOf(toAuto) - curBalance;
        }

        require(
            swapData.amountIn == 0 || swapData.amountOut == 0 ||
            amountIn * 1e18 / swapData.amountIn <= amountOut * 1e18 / swapData.amountOut,
            "PoolFunctionality: OOS"
        );

        if (isLastWETH) {
            SafeTransferHelper.safeAutoTransferTo(
                WETH,
                address(0),
                swapData.to,
                amountOut
            );
        } else if (swapData.curFactoryType == FactoryType.CURVE) {
            IERC20(swapData.path[swapData.path.length - 1]).safeTransfer(swapData.to, amountOut);
        }

        emit OrionPoolSwap(
            tx.origin,
            convertFromWETH(swapData.path[0]),
            convertFromWETH(swapData.path[swapData.path.length - 1]),
            swapData.amountIn,
            amountIn,
            swapData.amountOut,
            amountOut,
            swapData.curFactory
        );
    }
```

7. 这里进行相应的代币兑换，之前的兑换path为[USDC,  ATK,  USDT]，这里通过PoolFunctionality合约中的_swap()完成相应的兑换，跟进 _swap()函数的源码

```solidity
    function _swap(
        address curFactory,
        uint256[] memory amounts,
        address[] memory path,
        address _to,
        bool supportingFee
    ) internal {
        for (uint256 i; i < path.length - 1; ++i) {
            (address input, address output) = (path[i], path[i + 1]);
            IOrionPoolV2Pair pair = IOrionPoolV2Pair(OrionMultiPoolLibrary.pairFor(curFactory, input, output));
            (address token0, ) = OrionMultiPoolLibrary.sortTokens(input, output);
            uint256 amountOut;

            if (supportingFee) {
                (uint reserve0, uint reserve1,) = pair.getReserves();
                (uint reserveInput, uint reserveOutput) = input == token0 ? (reserve0, reserve1) : (reserve1, reserve0);
                uint256 amountIn = IERC20(input).balanceOf(address(pair)).sub(reserveInput);
                amountOut = OrionMultiPoolLibrary.getAmountOutUv2(amountIn, reserveInput, reserveOutput);
            } else {
                amountOut = amounts[i + 1];
            }

            (uint256 amount0Out, uint256 amount1Out) = input == token0 ? (uint256(0), amountOut) : (amountOut, uint256(0));
            address to = i < path.length - 2 ? OrionMultiPoolLibrary.pairFor(curFactory, output, path[i + 2]) : _to;

            pair.swap(amount0Out, amount1Out, to, new bytes(0));
        }
    }
```

![image-20240116142931330](https://gitee.com/Emmanuel_scb/blogimage/raw/master/img/202401161429293.png)

8. path序列中的[USDC,  ATK,  USDT]，每两个代币对之间存在一个pair合约，即USDC转到ATK，ATK转到对应的USDT，实现对应的代币兑换，攻击者创建的pair对合约，这里通过相应的计算金融模型，得到对应的转账金额，调用pair合约中的swap函数，实现相应的代币转移。

   ![image-20240116150016939](https://gitee.com/Emmanuel_scb/blogimage/raw/master/img/202401161500400.png)

   ![image-20240116151407776](https://gitee.com/Emmanuel_scb/blogimage/raw/master/img/202401161514261.png)

9. 由于pair对中的swap函数，进行相应的转账，需要调用ATK代币的转账函数，ATK是攻击者部署的恶意代币，攻击者可控，攻击者这里调用自身的deposit()函数，调用ExchangeWithAtomic合约的depositAsset函数，并将闪电贷得到的200多万USDT全部转进Orion Protocol的depositAsset()函数中

10.  这时攻击者在ExchangeWithAtomic 合约中USDT的存款被记账为了200多万，原来ExchangeWithAtomic 合约的余额为200多万，两者数值相近（攻击者设计的）

11. 而通过`swapThroughOrionPool`函数中攻击者USDC兑换出多少的USDT最终是通过ExchangeWithAtomic 合约兑换前后的USDT余额计算的，相当于存入的200万USDT被认为是USDC兑换出来的，最后通过creditUserAssets 函数来更新ExchangeWithAtomic 维护的adress-balance的账本，攻击者被认为是存入了200+200万

![image-20240116151533445](https://gitee.com/Emmanuel_scb/blogimage/raw/master/img/202401161515801.png)

12. 攻击者进行相应的闪电贷还款，归还借出的200多万，获利200多万

![image-20240116151634701](https://gitee.com/Emmanuel_scb/blogimage/raw/master/img/202401161516963.png)

13. 调用闪电贷，借出WETH，归还USDT，实现对应的套利离场

### 攻击事件发生的主要原因

- doswapThroughOrionPool 函数，兑换路径攻击者可控，代币类型攻击者可控（恶意代币）
- 兑换后更新账本的记账方式不正确，利用前后余额计算（×）
- 合约兑换功能的函数没有做重入保护

## 3.  分析Orion Protocol攻击事件所需信息

1. 最关键的一点，重入的发生回调不在这个攻击合约之中，在攻击者创建的恶意代币合约之中（可能是这个案例的特殊情况）
2. 普适的一点：触发恶意合约回调的功能，是在经过5次外部函数调用后，才最终调用到攻击者的恶意代币合约中的函数，在我们的工具中是无法获得这样的调用过程，全路径覆盖不太现实。





