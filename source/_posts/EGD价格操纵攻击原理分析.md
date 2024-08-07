---
title: EGD价格操纵攻击原理分析--phalcon+etherscan
date: 2023-12-19 14:58:17
tags: [Defi安全, 安全事件分析]
categories: Defi安全
description: 摘要：EGD价格操纵攻击原理分析--phalcon+etherscan
---

## EGD攻击事件相关信息

发生在BSC上

- 攻击者地址：[Address 0xee0221d76504aec40f63ad7e36855eebf5ea5edd | BscScan](https://bscscan.com/address/0xee0221d76504aec40f63ad7e36855eebf5ea5edd)

- 攻击合约：[Contract Address 0xc30808d9373093fbfcec9e026457c6a9dab706a7 | BscScan](https://bscscan.com/address/0xc30808d9373093fbfcec9e026457c6a9dab706a7)
- 攻击交易：[BNB Smart Chain Transaction Hash (Txhash) Details | BscScan](https://bscscan.com/tx/0x50da0b1b6e34bce59769157df769eb45fa11efc7d0e292900d6b0a86ae66a2b3)

- 受害合约的地址：[EGD_Finance | Address 0x93c175439726797dcee24d08e4ac9164e88e7aee | BscScan](https://bscscan.com/address/0x93c175439726797dcee24d08e4ac9164e88e7aee#code)

## EGD-Finance代码分析及攻击流程讲解

EGD_Finance合约的调用都是通过代理合约进行调用

在区块链浏览器上点击“Read as Proxy”可以查看到最终的合约。

`EGD Finance`合约中实现的主要功能就是**质押USDT一段时候，可提取奖励EGD token**，相当于银行存款，存一段时间之后可以提取利息。

下面质押步骤和兑换奖励步骤都是攻击者真实发起的交易步骤

### 质押步骤

[Address 0xbc5e8602c4fba28d0efdbf3c6a52be455d9558f5 | BscScan](https://bscscan.com/address/0xbc5e8602c4fba28d0efdbf3c6a52be455d9558f5) 调用攻击合约的`stake()`函数进行相应的抵押操作，该地址应该也是攻击者地址，其创建了攻击合约

具体交易如下：[BNB Smart Chain Transaction Hash (Txhash) Details | BscScan](https://bscscan.com/tx/0x4a66d01a017158ff38d6a88db98ba78435c606be57ca6df36033db4d9514f9f8)

我们可以在Phalcon上看到该交易的具体调用信息：

![image-20231219160115062](https://gitee.com/Emmanuel_scb/blogimage/raw/master/img/202312191601130.png)

这里进一步进行分析：

[EGD_Finance | Address 0x93c175439726797dcee24d08e4ac9164e88e7aee | BscScan](https://bscscan.com/address/0x93c175439726797dcee24d08e4ac9164e88e7aee#code)中`bond()`函数应该只是填写以下邀请人，应该跟web2一样，每个地址的邀请人和质押收益相关

```    solidity
function bond(address invitor) external {        
        require(userInfo[msg.sender].invitor == address(0), 'have invitor');
        require(userInfo[invitor].invitor != address(0) || invitor == fund, 'wrong invitor');
        userInfo[msg.sender].invitor = invitor;
        userInfo[invitor].refer ++;

    }
```

接下来的`swapETHForExactTokens()`调用是Defi中很常见的代币交换操纵，通过地址看源码，其与uniswap_v2的对应函数一致

从名称中可以看出是向通过不确定数量的ETH来换取一定数量的代币，可以确定交换的是USDT

uniswap的参数列表

```solidity
function swapETHForExactTokens(
    uint amountOut, // 交易获得的代币数量
    address[] calldata path, // 交易路径列表
    address to, // 交易获得的 token 发送到的地址
    uint deadline // 过期时间
) external virtual override payable ensure(deadline) returns (
    uint[] memory amounts // 交易期望数量列表
){
    ...
}
```

[PancakeSwap: Router v2 | Address 0x10ed43c718714eb63d5aa57b78b54704e256024e | BscScan](https://bscscan.com/address/0x10ed43c718714eb63d5aa57b78b54704e256024e#readProxyContract)

```solidity
    function swapETHForExactTokens(uint amountOut, address[] calldata path, address to, uint deadline)
        external
        virtual
        override
        payable
        ensure(deadline)
        returns (uint[] memory amounts)
    {
    	//检查是否为WETH进行交换
        require(path[0] == WETH, 'PancakeRouter: INVALID_PATH');
        // 从library中获知得到amountOut数量的USDT，需要多少ETH
        amounts = PancakeLibrary.getAmountsIn(factory, amountOut, path);
        //发给pancake的ETH必须大于所需数量
        require(amounts[0] <= msg.value, 'PancakeRouter: EXCESSIVE_INPUT_AMOUNT');
        // 将 WETH 换成 ETH（对应phalcon的操作）
        IWETH(WETH).deposit{value: amounts[0]}();
        // 将 amounts[0] 数量的 path[0] 代币从用户账户中转移到 path[0], path[1] 的流动池
        assert(IWETH(WETH).transfer(PancakeLibrary.pairFor(factory, path[0], path[1]), amounts[0]));
        // 按 path 列表执行交易集合，不细究了，之后再详细看uniswap-qwq
        _swap(amounts, path, to);
        // 返回多余的ETH
        if (msg.value > amounts[0]) TransferHelper.safeTransferETH(msg.sender, msg.value - amounts[0]);
    }
```

最后调用代理合约的`stake()`函数，质押100个USDT，从Phalcon中的调用记录可看出，具体函数代码不进行分析了，主要是记录了很多相关信息，用于后续的奖励计算，可见[EGD_Finance | Address 0x93c175439726797dcee24d08e4ac9164e88e7aee | BscScan](https://bscscan.com/address/0x93c175439726797dcee24d08e4ac9164e88e7aee#code)

![image-20231219162437653](https://gitee.com/Emmanuel_scb/blogimage/raw/master/img/202312191624242.png)

### 兑换奖励步骤

[Address 0xee0221d76504aec40f63ad7e36855eebf5ea5edd | BscScan](https://bscscan.com/address/0xee0221d76504aec40f63ad7e36855eebf5ea5edd)攻击者调用攻击合约的`harvest()`函数进行相应的兑换奖励，phalcon的交易分析如下图所示：

![image-20231219162808682](https://gitee.com/Emmanuel_scb/blogimage/raw/master/img/202312191628484.png)

首先调用合约的`calculateAll()函数`对用户的质押奖励进行计算，计算用户总共能得到多少收益

```solidity
    function calculateReward(address addr, uint slot) public view returns (uint){
        UserSlot memory info = userSlot[addr][slot];
        if (info.leftQuota == 0) {
            return 0;
        }
        uint totalRew = (block.timestamp - info.claimTime) * info.rates;
        if (totalRew >= info.leftQuota) {
            totalRew = info.leftQuota;
        }
        return totalRew;
    }
```

随后用户就展开了闪电贷操作，

先是通过`PancakeSwap`（0x16b9a82891338f9ba80e2d6970fdda79d1eb0dae）调用`swap()函数`借到200个USDT，随后乐观转账，回调攻击合约的`pancakeCall()函数`可见之前的闪电贷分析文章。

![image-20240124150152057](https://gitee.com/Emmanuel_scb/blogimage/raw/master/img/202401241502690.png)

在`pancakecall()函数中`又发起闪电贷，从`Pancake LPs`（0xa361433e409adac1f87cdf133127585f8a93c67d）中调用`swap()函数`借到424456个USDT，再次回调到`pancakeCall()函数`中，这是用户调用`claimAllReward()函数`兑换自己之前质押的奖励。

> 为什么在这里兑换奖励，应该很明显能够猜到是因为，闪电贷的大笔金额影响了奖励的计算方法，这里应该是计算质押奖励的函数出现了漏洞问题。

下面去[PancakeSwap: Router v2 | Address 0x10ed43c718714eb63d5aa57b78b54704e256024e | BscScan](https://bscscan.com/address/0x10ed43c718714eb63d5aa57b78b54704e256024e#readProxyContract)项目的`claimAllReward()`中看一下具体源码，进行了详细的注释：

```solidity
 function claimAllReward() external {
 		//判断是否存在对应的质押
        require(userInfo[msg.sender].userStakeList.length > 0, 'no stake');
        require(!black[msg.sender],'black');
        //获取质押时的，一系列质押记录，包括金额、时间戳等等
        uint[] storage list = userInfo[msg.sender].userStakeList;
        uint rew;
        uint outAmount;
        uint range = list.length;
        //计算对应的奖励
        for (uint i = 0; i < range; i++) {
            UserSlot storage info = userSlot[msg.sender][list[i - outAmount]];
            require(info.totalQuota != 0, 'wrong index');
            //不能超过一个最大奖励
            uint quota = (block.timestamp - info.claimTime) * info.rates;
            if (quota >= info.leftQuota) {
                quota = info.leftQuota;
            }
            //关键步骤，计算对应的奖励，仔细看一下getEGDPrice()函数
            //根据EGD的价格，来确定奖励多少EGD
            rew += quota * 1e18 / getEGDPrice();
            //下面是一些计算账户剩下最大奖励，以及账户余额（+利息）等操作
            info.claimTime = block.timestamp;
            info.leftQuota -= quota;
            info.claimedQuota += quota;
            if (info.leftQuota == 0) {
                userInfo[msg.sender].totalAmount -= info.totalQuota;
                delete userSlot[msg.sender][list[i - outAmount]];
                list[i - outAmount] = list[list.length - 1];
                list.pop();
                outAmount ++;
            }
        }
        //更新相应的质押列表
        userInfo[msg.sender].userStakeList = list;
        //发送响应的奖励
        EGD.transfer(msg.sender, rew);
        userInfo[msg.sender].totalClaimed += rew;
        emit Claim(msg.sender,rew);
    }
    function getEGDPrice() public view returns (uint){
    	//可在phalcon上看到行营的记录
        uint balance1 = EGD.balanceOf(pair);
        uint balance2 = U.balanceOf(pair);
        //EGD的价格仅仅是根据两种代币的实时数量（流动性）来进行计算，可以被攻击者操纵
        return (balance2 * 1e18 / balance1);
    }
    function initialize() public initializer {
        __Context_init_unchained();
        __Ownable_init_unchained();
        rate = [200, 180, 160, 140];
        startTime = block.timestamp;
        referRate = [6, 3, 1, 1, 1, 1, 1, 1, 2, 3];
        rateList = [547,493,438,383];
        dailyStakeLimit = 1000000 ether;
        wallet = 0xC8D45fF624F698FA4E745F02518f451ec4549AE8;
        fund = 0x9Ce3Aded1422A8c507DC64Ce1a0C759cf7A4289F;
        EGD = IERC20(0x202b233735bF743FA31abb8f71e641970161bF98);
        U = IERC20(0x55d398326f99059fF775485246999027B3197955);
        router = IPancakeRouter02(0x10ED43C718714eb63d5aA57B78B54704E256024E);
        pair = IPancakeFactory(router.factory()).getPair(address(EGD),address(U));
    }
```

EGD的价格是根据两种代币在一个地址上的数量进行计算的，我们在`initialize()函数`中得到pair地址，pair地址是根据router地址进行计算，router为一个代理合约，在区块链浏览器上我们可以看到pair的地址为0xa361433e409adac1f87cdf133127585f8a93c67d，为pancake的一个提供流动性的合约，是不是有点眼熟。

到这里我们也肯定发现了攻击为什么能成功？

- 用户先通过闪电贷在`Pancake LPs`0xa361...中借走了大量的USDT，导致`Pancake LPs`中USDT与EGDpair对中，EGD的价格变得十分便宜。
- 这时用户在`pancakeCall()回调函数`中，兑换奖励，奖励的计算是根据`Pancake LPs`中两种代币的数量进行计算EDG价格，导致EDG的价格很便宜，这是看到`rew`的计算公式，用户获得超额奖励。

下面简单介绍一下，phalcon上后续的调用：

先将`Pancake LPs`上借用的闪电贷归还；随进行了相应的k值验证（确保还款=原款+手续费）

随后在`PancakeSwap: WBNB-BSC-USD 2`借用的闪电贷，进行相应的approve授权

调用swapExactTokensForTokensSupportingFeeOnTransferTokens函数将得到的EGD全部兑换成USDT

随后`PancakeSwap: WBNB-BSC-USD 2`借用的闪电贷归还，并进行相应的k值验证

最后攻击者获利36044 USDT

### 污点分析的方式为什么能够进行检测？

针对脆弱的询价机制，该种机制中某种代币的计算是根据其它代币的余额

- taint source：代表代币的余额，能够被攻击者之间或间接的进行操纵，这时攻击者就能够操作代币的余额
- taint sink：转账的操作，Defi交易中，最终将具体的收益或金额转给用户，判断这里的转账地址能够被攻击者操纵
- source与sink之间存在路径：说明某种代币的余额能够被攻击者所操纵（能够被闪电贷操纵），并且收益或转账金额是于该代币余额有关（说明金融模型询价机制的脆弱），并且最终的收款地址能被攻击者操纵。

![image-20240305154652135](https://gitee.com/Emmanuel_scb/blogimage/raw/master/img/202403051546677.png)



















