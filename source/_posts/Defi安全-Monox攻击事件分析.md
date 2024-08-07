---
title: Defi安全--Monox攻击事件分析--phalcon+etherscan
date: 2023-12-23 16:37:52
tags: [区块链安全, 安全事件分析]
categories: 
  - [Defi安全]
  - [安全事件分析]
description: 摘要：Defi安全--Monox攻击事件分析--phalcon+etherscan
---

## MonoX攻击事件相关信息

在Ethereum和Polygon网络都发生了，攻击手段相同，以Ethereum为例进行分析：

- 攻击者地址：[MonoX Finance Exploiter | Address 0xecbe385f78041895c311070f344b55bfaa953258 | Etherscan](https://etherscan.io/address/0xecbe385f78041895c311070f344b55bfaa953258#code)
- 攻击合约：[Contract Address 0xf079d7911c13369e7fd85607970036d2883afcfd | Etherscan](https://etherscan.io/address/0xf079d7911c13369e7fd85607970036d2883afcfd#code)

- 攻击交易：[Ethereum Transaction Hash (Txhash) Details | Etherscan](https://etherscan.io/tx/0x9f14d093a2349de08f02fc0fb018dadb449351d0cdb7d0738ff69cc6fef5f299)
- 漏洞合约：[Monoswap | Address 0x66e7d7839333f502df355f5bd87aea24bac2ee63 | Etherscan](https://etherscan.io/address/0x66e7d7839333f502df355f5bd87aea24bac2ee63#code)

## Monox代码分析及攻击流程讲解

### Monox介绍：

与Uniswap不同，其使用的是单边代币池模型，其`使用vCash稳定币与AMM提供的代币创建虚拟的交易对`。Monox创建的是代币-vCash交易对，添加流动性的时候，只需添加代币，进行任意代币兑换，兑换方式为：`代币A -- vCash -- 代币B`。

### 攻击原理及过程：

极大地提高Monoswap中Mono代币的价格，后将拥有的Mono代币通过Monoswap换取代币。

具体步骤，查看phalcon上攻击交易的调用序列进行分析

1. 前置阶段

![image-20231223171211651](https://gitee.com/Emmanuel_scb/blogimage/raw/master/img/202312231712103.png)

- 首先调用`WETH`的`deposit（）`函数，向WETH中存入0.1WETH
- 随后调用`approve（）`函数，向Monoswap进行授权，以便后续代币兑换正常进行（在foundry中写测试函数时，很容易遗忘approve这点）
- 随后调用Monoswap的`swapExactTokenForToken（）`函数，将0.1个WETH换成一定数量的Mono(该函数如何实现，可见漏洞合约[Monoswap](https://etherscan.io/address/0x66e7d7839333f502df355f5bd87aea24bac2ee63#code))
- 调用Monoswap的`pools()`函数，具体后续介绍，获得Mono代币在Monoswap中的pid
- 根据pid调用Monoxpool中的`totalSupplyOf()`函数，查询Mono-vCash池子中作为LP流动性证明的Mono总量。

2. 移除用户流动性

![image-20231223215453923](https://gitee.com/Emmanuel_scb/blogimage/raw/master/img/202312232154206.png)

在Monox的官方界面可以看到给Mono代币提供代币流动的用户地址，这里从交易序列中可以很明显发现一个漏洞，别的用户的流动性，攻击者竟然可以任意移除

在Monoswap源码中可以很明显发现，并没有流动性所有者进行相应的校验

```solidity
function _removeLiquidity (address _token, uint256 liquidity,
    address to) view public returns(
    uint256 poolValue, uint256 liquidityIn, uint256 vcashOut, uint256 tokenOut) {
    
    require (liquidity>0, "MonoX:BAD_AMOUNT");
    uint256 tokenBalanceVcashValue;
    uint256 vcashCredit;
    uint256 vcashDebt;
    PoolInfo memory pool = pools[_token];
    IMonoXPool monoXPoolLocal = monoXPool;
    uint256 lastAdded = monoXPoolLocal.liquidityLastAddedOf(pool.pid, msg.sender);
    
    require((lastAdded + (pool.status == PoolStatus.OFFICIAL ? 4 hours : pool.status == PoolStatus.LISTED ? 24 hours : 0)) <= block.timestamp, "MonoX:WRONG_TIME"); // Users are not allowed to remove liquidity right after adding
    address topLPHolder = monoXPoolLocal.topLPHolderOf(pool.pid);
    require(pool.status != PoolStatus.LISTED || msg.sender != topLPHolder || pool.createdAt + 90 days < block.timestamp, "MonoX:TOP_HOLDER & WRONG_TIME"); // largest LP holder is not allowed to remove LP within 90 days after pool creation

    (poolValue, tokenBalanceVcashValue, vcashCredit, vcashDebt) = getPool(_token);
    uint256 _totalSupply = monoXPool.totalSupplyOf(pool.pid);

    liquidityIn = monoXPool.balanceOf(to, pool.pid)>liquidity?liquidity:monoXPool.balanceOf(to, pool.pid);
    uint256 tokenReserve = IERC20(_token).balanceOf(address(monoXPool));
    
    if(tokenReserve < pool.tokenBalance){
      tokenBalanceVcashValue = tokenReserve.mul(pool.price)/1e18;
    }

    if(vcashDebt>0){
      tokenReserve = (tokenBalanceVcashValue.sub(vcashDebt)).mul(1e18).div(pool.price);
    }

    // if vcashCredit==0, vcashOut will be 0 as well
    vcashOut = liquidityIn.mul(vcashCredit).div(_totalSupply);
    tokenOut = liquidityIn.mul(tokenReserve).div(_totalSupply);
  }
```

攻击者发现三个主要提供流动性的用户，先调用Monoxpool的`balanceOf（）`函数查看地址在Monoswap中的Mono数量，后调用移除流动性函数，使得池子中的Mono为0.

3. 添加流动性

攻击者自己添加极少的Mono代币到Monoswap中，获得927个LP，为后续拉升Mono的价格做准备

![image-20231223220301534](https://gitee.com/Emmanuel_scb/blogimage/raw/master/img/202312232203080.png)

4. 拉高Mono代币在Monoswap中的价格

![image-20231223220818186](https://gitee.com/Emmanuel_scb/blogimage/raw/master/img/202312232208153.png)

攻击交易中，重复了55次上述行为

先是调用Monoswap中的`pools()`函数，从中我们可以看出solidity中这种mapping映射的获得，是通过调用函数的形式活动，可以看一下该函数返回的函数类型：

```solidity
mapping (address => PoolInfo) public pools;
  struct PoolInfo {
    uint256 pid;
    uint256 lastPoolValue;
    address token;
    PoolStatus status;
    uint112 vcashDebt;
    uint112 vcashCredit;
    uint112 tokenBalance;
    uint256 price; // over 1e18
    uint256 createdAt; // timestamp
  }
```

这里重点关注的是我们可以通过调用该函数获得该代币在Monoswap中的`tokenBalance`余额和`price`当前价格，攻击交易这里主要想获得池子中的tokenBalance余额。

随后查看攻击者先前用0.1个WETH兑换的Mono代币的余额，即还剩多少个

随后最关键的步骤调用Monoswap的`swapExactTokenForToken()`函数，这个函数的功能与uniswap很像，顾名思义，将精准数量的代币兑换成一定数量的另一种代币，这里我们能够很明显发现，参数`tokenIn`和`tokenOut`都是Mono，这就是攻击手段！

所以肯定是该函数中存在漏洞，导致Mono代币价格的拉高。进入函数中看一下。

```solidity
  function swapExactTokenForToken(
    address tokenIn,
    address tokenOut,
    uint amountIn,
    uint amountOutMin,
    address to,
    uint deadline
  ) external virtual ensure(deadline) returns (uint amountOut) {
    amountOut = swapIn(tokenIn, tokenOut, msg.sender, to, amountIn);
    require(amountOut >= amountOutMin, 'MonoX:INSUFF_OUTPUT');
  }
  
  function swapIn (address tokenIn, address tokenOut, address from, address to,
      uint256 amountIn) internal lockToken(tokenIn) returns(uint256 amountOut)  {

    address monoXPoolLocal = address(monoXPool);

    amountIn = transferAndCheck(from,monoXPoolLocal,tokenIn,amountIn); 
    
    // uint256 halfFeesInTokenIn = amountIn.mul(fees)/2e5;

    uint256 tokenInPrice;
    uint256 tokenOutPrice;
    uint256 tradeVcashValue;
    
    (tokenInPrice, tokenOutPrice, amountOut, tradeVcashValue) = getAmountOut(tokenIn, tokenOut, amountIn);

    uint256 oneSideFeesInVcash = tokenInPrice.mul(amountIn.mul(fees)/2e5)/1e18;

    // trading in
    if(tokenIn==address(vCash)){
      vCash.burn(monoXPoolLocal, amountIn);
      // all fees go to the other side
      oneSideFeesInVcash = oneSideFeesInVcash.mul(2);
    }else{
      _updateTokenInfo(tokenIn, tokenInPrice, 0, tradeVcashValue.add(oneSideFeesInVcash), 0);
    }

    // trading out
    if(tokenOut==address(vCash)){
      vCash.mint(to, amountOut);
    }else{
      if (to != monoXPoolLocal) {
        IMonoXPool(monoXPoolLocal).safeTransferERC20Token(tokenOut, to, amountOut);
      }
      _updateTokenInfo(tokenOut, tokenOutPrice, tradeVcashValue.add(oneSideFeesInVcash), 0, 
        to == monoXPoolLocal ? amountOut : 0);
    }

    if(pools[tokenIn].vcashDebt > 0 && pools[tokenIn].status == PoolStatus.OFFICIAL){
      _internalRebalance(tokenIn);
    }

    emit Swap(to, tokenIn, tokenOut, amountIn, amountOut, tradeVcashValue);
    
  }
  
```

swapIn函数较复杂，我们可以从后往前看，看到它有个`_updateTokenInfo()`函数，更新token的信息，看一下源码

```solidity
  function _updateTokenInfo (address _token, uint256 _price,
      uint256 _vcashIn, uint256 _vcashOut, uint256 _ETHDebt) internal {
    uint256 _balance = IERC20(_token).balanceOf(address(monoXPool));
    _balance = _balance.sub(_ETHDebt);
    require(pools[_token].status!=PoolStatus.PAUSED,"MonoX:PAUSED");
    require(_balance <= uint112(-1));
    (uint initialPoolValue, , ,) = getPool(_token);
    pools[_token].tokenBalance = uint112(_balance);
    pools[_token].price = _price;

    // record last trade's block number in mapping: lastTradedBlock
    lastTradedBlock[_token] = block.number;

    _updateVcashBalance(_token, _vcashIn, _vcashOut);

    (uint poolValue, , ,) = getPool(_token);

    require(initialPoolValue <= poolValue || poolValue >= poolSizeMinLimit,
      "MonoX:MIN_POOL_SIZE");
    
    
  }
```

从代码中我们可以看出，将Monoswap池子中代币的数量和价格更新，其中代币的价格就是函数参数的`tokenInPrice`和`tokenOutPrice`,这两个参数都是通过`getAmountOut（）`函数计算得到，进入该函数，分析源码：

```solidity
function getAmountOut(address tokenIn, address tokenOut, 
    uint256 amountIn) public view returns (uint256 tokenInPrice, uint256 tokenOutPrice, 
    uint256 amountOut, uint256 tradeVcashValue) {
    require(amountIn > 0, 'MonoX:INSUFF_INPUT');
    
    uint256 amountInWithFee = amountIn.mul(1e5-fees)/1e5;
    address vcashAddress = address(vCash);
    uint tokenInPoolPrice = pools[tokenIn].price;
    uint tokenInPoolTokenBalance = pools[tokenIn].tokenBalance;

    if(tokenIn==vcashAddress){
      tradeVcashValue = amountInWithFee;
      tokenInPrice = 1e18;
    }else{
      require (tokenPoolStatus[tokenIn]==1, "MonoX:NO_POOL");
      // PoolInfo memory tokenInPool = pools[tokenIn];
      PoolStatus tokenInPoolStatus = pools[tokenIn].status;
      
      require (tokenInPoolStatus != PoolStatus.UNLISTED, "MonoX:POOL_UNLST");
      
      tokenInPrice = _getNewPrice(tokenInPoolPrice, tokenInPoolTokenBalance, 
        amountInWithFee, 0, TxType.SELL);
      tradeVcashValue = _getAvgPrice(tokenInPoolPrice, tokenInPrice).mul(amountInWithFee)/1e18;
    }

    if(tokenOut==vcashAddress){
      amountOut = tradeVcashValue;
      tokenOutPrice = 1e18;
    }else{
      require (tokenPoolStatus[tokenOut]==1, "MonoX:NO_POOL");
      // PoolInfo memory tokenOutPool = pools[tokenOut];
      PoolStatus tokenOutPoolStatus = pools[tokenOut].status;
      uint tokenOutPoolPrice = pools[tokenOut].price;
      uint tokenOutPoolTokenBalance = pools[tokenOut].tokenBalance;

      require (tokenOutPoolStatus != PoolStatus.UNLISTED, "MonoX:POOL_UNLST");
      
      amountOut = tradeVcashValue.add(tokenOutPoolTokenBalance.mul(tokenOutPoolPrice).div(1e18));
      amountOut = tradeVcashValue.mul(tokenOutPoolTokenBalance).div(amountOut);

      bool allowDirectSwap=directSwapAllowed(tokenInPoolPrice,tokenOutPoolPrice,tokenInPoolTokenBalance,tokenOutPoolTokenBalance,tokenOutPoolStatus,true);

      // assuming p1*p2 = k, equivalent to uniswap's x * y = k
      uint directSwapTokenOutPrice = allowDirectSwap?tokenInPoolPrice.mul(tokenOutPoolPrice).div(tokenInPrice):uint(-1);

      // prevent the attack where user can use a small pool to update price in a much larger pool
      tokenOutPrice = _getNewPrice(tokenOutPoolPrice, tokenOutPoolTokenBalance, 
        amountOut, 0, TxType.BUY);
      tokenOutPrice = directSwapTokenOutPrice < tokenOutPrice?directSwapTokenOutPrice:tokenOutPrice;

      amountOut = tradeVcashValue.mul(1e18).div(_getAvgPrice(tokenOutPoolPrice, tokenOutPrice));
    }
  }

```

通过上述代码可以得到，`tokenInPrice`和`tokenOutPrice`参数的计算都是通过`_getNewPrice（）`函数，得到函数源码

```solidity
  function _getNewPrice (uint256 originalPrice, uint256 reserve, 
    uint256 delta, uint256 deltaBlocks, TxType txType) pure internal returns(uint256 price) {
    if(txType==TxType.SELL) {
      // no risk of being div by 0
      price = originalPrice.mul(reserve)/(reserve.add(delta));
    }else{ // BUY
      price = originalPrice.mul(reserve).div(reserve.sub(delta));
    }
  }
```

通过，我们可以发现tokenIn代币，其TxType为SELL，tokenOut代币其Txtype为BUY。

故可分析，tokenIn代表先进行价格更新计算，originalPrice和reserve都是池子中原来保存的参数，其不会发生变动，相较于originalPrice价格,tokenInPrice变低了。

分析`_getAvgPrice()`函数，我们进一步可以分析得到trashVcashValue也变低了，其与toknInPrice呈相同趋势。

```solidity
  function _getAvgPrice (uint256 originalPrice, uint256 newPrice) pure internal returns(uint256 price) {
    price = originalPrice.add(newPrice.mul(4))/5;
  }
```

随后，`getAmountOut（）`函数正常执行，计算tokenOut代币的相关信息，分析`_getNewPrice（）`函数，肯定可以得到的一个结论是相比于originalPrice也就是池子中代币的价格，tokenOutPrice变高的。

这时可以不用管其它参数的变化，这里最大的问题，就是这种同种代币的兑换，在`swapIn()`函数中，其先对tokenIn进行处理，更新代币相应的信息，但其后对tokenOut进行处理时，*没有考虑前后兑换为同一种代币的情况*，导致代币的价格被覆盖。

从上述分析中，可得到tokenOut的价格被抬升，tokenIn价格降低，但Mono的价格在兑换时，被覆盖，导致Mono价格异常增长。

对phalcon中兑换交易的参数分析可得，每次兑换的数量都是交易池中Mono的总量减去1，使得`_getNewPrice（）`函数计算tokenOutPrice时，能够快速提升价格，**这里也就不能理解第3步中添加流动性的时候，添加很少的Mono**，确保攻击者有足够的余额拉高mono的价格。

5. 转移非法资产

![image-20231224105100083](https://gitee.com/Emmanuel_scb/blogimage/raw/master/img/202312241051714.png)

攻击者先通过Monoswap查看池子中USDC的价格和余额，随后通过uniswap的USDC/WETH池接入WETH，乐观转账，在`uniswapV2call()`函数中调用Monoswap的`swapTokenForExactToken()`函数，将价格极高的Mono代币，换成一定数量的USDB，用以偿还uniswap闪电贷中的USDC（在uniswap闪电贷中，其可以通过还对应的pair代币），这样就将高价格的Mono代币转换成了对应的WETH（可以注意一下phalcon上这里的USDC数字，应该只是6位小数）。

随后的资产转移方式相同。



























