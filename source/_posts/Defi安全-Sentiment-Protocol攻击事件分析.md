---
title: Defi安全--Sentiment Protocol攻击事件分析
date: 2024-01-21 10:40:55
tags: ['Defi安全','安全事件分析']
categories:
  - ['Defi安全']
  - ['安全事件分析']
description: 摘要：Defi安全-Sentiment Protocol攻击事件分析--phalcon+arbiscan
---

## 1. Sentiment Protocol攻击事件相关信息

2023年4月5日，在Arbitrum上的Sentiment项目被攻击

- 攻击合约的地址：[Contract Address 攻击合约| Arbiscan](https://arbiscan.io/address/0x9f626f5941fafe0a5b839907d77fbbd5d0dea9d0)
- 攻击者地址：[Sentimentxyz Exploiter  Arbiscan](https://arbiscan.io/address/0xdd0cdb4c3b887bc533957bc32463977e432e49c3)
- 攻击交易：[Arbitrum Transaction Hash (Txhash) Details | Arbiscan](https://arbiscan.io/tx/0xa9ff2b587e2741575daf893864710a5cbb44bb64ccdc487a100fa20741e0f74d)
- Phalcon序列分析：[0xa9ff2b587e2741575d | Phalcon Explorer (blocksec.com)](https://phalcon.blocksec.com/explorer/tx/arbitrum/0xa9ff2b587e2741575daf893864710a5cbb44bb64ccdc487a100fa20741e0f74d)

## 2. Sentiment Protocol攻击事件分析

### Sentiment项目简介

Sentiment项目：`不足额抵押`，抵押价值较少的token，却能够借贷较多价值的token，`不足额抵押`的token不会直接给到用户，而是存在一个和用户一一对应的Account中，用户可以指挥Account去Defi中（Sentiment的白名单合作伙伴），如aave、balancer等项目中投资。

大多数情况用户不能自由对资金操作，用户能否自由地处理这笔资金，取决于是否能够绕过Sentiment的RiskEngine的安全检查。

### 攻击流程详解：

1. 该攻击是发生在Arbitrum链上的Sentiment项目，攻击者直接调用对应的run()函数，发起攻击

<img src="https://gitee.com/Emmanuel_scb/blogimage/raw/master/img/202401211048889.png" alt="image-20240121104839972" style="zoom:80%;" />

![image-20240121104910090](https://gitee.com/Emmanuel_scb/blogimage/raw/master/img/202401211049470.png)

2. 攻击合约调用Aave的闪电贷函数，借出对应的WBTC、WETH、USDC.e三种代币，606个WBTC，10050个WETH和18,000,000个 USDC，`isFlashBorrower`会判断是否已经借款，随后执行响应的闪电贷逻辑，乐观转账，将三种代币转到攻击者合约账户上

![image-20240121110845649](https://gitee.com/Emmanuel_scb/blogimage/raw/master/img/202401211108030.png)

3. 攻击者先查看的pair(B-33WETH-33WBTC-33USDC)池子中的价格，随后调用Proxy_62c5_6403合约（Sentiment协议中）去创建一个Account账户，对应攻击者的账户，地址记为BeaconProxy，下图是创建Account的步骤，涉及到Balancer项目逻辑。

![image-20240121111747175](https://gitee.com/Emmanuel_scb/blogimage/raw/master/img/202401211117349.png)

4. 随后攻击者给Proxy代理合约，授权了50个WETH，随后调用proxy代理合约的`deposit()`函数，给BeaconProxy攻击者对应的账户进行响应的存款，将对应的50个WETH转到BeaconProxy合约中，具体步骤如下：

![image-20240121112351411](https://gitee.com/Emmanuel_scb/blogimage/raw/master/img/202401211123766.png)

5. 随后攻击者调用Proxy代理合约的approve函数，即AccountManager合约进行授权，让AccountManager将存款的50个WETH，授权给Balancer: Vault合约进行相应的投资

6. 随后攻击者调用的AccountManager的exec函数，执行相应的Balancer: Vault投资，判断是不是BeaconProxy合约等，然后调用BeaconProxy合约的exec函数，向Balancer的B-33WETH-33WBTC-33USDC池子中，存入50个WETH，进行相应的转账，攻击者获得221个B-33WETH-33WBTC-33USDC的LP

![image-20240121113357220](https://gitee.com/Emmanuel_scb/blogimage/raw/master/img/202401211134707.png)

7. 随后攻击者将相应的606个WBTC，10000个WETH和18,000,000个 USDC都给Balancer: Vault，该项目的合约进行相应的授权

![image-20240121113943173](https://gitee.com/Emmanuel_scb/blogimage/raw/master/img/202401211139904.png)

8. 随后攻击者绕过Sentiment项目，直接给Balancer: Vault该项目的B-33WETH-33WBTC-33USDC池进行投资，同样调用的是`onJoinPool`函数，这时候池子中的LP价格上升，攻击者有13w个LP

![image-20240121114252559](https://gitee.com/Emmanuel_scb/blogimage/raw/master/img/202401211142981.png)

9. 这时候攻击者调用Balancer: Vault的`exitPool`函数，想取走所有的存款，这是Balancer会进行相应的转账，将资金转给攻击者，而这时WETH的转账就触发了攻击者的fallback函数，这里注意取款的时候，会先对相应的LP进行销毁（关键步骤）

![image-20240121154256697](https://gitee.com/Emmanuel_scb/blogimage/raw/master/img/202401211543577.png)10.  因为在4-6步中，攻击者在sentiment中存入了50个WETH，作为抵押物，攻击者能够进行不足额借贷，这是攻击者想借出461000USDC、361000USDT、81ETH、125000FRAX，看一下这里的借币逻辑，抵押物能借多少款，是有对应的限制

11. 攻击者调用AccountManager合约中的borrow函数，以USDC为例进行说明，会直接调用到LUSD Coin (LUSDC)合约的lendTo函数，lendTo将将借款的USDC，减去部分手续费后，转给BeaconProxy，管理用户account的合约。

![image-20240121150832950](https://gitee.com/Emmanuel_scb/blogimage/raw/master/img/202401211508106.png)

12. RiskEngine调用`isAccountHealthy`函数，检查用户的仓位是否健康，正常；攻击者手上因为抵押50WETH，现有有200多LP，随后通过OracleFacade合约，得到LP当前的价格，进入该函数看一下函数源码：

    - 该函数先获得池子中token种类，以及对应的余额，即为B-33WETH-33WBTC-33USDC三种代币
    - 池子代币权重应该是相同的
    - 计算对应的LP价格，忽略乘除法，指数运算，关注变量在分子还是分母即可

    $$
    price = \frac{Price(token_i)*Balance(token_i)....}{TotalSupply(LP token)}
    $$

```solidity
    function getPrice(address token) external view returns (uint) {
        (
            address[] memory poolTokens,
            uint256[] memory balances,
        ) = vault.getPoolTokens(IPool(token).getPoolId());

        uint256[] memory weights = IPool(token).getNormalizedWeights();

        uint length = weights.length;
        uint temp = 1e18;
        uint invariant = 1e18;
        for(uint i; i < length; i++) {
            temp = temp.mulDown(
                (oracleFacade.getPrice(poolTokens[i]).divDown(weights[i]))
                .powDown(weights[i])
            );
            invariant = invariant.mulDown(
                (balances[i] * 10 ** (18 - IERC20(poolTokens[i]).decimals()))
                .powDown(weights[i])
            );
        }
        return invariant
            .mulDown(temp)
            .divDown(IPool(token).totalSupply());
    }
}
```

![image-20240121153045993](https://gitee.com/Emmanuel_scb/blogimage/raw/master/img/202401211530739.png)

13. 这里`isAccountHealthy`判断账户是否正常的逻辑是判断，用户的资产和用户想借贷的金额不能超出一个阈值，而用户的资产是和用户代币的数量和代币目前的价格计算决定的。通过上图，能发现LP的价格在经过Balancer直接存款后，是大大增加的
14. 由于取款的时候，先将对应的LPtoken销毁，随后进行三种代币的转账，其中ETH触发fallback函数，这是攻击者通过Sentiment进行借款，通过上述公式，可见LPtoken数量减少，但这是Token的余额都还没有更新，导致LP代币的价格大幅度增加，用户可以借出超出它抵押的金额

15. 在借出大量的资金后，攻击者将所有的代币都通过AccountManager合约，进行相应的投资，先进行approve操作，后调用exec函数，都投资到Aave中

![image-20240121155340470](https://gitee.com/Emmanuel_scb/blogimage/raw/master/img/202401211553791.png)

16. 这里看一下AccountManager的六个exec都干了什么事情：将对应的稳定币都转换为aArbitrum上的币，并通过AccountManager合约转出给攻击者，为什么能转给攻击者？
    - `isAccountHealthy`判断账户是否正常的逻辑是判断，用户的资产和用户想借贷的金额不能超出一个阈值，用户的LP资产价值大大增加，故可进行其它代币的转账操作
17. 这是fallback函数执行结束，USDC也完成相应的转账，PoolBalanceChanged池子中的代币余额才发生变化，随后攻击者给Aave合约进行相应的代币授权，其要包含交易的手续费，Aave的闪电贷函数会自动进行扣款

![image-20240121155918090](https://gitee.com/Emmanuel_scb/blogimage/raw/master/img/202401211559941.png)

## 攻击原因分析：

Read-only Reentrancy：攻击者调用一个项目合约中，攻击者操纵了合约中的一个状态，这时回调到了攻击者，另一个项目合约的状态依赖于该合约，这时攻击者回调进入另一合约，进行不当获利。

- Balancer项目在添加或移除流动性的时候，都是先进行LPtoken的余额变化，后进行转账，再更新池子余额，转账ETH，会进入攻击合约的fallback函数
- 而在Sentiment协议中，用户抵押后能贷款的数量，是一定程度依赖于Balancer，而Balancer并未及时更新，被攻击者操作，导致比质押更多的资产被借出。

ROR与典型重入的关键不同是，ROR不是发生在一个合约中，不是重入同一个合约，这样通过序列判断的方式就不太可能实现
