---
title: Defi中的价格操纵攻击
date: 2023-12-16 11:20:43
tags: [区块链安全, Defi安全]
categories: 
  - [Defi安全]
  - [智能合约]
description: 摘要：Defi中的价格操纵攻击
---

# Defi中的价格操纵攻击
## 直接价格操纵攻击：

某些Defi应用程序具有AMM中交易Token的接口，但是，这些接口如果没有得到适当的保护，则攻击者可以滥用这些接口来代表受攻击的Defi应用程序交易Token，会影响Token对的汇率，然后攻击者可以利用自己的Token进行另一笔交易以获取利益。

Token的价格是通过在AMM中交易Token对来直接操纵的，称为直接价格操纵攻击。‘

![https://pic1.zhimg.com/80/v2-6a170a2bb1213a4bdfd3ad9f98b0bcc8_720w.webp](https://gitee.com/Emmanuel_scb/blogimage/raw/master/img/202312161121807.png)

上图显示了一个示例。假设池具有与Token对X和Y相同的初始储备金（1，000）。在正常交易中，根据公式（1），用户可以用10 X获得9.9Y。攻击者可以使用以下三个步骤来执行直接价格操纵攻击。

步骤一：价格操纵第一阶段，攻击者使用900 X（占池的大部分）来交换TokenY，这破坏了Token对的余额并提高了TokenY在池中的价格。

步骤二：价格操纵第二阶段，攻击者调用易受攻击的DeFi应用程序的公共界面来出售10X。但是，DeFi应用程序在消耗10 X后只能获得2.75Y。这是因为上一步降低了TokenX的价格。此外，该交易进一步提升了X X的价格。池中TokenY的价格。

步骤三：成本赎回和获利，攻击者通过反向交易出售473 Y，获得905X。那是因为TokenY的价格已在第二步中提高了。这样，攻击者可以获得5倍的利润。

具体来说，第一步是增加TokenY的价格，并降低TokenX在池中的价格。根公式（1），这是预期的行为。但是，第二步使易受攻击的DeFi应用程序出售其TokenX，并进一步提高TokenY的价格。这是通过利用易受攻击的DeFi应用程序的公开接口来实现的。结果，攻击者可以通过出售TokenY进行反向交换，并获得更多的X（本示例中为5）。与正常交易（10 X和9.9 Y）相比，受害者DeFi应用损失了7.15 Y（即7.15 = 9.9 – 2.75）。

## 间接价格操纵攻击

一些Defi应用需要出于商业目的使用Token价格，例如，需要一个借款应用程序来计算抵押物的价格，以决定借款人有资格借多少枚Token。如果借款应用程序的价格机制是可操纵的，则借款人所借的Token可能会比抵押品的未偿本金余额更多（即抵押不足）

![https://pic1.zhimg.com/80/v2-9ae2145434d17f36a6c867d59541a16c_720w.webp](https://gitee.com/Emmanuel_scb/blogimage/raw/master/img/202312161121787.png)

上面的例子中，借款应用程序使用从AMM中获取的Token对的实时汇率（通过调用AMM的智能合约公开的API）来确定抵押物的价值。假设TokenX和Y之间的初始汇率为1：1。在正常借款情况下，由于借款应用程序的抵押物比率为150％，因此用户将1.5个TokenX存入贷方应用程序作为抵押，并借入1个TokenY。攻击者通过以下步骤发起间接价格操纵攻击：

步骤一：价格操纵，攻击者用大量的TokenY来交换TokenX，耗尽了池中很大一部分的TokenX，从而为TokenX产生了虚高的价格。由于借用应用程序的价格机制取决于AMM的实时报价，TokenX的价格也会在借款应用中被夸大。

步骤二：获利，在操纵了TokenX的价格之后，攻击者只需使用TokenX作为抵押品就可以借入TokenY。特别是，他或她可以以与正常借款情况相同的抵押物（1.5 X）借入2 Y而不是1Y。

步骤三：成本补偿，攻击者只需要通过在AMM池中进行反向交换来赎回价格操纵的成本。这种攻击的根本原因是，脆弱的借款应用利用AMM的实时报价来决定抵押物的价格。结果，攻击者可以在AMM的交易池中进行交易以影响Token价格（步骤I），然后从借款应用借入抵押不足的借款（步骤II）。之后，攻击者进行反向交易以赎回成本（步骤III）

## 1. HEALTH -20221020

不正确的计算

```solidity
function _transfer(address from, address to, uint256 value) private {
        require(value <= _balances[from]);
        require(to != address(0));
        
        uint256 contractTokenBalance = balanceOf(address(this));

        bool overMinTokenBalance = contractTokenBalance >= numTokensSellToAddToLiquidity;
        if (
            overMinTokenBalance &&
            !inSwapAndLiquify &&
            to == uniswapV2Pair &&
            swapAndLiquifyEnabled
        ) {
            contractTokenBalance = numTokensSellToAddToLiquidity;
            //add liquidity
            swapAndLiquify(contractTokenBalance);
        }
        if (block.timestamp >= pairStartTime.add(jgTime) && pairStartTime != 0) {
            if (from != uniswapV2Pair) {
                uint256 burnValue = _balances[uniswapV2Pair].mul(burnFee).div(1000);  //vulnerable point
                _balances[uniswapV2Pair] = _balances[uniswapV2Pair].sub(burnValue);  //vulnerable point
                _balances[_burnAddress] = _balances[_burnAddress].add(burnValue);  //vulnerable point
                if (block.timestamp >= pairStartTime.add(jgTime)) {
                    pairStartTime += jgTime;
                }
                emit Transfer(uniswapV2Pair,_burnAddress, burnValue);
                IPancakePair(uniswapV2Pair).sync();
            }
```

攻击者可以通过多次转移HEALTH代币，以减少Uniswap对中的HEALTH代币，来执行价格操纵。

攻击过程：

1. 攻击合约首先通过闪电贷获得大量WBNB，然后通过PancakeRouter交易所兑换HEALTH。
2. 查看攻击过程，发现反复调用HEALTH.transfer，销毁了流动池大量的Health代币
3. 合约调用_transfer时，校验条件太松，销毁流动池中的Health代币，导致Health兑换WBNB价格升高。

## 2. ATK-20221012

balanceOf函数导致的不正确的价格计算

不安全地使用balanceOf函数，导致很容易收到闪电贷价格操纵的影响

在AST代币合约中使用getPrice()函数

```solidity
function getPrice() public view returns(uint256){
        uint256 UDPrice;
        uint256 UDAmount  = balanceOf(_uniswapV2Pair); //vulnerable point
        uint256 USDTAmount = USDT.balanceOf(_uniswapV2Pair); //vulnerable point
        UDPrice = UDAmount.mul(10**18).div(USDTAmount);
        return UDPrice;
```

## 3. RES Token-20221006

不正确的奖励计算

thisAToB()函数，burn RES代币以提高兑换率

攻击者进行了多次交换以获得奖励ALL代币，并且burn RES代币以提高兑换率

```solidity
function _transfer(address sender, address recipient, uint256 amount) internal {
        require(!_blacklist[tx.origin], "blacklist!");
        require(!isContract(recipient) || _whiteContract[recipient] || sender == owner() || recipient == owner(), "no white contract");
        require(sender != address(0), "BEP20: transfer from the zero address");
        require(recipient != address(0), "BEP20: transfer to the zero address");
        require(recipient != address(this), "transfer fail");
        require(_allToken != address(0), "no set allToken");
        if(sender != owner() && recipient != owner() && IPancakePair(_swapV2Pair).totalSupply() == 0) {
            require(recipient != _swapV2Pair,"no start");
        }
        _balances[sender] = _balances[sender].sub(amount, "BEP20: transfer amount exceeds balance");
        
        bool skip = _isSkip(sender, recipient);
        TransferType transferType = _transferType(sender, recipient);
        
        uint256 amountRecipient = amount;
        if (!_lockSwapFee && !skip && transferType != TransferType.TRANSFER){
            if (transferType == TransferType.SWAP_BUY){
                if (_isBuySwap(amount)){
                    amountRecipient = amount.mul(uint256(100).sub(_buyFee)).div(100);
                    _distBuyFee(recipient, amount.mul(_buyFee).div(100)); //Get ALLtoken reward
                }
            }else if(transferType == TransferType.SWAP_SELL){
                if (_isSellSwap(amount)){
                    amountRecipient = amount.mul(uint256(100).sub(_sellFee)).div(100);
                    _distSellFee(sender, amount.mul(_sellFee).div(100));
                }
            }
        }
        
        if (transferType == TransferType.TRANSFER){
            _thisAToB(); //vulnerable point - burn RES
        }

function _thisAToB() internal{
        if (_balances[address(this)] > _minAToB){
            uint256 burnNumber = _balances[address(this)];
            _approve(address(this),_pancakeRouterToken, _balances[address(this)]);
            IPancakeRouter(_pancakeRouterToken).swapExactTokensForTokensSupportingFeeOnTransferTokens(
                _balances[address(this)],
                0,
                _pathAToB,
                address(this),
                block.timestamp);
            _burn(_swapV2Pair, burnNumber);  //vulnerable point
            IPancakePair(_swapV2Pair).sync();
        }
    }
```

## 4. RL Token-20221001

不正确的奖励计算

```solidity
function transferFrom( 
        address from,
        address to,
        uint256 amount
    ) public virtual override returns (bool) { 
        if (from != address(pancakeSwapV2Pair) && from != address(pancakeSwapV2Router)) {
            incentive.distributeAirdrop(from);
        }
        if (to != address(pancakeSwapV2Pair) && to != address(pancakeSwapV2Router)) {
            incentive.distributeAirdrop(to); //trace function
        }
        if (msg.sender != address(pancakeSwapV2Pair) && msg.sender != address(pancakeSwapV2Router)) {
            incentive.distributeAirdrop(msg.sender); //trace function
        }
        require(allowance(from, msg.sender) >= amount, "insufficient allowance");
        if (govIDO != address(0)) {
            if (IKBKGovIDO(govIDO).isPriSaler(from)) {
                IKBKGovIDO(govIDO).releasePriSale(from);
            }
            if (IKBKGovIDO(govIDO).isPriSaler(to)) {
                IKBKGovIDO(govIDO).releasePriSale(to);
            }
        }
        //sell
        if (to == address(pancakeSwapV2Pair) && msg.sender == address(pancakeSwapV2Router)) {
            if (!isCommunityAddress[from]) {
                uint burnAmt = amount / 100;
                _burn(from, burnAmt);
                uint slideAmt = amount * 2 / 100;
                _transfer(from, slideReceiver, slideAmt);
                amount -= (burnAmt + slideAmt);
            }
        } else {
            if (!isCommunityAddress[from] && !isCommunityAddress[to]) {
                uint burnAmt = amount / 100;
                amount -= burnAmt;
                _burn(from, burnAmt);
            }
        }
        return super.transferFrom(from, to, amount);
    }
```

```solidity
function distributeAirdrop(address user) public override {
        if (block.timestamp < airdropStartTime) {
            return;
        }
        updateIndex();
        uint256 rewards = getUserUnclaimedRewards(user); //vulnerable point
        usersIndex[user] = globalAirdropInfo.index;
        if (rewards > 0) {
            uint256 bal = rewardToken.balanceOf(address(this));
            if (bal >= rewards) {
                rewardToken.transfer(user, rewards);
                userUnclaimedRewards[user] = 0;
            }
        }
    }
function getUserUnclaimedRewards(address user) public view returns (uint256) {
        if (block.timestamp < airdropStartTime) {
            return 0;
        }
        (uint256 newIndex,) = getNewIndex();
        uint256 userIndex = usersIndex[user];
        if (userIndex >= newIndex || userIndex == 0) {
            return userUnclaimedRewards[user];
        } else {
				//vulnerable point, Incorrect Reward calculation. only check balanceof of user without any requirement.
            return userUnclaimedRewards[user] + (newIndex - userIndex) * lpToken.balanceOf(user) / PRECISION;
        }
    }
```

## 5. BXH -20220928

不正确的奖励计算

错误地使用getReserves()函数来获取池中的余额，并通过getAmountOut来计算bonus

```solidity
function getITokenBonusAmount( uint256 _pid, uint256 _amountInToken ) public view returns (uint256){
        PoolInfo storage pool = poolInfo[_pid];

        (uint112 _reserve0, uint112 _reserve1, ) = IUniswapV2Pair(pool.swapPairAddress).getReserves(); //vulnerable point
        uint256 amountTokenOut = 0; 
        uint256 _fee = 0;
        if(IUniswapV2Pair(pool.swapPairAddress).token0() == address(iToken)){
            amountTokenOut = getAmountOut( _amountInToken , _reserve0, _reserve1, _fee); //vulnerable point
        } else {
            amountTokenOut = getAmountOut( _amountInToken , _reserve1, _reserve0, _fee); //vulnerable point
        }
        return amountTokenOut;
    }

    function getAmountOut(uint amountIn, uint reserveIn, uint reserveOut, uint256 feeFactor) private pure returns (uint ) {
        require(amountIn > 0, 'UniswapV2Library: INSUFFICIENT_INPUT_AMOUNT');
        require(reserveIn > 0 && reserveOut > 0, 'UniswapV2Library: INSUFFICIENT_LIQUIDITY');

        uint256 feeBase = 10000;

        uint amountInWithFee = amountIn.mul(feeBase.sub(feeFactor));
        uint numerator = amountInWithFee.mul(reserveOut);
        uint denominator = reserveIn.mul(feeBase).add(amountInWithFee);
        uint amountOut = numerator / denominator;
        return amountOut;
    }
```
