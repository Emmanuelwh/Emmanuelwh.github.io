---
title: foundry使用二
date: 2023-12-16 10:59:52
tags: [区块链安全, 区块链工具]
categories: 区块链工具
description: 摘要：forge命令行的使用
---

# 2. Forge：

Forge是Foundry附带的命令行工具，用来测试、构建和部署智能合约

```docker
forge test
```

运行测试用例，所有测试都是Solidity编写

Forge将从源目录的任何位置查找测试，任何具有以test开头的函数的合约都被认为是一个测试。

通常测试放在`src/test中`

通过传递过滤器运行特定测试：

```docker
forge test --match-contract ComplicatedContractTest --match-test testDeposit
```

这将在名称中带有 `testDeposit` 的 `ComplicatedContractTest` 测试合约中运行测试。

## 2.1 编写测试：

测试代码是用Solidity编写的，最常见的测试编写是通过`Forge` ****标准库的`Test`合约实现。

使用Forge标准库，会利用到DSTest合约，其提供基本的日志记录和断言功能

导入`forge-std/Test.sol` 并继承自测试合约`Test`

```solidity
import "forge-std/Test.sol";
```

一个测试案例：

```solidity
pragma solidity 0.8.10;

import "forge-std/Test.sol";

contract ContractBTest is Test {
    uint256 testNumber;

    function setUp() public {
        testNumber = 42;
    }

    function testNumberIs42() public {
        assertEq(testNumber, 42);
    }

    function testFailSubtract43() public {
        testNumber -= 43;
    }
}
```

- `setUp()` :在每个测试用例运行之前调用的可选函数
- `test()` :以`test` 为前缀的函数作为测试用例执行
- `testFail()` :`test` 的相反情况，如果函数没有报错revert，那么测试失败

> 测试函数必须具有`external` 或`public` ，否则测试函数将无效
>

## 2.2 cheatcodes

为了操纵区块链的状态，以及测试特定的`reverts` 和事件`Events` ，Foundry附带一组cheatcodes

通过Forge标准库中的`Test` 合约提供的`vm` 实例可以访问cheatcode。

以一个例子进行详细说明：

我们的目的是为了验证一个合约的函数只能被合约所有者所调用，编写个测试

在`./test` 文件夹下添加一个Owner.t.sol测试文件

```solidity
pragma solidity 0.8.10;
import "forge-std/Test.sol";
error Unauthorized();

contract OwnerUpOnly {
    address public immutable owner;
    uint256 public count;
    constructor() {
        owner = msg.sender;
    }
    function increment() external {
        if (msg.sender != owner) {
            revert Unauthorized();
        }
        count++;
    }
}

contract OwnerUpOnlyTest is Test {
    OwnerUpOnly upOnly;
    function setUp() public {
        upOnly = new OwnerUpOnly();
    }
    function testIncrementAsOwner() public {
        assertEq(upOnly.count(), 0);
        upOnly.increment();
        assertEq(upOnly.count(), 1);
    }
}
```

运行`forge test` ,发现测试通过

接下来测试不是所有者的人不能增加计数

合约`OwnerUpOnlyTest` 中添加一函数：

```solidity
function testIncrementAsNotOwner() public {
        vm.prank(address(0));
        upOnly.increment();
    }
```

再次运行`forge test` ,发现测试revert，说明不是合约所有者不能增加计数

![forge test示例](https://gitee.com/Emmanuel_scb/blogimage/raw/master/img/202312161100300.png)

`**vm.prank(address)`** cheatcode将msg.sender的身份更改为零地址后，进行下一次调用，保证调用者不是合约所有者。

完整的 `cheatcode` 的详细介绍可见 [[Cheatcodes 参考 - Foundry 中文文档 (learnblockchain.cn)](https://learnblockchain.cn/docs/foundry/i18n/zh/cheatcodes/index.html)]

## 2.3 Forge标准库概览

`Forge Std`提供了编写测试代码所需的所有基本功能

- `Vm.sol`：最新的作弊码接口
- `console.sol` 和 `console2.sol`：Hardhat 风格的日志记录功能
- `Script.sol`：[Solidity 脚本](https://learnblockchain.cn/docs/foundry/i18n/zh/tutorials/solidity-scripting.html) 的基本实用程序
- `Test.sol`：DSTest 的超集，包含标准库、作弊码实例 (`vm`) 和 Hardhat 控制台

## 2.4 了解Traces

Forge可以为失败的测试（`-vvv`）或所有测试（`-vvvv`）生成跟踪`Traces`

`Traces` 的不同颜色

- **绿色**：对于不会 revert 的调用
- **红色**：用于有 revert 的调用
- **蓝色**：用于调用作弊码
- **青色**：用于触发日志
- **黄色**：用于合约部署
![forge trace示例](https://gitee.com/Emmanuel_scb/blogimage/raw/master/img/202312161100797.png)   


## 2.5 分叉测试

Forge支持使用两种不同方式进行分叉测试：

- 分叉模式（Forking Mode）：通过`forge test --fork-url` 标准使用一个单独分叉进行所有测试
- 分叉作弊码（Forking Cheatcodes)：通过[forking 作弊码](https://learnblockchain.cn/docs/foundry/i18n/zh/cheatcodes/forking.html) 在 Solidity 测试代码中直接创建、选择和管理多个分叉

### 2.5.1 分叉模式：

通过`--fork-url` 传递RPC URL，`--fork-block-number` 指定分叉的区块高度

```solidity
forge test --fork-url "https://mainnet.infura.io/v3/10973852e3ce414296d70fd551402e92" --fork-block-number 17001200
```

### 2.5.2分叉作弊码：

在Solidity测试代码中以编程方式进入分叉模式。

Foundry测试代码中：所有的测试函数的隔离的，每个测试函数都使用`setup()` 之后的拷贝状态执行, `setup()` 期间创建的分支可用于测试。

- `createFork('mainnet', blocknumber)` cheatcode创建分支，并返回唯一的标识符
- `selectFork(Forkid)` 传递Forkid，启用对应的分支
- `activeFork()` 返回当前启用分支的Forkid
- `rollFork(blocknumber)` 设置分叉的区块高度

每个分叉是一个独立的EVM，所有分叉使用完全独立的存储，但`msg.sender` 的状态和测试合约本身在分叉更改中是持久的
