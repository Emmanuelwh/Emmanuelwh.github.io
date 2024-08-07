---
title: Solidity合约调用详解
date: 2023-12-16 11:26:37
tags: [Solidity, 智能合约]
categories: 
  - [智能合约]
  - [以太坊]
description: 摘要：Solidity合约调用详解
---

最近在做毕设，在slither的基础上搭建一个检测器，需要对solidity中的合约调用范式进行建模，在remix上对合约调用进行了很多尝试qwq，说多了都是泪，故系统总结一下。
`solidity环境：0.8.13`

# 1. 利用call函数进行合约内的调用。
这里我们不考虑利用call函数进行转账的情况，仅仅考虑利用call函数进行合约间的函数调用。
call(）函数调用其他合约或者本合约的函数时，需要有对应的函数标识符进行调用。
函数标识符通过abi编码函数生成。
这里的环境应该，不出意外的话，只支持`encodeWithSignature`，`encodeWithSelector`
- 基本的调用方式：
1. `encodeWithSignature`
对函数签名进行keccak256运算后，取前四字节的结果，之后剩下的字节是encode()的结果，将每个数据填充为32字节
```solidity
bytes memory method = abi.encodeWithSignature("函数名(参数列表)", 对应的参数列表);
（bool , bytes memory returnData）= address(this) .call(method);
```
这里以调用自身合约中的一个函数为例进行说明，给出一个实例，在remix上进行了测试。
```Solidity
pragma solidity ^0.8.13;
//基合约实现
contract TestFallback {
    string message;
    address add;
    uint inter;
    //构造函数，初始化状态变量message
    constructor() {
        message = "hello";
    }
    fallback() external {
        message = "fallback";
    }
    function testFallbackWithParam(string memory _message) external returns (bytes memory) {
        bytes memory method = abi.encodeWithSignature("setMsg(uint)",_message);
        (bool success, bytes memory returnData) = address(this).call(method);

        require(success, "set fail");
        return returnData;
    }
    function setAddr(address a1) external {
        add = a1;
    }

    function getMsg() external view returns (string memory) {
        return message;
    }
    function setMsg(string memory _message) external {
        message = _message;
    }
```
 2. `encodeWithSelector`
 其与上面十分相似，可以认为前者是后者的简写，因为它会自动对函数签名先进行keccak256运算再取前四字节。而encodeWithSelector不会.
  调用方式如下：
 ```solidity
bytes memory method = abi.encodeWithSignature(bytes4(keccak256("函数名(参数列表)")), 对应的参数列表);
（bool , bytes memory returnData）= address(this) .call(method);
 ```
因为该函数用法和上面一模一样，这里就不贴在remix上的示例了。

# 这里分享一个踩过的坑，浪费了我一天时间qwq
```Solidity
contract B{
    function toeat(address _add , uint a) public{
        bytes memory method =abi.encodeWithSignature("eat(uint)",a);
        (bool answer, bytes memory value) = address(cat(_add)).call(method);  //通过bytes32(keccak256("eat()"指定方法，后面的是参数
        require(answer, "call failed");
    }
}
```
这里想调用cat合约中的eat()函数，编码的时候函数名(参数列表)写的是`eat(uint)`。问题就出在这，solidity有时候会默认uint就是uint256，但是在这里它不知道不默认了！！！！！！！！！，调用toeat()函数的时候，它总是会报错，或者调用到fallback函数，很寄
所以应该改成：
```solidity
contract B{
    function toeat(address _add , uint a) public{
        bytes memory method =abi.encodeWithSignature("eat(uint256)",a);
        (bool answer, bytes memory value) = address(cat(_add)).call(method);  //通过bytes32(keccak256("eat()"指定方法，后面的是参数
        require(answer, "call failed");
    }
}
```
# 2.利用call函数进行合约间的函数调用
话不多说，直接先上代码，remix上测试过：
```
pragma solidity ^0.8.13;

import "./testFallbackImport3.sol" ;

contract Animal{
    cat c;
    constructor(address _add){
        c = cat(_add);
    }
    function test()public view returns(uint) { //普通实例化合约调用
       return c.eat(1);
   }
    function test2()external returns(bool) {  //通过call方法调用
        bytes memory method =abi.encodeWithSignature("use(uint256)",2);
        (bool answer, bytes memory value) = address(c).call(method);  //通过bytes32(keccak256("eat()"指定方法，后面的是参数
        require(answer, "call failed");
} }

contract test{
    function toeat (address _add , uint a) public{
        bytes memory method =abi.encodeWithSignature("eat(uint256)",a);
        (bool answer, bytes memory value) = address(cat(_add)).call(method);  //通过bytes32(keccak256("eat()"指定方法，后面的是参数
        require(answer, "call failed");
    }

    function toeat1(address _add , uint a) public{
        cat chu = cat(_add);
        bytes memory method =abi.encodeWithSignature("eat(uint256)",a);
        (bool answer, bytes memory value) = address(chu).call(method);  //通过bytes32(keccak256("eat()"指定方法，后面的是参数
        require(answer, "call failed");
    }

    function toeat2(cat _add , uint a) public{
        bytes memory method =abi.encodeWithSignature("eat(uint256)",a);
        (bool answer, bytes memory value) = address(_add).call(method);  //通过bytes32(keccak256("eat()"指定方法，后面的是参数
        require(answer, "call failed");
    }

}
```
test合约，三个函数代表了利用call函数进行合约调用的三种方式：
`toeat()`
传入目标合约的地址，生成目标合约的引用，然后调用目标函数
```
    function toeat (address _add , uint a) public{
        bytes memory method =abi.encodeWithSignature("eat(uint256)",a);
        (bool answer, bytes memory value) = address(cat(_add)).call(method);  //通过bytes32(keccak256("eat()"指定方法，后面的是参数
        require(answer, "call failed");
    }
```
`toeat1()`
创建合约变量，然后利用它来调用目标函数
```
    function toeat1(address _add , uint a) public{
        cat chu = cat(_add);
        bytes memory method =abi.encodeWithSignature("eat(uint256)",a);
        (bool answer, bytes memory value) = address(chu).call(method);  //通过bytes32(keccak256("eat()"指定方法，后面的是参数
        require(answer, "call failed");
    }
```
`toeat2()`
传入合约变量，利用address类型进行调用
```
    function toeat2(cat _add , uint a) public{
        bytes memory method =abi.encodeWithSignature("eat(uint256)",a);
        (bool answer, bytes memory value) = address(_add).call(method);  //通过bytes32(keccak256("eat()"指定方法，后面的是参数
        require(answer, "call failed");
    }
```
