---
title: "SEETF 2022 Smart Contract DuperSuperSafe"
destription: "A Smart Contract challenge during SEETF 2022 that required exploiting the mis-use of tx.origin vs msg.sender and publicly stored secrets"
date: 2022-07-03T15:55:11+08:00

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

## DuperSuperSafe Challenge Description
This was a smart-contract challenge that was part of the recent [SEETF 2022](https://ctftime.org/event/1543/) hosted by the [Social Engineering Experts](https://seetf.sg/seetf/). I played this together under [3_Blind_Mice](https://ctftime.org/team/190705), a random team made together with [@chuayupeng](https://github.com/chuayupeng) and [ethon](https://github.com/gnosis-agora) for pure fun and memes.

Like all the other smart-contract challenges in this CTF, a vulnerable contract was deployed onto [SEETF's very own private blockchain network](https://github.com/Social-Engineering-Experts/ETH-Guide).

Solving this challenge required knowing a concept in blockchain --> that `private` variables in a contract are technically public and still readable, and also understanding the difference between `tx.origin` and `msg.sender`.

### Contract Code
We are given this `DuperSuperSafe.sol` contract as shown below:
```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

contract DuperSuperSafeSafe {

  address private owner;
  mapping(uint => bytes32) private secret_passphrases;
  uint timestamp;

  constructor(bytes32 _secret_passphrase, bytes32 _secret_passphrase_2) payable {
    owner = msg.sender;
    timestamp = block.timestamp;
    secret_passphrases[0] = _secret_passphrase;
    secret_passphrases[1] = _secret_passphrase_2;
  }

  receive() external payable {}

  modifier restricted() {
    require(
      msg.sender == owner,
      "This function is restricted to the contract's owner"
    );
    _;
  }

  modifier passwordProtected(bytes32 _secret_passphrase, bytes32 _secret_passphrase_2, uint _timestamp) {
    require(keccak256(abi.encodePacked(secret_passphrases[0], secret_passphrases[1], timestamp)) == keccak256(abi.encodePacked(_secret_passphrase, _secret_passphrase_2, _timestamp)), "Wrong secret passphrase");
    _;
  }


  function changeOwner(address _newOwner) public {
    if (tx.origin != msg.sender) {
      owner = _newOwner;
    }
  }

  function changeSecretPassphrase(bytes32 _new_secret_passphrase, bytes32 _new_secret_passphrase_2, bytes32 _secret_passphrase, bytes32 _secret_passphrase_2, uint _timestamp) public restricted passwordProtected(_secret_passphrase, _secret_passphrase_2, _timestamp) {
    secret_passphrases[0] = _new_secret_passphrase;
    secret_passphrases[1] = _new_secret_passphrase_2;
    timestamp = block.timestamp;

  }

  function withdrawFunds(uint _amount, bytes32 _secret_passphrase, bytes32 _secret_passphrase_2, uint _timestamp) external payable restricted passwordProtected(_secret_passphrase, _secret_passphrase_2, _timestamp) {
    require(balanceOf(msg.sender) >= _amount, "Not enough funds");
    payable(address(msg.sender)).transfer(_amount);
  }

  function balanceOf(address _addr) public view returns (uint balance) {
    return address(_addr).balance;
  }

  function isSolved() public view returns (bool) {
    return balanceOf(address(this)) == 0;
  }

}
```

### Contract Functions
Based on the source code itself, we can learn a couple of things
- We can see in the `constructor()` that when the contract is first created, the 2 secret passphrases are passed in to the constructor and the `timestamp` is set to `block.timestamp`, which is essentially the timestamp of the block that holds the transaction of the contract creation.
- There is a `withdrawFunds()` function which has 2 modifiers
  - `restricted()` which requires `msg.sender` to be the owner
  - `passwordProtected(_secret_passphrase, _secret_passphrase_2, _timestamp)` which requires inputting the correct 2 secret passphrases and then being compared against `secret_passphrases[0]` and `secret_passphrases[1]`, along with the timestamp.
- There is also a `changeOwner()` function which takes in the new owner's address. The only requirement to call this function is that `tx.origin` matches `msg.sender`.
- We solve the problem when we drain all the funds in the contract itself as seen in `isSolved()`.
  - We can see the available balance of the contract with `web3.eth.getBalance()` as shown below:

## Exploit 1 - Making tx.origin != msg.sender
We first go to understand what's the difference between `tx.origin` and `msg.sender`. I believe this [article](https://blockchain-academy.hs-mittweida.de/courses/solidity-coding-beginners-to-intermediate/lessons/solidity-5-calling-other-contracts-visibility-state-access/topic/tx-origin-and-msg-sender/) explains things really well but in short, `tx.origin` refers to the account that makes the function call and `msg.sender` refers to the immediate last instance to a function call. 

To exploit this, what we really need to do is essentially, craft a scenario such that `tx.origin` is not the same as `msg.sender`. We can simply do this by creating a contract and making the contract call the `changeOwner()` function of the deployed `DuperSuperSafe.sol` contract. The contract we created in this case would be our `msg.sender`, and while that happens, when we use this contract to call `changeOwner()`, we ourselves become `tx.origin` :)

Here's an exploit contract to successfully run the `changeOwner()` function :)

```solidity
contract Attack {
    DuperSuperSafeSafe dsss;

    constructor(address payable _addr) {
        dsss = DuperSuperSafeSafe(_addr);
    }

    function pwn(address _newOwner) public {
        dsss.changeOwner(_newOwner);
    }
}
```

Now let's compile and deploy this contract. 

We can then make use of the `web3.eth.getStorageAt()` function to read the value of `owner` (more will be explained in the next section).

Before running the `pwn()` function:

![image](https://user-images.githubusercontent.com/33711159/173194863-93a0f829-93b4-4d78-9aaa-b71f05db71b1.png)

Now let's run the `pwn()` function in our exploit contract. We will attempt to change the owner to my own SEETF account's address `0x042Fc3887645C68fF08DF5F6304C81d5Ef59546D`

![image](https://user-images.githubusercontent.com/33711159/173194796-26595053-6d9c-47b9-ae91-c9703c89864c.png)

Let's check to see if we managed to successfully change the owner of the contract to `0x042Fc3887645C68fF08DF5F6304C81d5Ef59546D`:

![image](https://user-images.githubusercontent.com/33711159/173194871-84706e96-2975-4fee-96ab-15241a423c30.png)

And yes we did! On to the next part!

## Exploit 2 - Publicly Readable Private Variables
Initially my understanding of how variables would be retrievable was that I could use [`web3.eth.getStorageAt(address, position)`](https://web3js.readthedocs.io/en/v1.2.11/web3-eth.html#getstorageat) to retrieve whatever I needed, where `address` would be the address of the contract that was deployed, and `position` would be in order based on the order they were declared. So in this case, position 0 would be storing the value of `owner`, position 1 would be storing the value of `secret_passphrases` and position 2 would be storing the value of `timestamp`.

As demonstrated in the previous section, I could indeed get the value of `owner` successfully, and the same went for `timestamp` at index 2. But when I tried to get the value of `secret_passphrases`, that's where things got weird when I saw the values being `0x0`.
![image](https://user-images.githubusercontent.com/33711159/173195256-b368e64e-6100-4136-8102-4b36ac250102.png)

I got stuck for awhile until I stumbled across this [article](https://blockchain-academy.hs-mittweida.de/courses/solidity-coding-beginners-to-intermediate/lessons/solidity-12-reading-the-storage/topic/reading-the-ethereum-storage/), which from my undestanding, explains that with regards to a `mapping`, to retrieve the value of a `mapping` at a specific index, we have to pass in to `position = web3.utils.soliditySha3(mappingIndexOfInterest, positionOfMapping)` to `web3.eth.getStorageAt()`. In this case, the `mappingIndexOfInterest` would be `0` for `secret_passphrases[0]` and `1` for `secret_passphrases[1]`, and the `positionOfMapping` would be `1`.

So to get the value of `secret_passphrases[0]`, we can run the web3 command `web3.eth.getStorageAt("contractAddress", web3.utils.soliditySha3(0, 1))` as shown below:
![image](https://user-images.githubusercontent.com/33711159/173195641-fd53fe43-78e9-45dd-a175-92b29c25dda1.png)

We can repeat the same for `secret_passphrases[1]` but instead `mappingIndexOfInterest` would be `1`, so we run `web3.eth.getStorageAt("contractAddress", web3.utils.soliditySha3(1, 1))` as shown below:
![image](https://user-images.githubusercontent.com/33711159/173195696-36f7ef2f-277a-478f-8603-b927953554d6.png)


## Wrapping it up like a tortilla
Great ! Now we have `secret_passphrases[0]`, `secret_passphrases[1]`, `timestamp`, and we have also successfully changed the owner of the contract. We can attempt to run the `withdrawFunds()` function in the deployed `DuperSuperSafeSafe.sol` contract. Let's run the function and pass in the appropriate parameters.

Before that, `withdrawFunds()` takes in `timestamp` as an uint256, and we've only got its value in its hex form. Let's use web3 to convert that to a uint256 value using `web3.utils.hexToNumber()`:
![image](https://user-images.githubusercontent.com/33711159/173195963-de27d22d-b033-4a4d-8236-0330e4a259d8.png)

While we're at it, we can also check the amount of funds present in the contract using `web3.eth.getBalance()` or by calling the `getBalance` function:
![image](https://user-images.githubusercontent.com/33711159/173196021-82c5c115-378b-440c-8a0f-e5b14ffeafaf.png)


Now let's call the `withdrawFunds()` function with the values we have found (of course, from the account which we changed the owner to):

![image](https://user-images.githubusercontent.com/33711159/173196090-55fa70a1-5e63-4388-b5cf-415a9318ad3d.png)

Great! We have successfully run the `withdrawFunds()` function. We can now see that the contract's balance is indeed 0 and `isSolved()` has been set to true.

![image](https://user-images.githubusercontent.com/33711159/173196141-8b0336c9-f9ad-4a21-aac0-d444e98e7baf.png)

Let's go grab our flag :)
![image](https://user-images.githubusercontent.com/33711159/173196211-3c18686f-64d4-4cbe-8bf4-d826521e345c.png)
`SEE{B10cKcH41n_I5_sUp3r_53cuRe!}`