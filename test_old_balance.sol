pragma solidity ^0.4.25;
contract C {
    function getBalance() public view returns (uint) {
        return this.balance;
    }
}
