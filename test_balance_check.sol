contract B {
    function isFunded() public view returns (bool) {
        return address(this).balance == 100 ether;
    }
}
