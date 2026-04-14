contract C {
    address a;
    function check() public view returns (bool) {
        return a.balance == 100;
    }
}
