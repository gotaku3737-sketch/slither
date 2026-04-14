from slither.core.cfg.node import Node
from slither.core.declarations.contract import Contract
from slither.detectors.abstract_detector import (
    AbstractDetector,
    DetectorClassification,
    DETECTOR_INFO,
)
from slither.slithir.operations import Binary, BinaryType, Member, SolidityCall, HighLevelCall
from slither.core.declarations.solidity_variables import SolidityFunction
from slither.analyses.data_dependency.data_dependency import is_dependent_ssa
from slither.utils.output import Output

class StrictBalanceEquality(AbstractDetector):
    """
    Detects strict equality checks involving address(this).balance
    """

    ARGUMENT = "strict-balance"
    HELP = "Strict equality on balance"
    IMPACT = DetectorClassification.MEDIUM
    CONFIDENCE = DetectorClassification.HIGH

    WIKI = "https://github.com/crytic/slither/wiki/Detector-Documentation#strict-balance-equality"

    WIKI_TITLE = "Strict balance equality"
    WIKI_DESCRIPTION = "Strict equality checks on `address(this).balance` can be manipulated by an attacker."

    WIKI_EXPLOIT_SCENARIO = """
```solidity
contract Crowdsale{
    function fund_reached() public returns(bool){
        return this.balance == 100 ether;
    }
}
```
An attacker can forcefully send ether to the contract via `selfdestruct` and bypass the equality check."""

    WIKI_RECOMMENDATION = "Use `>=` or `<=` instead of `==` for balance checks."

    def _detect(self) -> list[Output]:
        results = []

        for contract in self.compilation_unit.contracts_derived:
            for function in contract.functions_declared + list(contract.modifiers_declared):
                if function.is_implemented:
                    balance_vars = []
                    for node in function.nodes:
                        for ir in node.irs_ssa:
                            if isinstance(ir, SolidityCall) and ir.function == SolidityFunction("balance(address)"):
                                balance_vars.append(ir.lvalue)
                            elif isinstance(ir, Member) and ir.variable_right == "balance":
                                balance_vars.append(ir.lvalue)

                    for node in function.nodes:
                        for ir in node.irs_ssa:
                            if isinstance(ir, Binary) and ir.type == BinaryType.EQUAL:
                                is_balance = False
                                for balance_var in balance_vars:
                                    if is_dependent_ssa(ir.variable_left, balance_var, function.contract) or \
                                       is_dependent_ssa(ir.variable_right, balance_var, function.contract):
                                        is_balance = True
                                        break
                                if is_balance:
                                    info: DETECTOR_INFO = [function, " uses strict equality on balance: ", node, "\n"]
                                    res = self.generate_result(info)
                                    results.append(res)
        return results
