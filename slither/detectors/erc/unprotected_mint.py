from slither.core.cfg.node import Node
from slither.core.declarations.contract import Contract
from slither.core.declarations.function_contract import FunctionContract
from slither.detectors.abstract_detector import (
    AbstractDetector,
    DetectorClassification,
    DETECTOR_INFO,
)
from slither.slithir.operations import EventCall
from slither.utils.output import Output

def detect_unprotected_mint(contract: Contract) -> list[FunctionContract]:
    """
    Detects public/external functions that appear to mint tokens and are unprotected.
    """
    results = []

    if not (contract.is_possible_erc20() or contract.is_possible_erc721()):
        return results

    for f in contract.functions_declared:
        # Check if function is public or external
        if f.visibility not in ["public", "external"]:
            continue

        # Check if function seems to be a mint function
        # by looking at its name or internal events
        is_mint = False
        if "mint" in f.name.lower():
            is_mint = True
        else:
            # check if it emits a mint-like event or Transfer(0, ...)
            for node in f.nodes:
                for ir in node.irs:
                    if isinstance(ir, EventCall):
                        # Simple heuristic: if event name contains 'mint'
                        if "mint" in ir.name.lower():
                            is_mint = True
                            break
                        # OR if it's a Transfer from address(0) (common in minting)
                        # We won't over-complicate this logic for a simple detector,
                        # but we can look for Transfer(0, to, amount)
                if is_mint:
                    break

        if not is_mint:
            continue

        # Check if it has modifiers that sound like protection
        is_protected = False
        protection_modifiers = ["onlyowner", "hasrole", "onlyminter", "onlyadmin", "auth", "requiresauth"]
        for mod in f.modifiers:
            if any(p in mod.name.lower() for p in protection_modifiers):
                is_protected = True
                break

        # Check if it is protected by internal calls / requires on msg.sender
        if not is_protected:
            if f.is_protected():
                is_protected = True

        if not is_protected:
            results.append(f)

    return results


class UnprotectedMint(AbstractDetector):
    """
    Unprotected mint detector
    """

    ARGUMENT = "unprotected-mint"
    HELP = "Unprotected mint function"
    IMPACT = DetectorClassification.HIGH
    CONFIDENCE = DetectorClassification.HIGH

    WIKI = "https://github.com/crytic/slither/wiki/Detector-Documentation#unprotected-mint"

    WIKI_TITLE = "Unprotected mint"
    WIKI_DESCRIPTION = "An unprotected mint function allows anyone to mint tokens."

    # region wiki_exploit_scenario
    WIKI_EXPLOIT_SCENARIO = """
```solidity
contract ERC20 {
    function mint(address to, uint256 amount) public {
        _mint(to, amount);
    }
}
```
Bob calls `mint` and mints himself infinite tokens."""
    # endregion wiki_exploit_scenario

    WIKI_RECOMMENDATION = "Protect the mint function with `onlyOwner` or another authorization mechanism."

    def _detect(self) -> list[Output]:
        results = []
        for c in self.compilation_unit.contracts_derived:
            unprotected_mints = detect_unprotected_mint(c)
            for f in unprotected_mints:
                info: DETECTOR_INFO = [f, " is an unprotected mint function\n"]
                res = self.generate_result(info)
                results.append(res)
        return results
