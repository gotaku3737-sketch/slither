from slither.core.cfg.node import NodeType, Node
from slither.core.declarations.contract import Contract
from slither.detectors.abstract_detector import (
    AbstractDetector,
    DetectorClassification,
    DETECTOR_INFO,
)
from slither.slithir.operations import InternalCall
from slither.utils.output import Output

Result = list[tuple[Node, list[str]]]

def detect_tx_origin_in_loop(contract: Contract) -> Result:
    results: Result = []
    for f in contract.functions_entry_points:
        if f.is_implemented:
            tx_origin_in_loop(f.entry_point, 0, [], [], results)
    return results

def tx_origin_in_loop(
    node: Node | None,
    in_loop_counter: int,
    visited: list[Node],
    calls_stack: list[str],
    results: Result,
) -> None:
    if node is None:
        return

    if node in visited:
        return
    # shared visited
    visited.append(node)

    if node.type == NodeType.STARTLOOP:
        in_loop_counter += 1
    elif node.type == NodeType.ENDLOOP:
        in_loop_counter -= 1

    if in_loop_counter > 0:
        solidity_var_read = node.solidity_variables_read
        if solidity_var_read and any(v.name == "tx.origin" for v in solidity_var_read):
            results.append((node, calls_stack.copy()))

    for ir in node.irs:
        if isinstance(ir, InternalCall) and ir.function:
            calls_stack.append(node.function.canonical_name)
            tx_origin_in_loop(
                ir.function.entry_point, in_loop_counter, visited, calls_stack, results
            )
            calls_stack.pop()

    for son in node.sons:
        tx_origin_in_loop(son, in_loop_counter, visited, calls_stack, results)


class TxOriginInLoop(AbstractDetector):
    """
    Detect the use of tx.origin inside a loop
    """

    ARGUMENT = "tx-origin-loop"
    HELP = "tx.origin used inside a loop"
    IMPACT = DetectorClassification.LOW
    CONFIDENCE = DetectorClassification.HIGH

    WIKI = "https://github.com/crytic/slither/wiki/Detector-Documentation/#txorigin-inside-a-loop"

    WIKI_TITLE = "tx.origin used inside a loop"
    WIKI_DESCRIPTION = "Detect the use of `tx.origin` inside a loop."

    # region wiki_exploit_scenario
    WIKI_EXPLOIT_SCENARIO = """
```solidity
contract TxOriginInLoop{

    function bad(address[] memory receivers) public {
        for (uint256 i = 0; i < receivers.length; i++) {
            if (tx.origin == receivers[i]) {
                // do something
            }
        }
    }

}
```
When calling `bad` the `tx.origin` is repeatedly evaluated, which is likely poor design or an unintended usage."""
    # endregion wiki_exploit_scenario

    WIKI_RECOMMENDATION = "Do not use `tx.origin` inside a loop. Cache it if needed."

    def _detect(self) -> list[Output]:
        results: list[Output] = []
        for c in self.compilation_unit.contracts_derived:
            values = detect_tx_origin_in_loop(c)
            for node, calls_stack in values:
                func = node.function

                info: DETECTOR_INFO = [
                    func,
                    " uses tx.origin inside a loop: ",
                    node,
                    "\n",
                ]

                if len(calls_stack) > 0:
                    info.append("\tCalls stack containing the loop:\n")
                    for call in calls_stack:
                        info.extend(["\t\t", call, "\n"])

                res = self.generate_result(info)
                results.append(res)

        return results
