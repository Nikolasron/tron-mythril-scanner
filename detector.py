# detector.py
import logging
from typing import List
from mythril.analysis import solver
from mythril.analysis.module.base import DetectionModule, EntryPoint
from mythril.analysis.report import Issue
from mythril.exceptions import UnsatError
from mythril.laser.ethereum.state.global_state import GlobalState
from mythril.laser.ethereum.transaction.symbolic import ACTORS
from mythril.laser.smt import Extract, symbol_factory

log = logging.getLogger(__name__)

class OwnershipTakeoverDetector(DetectionModule):
    name = "Detects ownership takeover vulnerabilities"
    swc_id = "CUSTOM-OWNERSHIP"
    description = "Detects if an attacker can take over ownership (storage slot 0, offset 0)"
    entry_point = EntryPoint.CALLBACK
    pre_hooks = ["SSTORE"]

    def _execute(self, state: GlobalState) -> None:
        issues = self._analyze_state(state)
        self.issues.extend(issues)

    @staticmethod
    def _analyze_state(state: GlobalState) -> List[Issue]:
        instruction = state.get_current_instruction()
        if instruction["opcode"] != "SSTORE":
            return []

        # SSTORE pops 2 values: [slot, value]
        address, value = state.mstate.stack[-1], state.mstate.stack[-2]
        
        # We assume the owner variable is at storage slot 0, offset 0
        target_slot = 0
        target_offset = 0

        # Constraints to determine if this is a vulnerability
        vulnerable_conditions = [
            address == symbol_factory.BitVecVal(target_slot, 256),
            # Before the write, the owner must NOT be the attacker
            Extract(20 * 8 + target_offset, 0 + target_offset,
                    state.environment.active_account.storage[symbol_factory.BitVecVal(0, 256)]
                    ) != ACTORS.attacker,
            # The value being written MUST be the attacker's address
            Extract(20 * 8 + target_offset, 0 + target_offset, value) == ACTORS.attacker,
            # The attacker must be the sender of the transaction
            state.environment.sender == ACTORS.attacker,
        ]

        try:
            # Check if these conditions are satisfiable (i.e., possible)
            transaction_sequence = solver.get_transaction_sequence(
                state,
                state.world_state.constraints + vulnerable_conditions,
            )
        except UnsatError:
            # Conditions are impossible, no vulnerability
            return []

        # If satisfiable, we have a vulnerability
        issue = Issue(
            contract=state.environment.active_account.contract_name,
            function_name=state.environment.active_function_name,
            address=instruction["address"],
            title="Ownership Takeover Vulnerability",
            severity="High",
            description_head="An attacker can take over contract ownership.",
            description_tail=(
                "The contract's owner variable (storage slot 0) can be overwritten "
                "by an arbitrary attacker. This allows the attacker to gain "
                "administrative privileges."
            ),
            swc_id="CUSTOM-OWNERSHIP",
            bytecode=state.environment.code.bytecode,
            gas_used=(state.mstate.min_gas_used, state.mstate.max_gas_used),
            transaction_sequence=transaction_sequence,
        )
        return [issue]
