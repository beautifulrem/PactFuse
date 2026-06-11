// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {IERC20} from "../interfaces/IERC20.sol";
import {ISourceStateRegistry} from "../interfaces/ISourceStateRegistry.sol";
import {SourceFreshGuard} from "../SourceFreshGuard.sol";

contract FreshSourceEscrow is SourceFreshGuard {
    struct Escrow {
        address token;
        address payer;
        address recipient;
        uint256 amount;
        bool released;
        bytes32[] sourceHashes;
    }

    mapping(bytes32 => Escrow) public escrows;

    event EscrowFunded(bytes32 indexed escrowId, address indexed payer, address indexed recipient, uint256 amount);
    event EscrowReleased(bytes32 indexed escrowId, address indexed recipient, uint256 amount);

    error EscrowAlreadyExists(bytes32 escrowId);
    error EscrowNotFound(bytes32 escrowId);
    error EscrowAlreadyReleased(bytes32 escrowId);
    error InvalidEscrowConfig(bytes32 escrowId);
    error TokenTransferFailed();

    constructor(ISourceStateRegistry registry) SourceFreshGuard(registry) {}

    function fund(bytes32 escrowId, address token, address recipient, uint256 amount, bytes32[] calldata sourceHashes) external {
        if (escrows[escrowId].payer != address(0)) {
            revert EscrowAlreadyExists(escrowId);
        }
        if (token == address(0) || recipient == address(0) || amount == 0 || sourceHashes.length == 0) {
            revert InvalidEscrowConfig(escrowId);
        }
        escrows[escrowId].token = token;
        escrows[escrowId].payer = msg.sender;
        escrows[escrowId].recipient = recipient;
        escrows[escrowId].amount = amount;
        for (uint256 i = 0; i < sourceHashes.length; i++) {
            escrows[escrowId].sourceHashes.push(sourceHashes[i]);
        }
        if (!IERC20(token).transferFrom(msg.sender, address(this), amount)) {
            revert TokenTransferFailed();
        }
        emit EscrowFunded(escrowId, msg.sender, recipient, amount);
    }

    function release(bytes32 escrowId) external freshSources(escrows[escrowId].sourceHashes) {
        Escrow storage escrow = escrows[escrowId];
        if (escrow.payer == address(0)) {
            revert EscrowNotFound(escrowId);
        }
        if (escrow.released) {
            revert EscrowAlreadyReleased(escrowId);
        }
        escrow.released = true;
        if (!IERC20(escrow.token).transfer(escrow.recipient, escrow.amount)) {
            revert TokenTransferFailed();
        }
        emit EscrowReleased(escrowId, escrow.recipient, escrow.amount);
    }
}
