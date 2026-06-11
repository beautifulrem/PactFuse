// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {IERC20} from "./interfaces/IERC20.sol";
import {ISourceStateRegistry} from "./interfaces/ISourceStateRegistry.sol";
import {PaidArtifactMarket} from "./PaidArtifactMarket.sol";
import {SourceFreshGuard} from "./SourceFreshGuard.sol";

contract ProcurementGate is SourceFreshGuard {
    enum SpendState {
        Unknown,
        Registered,
        Tripped,
        Settled
    }

    struct Spend {
        bytes32 sessionId;
        bytes32 pactId;
        bytes32 toolId;
        bytes32 sourceSetHash;
        address agentWallet;
        address paymentToken;
        uint256 price;
        bytes32 artifactHash;
        PaidArtifactMarket market;
        SpendState state;
        bytes32[] sourceHashes;
    }

    mapping(bytes32 => Spend) private spends;

    event SpendRegistered(
        bytes32 indexed sessionId,
        bytes32 indexed spendId,
        bytes32 pactId,
        bytes32 toolId,
        bytes32 sourceSetHash,
        address agentWallet,
        address paymentToken,
        uint256 price,
        bytes32 artifactHash,
        address market
    );
    event SpendSourceRegistered(
        bytes32 indexed sessionId,
        bytes32 indexed sourceHash,
        bytes32 indexed spendId,
        bytes32 pactId,
        bytes32 toolId,
        address agentWallet
    );
    event SpendTripped(bytes32 indexed sessionId, bytes32 indexed spendId);
    event SpendSettled(bytes32 indexed sessionId, bytes32 indexed spendId);

    error SpendAlreadyRegistered(bytes32 spendId);
    error SpendNotRegistered(bytes32 spendId);
    error SpendAlreadyFinal(bytes32 spendId);
    error InvalidSpendConfig(bytes32 spendId);
    error InvalidSpendId(bytes32 expected, bytes32 actual);
    error InvalidSourceSetHash(bytes32 expected, bytes32 actual);
    error UnsortedSourceSet(bytes32 previous, bytes32 current);
    error OnlyAgentWallet(address expected, address actual);
    error TokenTransferFailed();

    constructor(ISourceStateRegistry registry) SourceFreshGuard(registry) {}

    function registerSpend(
        bytes32 spendId,
        bytes32 sessionId,
        bytes32 pactId,
        bytes32 toolId,
        bytes32 sourceSetHash,
        address agentWallet,
        address paymentToken,
        uint256 price,
        bytes32 artifactHash,
        PaidArtifactMarket market,
        bytes32[] calldata sourceHashes
    ) external {
        if (spends[spendId].state != SpendState.Unknown) {
            revert SpendAlreadyRegistered(spendId);
        }
        if (
            sourceHashes.length == 0 || agentWallet == address(0) || paymentToken == address(0) || address(market) == address(0) || price == 0
                || artifactHash == bytes32(0)
        ) {
            revert InvalidSpendConfig(spendId);
        }
        bytes32 computedSourceSetHash = hashSourceSet(sourceHashes);
        if (computedSourceSetHash != sourceSetHash) {
            revert InvalidSourceSetHash(computedSourceSetHash, sourceSetHash);
        }
        bytes32 computedSpendId = computeSpendId(
            sessionId, pactId, toolId, sourceSetHash, agentWallet, paymentToken, price, artifactHash, address(market)
        );
        if (computedSpendId != spendId) {
            revert InvalidSpendId(computedSpendId, spendId);
        }
        Spend storage spend = spends[spendId];
        spend.sessionId = sessionId;
        spend.pactId = pactId;
        spend.toolId = toolId;
        spend.sourceSetHash = sourceSetHash;
        spend.agentWallet = agentWallet;
        spend.paymentToken = paymentToken;
        spend.price = price;
        spend.artifactHash = artifactHash;
        spend.market = market;
        spend.state = SpendState.Registered;
        for (uint256 i = 0; i < sourceHashes.length; i++) {
            spend.sourceHashes.push(sourceHashes[i]);
            emit SpendSourceRegistered(sessionId, sourceHashes[i], spendId, pactId, toolId, agentWallet);
        }
        emit SpendRegistered(sessionId, spendId, pactId, toolId, sourceSetHash, agentWallet, paymentToken, price, artifactHash, address(market));
    }

    function activateTool(bytes32 spendId, bytes calldata) external returns (bytes32 artifactHash) {
        Spend storage spend = spends[spendId];
        if (spend.state == SpendState.Unknown) {
            revert SpendNotRegistered(spendId);
        }
        if (spend.state != SpendState.Registered) {
            revert SpendAlreadyFinal(spendId);
        }
        if (msg.sender != spend.agentWallet) {
            revert OnlyAgentWallet(spend.agentWallet, msg.sender);
        }
        (bool active,) = _allSourcesActive(spend.sourceHashes);
        if (!active) {
            spend.state = SpendState.Tripped;
            emit SpendTripped(spend.sessionId, spendId);
            return bytes32(0);
        }
        if (!IERC20(spend.paymentToken).transferFrom(msg.sender, address(spend.market), spend.price)) {
            revert TokenTransferFailed();
        }
        spend.state = SpendState.Settled;
        artifactHash = spend.market.activateFromGate(spend.toolId, spendId, msg.sender, spend.paymentToken, spend.price, spend.artifactHash);
        emit SpendSettled(spend.sessionId, spendId);
    }

    function registeredSpend(bytes32 spendId)
        external
        view
        returns (
            bytes32 sessionId,
            bytes32 pactId,
            bytes32 toolId,
            bytes32 sourceSetHash,
            address agentWallet,
            address paymentToken,
            uint256 price,
            bytes32 artifactHash,
            address market,
            SpendState state
        )
    {
        Spend storage spend = spends[spendId];
        return (
            spend.sessionId,
            spend.pactId,
            spend.toolId,
            spend.sourceSetHash,
            spend.agentWallet,
            spend.paymentToken,
            spend.price,
            spend.artifactHash,
            address(spend.market),
            spend.state
        );
    }

    function spendSourceHashes(bytes32 spendId) external view returns (bytes32[] memory) {
        return spends[spendId].sourceHashes;
    }

    function computeSpendId(
        bytes32 sessionId,
        bytes32 pactId,
        bytes32 toolId,
        bytes32 sourceSetHash,
        address agentWallet,
        address paymentToken,
        uint256 price,
        bytes32 artifactHash,
        address market
    ) public pure returns (bytes32) {
        return keccak256(abi.encode(sessionId, pactId, toolId, sourceSetHash, agentWallet, paymentToken, price, artifactHash, market));
    }

    function hashSourceSet(bytes32[] memory sourceHashes) public pure returns (bytes32) {
        if (sourceHashes.length == 0) {
            return bytes32(0);
        }
        bytes32 previous = sourceHashes[0];
        for (uint256 i = 1; i < sourceHashes.length; i++) {
            bytes32 current = sourceHashes[i];
            if (current <= previous) {
                revert UnsortedSourceSet(previous, current);
            }
            previous = current;
        }
        return keccak256(abi.encode(sourceHashes));
    }
}
