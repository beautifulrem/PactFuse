// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {ISourceStateRegistry} from "./interfaces/ISourceStateRegistry.sol";

contract SourceStateRegistry is ISourceStateRegistry {
    struct SourceRecord {
        SourceState state;
        address issuer;
        bytes32 manifestHash;
    }

    mapping(bytes32 => SourceRecord) private records;

    event SourceRegistered(bytes32 indexed sourceHash, address indexed issuer, bytes32 manifestHash);
    event SourceChallenged(bytes32 indexed sessionId, bytes32 indexed sourceHash, bytes32 indexed reasonHash);
    event SourceRevoked(bytes32 indexed sourceHash, bytes32 indexed reasonHash);

    error SourceAlreadyRegistered(bytes32 sourceHash);
    error SourceNotRegistered(bytes32 sourceHash);
    error NotSourceIssuer(bytes32 sourceHash, address caller);
    error InvalidIssuer();

    function registerSource(bytes32 sourceHash, address issuer, bytes32 manifestHash) external {
        if (issuer == address(0)) {
            revert InvalidIssuer();
        }
        if (msg.sender != issuer) {
            revert NotSourceIssuer(sourceHash, msg.sender);
        }
        if (records[sourceHash].issuer != address(0)) {
            revert SourceAlreadyRegistered(sourceHash);
        }
        records[sourceHash] = SourceRecord({state: SourceState.Active, issuer: issuer, manifestHash: manifestHash});
        emit SourceRegistered(sourceHash, issuer, manifestHash);
    }

    function challengeSource(bytes32 sessionId, bytes32 sourceHash, bytes32 reasonHash) external {
        SourceRecord storage record = records[sourceHash];
        if (record.issuer == address(0)) {
            revert SourceNotRegistered(sourceHash);
        }
        if (msg.sender != record.issuer) {
            revert NotSourceIssuer(sourceHash, msg.sender);
        }
        record.state = SourceState.Challenged;
        emit SourceChallenged(sessionId, sourceHash, reasonHash);
    }

    function revokeSource(bytes32 sourceHash, bytes32 reasonHash) external {
        SourceRecord storage record = records[sourceHash];
        if (record.issuer == address(0)) {
            revert SourceNotRegistered(sourceHash);
        }
        if (msg.sender != record.issuer) {
            revert NotSourceIssuer(sourceHash, msg.sender);
        }
        record.state = SourceState.Revoked;
        emit SourceRevoked(sourceHash, reasonHash);
    }

    function sourceState(bytes32 sourceHash) external view returns (SourceState) {
        return records[sourceHash].state;
    }

    function sourceIssuer(bytes32 sourceHash) external view returns (address) {
        return records[sourceHash].issuer;
    }

    function sourceManifestHash(bytes32 sourceHash) external view returns (bytes32) {
        return records[sourceHash].manifestHash;
    }
}
