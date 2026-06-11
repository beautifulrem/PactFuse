// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

interface ISourceStateRegistry {
    enum SourceState {
        Unknown,
        Active,
        Challenged,
        Revoked
    }

    function sourceState(bytes32 sourceHash) external view returns (SourceState);
}
