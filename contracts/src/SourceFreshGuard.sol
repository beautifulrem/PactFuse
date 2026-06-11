// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {ISourceStateRegistry} from "./interfaces/ISourceStateRegistry.sol";

abstract contract SourceFreshGuard {
    ISourceStateRegistry public immutable SOURCE_REGISTRY;

    error StaleSource(bytes32 sourceHash);

    constructor(ISourceStateRegistry registry) {
        SOURCE_REGISTRY = registry;
    }

    function _allSourcesActive(bytes32[] memory sourceHashes) internal view returns (bool ok, bytes32 staleSource) {
        for (uint256 i = 0; i < sourceHashes.length; i++) {
            if (SOURCE_REGISTRY.sourceState(sourceHashes[i]) != ISourceStateRegistry.SourceState.Active) {
                return (false, sourceHashes[i]);
            }
        }
        return (true, bytes32(0));
    }

    modifier freshSources(bytes32[] memory sourceHashes) {
        _requireFreshSources(sourceHashes);
        _;
    }

    function _requireFreshSources(bytes32[] memory sourceHashes) internal view {
        (bool ok, bytes32 staleSource) = _allSourcesActive(sourceHashes);
        if (!ok) {
            revert StaleSource(staleSource);
        }
    }
}
