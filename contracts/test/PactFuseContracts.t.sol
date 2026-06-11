// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {FreshSourceEscrow} from "../src/examples/FreshSourceEscrow.sol";
import {PaidArtifactMarket} from "../src/PaidArtifactMarket.sol";
import {ProcurementGate} from "../src/ProcurementGate.sol";
import {SourceStateRegistry} from "../src/SourceStateRegistry.sol";
import {MockERC20} from "./MockERC20.sol";

contract Actor {
    function registerSource(SourceStateRegistry registry, bytes32 sourceHash, bytes32 manifestHash) external {
        registry.registerSource(sourceHash, address(this), manifestHash);
    }

    function approve(MockERC20 token, address spender, uint256 amount) external {
        token.approve(spender, amount);
    }

    function activate(ProcurementGate gate, bytes32 spendId) external returns (bytes32) {
        return gate.activateTool(spendId, "");
    }

    function challenge(SourceStateRegistry registry, bytes32 sessionId, bytes32 sourceHash, bytes32 reasonHash) external {
        registry.challengeSource(sessionId, sourceHash, reasonHash);
    }

    function fundEscrow(FreshSourceEscrow escrow, bytes32 escrowId, MockERC20 token, address recipient, uint256 amount, bytes32[] calldata sources)
        external
    {
        escrow.fund(escrowId, address(token), recipient, amount, sources);
    }

    function releaseEscrow(FreshSourceEscrow escrow, bytes32 escrowId) external {
        escrow.release(escrowId);
    }

    function voidQuote(PaidArtifactMarket market, bytes32 spendId, bytes32 quoteHash, bytes32 reasonHash) external {
        market.voidQuote(spendId, quoteHash, reasonHash);
    }
}

contract PactFuseContractsTest {
    SourceStateRegistry registry;
    PaidArtifactMarket market;
    ProcurementGate gate;
    MockERC20 token;
    Actor issuer;
    Actor agent;
    Actor recipient;

    bytes32 constant SESSION_ID = keccak256("session");
    bytes32 constant PACT_ID = keccak256("pact");
    bytes32 constant TOOL_ID = keccak256("tool");
    bytes32 constant SOURCE_A = keccak256("source-a");
    bytes32 constant SOURCE_C = keccak256("source-c");
    bytes32 constant REASON_HASH = keccak256("reason");
    bytes32 constant ARTIFACT_HASH = keccak256("artifact");

    function setUp() public {
        issuer = new Actor();
        agent = new Actor();
        recipient = new Actor();
        registry = new SourceStateRegistry();
        market = new PaidArtifactMarket(address(this), 1 days);
        gate = new ProcurementGate(registry);
        market.setGate(address(gate));
        token = new MockERC20();
        token.mint(address(agent), 1_000 ether);
    }

    function testChallengedSpendTripsBeforeAllowanceAndMovesNoTokens() public {
        bytes32[] memory sources = oneSource(SOURCE_A);
        issuer.registerSource(registry, SOURCE_A, keccak256("manifest-a"));
        bytes32 spendId = registerSpend(sources);
        issuer.challenge(registry, SESSION_ID, SOURCE_A, REASON_HASH);

        uint256 agentBefore = token.balanceOf(address(agent));
        uint256 marketBefore = token.balanceOf(address(market));
        bytes32 artifact = agent.activate(gate, spendId);

        (,,,,,,,,, ProcurementGate.SpendState state) = gate.registeredSpend(spendId);
        require(artifact == bytes32(0), "tripped artifact");
        require(state == ProcurementGate.SpendState.Tripped, "not tripped");
        require(token.balanceOf(address(agent)) == agentBefore, "agent moved");
        require(token.balanceOf(address(market)) == marketBefore, "market moved");
    }

    function testCleanSpendSettlesAndCreatesDeliveryPending() public {
        bytes32[] memory sources = oneSource(SOURCE_C);
        issuer.registerSource(registry, SOURCE_C, keccak256("manifest-c"));
        bytes32 spendId = registerSpend(sources);
        agent.approve(token, address(gate), 100 ether);

        bytes32 artifact = agent.activate(gate, spendId);
        (address payer, address paymentToken, uint256 price, bytes32 artifactHash,, bytes32 receiptPackHash, PaidArtifactMarket.DeliveryState deliveryState) =
            market.deliveries(spendId);
        (,,,,,,,,, ProcurementGate.SpendState spendState) = gate.registeredSpend(spendId);

        require(artifact == ARTIFACT_HASH, "artifact mismatch");
        require(spendState == ProcurementGate.SpendState.Settled, "not settled");
        require(payer == address(agent), "payer");
        require(paymentToken == address(token), "token");
        require(price == 100 ether, "price");
        require(artifactHash == ARTIFACT_HASH, "delivery artifact");
        require(receiptPackHash == bytes32(0), "receipt premature");
        require(deliveryState == PaidArtifactMarket.DeliveryState.Pending, "not pending");
        require(token.balanceOf(address(agent)) == 900 ether, "agent balance");
        require(token.balanceOf(address(market)) == 100 ether, "market balance");
    }

    function testFreshSourceEscrowReleasesOnlyWhileSourcesActive() public {
        bytes32 escrowId = keccak256("escrow");
        bytes32[] memory sources = oneSource(SOURCE_C);
        issuer.registerSource(registry, SOURCE_C, keccak256("manifest-c"));
        FreshSourceEscrow escrow = new FreshSourceEscrow(registry);
        agent.approve(token, address(escrow), 25 ether);
        agent.fundEscrow(escrow, escrowId, token, address(recipient), 25 ether, sources);

        recipient.releaseEscrow(escrow, escrowId);

        require(token.balanceOf(address(recipient)) == 25 ether, "recipient balance");
    }

    function testFreshSourceEscrowRejectsChallengedSources() public {
        bytes32 escrowId = keccak256("escrow-stale");
        bytes32[] memory sources = oneSource(SOURCE_A);
        issuer.registerSource(registry, SOURCE_A, keccak256("manifest-a"));
        FreshSourceEscrow escrow = new FreshSourceEscrow(registry);
        agent.approve(token, address(escrow), 25 ether);
        agent.fundEscrow(escrow, escrowId, token, address(recipient), 25 ether, sources);
        issuer.challenge(registry, SESSION_ID, SOURCE_A, REASON_HASH);

        try recipient.releaseEscrow(escrow, escrowId) {
            revert("release should fail");
        } catch {}

        require(token.balanceOf(address(recipient)) == 0, "recipient moved");
        require(token.balanceOf(address(escrow)) == 25 ether, "escrow moved");
    }

    function testRegisterSpendRejectsForgedSpendIdAndSourceSetHash() public {
        bytes32[] memory sources = oneSource(SOURCE_C);
        bytes32 sourceSetHash = gate.hashSourceSet(sources);
        bytes32 spendId = gate.computeSpendId(
            SESSION_ID, PACT_ID, TOOL_ID, sourceSetHash, address(agent), address(token), 100 ether, ARTIFACT_HASH, address(market)
        );

        try gate.registerSpend(
            bytes32(uint256(spendId) ^ uint256(1)),
            SESSION_ID,
            PACT_ID,
            TOOL_ID,
            sourceSetHash,
            address(agent),
            address(token),
            100 ether,
            ARTIFACT_HASH,
            market,
            sources
        ) {
            revert("forged spend id accepted");
        } catch {}

        try gate.registerSpend(
            spendId,
            SESSION_ID,
            PACT_ID,
            TOOL_ID,
            bytes32(uint256(sourceSetHash) ^ uint256(1)),
            address(agent),
            address(token),
            100 ether,
            ARTIFACT_HASH,
            market,
            sources
        ) {
            revert("forged source set accepted");
        } catch {}
    }

    function testRegisterSpendRejectsUnsortedOrDuplicateSources() public view {
        bytes32[] memory duplicate = new bytes32[](2);
        duplicate[0] = SOURCE_C;
        duplicate[1] = SOURCE_C;

        try gate.hashSourceSet(duplicate) {
            revert("duplicate source set accepted");
        } catch {}

        bytes32[] memory unsorted = new bytes32[](2);
        unsorted[0] = bytes32(uint256(2));
        unsorted[1] = bytes32(uint256(1));

        try gate.hashSourceSet(unsorted) {
            revert("unsorted source set accepted");
        } catch {}
    }

    function testSourceRegistrationRequiresIssuerCaller() public {
        try registry.registerSource(SOURCE_A, address(issuer), keccak256("manifest-a")) {
            revert("unauthorized source registration accepted");
        } catch {}

        issuer.registerSource(registry, SOURCE_A, keccak256("manifest-a"));
        require(registry.sourceIssuer(SOURCE_A) == address(issuer), "issuer");
    }

    function testVoidQuoteCannotLockPendingDeliveryFunds() public {
        bytes32[] memory sources = oneSource(SOURCE_C);
        issuer.registerSource(registry, SOURCE_C, keccak256("manifest-c"));
        bytes32 spendId = registerSpend(sources);
        agent.approve(token, address(gate), 100 ether);
        agent.activate(gate, spendId);

        try market.voidQuote(spendId, keccak256("quote"), keccak256("void")) {
            revert("pending quote void accepted");
        } catch {}

        (,,,,,, PaidArtifactMarket.DeliveryState deliveryState) = market.deliveries(spendId);
        require(deliveryState == PaidArtifactMarket.DeliveryState.Pending, "delivery not pending");
        require(token.balanceOf(address(market)) == 100 ether, "funds moved");
    }

    function testFreshSourceEscrowRejectsEmptySourceSet() public {
        FreshSourceEscrow escrow = new FreshSourceEscrow(registry);
        bytes32[] memory emptySources = new bytes32[](0);
        agent.approve(token, address(escrow), 25 ether);

        try agent.fundEscrow(escrow, keccak256("empty-escrow"), token, address(recipient), 25 ether, emptySources) {
            revert("empty source escrow accepted");
        } catch {}
    }

    function registerSpend(bytes32[] memory sources) internal returns (bytes32 spendId) {
        bytes32 sourceSetHash = gate.hashSourceSet(sources);
        spendId = gate.computeSpendId(
            SESSION_ID, PACT_ID, TOOL_ID, sourceSetHash, address(agent), address(token), 100 ether, ARTIFACT_HASH, address(market)
        );
        gate.registerSpend(
            spendId,
            SESSION_ID,
            PACT_ID,
            TOOL_ID,
            sourceSetHash,
            address(agent),
            address(token),
            100 ether,
            ARTIFACT_HASH,
            market,
            sources
        );
    }

    function oneSource(bytes32 sourceHash) internal pure returns (bytes32[] memory sources) {
        sources = new bytes32[](1);
        sources[0] = sourceHash;
    }
}
