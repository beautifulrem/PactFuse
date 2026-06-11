// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {IERC20} from "./interfaces/IERC20.sol";

contract PaidArtifactMarket {
    enum DeliveryState {
        None,
        Pending,
        Delivered,
        Refunded,
        Voided
    }

    struct Delivery {
        address payer;
        address paymentToken;
        uint256 price;
        bytes32 artifactHash;
        uint256 deliveryDeadline;
        bytes32 receiptPackHash;
        DeliveryState state;
    }

    address public immutable ADMIN;
    address public immutable ARTIFACT_SIGNER;
    address public gate;
    uint256 public immutable DELIVERY_TTL_SECONDS;

    mapping(bytes32 => Delivery) public deliveries;

    event GateConfigured(address indexed gate);
    event DeliveryPending(
        bytes32 indexed spendId,
        address indexed payer,
        address paymentToken,
        uint256 price,
        bytes32 artifactHash,
        uint256 deliveryDeadline
    );
    event ArtifactDelivered(bytes32 indexed spendId, bytes32 indexed artifactHash, bytes32 receiptPackHash);
    event ArtifactRefunded(bytes32 indexed spendId, address indexed payer, address paymentToken, uint256 amount);
    event QuoteVoided(bytes32 indexed spendId, bytes32 indexed quoteHash, bytes32 reasonHash);

    error OnlyAdmin();
    error OnlyGate();
    error OnlyArtifactSigner();
    error DeliveryAlreadyExists(bytes32 spendId);
    error DeliveryNotPending(bytes32 spendId);
    error DeliveryDeadlineNotReached(bytes32 spendId);
    error InvalidAddress();
    error TokenTransferFailed();

    constructor(address artifactSigner_, uint256 deliveryTtlSeconds_) {
        if (artifactSigner_ == address(0)) {
            revert InvalidAddress();
        }
        ADMIN = msg.sender;
        ARTIFACT_SIGNER = artifactSigner_;
        DELIVERY_TTL_SECONDS = deliveryTtlSeconds_;
    }

    function setGate(address gate_) external {
        if (msg.sender != ADMIN) {
            revert OnlyAdmin();
        }
        if (gate_ == address(0)) {
            revert InvalidAddress();
        }
        gate = gate_;
        emit GateConfigured(gate_);
    }

    function activateFromGate(
        bytes32,
        bytes32 spendId,
        address payer,
        address paymentToken,
        uint256 price,
        bytes32 artifactHash
    ) external returns (bytes32) {
        if (msg.sender != gate) {
            revert OnlyGate();
        }
        if (deliveries[spendId].state != DeliveryState.None) {
            revert DeliveryAlreadyExists(spendId);
        }
        uint256 deadline = block.timestamp + DELIVERY_TTL_SECONDS;
        deliveries[spendId] = Delivery({
            payer: payer,
            paymentToken: paymentToken,
            price: price,
            artifactHash: artifactHash,
            deliveryDeadline: deadline,
            receiptPackHash: bytes32(0),
            state: DeliveryState.Pending
        });
        emit DeliveryPending(spendId, payer, paymentToken, price, artifactHash, deadline);
        return artifactHash;
    }

    function markDelivered(bytes32 spendId, bytes32 receiptPackHash) external {
        if (msg.sender != ARTIFACT_SIGNER && msg.sender != ADMIN) {
            revert OnlyArtifactSigner();
        }
        Delivery storage delivery = deliveries[spendId];
        if (delivery.state != DeliveryState.Pending) {
            revert DeliveryNotPending(spendId);
        }
        delivery.state = DeliveryState.Delivered;
        delivery.receiptPackHash = receiptPackHash;
        emit ArtifactDelivered(spendId, delivery.artifactHash, receiptPackHash);
    }

    function refundArtifact(bytes32 spendId) external returns (uint256 amount) {
        Delivery storage delivery = deliveries[spendId];
        if (delivery.state != DeliveryState.Pending) {
            revert DeliveryNotPending(spendId);
        }
        if (block.timestamp < delivery.deliveryDeadline) {
            revert DeliveryDeadlineNotReached(spendId);
        }
        delivery.state = DeliveryState.Refunded;
        amount = delivery.price;
        if (!IERC20(delivery.paymentToken).transfer(delivery.payer, amount)) {
            revert TokenTransferFailed();
        }
        emit ArtifactRefunded(spendId, delivery.payer, delivery.paymentToken, amount);
    }

    function voidQuote(bytes32 spendId, bytes32 quoteHash, bytes32 reasonHash) external {
        if (msg.sender != ARTIFACT_SIGNER && msg.sender != ADMIN) {
            revert OnlyArtifactSigner();
        }
        Delivery storage delivery = deliveries[spendId];
        if (delivery.state != DeliveryState.None) {
            revert DeliveryNotPending(spendId);
        }
        delivery.state = DeliveryState.Voided;
        emit QuoteVoided(spendId, quoteHash, reasonHash);
    }
}
