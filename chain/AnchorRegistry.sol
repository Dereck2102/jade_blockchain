// SPDX-License-Identifier: MIT
pragma solidity 0.8.39;

contract AnchorRegistry {
    address public owner;
    mapping(string => address) public authorizedEmitter;
    mapping(string => uint64) public lastCounter;
    mapping(string => mapping(uint64 => bytes32)) public eventHashAt;
    mapping(string => mapping(uint64 => bytes32)) public signatureHashAt;
    mapping(string => mapping(uint64 => uint64)) public anchorTimestampAt;

    event EmitterAuthorized(string indexed node, address indexed emitter);
    event EventAnchored(
        string indexed node,
        uint64 indexed counter,
        bytes32 eventHash,
        bytes32 signatureHash,
        uint64 timestamp
    );

    error Unauthorized();
    error CounterNotIncreasing();
    error EmptyNode();

    constructor() {
        owner = msg.sender;
    }

    function authorizeEmitter(string calldata node, address emitter) external {
        if (msg.sender != owner) revert Unauthorized();
        if (bytes(node).length == 0) revert EmptyNode();
        authorizedEmitter[node] = emitter;
        emit EmitterAuthorized(node, emitter);
    }

    function anchor(
        string calldata node,
        uint64 counter,
        bytes32 eventHash,
        bytes32 signatureHash
    ) external {
        if (authorizedEmitter[node] != msg.sender) revert Unauthorized();
        if (counter <= lastCounter[node]) revert CounterNotIncreasing();
        lastCounter[node] = counter;
        eventHashAt[node][counter] = eventHash;
        signatureHashAt[node][counter] = signatureHash;
        anchorTimestampAt[node][counter] = uint64(block.timestamp);
        emit EventAnchored(node, counter, eventHash, signatureHash, uint64(block.timestamp));
    }
}
