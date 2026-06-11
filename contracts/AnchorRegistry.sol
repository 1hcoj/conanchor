// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract AnchorRegistry {
    struct AnchorRecord {
        uint64 blockHeight;
        string txID;
        string containerInstanceID;
        uint64 containerBatchID;
        uint64 firstContainerSeq;
        uint64 lastContainerSeq;
        uint64 firstGlobalSeq;
        uint64 lastGlobalSeq;
        string containerMerkleRoot;
        string containerBatchHash;
        string previousContainerBatchHash;
        uint64 eventCount;
        uint64 droppedEventCount;
        uint64 startTimeNS;
        uint64 endTimeNS;
        string collectorID;
    }

    mapping(bytes32 => AnchorRecord) private anchors;
    mapping(bytes32 => bool) private exists;
    mapping(bytes32 => uint64[]) private containerBatchIDs;

    event AnchorAppended(
        bytes32 indexed anchorKey,
        bytes32 indexed containerKey,
        string containerInstanceID,
        uint64 indexed containerBatchID,
        string containerMerkleRoot,
        string containerBatchHash
    );

    function anchorKey(string memory containerInstanceID, uint64 containerBatchID) public pure returns (bytes32) {
        return keccak256(abi.encodePacked(containerInstanceID, containerBatchID));
    }

    function containerKey(string memory containerInstanceID) public pure returns (bytes32) {
        return keccak256(abi.encodePacked(containerInstanceID));
    }

    function appendAnchor(
        string memory containerInstanceID,
        uint64 containerBatchID,
        uint64 firstContainerSeq,
        uint64 lastContainerSeq,
        uint64 firstGlobalSeq,
        uint64 lastGlobalSeq,
        string memory containerMerkleRoot,
        string memory containerBatchHash,
        string memory previousContainerBatchHash,
        uint64 eventCount,
        uint64 droppedEventCount,
        uint64 startTimeNS,
        uint64 endTimeNS,
        string memory collectorID
    ) external {
        bytes32 key = anchorKey(containerInstanceID, containerBatchID);
        require(!exists[key], "anchor already exists");

        anchors[key] = AnchorRecord({
            blockHeight: 0,
            txID: "",
            containerInstanceID: containerInstanceID,
            containerBatchID: containerBatchID,
            firstContainerSeq: firstContainerSeq,
            lastContainerSeq: lastContainerSeq,
            firstGlobalSeq: firstGlobalSeq,
            lastGlobalSeq: lastGlobalSeq,
            containerMerkleRoot: containerMerkleRoot,
            containerBatchHash: containerBatchHash,
            previousContainerBatchHash: previousContainerBatchHash,
            eventCount: eventCount,
            droppedEventCount: droppedEventCount,
            startTimeNS: startTimeNS,
            endTimeNS: endTimeNS,
            collectorID: collectorID
        });
        exists[key] = true;
        containerBatchIDs[containerKey(containerInstanceID)].push(containerBatchID);

        emit AnchorAppended(key, containerKey(containerInstanceID), containerInstanceID, containerBatchID, containerMerkleRoot, containerBatchHash);
    }

    function getAnchor(string memory containerInstanceID, uint64 containerBatchID) external view returns (
        uint64 blockHeight,
        string memory txID,
        string memory outContainerInstanceID,
        uint64 outContainerBatchID,
        uint64 firstContainerSeq,
        uint64 lastContainerSeq,
        uint64 firstGlobalSeq,
        uint64 lastGlobalSeq,
        string memory containerMerkleRoot,
        string memory containerBatchHash,
        string memory previousContainerBatchHash,
        uint64 eventCount,
        uint64 droppedEventCount,
        uint64 startTimeNS,
        uint64 endTimeNS,
        string memory collectorID
    ) {
        bytes32 key = anchorKey(containerInstanceID, containerBatchID);
        require(exists[key], "anchor not found");
        AnchorRecord storage record = anchors[key];
        return (
            record.blockHeight,
            record.txID,
            record.containerInstanceID,
            record.containerBatchID,
            record.firstContainerSeq,
            record.lastContainerSeq,
            record.firstGlobalSeq,
            record.lastGlobalSeq,
            record.containerMerkleRoot,
            record.containerBatchHash,
            record.previousContainerBatchHash,
            record.eventCount,
            record.droppedEventCount,
            record.startTimeNS,
            record.endTimeNS,
            record.collectorID
        );
    }

    function getContainerBatchCount(string memory containerInstanceID) external view returns (uint256) {
        return containerBatchIDs[containerKey(containerInstanceID)].length;
    }

    function getContainerBatchID(string memory containerInstanceID, uint256 index) external view returns (uint64) {
        return containerBatchIDs[containerKey(containerInstanceID)][index];
    }
}
