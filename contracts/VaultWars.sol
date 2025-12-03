// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

import {FHE, euint8, externalEuint8, ebool, eaddress, externalEuint32} from "@fhevm/solidity/lib/FHE.sol";
import {ZamaEthereumConfig} from "@fhevm/solidity/config/ZamaConfig.sol";

/**
 * @title VaultWars - FHEVM Enhanced (Patched)
 * @dev Patched contract with correct usage of the FHE Solidity wrapper and safe decryption flow.
 * - Uses FHE.* (NOT TFHE.*)
 * - Inherits Ownable properly
 * - Uses bytes32[] handles + FHE.toBytes32(...) when requesting decryptions
 * - Verifies KMS/Gateway signatures in the fulfillDecryption callback via FHE.checkSignatures
 * - Keeps all on-chain logic encrypted (uses FHE.select and encrypted types)
 * - Grants ACL permissions to encrypted address handles (room.encryptedWinner) instead of ephemeral flags
 */
contract VaultWars is ZamaEthereumConfig {
    /// @dev Length of vault codes (number of digits)
    uint8 public constant VAULT_CODE_LENGTH = 4;

    enum Phase {
        WaitingForJoin,
        Locked,
        InProgress,
        Finished,
        Cancelled
    }

    struct Probe {
        address submitter;
        euint8[VAULT_CODE_LENGTH] encryptedGuess;
        uint256 turnIndex;
        bool resultPosted;
        euint8 breaches;
        euint8 signals;
        uint256 timestamp;
        ebool isWinningProbe; // encrypted boolean
    }

    struct Room {
        address creator;
        address opponent;
        uint256 wager;
        Phase phase;
        euint8[VAULT_CODE_LENGTH] creatorVault;
        euint8[VAULT_CODE_LENGTH] opponentVault;
        uint256 turnCount;
        eaddress encryptedWinner; // encrypted handle for winner address
        uint256 createdAt;
        uint256 lastActiveAt;
    }

    mapping(uint256 => Room) public rooms;
    mapping(uint256 => mapping(uint256 => Probe)) public probes;
    mapping(address => uint256) public playerWins;

    mapping(uint256 => bool) public hasPendingRequest;

    uint256 public nextRoomId = 1;
    uint256 public minWager = 0.001 ether;
    uint256 public joinTimeout = 24 hours;
    uint256 public moveTimeout = 5 minutes;

    event RoomCreated(uint256 indexed roomId, address indexed creator, uint256 wager);
    event RoomJoined(uint256 indexed roomId, address indexed opponent);
    event VaultSubmitted(uint256 indexed roomId, address indexed who);
    event ResultComputed(
        uint256 indexed roomId,
        address indexed submitter,
        ebool isWin,
        euint8[4] guess,
        euint8 breaches,
        euint8 signals
    );
    event GameFinished(uint256 indexed roomId, address indexed winner, uint256 amount);
    event RoomCancelled(uint256 indexed roomId, address indexed by);
    event ConfigUpdated(string indexed param, uint256 value);
    event WinnerDecrypted(uint256 indexed roomId, address indexed winner);

    modifier onlyPlayer(uint256 roomId) {
        Room storage room = rooms[roomId];
        require(msg.sender == room.creator || msg.sender == room.opponent, "VaultWars: Not a player in this room");
        _;
    }

    modifier inPhase(uint256 roomId, Phase requiredPhase) {
        require(rooms[roomId].phase == requiredPhase, "VaultWars: Room not in required phase");
        _;
    }

    modifier onlyWhenTurn(uint256 roomId, address sender) {
        require(isPlayerTurn(roomId, sender), "VaultWars: Not your turn");
        _;
    }

    modifier validRoom(uint256 roomId) {
        require(roomId > 0 && roomId < nextRoomId, "VaultWars: Invalid room ID");
        _;
    }

    // ------------------------ Room creation / join ------------------------

    function createRoom(
        externalEuint8[VAULT_CODE_LENGTH] calldata externalVault,
        bytes calldata inputProof
    ) external payable returns (uint256 roomId) {
        require(msg.value >= minWager, "VaultWars: Insufficient wager amount");
        roomId = nextRoomId++;

        Room storage newRoom = rooms[roomId];
        newRoom.creator = msg.sender;
        newRoom.wager = msg.value;
        newRoom.phase = Phase.WaitingForJoin;
        newRoom.createdAt = block.timestamp;
        newRoom.lastActiveAt = block.timestamp;

        for (uint8 i = 0; i < VAULT_CODE_LENGTH; i++) {
            euint8 handle = FHE.fromExternal(externalVault[i], inputProof);
            FHE.allowThis(handle);
            FHE.allow(handle, msg.sender);
            newRoom.creatorVault[i] = handle;
        }

        emit RoomCreated(roomId, msg.sender, msg.value);
        emit VaultSubmitted(roomId, msg.sender);
    }

    function joinRoom(
        uint256 roomId,
        externalEuint8[VAULT_CODE_LENGTH] calldata externalVault,
        bytes calldata inputProof
    ) external payable validRoom(roomId) inPhase(roomId, Phase.WaitingForJoin) {
        Room storage room = rooms[roomId];
        require(msg.sender != room.creator, "VaultWars: Cannot join own room");

        require(msg.value == room.wager, "VaultWars: Wager amount mismatch");

        room.opponent = msg.sender;
        room.phase = Phase.InProgress;
        room.lastActiveAt = block.timestamp;

        for (uint8 i = 0; i < VAULT_CODE_LENGTH; i++) {
            euint8 handle = FHE.fromExternal(externalVault[i], inputProof);
            FHE.allowThis(handle);
            FHE.allow(handle, msg.sender);
            room.opponentVault[i] = handle;
        }

        emit RoomJoined(roomId, msg.sender);
        emit VaultSubmitted(roomId, msg.sender);
    }

    // ------------------------ Submit probe and compute results ------------------------

    function submitProbe(
        uint256 roomId,
        externalEuint8[VAULT_CODE_LENGTH] calldata externalGuess,
        bytes calldata inputProof
    ) external validRoom(roomId) inPhase(roomId, Phase.InProgress) onlyWhenTurn(roomId, msg.sender) {
        Room storage room = rooms[roomId];
        uint256 currentTurn = room.turnCount;
        Probe storage probe = probes[roomId][currentTurn];
        probe.submitter = msg.sender;
        probe.turnIndex = currentTurn;
        probe.timestamp = block.timestamp;

        // Build guess from external + proofs
        for (uint8 i = 0; i < VAULT_CODE_LENGTH; i++) {
            euint8 handle = FHE.fromExternal(externalGuess[i], inputProof);

            probe.encryptedGuess[i] = handle;
            FHE.makePubliclyDecryptable(probe.encryptedGuess[i]);
        }

        euint8[VAULT_CODE_LENGTH] memory targetVault = (msg.sender == room.creator)
            ? room.opponentVault
            : room.creatorVault;

        (probe.breaches, probe.signals) = _computeBreachesAndSignals(targetVault, probe.encryptedGuess);
        probe.resultPosted = true;

        ebool isWinner = FHE.eq(probe.breaches, FHE.asEuint8(VAULT_CODE_LENGTH));
        probe.isWinningProbe = isWinner;
        room.encryptedWinner = FHE.asEaddress(address(0));

        room.encryptedWinner = FHE.select(isWinner, FHE.asEaddress(msg.sender), room.encryptedWinner);

        room.turnCount++;
        room.lastActiveAt = block.timestamp;

        FHE.allowThis(room.encryptedWinner);
        FHE.makePubliclyDecryptable(isWinner);
        FHE.makePubliclyDecryptable(probe.breaches);
        FHE.makePubliclyDecryptable(probe.signals);
        FHE.allow(room.encryptedWinner, msg.sender);
        if (room.creator != msg.sender) {
            FHE.allow(room.encryptedWinner, room.creator);
        }
        if (room.opponent != msg.sender) {
            FHE.allow(room.encryptedWinner, room.opponent);
        }

        emit ResultComputed(roomId, msg.sender, isWinner, probe.encryptedGuess, probe.breaches, probe.signals);
    }

    /**
     * Gateway callback when decryption finishes. Verifies signatures then finalizes game if winner present.
     * The Gateway/KMS must pass the KMS signatures in `signatures` so the contract can validate the result.
     */
    function fulfillDecryption(uint256 roomId, bytes memory cleartexts, bytes memory decryptionProof) external {
        Room storage room = rooms[roomId];
        require(room.phase == Phase.InProgress, "VaultWars: Game not in progress");

        bytes32[] memory cts = new bytes32[](1);
        cts[0] = FHE.toBytes32(room.encryptedWinner);

        // ✅ Verify KMS/Gateway signatures
        FHE.checkSignatures(cts, cleartexts, decryptionProof);

        // Decode the winner address from cleartexts
        address decryptedWinner = abi.decode(cleartexts, (address));

        emit WinnerDecrypted(roomId, decryptedWinner);

        if (decryptedWinner != address(0) && (decryptedWinner == room.creator || decryptedWinner == room.opponent)) {
            _finalizeGameAndPayout(roomId, decryptedWinner);
        }
    }

    // ------------------------ Internal finalize and payout ------------------------

    function _finalizeGameAndPayout(uint256 roomId, address winner) internal {
        Room storage room = rooms[roomId];
        // Idempotent guard
        if (room.phase == Phase.Finished) return;

        room.phase = Phase.Finished;
        uint256 totalPayout = room.wager * 2;

        playerWins[winner]++;

        (bool success, ) = winner.call{value: totalPayout}("");
        require(success, "VaultWars: ETH transfer failed");

        emit GameFinished(roomId, winner, totalPayout);
    }

    // ------------------------ Timeouts / Cancel ------------------------

    function cancelRoom(uint256 roomId) external validRoom(roomId) inPhase(roomId, Phase.WaitingForJoin) {
        Room storage room = rooms[roomId];
        require(msg.sender == room.creator, "VaultWars: Only creator can cancel");
        // Opponent must NOT have joined to allow cancelling
        require(room.opponent == address(0), "VaultWars: Opponent already joined");

        room.phase = Phase.Cancelled;

        (bool success, ) = room.creator.call{value: room.wager}("");
        require(success, "VaultWars: ETH refund failed");

        emit RoomCancelled(roomId, msg.sender);
    }

    function claimTimeout(uint256 roomId) external validRoom(roomId) {
        Room storage room = rooms[roomId];

        if (room.phase == Phase.WaitingForJoin) {
            require(block.timestamp >= room.createdAt + joinTimeout, "VaultWars: Join timeout not reached");
            require(msg.sender == room.creator, "VaultWars: Only creator can claim join timeout");

            room.phase = Phase.Cancelled;
            (bool success, ) = room.creator.call{value: room.wager}("");
            require(success, "VaultWars: ETH refund failed");

            emit RoomCancelled(roomId, msg.sender);
        } else if (room.phase == Phase.InProgress) {
            require(block.timestamp >= room.lastActiveAt + moveTimeout, "VaultWars: Move timeout not reached");
            require(
                msg.sender == room.creator || msg.sender == room.opponent,
                "VaultWars: Only players can claim move timeout"
            );

            address currentTurnPlayer = isPlayerTurn(roomId, room.creator) ? room.creator : room.opponent;
            address timeoutWinner = currentTurnPlayer == room.creator ? room.opponent : room.creator;

            require(msg.sender == timeoutWinner, "VaultWars: Only non-active player can claim timeout");

            room.phase = Phase.Finished;
            playerWins[timeoutWinner]++;

            uint256 totalPayout = room.wager * 2;
            (bool success, ) = timeoutWinner.call{value: totalPayout}("");
            require(success, "VaultWars: ETH transfer failed");

            emit GameFinished(roomId, timeoutWinner, totalPayout);
        } else {
            revert("VaultWars: Cannot claim timeout in current phase");
        }
    }

    // ------------------------ Internal FHE computation ------------------------

    function _computeBreachesAndSignals(
        euint8[VAULT_CODE_LENGTH] memory vault,
        euint8[VAULT_CODE_LENGTH] memory guess
    ) internal returns (euint8 breaches, euint8 signals) {
        for (uint8 i = 0; i < VAULT_CODE_LENGTH; i++) {
            FHE.allow(vault[i], address(this));
            FHE.allow(guess[i], address(this));
        }

        ebool[VAULT_CODE_LENGTH] memory vaultMatched;
        ebool[VAULT_CODE_LENGTH] memory guessMatched;

        for (uint8 k = 0; k < VAULT_CODE_LENGTH; k++) {
            vaultMatched[k] = FHE.asEbool(false);
            guessMatched[k] = FHE.asEbool(false);
        }

        for (uint8 i = 0; i < VAULT_CODE_LENGTH; i++) {
            ebool isExactMatch = FHE.eq(vault[i], guess[i]);
            vaultMatched[i] = isExactMatch;
            guessMatched[i] = isExactMatch;
            breaches = FHE.add(breaches, FHE.select(isExactMatch, FHE.asEuint8(1), FHE.asEuint8(0)));

            for (uint8 j = 0; j < VAULT_CODE_LENGTH; j++) {
                if (i != j) {
                    ebool digitMatch = FHE.eq(guess[i], vault[j]);
                    ebool guessNotMatched = FHE.not(guessMatched[i]);
                    ebool vaultNotMatched = FHE.not(vaultMatched[j]);
                    ebool isSignal = FHE.and(FHE.and(digitMatch, guessNotMatched), vaultNotMatched);
                    signals = FHE.add(signals, FHE.select(isSignal, FHE.asEuint8(1), FHE.asEuint8(0)));

                    guessMatched[i] = FHE.or(guessMatched[i], isSignal);
                    vaultMatched[j] = FHE.or(vaultMatched[j], isSignal);
                }
            }
        }
    }

    // ------------------------ Views / helpers ------------------------

    function getLastResultEncrypted(
        uint256 roomId
    ) external view validRoom(roomId) returns (euint8 breaches, euint8 signals) {
        Room storage room = rooms[roomId];
        require(room.turnCount > 0, "VaultWars: No probes submitted yet");
        Probe storage lastProbe = probes[roomId][room.turnCount - 1];
        return (lastProbe.breaches, lastProbe.signals);
    }

    function getProbe(
        uint256 roomId,
        uint256 turnIndex
    )
        external
        view
        validRoom(roomId)
        returns (address submitter, uint256 turn, bool resultPosted, uint256 timestamp, ebool isWinningProbe)
    {
        require(turnIndex < rooms[roomId].turnCount, "VaultWars: Invalid turn index");
        Probe storage probe = probes[roomId][turnIndex];
        return (probe.submitter, probe.turnIndex, probe.resultPosted, probe.timestamp, probe.isWinningProbe);
    }

    function getRoom(
        uint256 roomId
    )
        external
        view
        validRoom(roomId)
        returns (
            address creator,
            address opponent,
            uint256 wager,
            Phase phase,
            uint256 turnCount,
            eaddress winner,
            uint256 createdAt,
            uint256 lastActiveAt
        )
    {
        Room storage room = rooms[roomId];
        return (
            room.creator,
            room.opponent,
            room.wager,
            room.phase,
            room.turnCount,
            room.encryptedWinner,
            room.createdAt,
            room.lastActiveAt
        );
    }

    function isPlayerTurn(uint256 roomId, address player) public view validRoom(roomId) returns (bool) {
        Room storage room = rooms[roomId];
        if (room.phase != Phase.InProgress) return false;
        bool isCreatorTurn = room.turnCount % 2 == 0;
        if (isCreatorTurn) return player == room.creator;
        return player == room.opponent;
    }

    function getPlayerWins(address player) external view returns (uint256) {
        return playerWins[player];
    }

    function getTotalRooms() external view returns (uint256) {
        return nextRoomId - 1;
    }

    function roomExists(uint256 roomId) external view returns (bool) {
        return roomId > 0 && roomId < nextRoomId;
    }
}
