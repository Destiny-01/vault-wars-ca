import { expect } from "chai";
import { Signer } from "ethers";
import { ethers, fhevm } from "hardhat";
import { VaultWars } from "../types";
import { FhevmType } from "@fhevm/hardhat-plugin";

// Helper: decrypt last result (breaches/signals) using publicDecrypt
async function decryptAndLogLastResult(vaultWars: VaultWars, roomId: number) {
  const [breaches, signals] = await vaultWars.getLastResultEncrypted(roomId);
  const decryptedBreaches = await fhevm.publicDecryptEuint(FhevmType.euint8, breaches);
  const decryptedSignals = await fhevm.publicDecryptEuint(FhevmType.euint8, signals);
  console.log(`Room ${roomId} - B=${decryptedBreaches}, S=${decryptedSignals}`);
  return { breaches: Number(decryptedBreaches), signals: Number(decryptedSignals) };
}

// Helper: create encrypted vault code
async function createEncryptedVault(
  vaultWars: VaultWars,
  player: Signer,
  vaultCode: number[],
): Promise<{ handles: any; inputProof: any }> {
  const input = fhevm.createEncryptedInput(await vaultWars.getAddress(), await player.getAddress());
  vaultCode.forEach((d) => input.add8(d));
  return await input.encrypt();
}

// Helper: submit a probe and return the result
async function submitProbeAndGetResult(
  vaultWars: VaultWars,
  roomId: number,
  player: Signer,
  guess: number[],
): Promise<{ breaches: number; signals: number; isWinner: boolean }> {
  const encryptedGuess = await createEncryptedVault(vaultWars, player, guess);
  const tx = await vaultWars
    .connect(player)
    .submitProbe(roomId, encryptedGuess.handles as any, encryptedGuess.inputProof);
  const receipt = await tx.wait();

  // Parse ResultComputed event
  const parsed = receipt?.logs
    .map((log) => {
      try {
        return vaultWars.interface.parseLog({ topics: log.topics, data: log.data });
      } catch {
        return null;
      }
    })
    .find((evt) => evt && evt.name === "ResultComputed");

  if (!parsed) {
    throw new Error("ResultComputed event not found");
  }

  const args = parsed.args as any;
  const breaches = await fhevm.publicDecryptEuint(FhevmType.euint8, args.breaches);
  const signals = await fhevm.publicDecryptEuint(FhevmType.euint8, args.signals);
  // isWinner is an ebool - decrypt as uint8 (0 or 1) then convert to boolean
  const isWinnerUint = await fhevm.publicDecryptEbool(args.isWin);
  const isWinner = Number(isWinnerUint) !== 0;

  return {
    breaches: Number(breaches),
    signals: Number(signals),
    isWinner: isWinner,
  };
}

describe("VaultWars Comprehensive Tests", function () {
  let owner: Signer, player1: Signer, player2: Signer, player3: Signer, player4: Signer;
  let vaultWars: VaultWars;
  let contractAddress: string;

  before(async () => {
    [owner, player1, player2, player3, player4] = await ethers.getSigners();

    // Deploy VaultWars contract
    const VaultWarsFactory = await ethers.getContractFactory("VaultWars");
    vaultWars = (await (VaultWarsFactory.deploy as any)()) as VaultWars;
    await vaultWars.waitForDeployment();
    contractAddress = await vaultWars.getAddress();
    console.log(`VaultWars deployed at: ${contractAddress}`);
  });

  describe("Room Creation", function () {
    it("should create a room with valid wager", async () => {
      const vaultCode = [1, 2, 3, 4];
      const wager = ethers.parseEther("0.01");
      const encryptedVault = await createEncryptedVault(vaultWars, player1, vaultCode);

      await expect(
        vaultWars.connect(player1).createRoom(encryptedVault.handles as any, encryptedVault.inputProof, {
          value: wager,
        }),
      )
        .to.emit(vaultWars, "RoomCreated")
        .withArgs(1, await player1.getAddress(), wager)
        .to.emit(vaultWars, "VaultSubmitted")
        .withArgs(1, await player1.getAddress());

      const totalRooms = await vaultWars.getTotalRooms();
      expect(totalRooms).to.equal(1);

      const room = await vaultWars.rooms(1);
      expect(room.creator).to.equal(await player1.getAddress());
      expect(room.wager).to.equal(wager);
      expect(room.phase).to.equal(0); // WaitingForJoin
      expect(room.opponent).to.equal(ethers.ZeroAddress);
    });

    it("should reject room creation with insufficient wager", async () => {
      const vaultCode = [5, 5, 5, 5];
      const encryptedVault = await createEncryptedVault(vaultWars, player1, vaultCode);
      const minWager = await vaultWars.minWager();
      const insufficientWager = minWager - 1n;

      await expect(
        vaultWars.connect(player1).createRoom(encryptedVault.handles as any, encryptedVault.inputProof, {
          value: insufficientWager,
        }),
      ).to.be.revertedWith("VaultWars: Insufficient wager amount");
    });

    it("should allow multiple rooms to be created", async () => {
      // Create room 2
      const vaultCode2 = [2, 3, 4, 5];
      const encryptedVault2 = await createEncryptedVault(vaultWars, player2, vaultCode2);
      await vaultWars.connect(player2).createRoom(encryptedVault2.handles as any, encryptedVault2.inputProof, {
        value: ethers.parseEther("0.01"),
      });

      // Create room 3
      const vaultCode3 = [3, 4, 5, 6];
      const encryptedVault3 = await createEncryptedVault(vaultWars, player3, vaultCode3);
      await vaultWars.connect(player3).createRoom(encryptedVault3.handles as any, encryptedVault3.inputProof, {
        value: ethers.parseEther("0.015"),
      });

      const totalRooms = await vaultWars.getTotalRooms();
      expect(totalRooms).to.equal(3);

      const room2 = await vaultWars.rooms(2);
      const room3 = await vaultWars.rooms(3);
      expect(room2.creator).to.equal(await player2.getAddress());
      expect(room3.creator).to.equal(await player3.getAddress());
      expect(room3.wager).to.equal(ethers.parseEther("0.015"));
    });
  });

  describe("Room Joining", function () {
    it("should allow opponent to join a room with matching wager", async () => {
      const vaultCode = [4, 3, 2, 1];
      const encryptedVault = await createEncryptedVault(vaultWars, player2, vaultCode);
      const room = await vaultWars.rooms(1);
      const wager = room.wager;

      await expect(
        vaultWars.connect(player2).joinRoom(1, encryptedVault.handles as any, encryptedVault.inputProof, {
          value: wager,
        }),
      )
        .to.emit(vaultWars, "RoomJoined")
        .withArgs(1, await player2.getAddress())
        .to.emit(vaultWars, "VaultSubmitted")
        .withArgs(1, await player2.getAddress());

      const updatedRoom = await vaultWars.rooms(1);
      expect(updatedRoom.opponent).to.equal(await player2.getAddress());
      expect(updatedRoom.phase).to.equal(2); // InProgress
    });

    it("should reject joining with mismatched wager", async () => {
      const vaultCode = [6, 6, 6, 6];
      const encryptedVault = await createEncryptedVault(vaultWars, player3, vaultCode);

      await expect(
        vaultWars.connect(player3).joinRoom(2, encryptedVault.handles as any, encryptedVault.inputProof, {
          value: ethers.parseEther("0.02"), // Different wager
        }),
      ).to.be.revertedWith("VaultWars: Wager amount mismatch");
    });

    it("should reject creator joining their own room", async () => {
      const vaultCode = [7, 7, 7, 7];
      const encryptedVault = await createEncryptedVault(vaultWars, player2, vaultCode);

      await expect(
        vaultWars.connect(player2).joinRoom(2, encryptedVault.handles as any, encryptedVault.inputProof, {
          value: ethers.parseEther("0.01"),
        }),
      ).to.be.revertedWith("VaultWars: Cannot join own room");
    });

    it("should reject joining a room that's already in progress", async () => {
      const vaultCode = [8, 8, 8, 8];
      const encryptedVault = await createEncryptedVault(vaultWars, player4, vaultCode);

      await expect(
        vaultWars.connect(player4).joinRoom(1, encryptedVault.handles as any, encryptedVault.inputProof, {
          value: ethers.parseEther("0.01"),
        }),
      ).to.be.revertedWith("VaultWars: Room not in required phase");
    });
  });

  describe("Probe Submission and Game Logic", function () {
    beforeEach(async function () {
      // Create a fresh room for each test
      const vaultCode1 = [1, 2, 3, 4];
      const encryptedVault1 = await createEncryptedVault(vaultWars, player1, vaultCode1);
      await vaultWars.connect(player1).createRoom(encryptedVault1.handles as any, encryptedVault1.inputProof, {
        value: ethers.parseEther("0.01"),
      });

      const vaultCode2 = [4, 3, 2, 1];
      const encryptedVault2 = await createEncryptedVault(vaultWars, player2, vaultCode2);
      await vaultWars
        .connect(player2)
        .joinRoom(await vaultWars.getTotalRooms(), encryptedVault2.handles as any, encryptedVault2.inputProof, {
          value: ethers.parseEther("0.01"),
        });
    });

    it("should correctly calculate breaches and signals for exact match", async () => {
      const roomId = Number(await vaultWars.getTotalRooms());
      // Player1 tries to guess opponent's vault [4,3,2,1] with exact match
      const result = await submitProbeAndGetResult(vaultWars, roomId, player1, [4, 3, 2, 1]);

      expect(result.breaches).to.equal(4);
      expect(result.signals).to.equal(0);
      expect(result.isWinner).to.be.true;

      // Winner is set when isWinner is true - we verify this via the isWinner flag
      // The encryptedWinner is not publicly decryptable, but we can verify the game state
      const room = await vaultWars.rooms(roomId);
      expect(room.encryptedWinner).to.not.equal(ethers.ZeroHash); // Winner should be set
    });

    it("should correctly calculate breaches and signals for partial match", async () => {
      const roomId = Number(await vaultWars.getTotalRooms());
      // Player1 guesses [4,3,2,0] - 3 exact matches, 0 signals
      const result = await submitProbeAndGetResult(vaultWars, roomId, player1, [4, 3, 2, 0]);

      expect(result.breaches).to.equal(3);
      expect(result.signals).to.equal(0);
      expect(result.isWinner).to.be.false;
    });

    it("should correctly calculate signals (right digit, wrong position)", async () => {
      const roomId = Number(await vaultWars.getTotalRooms());
      // Player1 guesses [1,2,3,4] - 0 exact matches, but all digits exist in different positions
      // Opponent vault is [4,3,2,1], so:
      // 1 exists at position 3 in vault -> signal
      // 2 exists at position 2 in vault -> signal
      // 3 exists at position 1 in vault -> signal
      // 4 exists at position 0 in vault -> signal
      const result = await submitProbeAndGetResult(vaultWars, roomId, player1, [1, 2, 3, 4]);

      expect(result.breaches).to.equal(0);
      expect(result.signals).to.equal(4);
      expect(result.isWinner).to.be.false;
    });

    it("should correctly calculate mixed breaches and signals", async () => {
      const roomId = Number(await vaultWars.getTotalRooms());
      // Player1 guesses [4,1,2,3] against opponent vault [4,3,2,1]
      // Position 0: 4 == 4 -> breach
      // Position 1: 1 exists at position 3 -> signal
      // Position 2: 2 == 2 -> breach
      // Position 3: 3 exists at position 1 -> signal
      const result = await submitProbeAndGetResult(vaultWars, roomId, player1, [4, 1, 2, 3]);

      expect(result.breaches).to.equal(2);
      expect(result.signals).to.equal(2);
      expect(result.isWinner).to.be.false;
    });

    it("should correctly handle no matches", async () => {
      const roomId = Number(await vaultWars.getTotalRooms());
      // Player1 guesses [9,9,9,9] - no matches at all
      const result = await submitProbeAndGetResult(vaultWars, roomId, player1, [9, 9, 9, 9]);

      expect(result.breaches).to.equal(0);
      expect(result.signals).to.equal(0);
      expect(result.isWinner).to.be.false;
    });

    it("should correctly handle duplicate digits in guess", async () => {
      const roomId = Number(await vaultWars.getTotalRooms());
      // Player1 guesses [4,4,4,4] against [4,3,2,1]
      // Only position 0 matches exactly -> 1 breach, 0 signals (duplicates don't count multiple times)
      const result = await submitProbeAndGetResult(vaultWars, roomId, player1, [4, 4, 4, 4]);

      expect(result.breaches).to.equal(1);
      expect(result.signals).to.equal(0);
      expect(result.isWinner).to.be.false;
    });

    it("should enforce turn order (creator goes first)", async () => {
      const roomId = Number(await vaultWars.getTotalRooms());

      // Creator should be able to submit first (turnCount = 0, so creator's turn)
      await expect(submitProbeAndGetResult(vaultWars, roomId, player1, [1, 1, 1, 1])).to.not.be.reverted;

      // After creator submits, turnCount becomes 1, so it's opponent's turn
      // Opponent should be able to submit now (not revert)
      await expect(submitProbeAndGetResult(vaultWars, roomId, player2, [2, 2, 2, 2])).to.not.be.reverted;

      // After opponent submits, turnCount becomes 2, so it's creator's turn again
      await expect(submitProbeAndGetResult(vaultWars, roomId, player1, [3, 3, 3, 3])).to.not.be.reverted;

      // Now it's opponent's turn again (turnCount = 3)
      // Creator should not be able to submit out of turn
      await expect(submitProbeAndGetResult(vaultWars, roomId, player1, [4, 4, 4, 4])).to.be.revertedWith(
        "VaultWars: Not your turn",
      );
    });

    it("should track turn count correctly", async () => {
      const roomId = Number(await vaultWars.getTotalRooms());
      let room = await vaultWars.rooms(roomId);
      expect(room.turnCount).to.equal(0);

      await submitProbeAndGetResult(vaultWars, roomId, player1, [1, 1, 1, 1]);
      room = await vaultWars.rooms(roomId);
      expect(room.turnCount).to.equal(1);

      await submitProbeAndGetResult(vaultWars, roomId, player2, [2, 2, 2, 2]);
      room = await vaultWars.rooms(roomId);
      expect(room.turnCount).to.equal(2);

      await submitProbeAndGetResult(vaultWars, roomId, player1, [3, 3, 3, 3]);
      room = await vaultWars.rooms(roomId);
      expect(room.turnCount).to.equal(3);
    });

    it("should allow multiple probes until winner is found", async () => {
      const roomId = Number(await vaultWars.getTotalRooms());
      // Player1's vault is [1,2,3,4], Player2's vault is [4,3,2,1]
      // Player1 is trying to guess [4,3,2,1], Player2 is trying to guess [1,2,3,4]

      // Wrong guesses
      let result1 = await submitProbeAndGetResult(vaultWars, roomId, player1, [1, 1, 1, 1]);
      expect(result1.isWinner).to.be.false;

      let result2 = await submitProbeAndGetResult(vaultWars, roomId, player2, [2, 2, 2, 2]);
      expect(result2.isWinner).to.be.false;

      let result3 = await submitProbeAndGetResult(vaultWars, roomId, player1, [5, 5, 5, 5]);
      expect(result3.isWinner).to.be.false;

      // Correct guess - Player2 guesses [1,2,3,4] against Player1's vault [1,2,3,4]
      let result4 = await submitProbeAndGetResult(vaultWars, roomId, player2, [1, 2, 3, 4]);
      expect(result4.isWinner).to.be.true;
      expect(result4.breaches).to.equal(4);

      // Winner is set when isWinner is true - we verify this via the isWinner flag
      // The encryptedWinner is not publicly decryptable, but we can verify the game state
      const room = await vaultWars.rooms(roomId);
      expect(room.encryptedWinner).to.not.equal(ethers.ZeroHash); // Winner should be set
    });

    it("should make probe results publicly decryptable", async () => {
      const roomId = Number(await vaultWars.getTotalRooms());
      await submitProbeAndGetResult(vaultWars, roomId, player1, [1, 2, 3, 4]);

      // Should be able to decrypt using publicDecrypt
      const result = await decryptAndLogLastResult(vaultWars, roomId);
      expect(result.breaches).to.be.a("number");
      expect(result.signals).to.be.a("number");
    });
  });

  describe("Room Cancellation", function () {
    it("should allow creator to cancel room before opponent joins", async () => {
      const vaultCode = [1, 1, 1, 1];
      const encryptedVault = await createEncryptedVault(vaultWars, player1, vaultCode);
      await vaultWars.connect(player1).createRoom(encryptedVault.handles as any, encryptedVault.inputProof, {
        value: ethers.parseEther("0.01"),
      });

      const roomId = Number(await vaultWars.getTotalRooms());
      const balanceBefore = await ethers.provider.getBalance(await player1.getAddress());

      await expect(vaultWars.connect(player1).cancelRoom(roomId))
        .to.emit(vaultWars, "RoomCancelled")
        .withArgs(roomId, await player1.getAddress());

      const room = await vaultWars.rooms(roomId);
      expect(room.phase).to.equal(4); // Cancelled

      const balanceAfter = await ethers.provider.getBalance(await player1.getAddress());
      expect(balanceAfter).to.be.gt(balanceBefore);
    });

    it("should reject cancellation after opponent joins", async () => {
      const vaultCode1 = [2, 2, 2, 2];
      const encryptedVault1 = await createEncryptedVault(vaultWars, player1, vaultCode1);
      await vaultWars.connect(player1).createRoom(encryptedVault1.handles as any, encryptedVault1.inputProof, {
        value: ethers.parseEther("0.01"),
      });

      const roomId = Number(await vaultWars.getTotalRooms());

      const vaultCode2 = [3, 3, 3, 3];
      const encryptedVault2 = await createEncryptedVault(vaultWars, player2, vaultCode2);
      await vaultWars.connect(player2).joinRoom(roomId, encryptedVault2.handles as any, encryptedVault2.inputProof, {
        value: ethers.parseEther("0.01"),
      });

      await expect(vaultWars.connect(player1).cancelRoom(roomId)).to.be.revertedWith(
        "VaultWars: Room not in required phase",
      );
    });

    it("should reject cancellation by non-creator", async () => {
      const vaultCode = [4, 4, 4, 4];
      const encryptedVault = await createEncryptedVault(vaultWars, player1, vaultCode);
      await vaultWars.connect(player1).createRoom(encryptedVault.handles as any, encryptedVault.inputProof, {
        value: ethers.parseEther("0.01"),
      });

      const roomId = Number(await vaultWars.getTotalRooms());

      await expect(vaultWars.connect(player2).cancelRoom(roomId)).to.be.revertedWith(
        "VaultWars: Only creator can cancel",
      );
    });
  });

  describe("Player Statistics", function () {
    it("should track player wins correctly", async () => {
      // Create and complete a game where player1 wins
      const vaultCode1 = [1, 2, 3, 4];
      const encryptedVault1 = await createEncryptedVault(vaultWars, player1, vaultCode1);
      await vaultWars.connect(player1).createRoom(encryptedVault1.handles as any, encryptedVault1.inputProof, {
        value: ethers.parseEther("0.01"),
      });

      const roomId = Number(await vaultWars.getTotalRooms());

      const vaultCode2 = [5, 5, 5, 5];
      const encryptedVault2 = await createEncryptedVault(vaultWars, player2, vaultCode2);
      await vaultWars.connect(player2).joinRoom(roomId, encryptedVault2.handles as any, encryptedVault2.inputProof, {
        value: ethers.parseEther("0.01"),
      });

      // Player1 wins by guessing correctly
      await submitProbeAndGetResult(vaultWars, roomId, player1, [5, 5, 5, 5]);

      // Note: In a real scenario, fulfillDecryption would be called by the gateway
      // For testing, we can check that the encrypted winner is set correctly
      // Winner is set when isWinner is true - we verify this via the isWinner flag
      // The encryptedWinner is not publicly decryptable, but we can verify the game state
      const room = await vaultWars.rooms(roomId);
      expect(room.encryptedWinner).to.not.equal(ethers.ZeroHash); // Winner should be set
    });
  });

  describe("Edge Cases and Error Handling", function () {
    it("should reject probe submission for invalid room", async () => {
      const encryptedGuess = await createEncryptedVault(vaultWars, player1, [1, 1, 1, 1]);
      await expect(
        vaultWars.connect(player1).submitProbe(999, encryptedGuess.handles as any, encryptedGuess.inputProof),
      ).to.be.revertedWith("VaultWars: Invalid room ID");
    });

    it("should reject probe submission when room is not in progress", async () => {
      const vaultCode = [1, 1, 1, 1];
      const encryptedVault = await createEncryptedVault(vaultWars, player1, vaultCode);
      await vaultWars.connect(player1).createRoom(encryptedVault.handles as any, encryptedVault.inputProof, {
        value: ethers.parseEther("0.01"),
      });

      const roomId = Number(await vaultWars.getTotalRooms());
      const encryptedGuess = await createEncryptedVault(vaultWars, player1, [2, 2, 2, 2]);

      await expect(
        vaultWars.connect(player1).submitProbe(roomId, encryptedGuess.handles as any, encryptedGuess.inputProof),
      ).to.be.revertedWith("VaultWars: Room not in required phase");
    });

    it("should handle getLastResultEncrypted for room with no probes", async () => {
      const vaultCode1 = [1, 1, 1, 1];
      const encryptedVault1 = await createEncryptedVault(vaultWars, player1, vaultCode1);
      await vaultWars.connect(player1).createRoom(encryptedVault1.handles as any, encryptedVault1.inputProof, {
        value: ethers.parseEther("0.01"),
      });

      const roomId = Number(await vaultWars.getTotalRooms());

      const vaultCode2 = [2, 2, 2, 2];
      const encryptedVault2 = await createEncryptedVault(vaultWars, player2, vaultCode2);
      await vaultWars.connect(player2).joinRoom(roomId, encryptedVault2.handles as any, encryptedVault2.inputProof, {
        value: ethers.parseEther("0.01"),
      });

      await expect(vaultWars.getLastResultEncrypted(roomId)).to.be.revertedWith("VaultWars: No probes submitted yet");
    });

    it("should correctly identify player turn", async () => {
      const vaultCode1 = [1, 1, 1, 1];
      const encryptedVault1 = await createEncryptedVault(vaultWars, player1, vaultCode1);
      await vaultWars.connect(player1).createRoom(encryptedVault1.handles as any, encryptedVault1.inputProof, {
        value: ethers.parseEther("0.01"),
      });

      const roomId = Number(await vaultWars.getTotalRooms());

      const vaultCode2 = [2, 2, 2, 2];
      const encryptedVault2 = await createEncryptedVault(vaultWars, player2, vaultCode2);
      await vaultWars.connect(player2).joinRoom(roomId, encryptedVault2.handles as any, encryptedVault2.inputProof, {
        value: ethers.parseEther("0.01"),
      });

      // Turn 0: creator's turn
      expect(await vaultWars.isPlayerTurn(roomId, await player1.getAddress())).to.be.true;
      expect(await vaultWars.isPlayerTurn(roomId, await player2.getAddress())).to.be.false;

      // Submit probe by creator
      await submitProbeAndGetResult(vaultWars, roomId, player1, [3, 3, 3, 3]);

      // Turn 1: opponent's turn
      expect(await vaultWars.isPlayerTurn(roomId, await player1.getAddress())).to.be.false;
      expect(await vaultWars.isPlayerTurn(roomId, await player2.getAddress())).to.be.true;
    });
  });

  describe("Complex Game Scenarios", function () {
    it("should handle a full game with multiple wrong guesses before winning", async () => {
      // Create room
      const vaultCode1 = [1, 2, 3, 4];
      const encryptedVault1 = await createEncryptedVault(vaultWars, player1, vaultCode1);
      await vaultWars.connect(player1).createRoom(encryptedVault1.handles as any, encryptedVault1.inputProof, {
        value: ethers.parseEther("0.01"),
      });

      const roomId = Number(await vaultWars.getTotalRooms());

      const vaultCode2 = [4, 3, 2, 1];
      const encryptedVault2 = await createEncryptedVault(vaultWars, player2, vaultCode2);
      await vaultWars.connect(player2).joinRoom(roomId, encryptedVault2.handles as any, encryptedVault2.inputProof, {
        value: ethers.parseEther("0.01"),
      });

      // Player1 tries to guess [4,3,2,1]
      // Turn 0: Player1 guesses [9,9,9,9] - 0 breaches, 0 signals
      let result = await submitProbeAndGetResult(vaultWars, roomId, player1, [9, 9, 9, 9]);
      expect(result.breaches).to.equal(0);
      expect(result.signals).to.equal(0);

      // Turn 1: Player2 tries to guess [1,2,3,4]
      result = await submitProbeAndGetResult(vaultWars, roomId, player2, [1, 2, 3, 4]);
      expect(result.breaches).to.equal(4);
      expect(result.signals).to.equal(0);

      // Turn 2: Player1 guesses [4,3,2,1] - WIN!
      result = await submitProbeAndGetResult(vaultWars, roomId, player1, [4, 3, 2, 1]);
      expect(result.breaches).to.equal(4);
      expect(result.signals).to.equal(0);
      expect(result.isWinner).to.be.true;

      // Winner is set when isWinner is true - we verify this via the isWinner flag
      // The encryptedWinner is not publicly decryptable, but we can verify the game state
      const room = await vaultWars.rooms(roomId);
      expect(room.encryptedWinner).to.not.equal(ethers.ZeroHash); // Winner should be set
    });

    it("should handle multiple concurrent rooms", async () => {
      // Room 1: player1 vs player2
      const vault1_1 = [1, 1, 1, 1];
      const enc1_1 = await createEncryptedVault(vaultWars, player1, vault1_1);
      await vaultWars.connect(player1).createRoom(enc1_1.handles as any, enc1_1.inputProof, {
        value: ethers.parseEther("0.01"),
      });
      const roomId1 = Number(await vaultWars.getTotalRooms());

      const vault1_2 = [2, 2, 2, 2];
      const enc1_2 = await createEncryptedVault(vaultWars, player2, vault1_2);
      await vaultWars.connect(player2).joinRoom(roomId1, enc1_2.handles as any, enc1_2.inputProof, {
        value: ethers.parseEther("0.01"),
      });

      // Room 2: player3 vs player4
      const vault2_1 = [3, 3, 3, 3];
      const enc2_1 = await createEncryptedVault(vaultWars, player3, vault2_1);
      await vaultWars.connect(player3).createRoom(enc2_1.handles as any, enc2_1.inputProof, {
        value: ethers.parseEther("0.01"),
      });
      const roomId2 = Number(await vaultWars.getTotalRooms());

      const vault2_2 = [4, 4, 4, 4];
      const enc2_2 = await createEncryptedVault(vaultWars, player4, vault2_2);
      await vaultWars.connect(player4).joinRoom(roomId2, enc2_2.handles as any, enc2_2.inputProof, {
        value: ethers.parseEther("0.01"),
      });

      // Submit probes in both rooms
      await submitProbeAndGetResult(vaultWars, roomId1, player1, [2, 2, 2, 2]);
      await submitProbeAndGetResult(vaultWars, roomId2, player3, [4, 4, 4, 4]);

      // Both rooms should be independent
      const room1 = await vaultWars.rooms(roomId1);
      const room2 = await vaultWars.rooms(roomId2);
      expect(room1.turnCount).to.equal(1);
      expect(room2.turnCount).to.equal(1);
      expect(room1.phase).to.equal(2); // InProgress
      expect(room2.phase).to.equal(2); // InProgress
    });
  });
});
