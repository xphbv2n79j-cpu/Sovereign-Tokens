import { Transaction, Script, PrivateKey, Utils, Hash } from '@bsv/sdk';
import { KERNEL_ASM } from './Kernel';
import { CurveMath, Point } from './MathUtils';

export enum TokenType {
    FUNGIBLE = 0,
    NFT = 1,          // 0x01
    SOULBOUND = 2,    // 0x02
    SOULBOUND_NFT = 3 // 0x01 | 0x02
}

export class TokenWallet {

    static cleanASM(asm: string): string {
        return asm
            .replace(/#.*/g, '') // Remove comments
            .replace(/\s+/g, ' ') // Collapse whitespace
            .trim();
    }

    /**
     * Create Active State Locking Script (Data-First)
     * Schema: <Push Token> <Push Owner> <Push Slot> <Push Type> <Push Amount> <Push AccX> <Push AccY> <KERNEL>
     */
    static createActiveStateScript(
        tokenId: string,
        ownerPkh: string,
        amount: bigint,
        accumulator: Point, // [NEW] Accumulator State (X, Y)
        type: TokenType = TokenType.FUNGIBLE,
        customKernel?: string
    ): Script {
        // 1. Prepare Tags
        const tokenTag = Utils.toArray(tokenId, 'hex');

        // Owner (20 bytes)
        const ownerTag = Utils.toArray(ownerPkh, 'hex');

        // Slot Tag
        const slotPreimage = new Uint8Array([...ownerTag, ...tokenTag]);
        const slotTag = Hash.sha256(slotPreimage);

        // Amount (8 Bytes LE)
        const amountHex = amount.toString(16).padStart(16, '0').match(/.{1,2}/g)?.reverse().join('');
        const amountBytes = Utils.toArray(amountHex || '00', 'hex');

        // Type (1 Byte)
        const typeHex = type.toString(16).padStart(2, '0');
        const typeBytes = Utils.toArray(typeHex, 'hex');

        // Accumulator (32 Bytes X + 32 Bytes Y)
        const accX = Utils.toArray(accumulator.x.toString(16).padStart(64, '0'), 'hex');
        const accY = Utils.toArray(accumulator.y.toString(16).padStart(64, '0'), 'hex');

        // 2. Build Script (Data FIRST)
        const asm = TokenWallet.cleanASM(customKernel || KERNEL_ASM);
        // console.log("DEBUG ASM:", asm);

        return new Script()
            .writeBin(tokenTag)       // Push TokenID to stack
            .writeBin(ownerTag)       // Push OwnerID to stack
            .writeBin(slotTag)        // Push SlotID to stack
            .writeBin(typeBytes)      // Push Type to stack
            .writeBin(amountBytes)    // Push Amount to stack
            .writeBin(accX)           // Push AccX
            .writeBin(accY)           // Push AccY
            .writeScript(Script.fromASM(asm)); // Then run logic
    }

    /**
     * Builds a Homomorphic Token Transfer Transaction
     */
    static buildTransfer(
        privateKey: PrivateKey,
        utxo: { txid: string; vout: number; script: string; satoshis: number },
        destPkh: string,
        amountToSend: bigint,
        tokenId: string,
        prevAcc: Point,
        type: TokenType = TokenType.FUNGIBLE
    ): Transaction {
        // 1. Derive Vector V = Amount * Hash(ID)
        // Use standard secure HashToCurve (Try-and-increment)
        const { point: P_Asset } = CurveMath.hashToCurve(tokenId);

        // V = Amount * P_Asset
        const V = CurveMath.multiply(P_Asset, amountToSend);

        // 2. Calculate Next State
        const nextAcc = CurveMath.add(prevAcc, V);

        // 3. Slope (Lambda) for Addition
        const slope = CurveMath.calculateSlope(prevAcc, V);

        const tx = new Transaction();

        // --- INPUT ---
        // Active State Kernel expects:
        // Stack at start of Logic: <Sig> <PubKey> <Hints> <Data...>
        // So Unlocking Script must provide: <Sig> <PubKey> <Hints>
        // Execution Order: Unlocking -> Locking
        // Result Stack: <Sig> <PubKey> <Hints> <Token> <Owner> <Slot> <Amount>

        // Pushing Dummy Sig/PubKey for Test
        const dummySig = new Uint8Array(71).fill(1, 0, 71);
        const pubKey = Array.from(privateKey.toPublicKey().encode(true));

        // Note: Stack order matters!
        // If we write (Hints, Pub, Sig), stack is: <Hints> <Pub> <Sig> (Top)
        // Kernel expects: ... <Sig> <PubKey> <Hints>
        // So Hints needed to be written FIRST. (Bottom).
        // Then Pub, Then Sig.
        // My Kernel code says:
        // "Index 0..6 = Hints. Index 7 = PubKey. Index 8 = Sig." (Relative to what?)
        // If Sig is Top, Picking 8 gets Hints?
        // If Stack: <Hints> <Pub> <Sig> (Top)
        // Pick 0 -> Sig.
        // Pick 1 -> Pub.
        // Pick 2 -> Hint.

        // My Kernel says:
        // "7 OP_PICK # Copy PubKey"
        // "8 OP_PICK # Copy Sig"
        // This implies Sig/Pub are DEEP? i.e. Pushed first?
        // Unlocking: Push Sig, Push Pub, Push Hints.
        // Stack: <Sig> <Pub> <Hints> (Top).
        // Then Locking pushes Data.
        // Stack: <Sig> <Pub> <Hints> <Data> (Top).

        // Kernel pops Data.
        // Stack: <Sig> <Pub> <Hints> (Top).
        // Hints are Top.
        // If Hints are Top (Index 0..6), then Pub is 7, Sig is 8.
        // So Unlocking sequence must be: <Sig> <Pub> <Hints>.
        // Write Sig, Write Pub, Write Hints. 

        const finalUnlocking = new Script()
            .writeBin(dummySig)
            .writeBin(pubKey)
            .writeBin(Utils.toArray(slope.toString(16), 'hex'))
            .writeBin(Utils.toArray(V.x.toString(16), 'hex'))
            .writeBin(Utils.toArray(V.y.toString(16), 'hex'))
            .writeBin(Utils.toArray(prevAcc.x.toString(16), 'hex'))
            .writeBin(Utils.toArray(prevAcc.y.toString(16), 'hex'))
            .writeBin(Utils.toArray(nextAcc.x.toString(16), 'hex'))
            .writeBin(Utils.toArray(nextAcc.y.toString(16), 'hex'));

        tx.addInput({
            sourceTransaction: {
                txid: utxo.txid,
                vout: utxo.vout,
                script: utxo.script,
                satoshis: utxo.satoshis
            },
            unlockingScript: finalUnlocking
        } as any);

        // --- OUTPUT ---
        const lockingScript = TokenWallet.createActiveStateScript(
            tokenId,
            destPkh,
            amountToSend,
            nextAcc, // [NEW] Pass Next Accumulator
            type
        );

        tx.addOutput({
            satoshis: 1000,
            lockingScript: lockingScript
        });

        // tx.sign(privateKey); // Disabled for custom script mock

        return tx;
    }
    /**
     * Serializes a single transaction output to binary format.
     */
    static serializeOutput(output: { satoshis: number; lockingScript: Script }): number[] {
        const writer = new Utils.Writer();
        writer.writeUInt64LE(output.satoshis);
        const scriptBytes = output.lockingScript.toBinary();
        writer.writeVarIntNum(scriptBytes.length);
        writer.write(scriptBytes);
        return writer.toArray();
    }

    /**
     * Generates the Preimage for SIGHASH_ALL (BIP-143 style for BSV Genesis)
     * Note: BSV Genesis uses standard Bitcoin pre-SegWit algorithm unless specialized?
     * Actually, BSV uses the SIGHASH algorithm defined in Bitcoin.
     * For OP_PUSH_TX (Sighash Introspection), we generally reproduce the SIGHASH_FORKID format.
     */
    static generatePreimage(
        tx: Transaction,
        inputIndex: number,
        utxoScript: Script,
        utxoSatoshis: number,
        sighashType: number = 0x41 // SIGHASH_ALL | SIGHASH_FORKID
    ): number[] {
        const writer = new Utils.Writer();

        // 1. nVersion
        writer.writeUInt32LE(tx.version);

        // 2. hashPrevouts
        const writerPrevouts = new Utils.Writer();
        for (const input of tx.inputs) {
            writerPrevouts.writeReverse(Utils.toArray(input.sourceTransaction?.txid || '', 'hex'));
            writerPrevouts.writeUInt32LE(input.sourceOutputIndex || 0);
        }
        writer.write(Hash.hash256(writerPrevouts.toArray()));

        // 3. hashSequence
        const writerSeq = new Utils.Writer();
        for (const input of tx.inputs) {
            writerSeq.writeUInt32LE(input.sequence || 0xffffffff);
        }
        writer.write(Hash.hash256(writerSeq.toArray()));

        // 4. outpoint (Input Index)
        const input = tx.inputs[inputIndex];
        writer.writeReverse(Utils.toArray(input.sourceTransaction?.txid || '', 'hex'));
        writer.writeUInt32LE(input.sourceOutputIndex || 0);

        // 5. scriptCode (UTXO Script)
        // For standard P2PKH or Custom scripts, this is usually the locking script.
        // CodeSeparator Note: We assume no OP_CODESEPARATOR.
        const scriptBytes = utxoScript.toBinary();
        writer.writeVarIntNum(scriptBytes.length);
        writer.write(scriptBytes);

        // 6. value
        writer.writeUInt64LE(utxoSatoshis);

        // 7. nSequence
        writer.writeUInt32LE(input.sequence || 0xffffffff);

        // 8. hashOutputs
        const writerOutputs = new Utils.Writer();
        for (const out of tx.outputs) {
            writerOutputs.writeUInt64LE(out.satoshis);
            const sBytes = out.lockingScript.toBinary();
            writerOutputs.writeVarIntNum(sBytes.length);
            writerOutputs.write(sBytes);
        }
        writer.write(Hash.hash256(writerOutputs.toArray()));

        // 9. nLocktime
        writer.writeUInt32LE(tx.lockTime);

        // 10. sighashType
        writer.writeUInt32LE(sighashType);

        return writer.toArray();
    }

    /**
     * Builds a Homomorphic Token Transfer Transaction
     */
    static buildTransfer(
        privateKey: PrivateKey,
        utxo: { txid: string; vout: number; script: string; satoshis: number },
        destPkh: string,
        amountToSend: bigint,
        tokenId: string,
        prevAcc: Point,
        type: TokenType = TokenType.FUNGIBLE
    ): Transaction {
        // 1. Derive Vector V = Amount * Hash(ID)
        const { point: P_Asset } = CurveMath.hashToCurve(tokenId);
        const V = CurveMath.multiply(P_Asset, amountToSend);

        // 2. Calculate Next State
        const nextAcc = CurveMath.add(prevAcc, V);

        // 3. Slope
        const slope = CurveMath.calculateSlope(prevAcc, V);

        const tx = new Transaction();

        const outputScript = TokenWallet.createActiveStateScript(
            tokenId,
            destPkh,
            amountToSend,
            type
        );

        tx.addOutput({ satoshis: 1000, lockingScript: outputScript });

        // Temporarily add Input to calculate Preimage
        const tempScript = Script.fromASM('OP_TRUE'); // Placeholder
        const txInput = {
            sourceTransaction: {
                txid: utxo.txid,
                vout: utxo.vout,
                script: utxo.script,
                satoshis: utxo.satoshis
            },
            unlockingScript: tempScript
        };
        tx.addInput(txInput as any);

        // --- PREIMAGE GENERATION ---
        // We must generate the Preimage for Index 0.
        // The scriptCode is the UTXO Locking Script.
        const utxoScriptObj = Script.fromHex(utxo.script);
        const preimage = TokenWallet.generatePreimage(tx, 0, utxoScriptObj, utxo.satoshis);

        // --- OUTPUT INSPECTION DATA ---
        // Push the full Output[0] serialization so the script can verify HashOutputs.
        // HashOutputs = Hash( Serialize(Output0) + Serialize(Output1)... )
        // We only have 1 Output here.
        const output0Serialized = TokenWallet.serializeOutput({ satoshis: 1000, lockingScript: outputScript });

        const dummySig = new Uint8Array(71).fill(1).fill(0x30, 0, 1);
        const pubKey = Array.from(privateKey.toPublicKey().encode(true));

        const finalUnlocking = new Script()
            .writeBin(dummySig)
            .writeBin(pubKey)
            // Push Physics Hints
            .writeBin(Utils.toArray(slope.toString(16), 'hex'))
            .writeBin(Utils.toArray(V.x.toString(16), 'hex'))
            .writeBin(Utils.toArray(V.y.toString(16), 'hex'))
            .writeBin(Utils.toArray(prevAcc.x.toString(16), 'hex'))
            .writeBin(Utils.toArray(prevAcc.y.toString(16), 'hex'))
            .writeBin(Utils.toArray(nextAcc.x.toString(16), 'hex'))
            .writeBin(Utils.toArray(nextAcc.y.toString(16), 'hex'))

            // Push Preimage Data for Lineage Check
            .writeBin(preimage)
            .writeBin(output0Serialized);

        // Replace Input with Real Unlocking Script
        tx.inputs[0].unlockingScript = finalUnlocking;

        return tx;
    }
}
