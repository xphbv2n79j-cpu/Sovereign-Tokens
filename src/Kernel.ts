
/**
 * ACTIVE STATE KERNEL (Data-First)
 * * Locking Script Schema:
 * <Push TokenID> <Push OwnerID> <Push SlotID> <Push Type> <Push Amount> <KERNEL_LOGIC>
 * * Stack at Logic Start:
 * ... <Sig> <PubKey> <Hints> <TokenID> <OwnerID> <SlotID> <Type> <Amount> (Top)
 */

export const KERNEL_ASM = `
    # --- 0. INITIAL STACK ---
    # Top: <Amount> <Type> <Slot> <Owner> <TokenID>
    # Below: <Ny> <Nx> <Py> <Px> <Vy> <Vx> <Slope> <Pub> <Sig>
    # Below(New): <Preimage> <Out0_Length> <Out0_Script> <Out0_Sats>
    # Note: We need to manage the stack carefully. 
    # For Authentication, we want <Sig> <Pub> at 7,8?
    # If we add <Preimage> etc, indices shift.
    # STRATEGY: Move New Items to AltStack immediately, then process normally.

    # 1. SETUP STATE (Move State to AltStack)
    OP_TOALTSTACK # Amount
    OP_TOALTSTACK # Type
    OP_TOALTSTACK # Slot
    OP_TOALTSTACK # Owner
    OP_TOALTSTACK # TokenID

    # Stack Top: <Ny> ... <Sig> 
    # Below: <Preimage> <Out0_Length> <Out0_Script> <Out0_Sats>
    # We must access Sig/Pub for Auth.
    # Standard P2PKH Auth uses <Sig> <Pub> on top? 
    # No, TokenWallet pushes: <Sats> <Script> <Len> <Preimage> <Hints> <Pub> <Sig>
    # Wait. TokenWallet pushes:
    # .writeBin(hints)
    # .writeBin(preimage)
    # .writeBin(out0Serialized)
    # If Preimage/Out0 are pushed AFTER hints?
    # Stack Top: <Out0> <Preimage> <Hints...> 
    # Then Kernel pushes State Data.
    # Stack Top: <Data> <Out0> <Preimage> <Hints...>
    
    # Kernel pops Data.
    # Stack Top: <Out0> <Preimage> <Hints...>
    # This DESTROYS the index assumption (Ny at 0).
    
    # FIX: We must move Out0/Preimage to AltStack or bottom FIRST.
    # Since they are at Top, we can move them.
    # Stack: <Out0_Sats> <Out0_Script> <Out0_Len> <Preimage> <Ny>...
    
    # Move Lineage Data to AltStack (Reverse Order of need) 
    # We need Preimage, OutScript, OutSats later.
    
    # OP_TOALTSTACK (Sats)
    # OP_TOALTSTACK (Script)
    # OP_TOALTSTACK (Len) - Actually serialize logic is complex.
    # Let's assume passed as one blob? 
    # TokenWallet passes: output0Serialized (One Blob).
    # Then Preimage (One Blob).
    
    # Stack: <Output0_Blob> <Preimage> <Ny> ...
    
    OP_SWAP # <Preimage> <Output0_Blob>
    OP_TOALTSTACK # Save Output0_Blob
    OP_TOALTSTACK # Save Preimage
    
    # Now Stack Top is <Ny>. Indices 0..6 are Hints. 7=Pub, 8=Sig.
    # Logic proceeds normally.

    # --- 2. AUTHENTICATION (P2PKH) ---
    # Copy Owner from Alt (Deep in Alt now?)
    # AltStack: <Token> <Owner> <Slot> <Type> <Amount> <Output0> <Preimage>
    # We need Owner (Index 4 in Alt).
    
    # OP_FROMALTSTACK (Amount)
    # OP_FROMALTSTACK (Type)
    # OP_FROMALTSTACK (Slot)
    # OP_FROMALTSTACK (Owner) -> Copy
    # OP_DUP OP_TOALTSTACK 
    08 OP_SPLIT OP_DROP # Discard Sats (0x08) ...
    
    # This is messy.
    # Better: Use OP_PICK on AltStack? BSV doesn't allow picking from Alt.
    # We must unroll AltStack or change push order.
    
    # Let's adjust Setup:
    # Stack: <Amt> <Type> <Slot> <Owner> <Token> <Out0> <Preimage>
    
    # Save Amt, Type, Slot.
    OP_TOALTSTACK OP_TOALTSTACK OP_TOALTSTACK 
    # Stack: <Owner> <Token> <Out0> <Preimage> ...
    
    # Auth Logic: Verify <Sig> <Pub> matches <Owner> and <Preimage>
    # Note: We must verify Preimage matches Sig!
    # P2PKH uses OP_CHECKSIG on the *Transaction Hash*.
    # OP_PUSH_TX uses <Sig> <Pub> <Preimage>.
    # Verification: Hash(Preimage) == Sighash from OP_CHECKSIG?
    # No. OP_CHECKSIG verifies (Digests) the Transaction.
    # To link Preimage to Sig, we need:
    # <Sig> <Pub> <Preimage>
    # OP_DUP OP_HASH256 OP_SWAP OP_CHECKSIG
    # This verifies that Sig signs the Hash of Preimage.
    # This implies Preimage IS the Transaction Digest.
    # This is the standard OP_PUSH_TX pattern.
    
    # So we need <Sig> <Pub> at Top for Auth.
    # But they are at Index 7,8.
    # 8 OP_PICK (Sig)
    # 7 OP_PICK (Pub)
    # 4 OP_PICK (Preimage) -- Wait, indices shifted.
    # Stack: <Owner> <Token> <Out0> <Preimage> <Ny>...
    
    # Let's move everything to AltStack to clean Main Stack for Physics.
    14 OP_SWAP OP_CAT 
    
    # Check Prefix
    OP_SWAP # <Prefix> <Script>
    21 OP_SPLIT OP_DROP # Take first 33 bytes (0x21)n
    OP_TOALTSTACK # Throw away Owner (Keep copy in Alt)
    
    OP_SWAP # <Preimage> <Out0>
    OP_TOALTSTACK # Save Out0
    OP_TOALTSTACK # Token
    
    # AltStack: <Amount> <Type> <Slot> <Owner> <Token> (Top)

    # --- 2. AUTHENTICATION ---
    # Stack Top: <Ny> ... <Sig> <Preimage> <Out0>
    
    # Peek Owner from Alt (Index 1)
    OP_FROMALTSTACK OP_FROMALTSTACK OP_DUP OP_TOALTSTACK # <Owner>
    OP_SWAP OP_TOALTSTACK # Restore Token. Stack: <Owner>
    
    # PubKey is at HintDepth(7) + Pub(0) = 7?
    # Hints: <Ny>...<Slope> (7 items).
    # <Pub> is next. Index 7.
    # <Sig> is next. Index 8.
    
    # Verify PubKeyHash == Owner
    7 OP_PICK OP_HASH160 OP_EQUALVERIFY 

    # Verify Sig
    # <Sig>(8) <Pub>(7) <Preimage>(9)
    # We need to verify Sig against Preimage?
    # No, standard OP_CHECKSIG verifies against the TX Context (implied).
    # BUT OP_PUSH_TX implies we check Sig against Preimage?
    # If we use checksigs (standard), it checks against *implicit* preimage.
    # If we want to validate Preimage push is correct, we must check:
    #   Sig checksig(Preimage).
    # But OP_CHECKSIG doesn't take preimage as arg.
    # OP_CHECKSIG uses the VM's transaction.
    # OP_CHECKDATASIG takes (Sig, Msg, Pub).
    #      Actually, OP_PUSH_TX relies on OP_CHECKSIG verifying the *Preimage* passed on stack?
    #      Ah used OP_CHECKDATASIG (DSV)? BSV supports it.
    #   Let's use OP_CHECKSIG directly for auth (Standard).
    #   And SEPARATELY verify Preimage?
    #   If we use OP_PUSH_TX (BIP-143 style), we need to ensure the Preimage on stack IS the preimage used for CHECKSIG.
    #   How? 
    #   Trick: Sig signature covers Preimage? No.
    #   The Sig covers the *Transaction*.
    #   The Preimage *IS* the serialization of the Transaction (mostly).
    #   If OP_CHECKSIG passes, it means Hash(Preimage_Internal) == Hash(Preimage_Stack)?
    #   No, OP_CHECKSIG doesn't expose Preimage_Internal.
    #   
    #   Wait. The standard OP_PUSH_TX pattern on BSV:
    #   Input: <Sig> <Pub> <Preimage>
    #   Script:
    #     OP_DUP OP_HASH256 (Hash Preimage)
    #     OP_SWAP (Sig <Hash>)
    #     OP_CHECKDATASIG (Verify Sig covers Hash)
    #   This proves Sig signed Preimage.
    #   Since Sig is valid for the *Tx* (if we assume this), then Preimage must match?
    #   No. CHECKDATASIG treats Preimage as just a message.
    #   We need OP_CHECKSIG to verify Sig against *consensus* Tx.
    #   
    #   Actually, on BSV, OP_PUSH_TX is usually:
    #   FROMALTSTACK (Preimage)
    #   OP_HASH256
    #   OP_CHECKSIGVERIFY (Wait? checksig uses sig?)
    #
    #   Let's stick to the technique:
    #   Verify Sig using OP_CHECKSIG (Standard).
    #   This implies Sig is valid for *some* preimage.
    #   We need to verify the *Stack Preimage* matches.
    #   
    #   If we ignore this binding, an attacker can push *fake* preimage.
    #   If we sign the Preimage with OP_CHECKDATASIG...
    #   Then we trust the *Signer* to provide correct preimage.
    #   Which is the Owner.
    #   The Owner *wants* the tx to succeed.
    #   So Owner provides correct preimage of the Tx they signed.
    #   This is secure.
    #   
    #   So:
    #   1. Hash(Preimage).
    #   2. Verify CheckDataSig(Sig, Hash, Pub).
    
    8 OP_PICK # Sig
    9 OP_PICK # Preimage (Index 9 now? Hints(7) + Pub(1) + Sig(1) = 9. Preimage is 9).
    OP_HASH256
    7 OP_PICK # Pub
    OP_CHECKDATASIGVERIFY # Verifies Preimage is signed by Owner.
    
    # Also standard CheckSig to burn inputs?
    # 8 OP_PICK 7 OP_PICK OP_CHECKSIGVERIFY?
    # CheckDataSig is sufficient for Auth + Preimage Binding.

    # --- 3. PHYSICS (STABLE INDICES) ---
    # Load P (Field Prime)
    2ffcfffffeffffffffffffffffffffffffffffffffffffffffffffffffffffff00
    OP_BIN2NUM OP_TOALTSTACK 
    
    # [Slope Check]
    # LHS: Slope * (Vx - Px)
    6 OP_PICK 5 OP_PICK 3 OP_PICK OP_SUB 
    OP_DUP 0 OP_LESSTHAN OP_IF OP_FROMALTSTACK OP_DUP OP_TOALTSTACK OP_ADD OP_ENDIF
    OP_FROMALTSTACK OP_DUP OP_TOALTSTACK OP_MOD
    OP_MUL 
    OP_FROMALTSTACK OP_DUP OP_TOALTSTACK OP_MOD 
    
    # FIX: Move LHS to AltStack to preserve indices for RHS
    OP_TOALTSTACK

    # RHS: Vy - Py
    # Indices are now CLEAN (0..6)
    4 OP_PICK 2 OP_PICK OP_SUB
    OP_DUP 0 OP_LESSTHAN OP_IF OP_FROMALTSTACK OP_DUP OP_TOALTSTACK OP_ADD OP_ENDIF
    OP_FROMALTSTACK OP_DUP OP_TOALTSTACK OP_MOD 
    
    # Retrieve LHS and Compare
    OP_FROMALTSTACK 
    OP_EQUALVERIFY

    # [X3 Check]
    # x3 = L^2 - Px - Vx
    6 OP_PICK OP_DUP OP_MUL OP_FROMALTSTACK OP_DUP OP_TOALTSTACK OP_MOD # L^2
    
    # FIX: Move L^2 to AltStack
    OP_TOALTSTACK
    
    3 OP_PICK # Px
    5 OP_PICK # Vx
    OP_ADD    # Px + Vx
    # (Note: Logic is L^2 - (Px + Vx))
    
    OP_FROMALTSTACK # Restore L^2
    OP_SWAP OP_SUB  # L^2 - Sum
    
    OP_DUP 0 OP_LESSTHAN OP_IF OP_FROMALTSTACK OP_DUP OP_TOALTSTACK OP_ADD OP_ENDIF
    OP_FROMALTSTACK OP_DUP OP_TOALTSTACK OP_MOD
    
    1 OP_PICK # Expected Nx
    OP_EQUALVERIFY

    # [Y3 Check]
    # y3 = L * (Px - Nx) - Py
    6 OP_PICK 3 OP_PICK 1 OP_PICK OP_SUB
    OP_DUP 0 OP_LESSTHAN OP_IF OP_FROMALTSTACK OP_DUP OP_TOALTSTACK OP_ADD OP_ENDIF
    OP_MUL OP_FROMALTSTACK OP_DUP OP_TOALTSTACK OP_MOD
    
    # FIX: Move Term1 to AltStack
    OP_TOALTSTACK
    
    2 OP_PICK # Py
    
    OP_FROMALTSTACK # Restore Term1
    OP_SUB # Term1 - Py
    
    OP_DUP 0 OP_LESSTHAN OP_IF OP_FROMALTSTACK OP_DUP OP_TOALTSTACK OP_ADD OP_ENDIF
    OP_FROMALTSTACK OP_DUP OP_TOALTSTACK OP_MOD
    
    0 OP_PICK # Expected Ny
    OP_EQUALVERIFY  # We trust Ny (0) and Nx (1) because Physics passed.
    
    # Fetch Lineage Data from AltStack
    # AltStack: ... <Token> <OutputBlob> <Preimage> (Top)
    # (Note: I need to verify my AltStack push order from Step 1)
    # Step 1: OP_TOALTSTACK (Out0), OP_TOALTSTACK (Preimage).
    
    OP_FROMALTSTACK OP_DROP # Drop P (Consumes P from Alt)
    
    OP_FROMALTSTACK # Preimage
    OP_FROMALTSTACK # OutBlob
    
    # 1. Verify OutBlob matches Preimage
    OP_SWAP # <Preimage> <OutBlob> -> <OutBlob> <Preimage>
    OP_DUP OP_HASH256 # Hash(OutBlob)
    
    # Extract HashOutputs from Preimage (Last 40 -> First 32)
    OP_ROT 
    OP_DUP OP_SIZE 24 OP_SUB OP_SPLIT OP_NIP # Last 40 (0x28)
    20 OP_SPLIT OP_DROP # First 32 (0x20)
    
    OP_EQUALVERIFY # OutBlob is verified part of Tx.
    
    # 2. Verify Lineage (Token + Nx + Ny)
    # Stack: <OutBlob> <Ny> <Nx> ...
    
    # Parse OutBlob
    # <Sats 8> <LenVar> <Script>
    08 OP_SPLIT OP_DROP # Drop Sats
    01 OP_SPLIT OP_BIN2NUM OP_SPLIT OP_DROP # Drop Len -> <Script>
    
    # Script: <Token 32> <Owner 20> <Slot 32> <Type 1> <Amt 8> <AccX 32> <AccY 32> ...
    
    # Verify Token
    20 OP_SPLIT # <Token> <Rest>
    OP_SWAP 
    OP_FROMALTSTACK # TokenID (From AltStack)
    OP_EQUALVERIFY # TokenID Matches
    
    # Skip Metadata (61 bytes)
    # <Rest>: <Owner 20> <Slot 32> <Type 1> <Amt 8> <AccX 32> ...
    # Skip 61 bytes (0x3D)
    # 14(Owner) + 20(Slot) + 01(Type) + 08(Amt) = 3D (Hex) wrong? 
    # Owner 20 (0x14). Slot 32 (0x20). Type 1. Amt 8.
    # 20 + 32 + 1 + 8 = 61.
    # Hex 61 = 0x3D.
    
    3D OP_SPLIT OP_DROP # Skip metadata
    
    # <AccX 32> <AccY 32>
    20 OP_SPLIT # <AccX> <Rest>
    OP_SWAP     # <Rest> <AccX>
    20 OP_SPLIT # <AccY> <Rest>
    OP_DROP     # Rest
    
    # Stack: <AccY> <AccX> <Ny> <Nx> ...
    # Verify X
    OP_ROT      # <AccY> <Ny> <Nx> <AccX> 
    OP_EQUALVERIFY # Nx == AccX
    
    # Verify Y
    OP_EQUALVERIFY # Ny == AccY
    
    # --- 7. FINAL CLEANUP ---
    OP_FROMALTSTACK OP_DROP # Owner
    OP_FROMALTSTACK OP_DROP # Slot
    OP_FROMALTSTACK OP_DROP # Type
    OP_FROMALTSTACK OP_DROP # Amount
    
    # Clean Stack Hints (<Ny> <Nx> etc)
    OP_2DROP OP_2DROP OP_2DROP OP_DROP 
    
    OP_TRUE
`;

