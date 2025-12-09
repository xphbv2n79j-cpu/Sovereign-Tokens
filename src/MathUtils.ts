
import { Point as SecpPoint, etc } from '@noble/secp256k1';
import { createHash } from 'crypto';
import { Buffer } from 'buffer'; // Explicit import for safety

// secp256k1 Field Prime P
// Defined in noble as etc.P? No, hardcode safely or inspect.
// P = 2^256 - 2^32 - 977
const P = 0xfffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2fn;

export interface Point {
    x: bigint;
    y: bigint;
}

export class CurveMath {
    /**
     * Point Addition using @noble/secp256k1 Point class
     */
    static add(p1: Point, p2: Point): Point {
        // Convert input Affine (x, y) to Projective (x, y, 1) generic Point
        // Handle Point at Infinity (0, 0) -> Point.ZERO
        const pt1 = (p1.x === 0n && p1.y === 0n) ? SecpPoint.ZERO : new SecpPoint(p1.x, p1.y, 1n);
        const pt2 = (p2.x === 0n && p2.y === 0n) ? SecpPoint.ZERO : new SecpPoint(p2.x, p2.y, 1n);

        const res = pt1.add(pt2);
        const aff = res.toAffine(); // Returns { x: bigint, y: bigint }
        return { x: aff.x, y: aff.y };
    }

    /**
     * Point Doubling
     */
    static double(p: Point): Point {
        const pt = (p.x === 0n && p.y === 0n) ? SecpPoint.ZERO : new SecpPoint(p.x, p.y, 1n);
        const res = pt.double();
        const aff = res.toAffine();
        return { x: aff.x, y: aff.y };
    }

    /**
     * Scalar Multiplication
     */
    static multiply(p: Point, scalar: bigint): Point {
        const pt = (p.x === 0n && p.y === 0n) ? SecpPoint.ZERO : new SecpPoint(p.x, p.y, 1n);
        const res = pt.multiply(scalar);
        const aff = res.toAffine();
        return { x: aff.x, y: aff.y };
    }

    /**
     * Derives a Point from a Token ID using Try-and-Increment
     * Uses Node's synchronous crypto module for hashing.
     */
    static hashToCurve(tokenId: string | Uint8Array): { point: Point, counter: number } {
        // Ensure idBytes is a proper Buffer
        const idBytes = typeof tokenId === 'string'
            ? Buffer.from(tokenId, 'hex')
            : Buffer.isBuffer(tokenId) ? tokenId : Buffer.from(tokenId);

        let counter = 0;
        while (counter < 256) {
            // Hash(ID || counter)
            const countBuf = Buffer.alloc(4);
            countBuf.writeUInt32BE(counter, 0);

            const seed = Buffer.concat([idBytes, countBuf]);
            const hash = createHash('sha256').update(seed).digest();

            const x = BigInt('0x' + hash.toString('hex'));

            // Check if X is valid on curve: y^2 = x^3 + 7
            try {
                // Noble Point.fromAffine typically validates.
                // But we don't know Y yet.
                // We calculate RHS = x^3 + 7
                const rhs = etc.mod(x * x * x + 7n, P);

                // Modular Sqrt to find Y
                // Noble exposes etc.invert, but maybe not sqrt?
                // Wait, if sqrt is not exposed, we must implement Tonelli-Shanks?
                // Actually `SecpPoint.fromHex` handles decompression.
                // We can construct a compressed pubkey check?
                // 02 + X (Compressed).

                const prefix = new Uint8Array([0x02]); // Try even Y
                // Convert X to 32-byte BE
                const xBytes = Buffer.alloc(32);
                // BigInt to Buffer... noble has numberToBytesBE
                const xb = etc.numberToBytesBE(x, 32);
                xBytes.set(xb);

                const compressed = Buffer.concat([prefix, xBytes]);

                // Try fromHex with hex string for maximum compatibility
                const pt = SecpPoint.fromHex(compressed.toString('hex'));
                // If this succeeds, X is valid.

                const aff = pt.toAffine();
                return {
                    point: { x: aff.x, y: aff.y },
                    counter: counter
                };
            } catch (e: any) {
                // Invalid X
                if (counter < 2) console.log(`[DEBUG] Attempt ${counter} failed. X=${x.toString(16).substring(0, 8)}... Error: ${e.message}`);
            }
            counter++;
        }
        throw new Error("Failed to map ID to Curve. Last error logged.");
    }

    /**
     * Computes the Slope (Lambda) for P1 -> P2
     * Using noble.etc for modular arithmetic robustness.
     */
    static calculateSlope(p1: Point, p2: Point): bigint {
        // etc.mod ensures result is always positive [0, P)

        if (p1.x === p2.x && p1.y === p2.y) {
            // Doubling: (3x^2) / (2y)
            const num = etc.mod(3n * p1.x * p1.x, P);
            const den = etc.mod(2n * p1.y, P);
            return etc.mod(num * etc.invert(den, P), P);
        }

        // Addition: (y2 - y1) / (x2 - x1)
        // Noble etc.mod handles negative inputs correctly?
        // Usually mod(a, n) handles negatives.

        const dy = p2.y - p1.y;
        const dx = p2.x - p1.x;

        // Ensure positive before invert?
        // let's wrap logic
        const dy_m = etc.mod(dy, P);
        const dx_m = etc.mod(dx, P);

        // invert(dx)
        const invDx = etc.invert(dx_m, P);

        return etc.mod(dy_m * invDx, P);
    }
}
