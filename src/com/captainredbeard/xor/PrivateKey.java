package com.captainredbeard.xor;

import java.math.BigInteger;

/**
 * RSA private key.
 *
 * @author captain-redbeard
 * @version 1.00
 * @since 29/12/16
 */
public class PrivateKey {
    public BigInteger modulus;
    public BigInteger publicExponent;
    public BigInteger privateExponent;
    private BigInteger p;
    private BigInteger q;
    private BigInteger dp;
    private BigInteger dq;
    private BigInteger qinv;
    private int keyLen;
    private OAEP oaep;

    /**
     * Construct a private key.
     *
     * @param modulus - modulus p * q
     * @param publicExponent - public exponent, e
     * @param privateExponent - private exponent, d
     * @param p - first prime number
     * @param q - second prime number
     * @param dp - d mod p-1
     * @param dq - d mod q-1
     * @param qinv inverse of q mod p
     * @param oaep - OAEP object
     */
    public PrivateKey(
            BigInteger modulus,
            BigInteger publicExponent,
            BigInteger privateExponent,
            BigInteger p,
            BigInteger q,
            BigInteger dp,
            BigInteger dq,
            BigInteger qinv,
            OAEP oaep) {
        this.modulus = modulus;
        this.publicExponent = publicExponent;
        this.privateExponent = privateExponent;
        this.p = p;
        this.q = q;
        this.dp = dp;
        this.dq = dq;
        this.qinv = qinv;
        this.keyLen = (int) Math.ceil(modulus.bitLength() / 8);
        this.oaep = oaep;
    }

    /**
     * Decode the cipher using CRT.
     * Expects cipher to be padded using OAEP.
     *
     * @param c - cipher text.
     * @return BigInteger
     */
    public BigInteger decode(BigInteger c) {
        return new BigInteger(
                oaep.removePadding(
                        decodeCRT(c).toByteArray(),
                        keyLen
                )
        );
    }

    /**
     * Sign a message to create a signature.
     * Uses CRT.
     *
     * @param m - message to sign
     * @return BigInteger
     */
    public BigInteger sign(BigInteger m) {
        return signCRT(m);
    }

    /**
     * Decode the cipher.
     * M = C to the power of D mod N
     *
     * NOTE: Calling this method directly will not
     * remove any padding.
     *
     *
     * @param c - Cipher text
     * @return BigInteger
     */
    public BigInteger decodeRaw(BigInteger c) {
        return c.modPow(privateExponent, modulus);
    }

    /**
     * Decode the cipher using CRT.
     *
     * @param c - cipher text
     * @return BigInteger
     */
    public BigInteger decodeCRT(BigInteger c) {
        BigInteger m1 = c.modPow(dp, p);
        BigInteger m2 = c.modPow(dq, q);
        BigInteger h = m1.subtract(m2).multiply(qinv).mod(p);
        BigInteger m = m2.add(q.multiply(h));

        return m;
    }

    /**
     * Sign a message to create a signature.
     *
     * @param m - message to sign
     * @return BigInteger
     */
    public BigInteger signRaw(BigInteger m) {
        return decodeRaw(
                new BigInteger(
                        Digest.getDigest(
                                m.toByteArray(),
                                null,
                                oaep.hLen
                        )
                )
        );
    }

    /**
     * Sign a message to create a signature using CRT.
     *
     * @param m - message to sign
     * @return BigInteger
     */
    public BigInteger signCRT(BigInteger m) {
        return decodeCRT(
                new BigInteger(
                        Digest.getDigest(
                                m.toByteArray(),
                                null,
                                oaep.hLen
                        )
                )
        );
    }

}
