package com.captainredbeard.xor;

import java.math.BigInteger;

/**
 * Keypair for easier RSA generation.
 *
 * @author captain-redbeard
 * @version 1.00
 * @since 29/12/16
 */
public class Keypair {
    private BigInteger publicKey;
    private BigInteger privateKey;
    private BigInteger modulus;
    private BigInteger p;
    private BigInteger q;
    private BigInteger dp;
    private BigInteger dq;
    private BigInteger qinv;

    /**
     * Construct a keypair.
     *
     * @param publicKey - public exponent, commonly 65537
     * @param privateKey - private exponent, commonly d
     * @param modulus - modulus p * q
     * @param p - first prime number
     * @param q - second prime number
     * @param dp - d mod p-1
     * @param dq - d mod q-1
     * @param qinv q-1 mod p
     */
    public Keypair(
            BigInteger publicKey,
            BigInteger privateKey,
            BigInteger modulus,
            BigInteger p,
            BigInteger q,
            BigInteger dp,
            BigInteger dq,
            BigInteger qinv) {
        this.publicKey = publicKey;
        this.privateKey = privateKey;
        this.modulus = modulus;
        this.p = p;
        this.q = q;
        this.dp = dp;
        this.dq = dq;
        this.qinv = qinv;
    }

    /**
     * Get public key.
     * N, E
     *
     * @return PublicKey
     */
    public PublicKey getPublicKey() {
        return new PublicKey(publicKey, modulus);
    }

    /**
     * Get private key.
     * D, N, P, Q, DP, DQ, QINV
     *
     * @return PrivateKey
     */
    public PrivateKey getPrivateKey() {
        return new PrivateKey(privateKey, modulus, p, q, dp, dq, qinv);
    }

}
