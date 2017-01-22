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
    private BigInteger modulus;
    private BigInteger publicExponent;
    private BigInteger privateExponent;
    private BigInteger p;
    private BigInteger q;
    private BigInteger dp;
    private BigInteger dq;
    private BigInteger qinv;
    private OAEP oaep;

    /**
     * Construct a keypair.
     *
     * @param modulus - modulus p * q
     * @param publicExponent - public exponent, e, commonly 65537
     * @param privateExponent - private exponent, d
     * @param p - first prime number
     * @param q - second prime number
     * @param dp - d mod p-1
     * @param dq - d mod q-1
     * @param qinv inverse of q mod p
     * @param oaep - OAEP object
     */
    public Keypair(
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
        this.oaep = oaep;
    }

    /**
     * Get public key.
     * E, N
     *
     * @return PublicKey
     */
    public PublicKey getPublicKey() {
        return new PublicKey(modulus, publicExponent, oaep);
    }

    /**
     * Get private key.
     * N, E, D, P, Q, DP, DQ, QINV
     *
     * @return PrivateKey
     */
    public PrivateKey getPrivateKey() {
        return new PrivateKey(modulus, publicExponent, privateExponent, p, q, dp, dq, qinv, oaep);
    }

}
