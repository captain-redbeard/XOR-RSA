package com.captainredbeard.xor;

import java.math.BigInteger;

/**
 * RSA public key.
 *
 * @author captain-redbeard
 * @version 1.00
 * @since 29/12/16
 */
public class PublicKey {
    public BigInteger publicExponent;
    public BigInteger modulus;
    private OAEP oaep;

    public PublicKey(BigInteger publicExponent, BigInteger modulus) {
        this.publicExponent = publicExponent;
        this.modulus = modulus;
        this.oaep = new OAEP();
    }

    /**
     * Encode the message with padding.
     *
     * @param m - message to encode
     * @return BigInteger
     */
    public BigInteger encode(BigInteger m) {
        BigInteger c = encodeRaw(
                new BigInteger(
                        oaep.addPadding(
                                m.toByteArray(),
                                256
                        )
                )
        );

        return c;
    }

    /**
     * Encode the message.
     * C = M to the power of E mod N
     *
     * NOTE: Calling this method directly will result
     * in a non padded message, which is insecure.
     *
     * @param m - Message
     * @return BigInteger
     */
    public BigInteger encodeRaw(BigInteger m) {
        return m.modPow(publicExponent, modulus);
    }

    /**
     * Verify the signature.
     *
     * @param s - Signature
     * @param m - Decoded message
     * @return boolean
     */
    public boolean verify(BigInteger s, BigInteger m) {
        s = encodeRaw(s);

        return s.equals(
                new BigInteger(
                        Digest.getDigest(
                                m.toByteArray(),
                                null
                        )
                )
        );
    }

}
