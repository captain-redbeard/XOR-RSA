package com.captainredbeard.xor;

import java.security.MessageDigest;
import java.util.Arrays;

/**
 * @author captain-redbeard
 * @version 1.00
 * @since 29/12/16
 */
public class Digest {

    /**
     * Get message digest for the specified input.
     *
     * @param m - data to get digest of
     * @param algorithm - algorithm to use, default SHA-512
     * @param length - length of returned digest, must be less than or equal to max length
     * @return byte[]
     */
    public static byte[] getDigest(byte[] m, String algorithm, int length) {
        if(algorithm == null) {
            algorithm = "SHA-512";
        }

        byte[] hash;

        try {
            MessageDigest digest = MessageDigest.getInstance(algorithm);
            hash = digest.digest(m);
        } catch (Exception e) {
            e.printStackTrace();
            return new byte[0];
        }

        return Arrays.copyOfRange(hash, 0, length);
    }
}
