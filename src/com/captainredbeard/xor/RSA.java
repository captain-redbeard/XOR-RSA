package com.captainredbeard.xor;

import java.math.BigInteger;
import java.security.InvalidKeyException;
import java.security.SecureRandom;

/**
 * RSA implementation.
 *
 * @author captain-redbeard
 * @version 1.00
 * @since 29/12/16
 */
public class RSA {
    public final int MIN_KEY_LENGTH = 2048;
    private BigInteger e;
    private SecureRandom random;
    private OAEP oaep;

    public RSA() {
        this(null, null);
    }

    /**
     * Construct RSA with specified random and exponent.
     *
     * @param random - secure random implementation
     * @param e - exponent
     */
    public RSA(SecureRandom random, BigInteger e) {
        //Set secure random
        if(random != null) {
            this.random = random;
        } else {
            this.random = new SecureRandom();
        }

        //Set exponent
        if(e != null) {
            this.e = e;
        } else {
            this.e = new BigInteger("65537");
        }

        this.oaep = new OAEP(this.random, null, 64);
    }

    /**
     * Generate a keypair.
     *
     * @param keyLength - desired key length
     * @return Keypair
     * @throws InvalidKeyException
     */
    public Keypair generateKeypair(int keyLength) throws InvalidKeyException {
        if (keyLength < MIN_KEY_LENGTH) {
            throw new InvalidKeyException();
        }

        //Get two prime numbers
        BigInteger p = BigInteger.probablePrime((keyLength / 2) + 2 + random.nextInt(64), random);
        BigInteger q = BigInteger.probablePrime((keyLength / 2), random);

        //Calculate modulus
        BigInteger n = p.multiply(q);

        //Calculate PHI
        BigInteger phi = p.subtract(BigInteger.ONE).multiply(q.subtract(BigInteger.ONE));

        //Calculate PHI of modulus
        BigInteger phiOfN = phi.mod(n);

        //Calculate inverse of E mod PHI
        BigInteger d = e.modInverse(phi);

        //Check if phi gcd(e) > 1
        if (phi.gcd(e).intValue() > 1) {
            System.out.println("phi.gcd(e) > 1");
            throw new InvalidKeyException();
        }

        //Check if 1 < e
        if (e.compareTo(BigInteger.ONE) != 1) {
            System.out.println("1 !< e");
            throw new InvalidKeyException();
        }

        //Check if e < phiOfN
        if (e.compareTo(phiOfN) != -1) {
            System.out.println("e !< phiOfN");
            throw new InvalidKeyException();
        }

        //Check if private key is correct
        if (!d.multiply(e).mod(phiOfN).equals(BigInteger.ONE)) {
            System.out.println("Private key is invalid.");
            throw new InvalidKeyException();
        }

        //Check if public key is valid
        if (!e.gcd(phiOfN).equals(BigInteger.ONE)) {
            System.out.println("Public key is invalid.");
            throw new InvalidKeyException();
        }

        BigInteger dp = d.mod(p.subtract(BigInteger.ONE));
        BigInteger dq = d.mod(q.subtract(BigInteger.ONE));
        BigInteger qinv = q.modInverse(p);

        //Return keypair
        return new Keypair(n, e, d, p, q, dp, dq, qinv, oaep);
    }

    /**
     * Wrapper method to encrypt with public key.
     *
     * @param message - message to encrypt
     * @param k - public key
     * @return String
     */
    public String encrypt(String message, PublicKey k) {
        return new String(k.encode(new BigInteger(message.getBytes())).toByteArray());
    }

    /**
     * Wrapper method to decrypt with private key.
     *
     * @param cipher - cipher to decrypt
     * @param k - private key
     * @return String
     */
    public String decrypt(String cipher, PrivateKey k) {
        return new String(k.decode(new BigInteger(cipher.getBytes())).toByteArray());
    }

    /**
     * Wrapper method to add padding.
     *
     * @param data - data to pad
     * @param keyLen - key length
     * @return byte[]
     */
    public byte[] addPadding(byte[] data, int keyLen) {
        return oaep.addPadding(data, keyLen);
    }

    /**
     * Wrapper method to remove padding.
     *
     * @param data - data to remove padding from
     * @param keyLen - key length
     * @return byte[]
     */
    public byte[] removePadding(byte[] data, int keyLen) {
        return oaep.removePadding(data, keyLen);
    }

}
