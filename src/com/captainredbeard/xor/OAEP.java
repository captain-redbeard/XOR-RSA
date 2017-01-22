package com.captainredbeard.xor;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.LinkedList;
import java.util.List;

/**
 * EME-OAEP implementation.
 *
 * @author captain-redbeard
 * @version 1.00
 * @since 30/12/16
 */
public class OAEP {
    private SecureRandom random = new SecureRandom();
    private byte[] separator;
    public int hLen;

    public OAEP() {
        this(null, null, 64);
    }

    /**
     * Construct OAEP with specified random.
     *
     * @param random - secure random
     * @param separator - separator for message
     */
    public OAEP(SecureRandom random, byte[] separator, int hLen) {
        //Set secure random
        if (random != null) {
            this.random = random;
        } else {
            this.random = new SecureRandom();
        }

        //Custom separator
        if (separator != null) {
            this.separator = separator;
        } else {
            this.separator = new byte[]{0x01};
        }

        //Custom hLen
        if (hLen != 64) {
            this.hLen = hLen;
        } else {
            this.hLen = 64;
        }
    }

    /**
     * Add padding to the specified message.
     * This method will loop over the add padding method
     * until we have a padded message that will not be
     * effected by converting to a BigInteger.
     *
     * @param data - data to add padding to
     * @param keyLength - modulus length in bytes
     * @return byte[]
     */
    public byte[] addPadding(byte[] data, int keyLength) {
        byte[] padded = new byte[2];

        while (padded[1] > -1) {
            padded = addPadding(data, "captain-redbeard", keyLength);
        }

        return padded;
    }

    /**
     * Removed padding from the specified encoded message.
     *
     * @param data - encoded message to remove padding from
     * @param keyLength - modulus length in bytes
     * @return byte[]
     */
    public byte[] removePadding(byte[] data, int keyLength) {
        return removePadding(data, "captain-redbeard", keyLength);
    }

    /**
     * Add padding to the specified message.
     *
     * @param M - message to add padding to
     * @param L - label to use for hash
     * @param k - modulus length in bytes
     * @return byte[]
     */
    public byte[] addPadding(byte[] M, String L, int k) {
        int mLen = M.length;
        byte[] DB;

        //Message length check
        if (mLen > k - (2 * hLen) - 1 - separator.length) {
            System.out.println("ERROR: message too long");
            return null;
        }

        //Label length check
        if (L.length() > k - (2 * hLen) - 1 - separator.length) {
            System.out.println("ERROR: label too long");
            return null;
        }

        //lHash = HASH(L);
        byte[] lHash = Digest.getDigest(L.getBytes(), null, hLen);

        //PS = k - mLen - 2hLen - 2
        byte[] PS = new byte[k - mLen - (2 * hLen) - 1 - separator.length];

        //DB = lHash || PS || 0x01 || M;     DB length  = k - hLen - 1;
        ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
        try {
            //Contact byte arrays
            outputStream.write(lHash);
            outputStream.write(PS);
            outputStream.write(separator);
            outputStream.write(M);

            //DB concatenated
            DB = outputStream.toByteArray();

            //Clean up
            outputStream.flush();
            outputStream.close();
        } catch (IOException e) {
            e.printStackTrace();
            return null;
        }

        //Random seed of length hLen
        byte[] seed = new byte[hLen];
        random.nextBytes(seed);

        //dbMask = MGF(seed, k - hLen -1)
        byte[] dbMask = MGF1(seed, k - hLen - 1);

        //maskedDB = DB XOR dbMask
        for (int i = 0; i < k - hLen - 1; i++) {
            DB[i] ^= dbMask[i];
        }

        //seedMask = MGF1(maskedDB, hLen)
        byte[] seedMask = MGF1(DB, hLen);

        //maskedSeed = seed XOR seedMask
        for (int i = 0; i < hLen; i++) {
            seed[i] ^= seedMask[i];
        }

        //EM = 0x00 || maskedSeed || maskedDB;      EM length of k
        byte[] EM;
        outputStream = new ByteArrayOutputStream();

        try {
            outputStream.write(0x00);
            outputStream.write(seed);
            outputStream.write(DB);

            //EM concatenated
            EM = outputStream.toByteArray();

            //Clean up
            outputStream.flush();
            outputStream.close();
        } catch(IOException ee) {
            ee.printStackTrace();
            return null;
        }

        //Return encoded message
        return EM;
    }

    /**
     * Removed padding from the specified encoded message.
     *
     * @param EM - encoded message
     * @param L - label to use for hash
     * @param k - modulus length in bytes
     * @return byte[]
     */
    public byte[] removePadding(byte[] EM, String L, int k) {
        //Separate EM into Y; maskedSeed length of hLen; maskedDB length of k - hLen - 1
        byte[] maskedSeed = new byte[hLen];
        byte[] maskedDB = new byte[k - hLen - 1];
        System.arraycopy(EM, 1, maskedSeed, 0, hLen);
        System.arraycopy(EM, 1 + hLen, maskedDB, 0, k - hLen - 1);

        //seedMask = MGF1(maskedDB, hLen)
        byte[] seedMask = MGF1(maskedDB, hLen);

        //seed = maskedSeed XOR seedMask
        for (int i = 0; i < hLen; i++) {
            maskedSeed[i] ^= seedMask[i];
        }

        //dbMask = MGF1(seed, k - hLen - 1)
        byte[] dbMask = MGF1(maskedSeed, k - hLen - 1);

        //DB = maskedDB XOR dbMask
        for (int i = 0; i < k - hLen - 1; i++) {
            maskedDB[i] ^= dbMask[i];
        }

        //Split to get actual message
        List<byte[]> splitByte = splitByteArray(maskedDB, separator);

        //Return message
        return splitByte.get(splitByte.size() - 1);
    }

    /**
     * @param x - non negative integer to be converted
     * @param xLen - length of result
     * @return byte[]
     */
    private static byte[] I2OSP(BigInteger x, int xLen) {
        byte[] temp = new byte[xLen];
        BigInteger tfs = new BigInteger("256");

        //Check x
        if (x.compareTo(x.pow(xLen)) == 1) {
            System.out.println("ERROR: integer too large");
            return null;
        }

        //x = x xLen–1 256 xLen–1 + x xLen–2 256 xLen–2 + ... + x 1 256 + x 0
        for (int i = 0; i < xLen; i++) {
            temp[i] = x.divideAndRemainder(tfs.pow(xLen - i))[0].byteValue();
        }

        return temp;
    }

    /**
     * @param x - octet string to be converted
     * @return BigInteger
     */
    private static BigInteger OS2IP(byte[] x) {
        BigInteger temp = new BigInteger("0");
        BigInteger tfs = new BigInteger("256");

        //x = x xLen–1 256 xLen–1 + x xLen–2 256 xLen–2 + ... + x 1 256 + x 0
        for (int i = 0; i < x.length; i++) {
            temp = temp.add(BigInteger.valueOf(0xFF & x[i - 1])).multiply(tfs.pow(x.length - i));
        }

        return temp;
    }

    /**
     * Mask generation function.
     *
     * @param mgfSeed - seed to use
     * @param maskLen - returned mask length
     * @return byte[]
     */
    private byte[] MGF1(byte[] mgfSeed, int maskLen) {
        ByteArrayOutputStream seedI2Stream = new ByteArrayOutputStream();
        ByteArrayOutputStream hashStream = new ByteArrayOutputStream();

        //Check mask length
        if (maskLen > Math.pow(2, hLen)) {
            System.out.println("ERROR: mask too long");
            return null;
        }

        for (int i = 0; i < Math.ceil(maskLen / hLen) - 1; i++) {
            try {
                seedI2Stream = new ByteArrayOutputStream();
                seedI2Stream.write(mgfSeed);
                //C = I2OSP(counter, 4)
                seedI2Stream.write(I2OSP(BigInteger.valueOf(i), 4));
                //hash(mgfSeed || C)
                hashStream.write(Digest.getDigest(seedI2Stream.toByteArray(), null, hLen));

                seedI2Stream.flush();
                seedI2Stream.close();
            } catch(Exception e ){
                e.printStackTrace();
            }
        }

        //T = T || Hash (mfgSeed || C)
        byte[] mask = Arrays.copyOfRange(hashStream.toByteArray(), 0, maskLen);

        try {
            seedI2Stream.flush();
            seedI2Stream.close();

            hashStream.flush();
            hashStream.close();
        } catch(Exception e ){
            e.printStackTrace();;
        }

        //Return mask
        return mask;
    }

    /**
     * Split byte array.
     *
     * @param array - array to split
     * @param delimiter - delimiter to use
     * @return List<byte[]>
     */
    private List<byte[]> splitByteArray(byte[] array, byte[] delimiter) {
        List<byte[]> byteArrays = new LinkedList<>();

        if (delimiter.length == 0) {
            return byteArrays;
        }

        int begin = 0;

        outer:
        for (int i = 0; i < array.length - delimiter.length + 1; i++) {
            for (int j = 0; j < delimiter.length; j++) {
                if (array[i + j] != delimiter[j]) {
                    continue outer;
                }
            }

            byteArrays.add(Arrays.copyOfRange(array, begin, i));
            begin = i + delimiter.length;
        }

        byteArrays.add(Arrays.copyOfRange(array, begin, array.length));

        //Return
        return byteArrays;
    }

}
