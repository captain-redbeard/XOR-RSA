package tests;

import com.captainredbeard.xor.*;

import java.math.BigInteger;
import java.security.InvalidKeyException;

/**
 * @author captain-redbeard
 * @version 1.00
 * @since 29/12/16
 */
public class TestRSA {
    private static int success;
    private static int failed;

    public static void main(String[] args) {
        final int tests = 1;
        final int subTests = 10;
        final boolean debug = true;

        for (int i = 0; i < tests; i++) {
            test(subTests, debug);
        }

        System.out.println();
        System.out.println("-- Test Results --");
        System.out.println("Tests ran: \t\t" + (tests * subTests));
        System.out.println("Failed: \t\t" + failed);
        System.out.println("Success: \t\t" + success);
        System.out.println("Overall pass: \t" + (success == (tests * subTests)));
    }

    public static void test(int subTests, boolean debug) {
        RSA rsa = new RSA();
        Keypair keypair = null;

        try {
            keypair = rsa.generateKeypair(rsa.MIN_KEY_LENGTH);
        } catch (InvalidKeyException e1) {
            e1.printStackTrace();
        }

        if(keypair != null) {
            long startEncode, endEncode, startDecode, endDecode, startSign, endSign;

            //Get public and private key
            PublicKey publicKey = keypair.getPublicKey();
            PrivateKey privateKey = keypair.getPrivateKey();

            //Assign message
            String rawMessage = "Hello World! " +
                    "ABCDEFGHIJKLMNOPQRSTUVWXYZ " +
                    "abcdefghijklmnopqrstuvwxyz " +
                    "0123456789 " +
                    "`~!@#$%^&*()-_=+[{]}\\|;:'\",<.>/?";
            BigInteger message = new BigInteger(rawMessage.getBytes());

            for (int i = 0; i < subTests; i++) {
                //Encode
                startEncode = System.currentTimeMillis();
                BigInteger cipher = publicKey.encode(message);
                endEncode = System.currentTimeMillis() - startEncode;

                //Decode
                startDecode = System.currentTimeMillis();
                BigInteger decoded = privateKey.decode(cipher);
                endDecode = System.currentTimeMillis() - startDecode;

                //Signature
                startSign = System.currentTimeMillis();
                BigInteger signature = privateKey.sign(message);
                boolean verifySignature = publicKey.verify(signature, decoded);
                endSign = System.currentTimeMillis() - startSign;

                //Sign another message to verify signatures | should fail
                BigInteger testMessage = new BigInteger("Test".getBytes());
                BigInteger testSignature = privateKey.sign(testMessage);
                boolean testVerifySignature = publicKey.verify(testSignature, testMessage);

                //Echo results
                if (debug) {
                    System.out.println("Key length: " + privateKey.modulus.bitLength());
                    System.out.println("Encoded: " + cipher);
                    System.out.println("Encoded length: " + cipher.bitLength());
                    System.out.println("Encoding time: " + endEncode + "ms");
                    System.out.println("Raw Bytes: " + message);
                    System.out.println("Decoded: " + decoded);
                    System.out.println("Decoding time: " + endDecode + "ms");
                    System.out.println("Raw text: " + rawMessage);
                    System.out.println("Decoded text: " + new String(decoded.toByteArray()));
                    System.out.println("Signature: " + signature);
                    System.out.println("Verify Signature: " + verifySignature);
                    System.out.println("Invalid Signature: " + testVerifySignature);
                    System.out.println("Signature sign time: " + endSign + "ms");
                    System.out.println();
                }

                if (rawMessage.equals(new String(decoded.toByteArray()))) {
                    success++;
                } else {
                    failed++;
                }
            }
        } else {
            System.out.println("Failed to create Keypair.");
        }
    }

}
