package tests;

import com.captainredbeard.xor.OAEP;

import java.math.BigInteger;

/**
 * @author captain-redbeard
 * @version 1.00
 * @since 30/12/16
 */
public class TestOAEP {
    private static int success;
    private static int failed;

    public static void main(String[] args) throws Exception {
        final int tests = 100;
        final int subTests = 100;
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
        OAEP oaep = new OAEP();
        String rawMessage = "Hello World!";

        for (int i = 0; i < subTests; i++) {
            byte[] encoded = oaep.addPadding(rawMessage.getBytes(), 256);
            byte[] decoded = oaep.removePadding(encoded, 256);

            if (debug) {
                System.out.println();
                System.out.println("Raw: " + rawMessage);
                System.out.println("Encoded: " + new BigInteger(encoded));
                System.out.println("Decoded: " + new String(decoded));
            }

            if (rawMessage.equals(new String(decoded))) {
                success++;
            } else {
                failed++;
            }
        }
    }

}
