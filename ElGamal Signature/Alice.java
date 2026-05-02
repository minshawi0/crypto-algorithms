import java.io.*;
import java.math.BigInteger;
import java.net.*;

/**
 * Alice: The RECEIVER / VERIFIER
 * - Receives public parameters (p, alpha, beta) from Bob
 * - Receives signed message (x, (r, s)) from Bob
 * - Verifies the signature:
 *       t  = beta^r * r^s  mod p
 *       t' = alpha^x        mod p
 *       valid if  t == t'
 *
 * From the assignment example:
 *   t  = 7^3 * 3^26 mod 29 = 22
 *   t' = 2^26       mod 29 = 22
 *   t == t'  =>  valid signature
 */
public class Alice {

    private static final String BOB_HOST = "localhost";
    private static final int    BOB_PORT  = 5000;

    public static void main(String[] args) throws Exception {

        System.out.println("============================================");
        System.out.println("         ALICE  (Receiver / Verifier)       ");
        System.out.println("============================================");

        System.out.println("[Alice] Connecting to Bob at " + BOB_HOST + ":" + BOB_PORT + " ...");

        try (Socket socket      = new Socket(BOB_HOST, BOB_PORT);
             BufferedReader in  = new BufferedReader(
                 new InputStreamReader(socket.getInputStream()))) {

            // ── Step 1: Read public parameters + signed message ───────────
            BigInteger p     = new BigInteger(in.readLine().trim());
            BigInteger alpha = new BigInteger(in.readLine().trim());
            BigInteger beta  = new BigInteger(in.readLine().trim());
            BigInteger x     = new BigInteger(in.readLine().trim());
            BigInteger r     = new BigInteger(in.readLine().trim());
            BigInteger s     = new BigInteger(in.readLine().trim());

            System.out.println("\n[Alice] Received:");
            System.out.println("        Public params  (p, alpha, beta) = ("
                               + p + ", " + alpha + ", " + beta + ")");
            System.out.println("        Signed message (x, (r, s))      = ("
                               + x + ", (" + r + ", " + s + "))");

            // ── Step 2: Verify signature ───────────────────────────────────
            System.out.println("\n[Alice] Verifying signature ...");

            // t = beta^r * r^s mod p
            BigInteger betaR = beta.modPow(r, p);
            BigInteger rS    = r.modPow(s, p);
            BigInteger t     = betaR.multiply(rS).mod(p);
            System.out.println("        beta^r mod p = " + betaR);
            System.out.println("        r^s    mod p = " + rS);
            System.out.println("        t  = beta^r * r^s mod p = " + t);

            // t' = alpha^x mod p
            BigInteger tPrime = alpha.modPow(x, p);
            System.out.println("        t' = alpha^x     mod p = " + tPrime);

            // ── Step 3: Decision ───────────────────────────────────────────
            System.out.println("\n============================================");
            if (t.equals(tPrime)) {
                System.out.println("  RESULT:  t == t'  =>  VALID SIGNATURE");
            } else {
                System.out.println("  RESULT:  t != t'  =>  INVALID SIGNATURE");
            }
            System.out.println("============================================");
        }

        System.out.println("\n[Alice] Done.");
    }
}