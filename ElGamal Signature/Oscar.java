import java.io.*;
import java.math.BigInteger;
import java.net.*;

/**
 * Oscar: The ATTACKER - Existential Forgery Attack Against ElGamal Signature
 *
 * Oscar does NOT know Bob's private key d.
 * He only knows the public key: (p, alpha, beta).
 *
 * Attack steps:
 *   1. Choose integers i, j  where gcd(j, p-1) = 1
 *   2. Compute forged signature:
 *         r = alpha^i * beta^j  mod p
 *         s = -r * j^-1         mod (p-1)
 *   3. Compute the message that matches this forged signature:
 *         x = s * i             mod (p-1)
 *   4. Send (x, (r, s)) to Alice -- Alice's verification will PASS!
 *
 * Architecture:
 *   - Bob   connects to Oscar on port 5001 (Oscar pretends to be Alice)
 *   - Alice connects to Oscar on port 5000 (Oscar pretends to be Bob)
 *
 * How to run:
 *   Terminal 1:  java Oscar
 *   Terminal 2:  java Bob 5001
 *   Terminal 3:  java Alice
 */
public class Oscar {

    // Port Oscar listens on for Bob (pretending to be Alice)
    private static final int BOB_FACING_PORT   = 5001;
    // Port Oscar listens on for Alice (pretending to be Bob)
    private static final int ALICE_FACING_PORT = 5000;

    // Oscar's chosen integers for the forgery (free choice)
    private static final BigInteger I = BigInteger.valueOf(3);
    private static final BigInteger J = BigInteger.valueOf(5);   // gcd(5, 28) = 1

    public static void main(String[] args) throws Exception {

        System.out.println("============================================");
        System.out.println("   OSCAR  (Existential Forgery Attacker)    ");
        System.out.println("============================================");
        System.out.println("[Oscar] Chosen i = " + I + ", j = " + J);
        System.out.println("[Oscar] Step 1: Waiting for Bob on port " + BOB_FACING_PORT + " ...");
        System.out.println("[Oscar] --> Run:  java Bob 5001");

        // ── Phase 1: Receive public key from Bob ───────────────────────────
        BigInteger p, alpha, beta;

        try (ServerSocket bobFacing = new ServerSocket(BOB_FACING_PORT);
             Socket bobSocket       = bobFacing.accept();
             BufferedReader bobIn   = new BufferedReader(
                 new InputStreamReader(bobSocket.getInputStream()))) {

            System.out.println("\n[Oscar] Bob connected! Intercepting transmission ...");

            // Read Bob's full transmission but only keep public params
            p     = new BigInteger(bobIn.readLine().trim());
            alpha = new BigInteger(bobIn.readLine().trim());
            beta  = new BigInteger(bobIn.readLine().trim());
            bobIn.readLine(); // x -- discarded (Oscar does not care)
            bobIn.readLine(); // r -- discarded
            bobIn.readLine(); // s -- discarded

            System.out.println("[Oscar] Intercepted public params:");
            System.out.println("        p     = " + p);
            System.out.println("        alpha = " + alpha);
            System.out.println("        beta  = " + beta);
        }

        BigInteger pMinus1 = p.subtract(BigInteger.ONE);

        // ── Phase 2: Verify gcd(j, p-1) = 1 ──────────────────────────────
        BigInteger gcd = J.gcd(pMinus1);
        System.out.println("\n[Oscar] Checking gcd(j, p-1) = gcd("
                           + J + ", " + pMinus1 + ") = " + gcd);
        if (!gcd.equals(BigInteger.ONE)) {
            throw new RuntimeException("[Oscar] gcd(j, p-1) != 1 -- choose different j!");
        }

        // ── Phase 3: Compute forged (r, s, x) ─────────────────────────────
        System.out.println("\n[Oscar] Step 2: Computing forged signature ...");

        // r = alpha^i * beta^j mod p
        BigInteger alphaI   = alpha.modPow(I, p);
        BigInteger betaJ    = beta.modPow(J, p);
        BigInteger r_forged = alphaI.multiply(betaJ).mod(p);
        System.out.println("        alpha^i mod p = " + alphaI);
        System.out.println("        beta^j  mod p = " + betaJ);
        System.out.println("        r = alpha^i * beta^j mod p = " + r_forged);

        // s = -r * j^-1 mod (p-1)
        BigInteger jInv     = J.modInverse(pMinus1);
        BigInteger s_forged = r_forged.negate().multiply(jInv).mod(pMinus1);
        System.out.println("        j^-1 mod (p-1) = " + jInv);
        System.out.println("        s = -r * j^-1 mod (p-1) = " + s_forged);

        // x = s * i mod (p-1)
        System.out.println("\n[Oscar] Step 3: Computing matching message ...");
        BigInteger x_forged = s_forged.multiply(I).mod(pMinus1);
        System.out.println("        x = s * i mod (p-1) = " + x_forged);

        System.out.println("\n[Oscar] FORGED packet ready:");
        System.out.println("        x      = " + x_forged + "  (fake message)");
        System.out.println("        (r, s) = (" + r_forged + ", " + s_forged + ")");

        // ── Phase 4: Self-check ────────────────────────────────────────────
        BigInteger tCheck = beta.modPow(r_forged, p)
                                .multiply(r_forged.modPow(s_forged, p)).mod(p);
        BigInteger tPrime = alpha.modPow(x_forged, p);
        System.out.println("\n[Oscar] Self-check (Alice's verification formula):");
        System.out.println("        t  = beta^r * r^s mod p = " + tCheck);
        System.out.println("        t' = alpha^x      mod p = " + tPrime);
        System.out.println("        Will Alice be fooled? "
                           + (tCheck.equals(tPrime) ? "YES -- Attack will succeed!" : "NO -- Error!"));

        // ── Phase 5: Wait for Alice and send forged data ───────────────────
        System.out.println("\n[Oscar] Step 4: Waiting for Alice on port "
                           + ALICE_FACING_PORT + " ...");
        System.out.println("[Oscar] --> Run:  java Alice");

        try (ServerSocket aliceFacing = new ServerSocket(ALICE_FACING_PORT);
             Socket aliceSocket       = aliceFacing.accept();
             PrintWriter aliceOut     = new PrintWriter(aliceSocket.getOutputStream(), true)) {

            System.out.println("\n[Oscar] Alice connected! Sending forged data ...");

            // Send same protocol Bob would use: p, alpha, beta, x, r, s
            aliceOut.println(p);
            aliceOut.println(alpha);
            aliceOut.println(beta);
            aliceOut.println(x_forged);
            aliceOut.println(r_forged);
            aliceOut.println(s_forged);

            System.out.println("[Oscar] Forged packet sent to Alice!");
        }

        System.out.println("\n[Oscar] Attack complete!");
        System.out.println("[Oscar] Alice accepted a signature Oscar created without knowing Bob's private key!");
    }
}