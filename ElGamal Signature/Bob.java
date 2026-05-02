import java.io.*;
import java.math.BigInteger;
import java.net.*;

/**
 * Bob: The SENDER
 *
 * Normal flow  (java Bob):
 *   Bob acts as SERVER on port 5000, waits for Alice to connect.
 *
 * Attack flow  (java Bob 5001):
 *   Bob acts as CLIENT, connects to Oscar who is listening on port 5001.
 *   Oscar is pretending to be Alice.
 */
public class Bob {

    private static final BigInteger P     = BigInteger.valueOf(29);
    private static final BigInteger ALPHA = BigInteger.valueOf(2);
    private static final BigInteger D     = BigInteger.valueOf(12);
    private static final BigInteger KE    = BigInteger.valueOf(5);
    private static final BigInteger X     = BigInteger.valueOf(26);

    public static void main(String[] args) throws Exception {

        System.out.println("============================================");
        System.out.println("           BOB  (Sender / Signer)          ");
        System.out.println("============================================");

        // ── Step 1: Compute public key beta = alpha^d mod p ───────────────
        BigInteger beta    = ALPHA.modPow(D, P);
        BigInteger pMinus1 = P.subtract(BigInteger.ONE);

        System.out.println("[Bob] Public parameters:");
        System.out.println("      p     = " + P);
        System.out.println("      alpha = " + ALPHA);
        System.out.println("      d     = " + D + "  (private key)");
        System.out.println("      beta  = alpha^d mod p = " + beta);

        // ── Step 2: Sign message x ────────────────────────────────────────
        BigInteger gcd = KE.gcd(pMinus1);
        System.out.println("\n[Bob] Signing message x = " + X);
        System.out.println("      kE = " + KE + "  (ephemeral key)");
        System.out.println("      gcd(kE, p-1) = " + gcd);
        if (!gcd.equals(BigInteger.ONE)) {
            throw new RuntimeException("gcd(kE, p-1) != 1 — invalid ephemeral key!");
        }

        BigInteger r     = ALPHA.modPow(KE, P);
        BigInteger keInv = KE.modInverse(pMinus1);
        BigInteger s     = X.subtract(D.multiply(r)).multiply(keInv).mod(pMinus1);

        System.out.println("      r = alpha^kE mod p = " + r);
        System.out.println("      kE^-1 mod (p-1) = " + keInv);
        System.out.println("      s = (x - d*r)*kE^-1 mod (p-1) = " + s);
        System.out.println("\n[Bob] Signature = (r=" + r + ", s=" + s + ")");

        // ── Step 3: Send data ─────────────────────────────────────────────
        if (args.length > 0) {
            // ── ATTACK MODE: Bob is a CLIENT connecting to Oscar ──────────
            int oscarPort = Integer.parseInt(args[0]);
            System.out.println("\n[Bob] ATTACK MODE: Connecting to Oscar on port " + oscarPort + " ...");

            try (Socket socket   = new Socket("localhost", oscarPort);
                 PrintWriter out = new PrintWriter(socket.getOutputStream(), true)) {

                out.println(P);
                out.println(ALPHA);
                out.println(beta);
                out.println(X);
                out.println(r);
                out.println(s);

                System.out.println("[Bob] Sent params to Oscar.");
                System.out.println("      (p, alpha, beta) = (" + P + ", " + ALPHA + ", " + beta + ")");
                System.out.println("      (x, (r, s))      = (" + X + ", (" + r + ", " + s + "))");
            }

        } else {
            // ── NORMAL MODE: Bob is a SERVER waiting for Alice ────────────
            int port = 5000;
            System.out.println("\n[Bob] NORMAL MODE: Starting server on port " + port + " ...");
            System.out.println("[Bob] Waiting for Alice to connect ...\n");

            try (ServerSocket serverSocket = new ServerSocket(port);
                 Socket socket             = serverSocket.accept();
                 PrintWriter out           = new PrintWriter(socket.getOutputStream(), true)) {

                System.out.println("[Bob] Alice connected!");

                out.println(P);
                out.println(ALPHA);
                out.println(beta);
                out.println(X);
                out.println(r);
                out.println(s);

                System.out.println("[Bob] Sent to Alice:");
                System.out.println("      (p, alpha, beta) = (" + P + ", " + ALPHA + ", " + beta + ")");
                System.out.println("      (x, (r, s))      = (" + X + ", (" + r + ", " + s + "))");
            }
        }

        System.out.println("\n[Bob] Done.");
    }
}