/*
 * Paillier Cryptosystem
 * 
 * References:
 * Paillier cryptosystem from Wikipedia. 
 * URL:<ahref="http://en.wikipedia.org/wiki/Paillier_cryptosystem">http://en.wikipedia.org/wiki/Paillier_cryptosystem</a>
 * 
 */
package jpailliercrypto;

import java.math.BigInteger;
import java.util.Random;

/**
 *
 * @author James Ren
 */
public class Paillier {

    int bitLength = 256;
    // p and q are two random primes. 
    // lambda = lcm(p-1, q-1).
    // n = p * q.
    // nsqr = n * n. 
    private BigInteger p, q, lambda;
    // a random BigInteger in Z*_{n^2} where gcd (L(g^lambda mod n^2), n) = 1.
    private BigInteger g;
    // public key
    public BigInteger n, nsqr;

    public BigInteger genCoPrime(BigInteger m) {
        boolean done = false;
        BigInteger result = null;

        while (!done) {
            result = BigInteger.probablePrime(this.bitLength, new Random());
            //Console.WriteLine(result.ToString(16));

            // gcd test
            BigInteger gcd = result.gcd(m);
            if (gcd.compareTo(BigInteger.ONE) == 0) {
                done = true;
            }
        }
        return result;
    }

    private BigInteger lcm(BigInteger p1, BigInteger q1) {
        BigInteger result = null;
        BigInteger gcd = p1.gcd(q1);

        result = p1.abs().divide(gcd);
        result = result.multiply(q1.abs());

        return result;
    }

    public Paillier() {
        KeyGeneration();
    }

    /**
     * Sets up the public key and private key.
     */
    public final void KeyGeneration() {
        // Generates two positive BigIntegers that are probably prime with 256-bit.
        this.p = BigInteger.probablePrime(bitLength, new Random());
        this.q = BigInteger.probablePrime(bitLength, new Random());
        //public key
        this.n = this.p.multiply(this.q);
        this.nsqr = this.n.multiply(this.n);
        //If using p,q of equivalent length, 
        //then  g = n + 1.        
        this.g = this.n.add(BigInteger.ONE);
        //private key
        this.lambda = this.lcm(this.p.subtract(BigInteger.ONE), this.q.subtract(BigInteger.ONE));
    }

    /**
     * Encrypts plaintext m. Ciphertext em = g^m * r^n mod n^2.
     *
     * @param m The plaintext.
     * @return ciphertext em.
     */
    public final BigInteger encrypt(BigInteger m) {
        BigInteger result = g.modPow(m, nsqr);
        BigInteger r = genCoPrime(m);
        result = result.multiply(r.modPow(n, nsqr));
        result = result.mod(nsqr);
        return result;
    }

    /**
     * Decrypts Ciphertext em. Plaintext m = L(c^lambda mod n^2) * u mod n where
     * u = (L(g^lambda mod n^2))^(-1) mod n.
     *
     * @param em ciphertext.
     * @return plaintext m,
     */
    public final BigInteger decrypt(BigInteger em) {
        BigInteger u = this.g.modPow(this.lambda, this.nsqr).subtract(BigInteger.ONE).divide(this.n).modInverse(this.n);
        BigInteger m = em.modPow(lambda, nsqr).subtract(BigInteger.ONE).divide(n).multiply(u).mod(n);
        return m;
    }

    /**
     * @param args the command line arguments
     */
    public static void main(String[] args) {
        System.out.println("=================================== Paillier cryptosystem in Java Test =================================== ");
        BigInteger m1 = BigInteger.valueOf(1981);
        BigInteger m2 = BigInteger.valueOf(1983);
        Paillier paillier = new Paillier();
        // Encryption
        BigInteger em1 = paillier.encrypt(m1);
        BigInteger em2 = paillier.encrypt(m2);
        System.out.println("Encrypted message em1 = " + em1.toString());
        System.out.println("Encrypted message em2 = " + em2.toString());
        // Homomorphic properties: D(E(m1)*E(m3) mod n^2) = (m1 + m3) mod n
        System.out.println("===================== Homomorphic properties: Homomorphic addition of plaintexts =====================");
        BigInteger em1em2 = em1.multiply(em2).mod(paillier.nsqr);
        BigInteger m1m2 = m1.add(m2).mod(paillier.n);
        System.out.println("Sum of m1 and m2 = " + m1m2.toString());
        System.out.println("Sum of em1 and em2 = " + paillier.decrypt(em1em2).toString());
         // Homomorphic properties: D(E(m1)^m2 mod n^2) = (m1*m2) mod n
        System.out.println("===================== Homomorphic properties: Homomorphic multiplication of plaintexts =====================");
        BigInteger em1m2 = em1.modPow(m2, paillier.nsqr);
        BigInteger m1xm2 = m1.multiply(m2).mod(paillier.n);
        System.out.println("Multiplication of m1 and m2 = " + m1xm2.toString());
        System.out.println("Multiplication of em1 and m2 = " + paillier.decrypt(em1m2).toString());
        System.out.println("================================================== The End ================================================== ");
    }

}
