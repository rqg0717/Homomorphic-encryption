/*
 * Paillier Cryptosystem
 * 
 * References:
 * Paillier cryptosystem from Wikipedia. 
 * URL:<ahref="http://en.wikipedia.org/wiki/Paillier_cryptosystem">http://en.wikipedia.org/wiki/Paillier_cryptosystem</a>
 * 
 */
package jpailliercrypto;

import java.security.SecureRandom;
import java.util.Random;
import java.math.BigInteger;

/**
 *
 * @author James Ren
 */
public class Paillier {

    private Random rnd = null;
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
    
    public BigInteger genCoPrime(BigInteger m, int bits, Random rand)
    {
        boolean done = false;
        BigInteger result = null;

        while (!done)
        {
            result = BigInteger.probablePrime(bitLength, rnd);
            //Console.WriteLine(result.ToString(16));

            // gcd test
            BigInteger gcd = result.gcd(m);
            if (gcd.compareTo(BigInteger.ONE) == 0)
                done = true;
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
    
    public Paillier()
    {
        KeyGeneration();
    }
    
    /**
     * Sets up the public key and private key.
     */
    public void KeyGeneration()
    {
        if (rnd == null) {
            rnd = new SecureRandom();
        }
        // Generates two positive BigIntegers that are probably prime with 256-bit.
        p = BigInteger.probablePrime(bitLength, rnd);
        q = BigInteger.probablePrime(bitLength, rnd);
        //public key
        n = p.multiply(q);
        nsqr = n.multiply(n);
        //If using p,q of equivalent length, 
        //then  g = n + 1.        
        g = n.add(BigInteger.ONE);
        //private key
        lambda = this.lcm(p.subtract(BigInteger.ONE), q.subtract(BigInteger.ONE));
    }
    
    /**
     * Encrypts plaintext m.
     * Ciphertext em = g^m * r^n mod n^2.
     * @param m The plaintext.
     * @return ciphertext em.
     */
    public final BigInteger encrypt(BigInteger m) {

        BigInteger result = g.modPow(m, nsqr);
        BigInteger r = genCoPrime(m,bitLength, new Random());
       
        result = result.multiply(r.modPow(n, nsqr));
        result = result.mod(nsqr);

        return result;
    }
    
    /**
     * @param args the command line arguments
     */
    public static void main(String[] args) {
        
    }
    
}
