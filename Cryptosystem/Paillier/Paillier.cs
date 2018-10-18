/* ============================================================================================
 *
 *  This file is part of the Extensions to the Paillier Cryptosystem with Applications Project
 *
 * ============================================================================================
 * Paillier.cs
 * Created by James Ren
 * Created Date: April 20, 2014
 * ==========================================
 *
 * Copyright (c) 2014, CFL, Temple University.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without modification,
 * are permitted provided that the following conditions are met:
 * Redistributions of source code must retain the above copyright notice, this list
 * of conditions and the following disclaimer.
 * Redistributions in binary form must reproduce the above copyright notice, this
 * list of conditions and the following disclaimer in the documentation and/or other
 * materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS for A PARTICULAR PURPOSE ARE DISCLAIMED.
 * in NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE for ANY DIRECT,
 * INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING,
 * BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA,
 * OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY,
 * WHETHER in CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF this SOFTWARE, EVEN if ADVISED OF THE POSSIBILITY
 * OF SUCH DAMAGE.
 *
 */
using System;
using System.Collections.Generic;
using System.Linq;
using System.Web;


/// <summary>
/// Paillier Cryptosystem
/// 
/// References:
/// Paillier cryptosystem from Wikipedia. URL: <a
/// href="http://en.wikipedia.org/wiki/Paillier_cryptosystem">http://en.wikipedia.org/wiki/Paillier_cryptosystem</a>
/// 
/// </summary>
public class PaillierCryptosys
{
    int bitLength = 256;
    //p and q are two random primes. 
    //lambda = lcm(p-1, q-1).
    //n = p * q.
    //nsqr = n * n. 
    private BigInteger p, q, lambda;
    public BigInteger n, nsqr;

    //a random BigInteger in Z*_{n^2} where gcd (L(g^lambda mod n^2), n) = 1.
    private BigInteger g;


    public PaillierCryptosys()
    {
        KeyGeneration();
    }


    ///Sets up the public key and private key.   
    public void KeyGeneration()
    {
        //Generates two positive BigIntegers that are probably prime with 256-bit.
        p = BigInteger.genPrime();
        q = BigInteger.genPrime();
        //public key
        n = p * q;
        nsqr = n * n;
        //If using p,q of equivalent length, 
        //then  g = n + 1.        
        g = n + 1;
        //private key
        lambda = (p - 1) * (q - 1) / (p - 1).gcd(q - 1);
    }

    ///Encrypts plaintext m. Ciphertext em = g^m * r^n mod n^2.
    ///<param name="m">plaintext</param>
    ///<returns>ciphertext em</returns>
    public BigInteger Encryption(BigInteger m)
    {
        //generates random input r
        BigInteger r = m.genCoPrime(bitLength, new Random());
        BigInteger em = ((g.modPow(m, nsqr)) * (r.modPow(n, nsqr))) % nsqr;
        return em;
    }

    ///Decrypts ciphertext em. Plaintext m = L(c^lambda mod n^2) * u mod n
    ///where u = (L(g^lambda mod n^2))^(-1) mod n.  
    ///<param name="em">ciphertext</param>
    ///<returns>plaintext m</returns>
    public BigInteger Decryption(BigInteger em)
    {
        BigInteger u = ((g.modPow(lambda, nsqr) - 1) / n).modInverse(n);
        BigInteger m = (((em.modPow(lambda, nsqr) - 1) / n) * u) % n;
        return m;
    }

    static void Main(string[] args)
    {
        Console.WriteLine("-= Paillier cryptosystem test =-\n");
        PaillierCryptosys paillier = new PaillierCryptosys();
        //instantiating four plaintext messages
        BigInteger m1 = new BigInteger(2);
        BigInteger m2 = new BigInteger(11);
        BigInteger m3 = new BigInteger(5);
        BigInteger m4 = new BigInteger(13);
        //encryption
        BigInteger em1 = paillier.Encryption(m1);
        BigInteger em2 = paillier.Encryption(m2);
        BigInteger em3 = paillier.Encryption(m3);
        BigInteger em4 = paillier.Encryption(m4);
        //printout encrypted text
        Console.WriteLine("\nencrypted text:");
        Console.WriteLine("\n" + em1);
        Console.WriteLine("\n" + em2);
        Console.WriteLine("\n" + em3);
        Console.WriteLine("\n" + em4);

        //test homomorphic properties: D(E(m1)*E(m3) mod n^2) = (m1 + m3) mod n
        Console.WriteLine("\n-= Homomorphic properties: Homomorphic addition of plaintexts =-\n");
        BigInteger em1xem3 = (em1 * em3) % paillier.nsqr;
        BigInteger m1m3 = (m1 + m3) % paillier.n;
        Console.WriteLine("\noriginal sum:" + Convert.ToString(m1m3));
        Console.WriteLine("\ndecrypted sum:" + Convert.ToString(paillier.Decryption(em1xem3)));

        //test homomorphic properties: D(E(m1)^m2 mod n^2) = (m1*m2) mod n
        Console.WriteLine("\n-= Homomorphic properties: Homomorphic multiplication of plaintexts =-\n");
        BigInteger em2modpowm4 = em2.modPow(m4, paillier.nsqr);
        BigInteger m2xm4 = (m2 * m4) % paillier.n;
        Console.WriteLine("\noriginal sum:" + Convert.ToString(m2xm4));
        Console.WriteLine("\ndecrypted sum:" + Convert.ToString(paillier.Decryption(em2modpowm4)));

    }
}
