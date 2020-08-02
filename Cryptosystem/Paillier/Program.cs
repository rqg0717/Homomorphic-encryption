using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;

namespace Paillier
{
    class Program
    {
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
            Console.WriteLine("\noriginal multiplication:" + Convert.ToString(m2xm4));
            Console.WriteLine("\ndecrypted multiplication:" + Convert.ToString(paillier.Decryption(em2modpowm4)));

        }
    }
}
