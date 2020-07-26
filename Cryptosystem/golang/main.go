package main

import (
	"crypto/rand"
	"fmt"
	"math/big"
)

var bitLength int = 256

//p and q are two random primes.
//lambda = lcm(p-1, q-1).
//n = p * q.
//nsqr = n * n.
var p, q *big.Int
var lambda, n, nsqr big.Int

//a random BigInteger in Z*_{n^2} where gcd (L(g^lambda mod n^2), n) = 1.
var g big.Int

// KeyGeneration Sets up the public key and private key.
func KeyGeneration() {
	//Generates two positive Big Integers that are probably prime with 256-bit.
	p, _ = rand.Prime(rand.Reader, bitLength)
	q, _ = rand.Prime(rand.Reader, bitLength)
	//public key
	n.Mul(p, q)
	nsqr.Mul(&n, &n)
	//If using p,q of equivalent length,
	//then  g = n + 1.
	g.Add(&n, big.NewInt(1))
	//private key
	p.Sub(p, big.NewInt(1))
	q.Sub(q, big.NewInt(1))
	lambda.Mul(p, q)
	p.GCD(nil, nil, p, q)
	lambda.Div(&lambda, p)
}

// Generates a random number with the specified number of bits such
// that gcd(number, this) = 1
func genCoPrime(this *big.Int) *big.Int {
	var done int = 0
	var result *big.Int
	for done == 0 {
		result, _ = rand.Prime(rand.Reader, bitLength)

		// gcd test
		gcd := result.GCD(nil, nil, result, this)
		if gcd.Int64() == int64(1) {
			done = 1
		}
	}
	return result
}

// Encryption Encrypts plaintext m. Ciphertext em = g^m * r^n mod n^2.
func Encryption(m *big.Int) big.Int {
	var em big.Int
	//generates random input r
	r := genCoPrime(m)
	gm := g.Exp(&g, m, nil)
	rn := r.Exp(r, &n, nil)
	em.Mul(gm, rn)
	em.Mod(&em, &nsqr)
	return em
}

// Decryption Decrypts ciphertext em. Plaintext m = L(c^lambda mod n^2) * u mod n
func Decryption(em *big.Int) *big.Int {
	var m *big.Int

	return m
}

func main() {
	KeyGeneration()
	m := big.NewInt(11)
	fmt.Println("Results: ", Encryption(m))
}
