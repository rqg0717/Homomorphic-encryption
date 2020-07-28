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
		gcd := big.NewInt(0)
		gcd.GCD(nil, nil, result, this)
		if gcd.Int64() == int64(1) {
			done = 1
		}
	}
	return result
}

// Encryption Encrypts plaintext m. Ciphertext em = g^m * r^n mod n^2.
func Encryption(m *big.Int) big.Int {
	var em, gm, rn big.Int
	//generates random input r
	r := genCoPrime(m)
	gm.Exp(&g, m, &nsqr)
	rn.Exp(r, &n, &nsqr)
	em.Mul(&gm, &rn)
	em.Mod(&em, &nsqr)
	return em
}

// Decryption Decrypts ciphertext em. Plaintext m = L(c^lambda mod n^2) * u mod n
// where u = (L(g^lambda mod n^2))^(-1) mod n.
func Decryption(em *big.Int) big.Int {
	var m, u big.Int
	u.Exp(&g, &lambda, &nsqr)
	u.Sub(&u, big.NewInt(1))
	u.Div(&u, &n)
	u.ModInverse(&u, &n)
	m.Exp(em, &lambda, &nsqr)
	m.Sub(&m, big.NewInt(1))
	m.Div(&m, &n)
	m.Mul(&m, &u)
	m.Mod(&m, &n)
	return m
}

func main() {
	var em1em2, m1m2 big.Int
	KeyGeneration()
	m1 := big.NewInt(11)
	m2 := big.NewInt(5)
	em1 := Encryption(m1)
	dm1 := Decryption(&em1)
	fmt.Println("Encryption of m1: ", em1)
	fmt.Println("Decryption of m1: ", dm1)
	em2 := Encryption(m2)
	dm2 := Decryption(&em2)
	fmt.Println("Encryption of m2: ", em2)
	fmt.Println("Decryption of m2: ", dm2)
	// tests homomorphic properties: D(E(m1)*E(m2) mod n^2) = (m1 + m2) mod n
	em1em2.Mul(&em1, &em2)
	em1em2.Mod(&em1em2, &nsqr)
	m1m2.Add(m1, m2)
	m1m2.Mod(&m1m2, &n)
	fmt.Println("Sum of m1 and m2: ", m1m2)
	fmt.Println("Sum of em1 and em2: ", Decryption(&em1em2))
}
