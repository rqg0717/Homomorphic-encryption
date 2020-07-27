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
	fmt.Println("g: ", g)
	fmt.Println("n: ", n)
	gm.Exp(&g, m, nil)
	rn.Exp(r, &n, nil)
	em.Mul(&gm, &rn)
	em.Mod(&em, &nsqr)
	return em
}

// Decryption Decrypts ciphertext em. Plaintext m = L(c^lambda mod n^2) * u mod n
// where u = (L(g^lambda mod n^2))^(-1) mod n.
func Decryption(em *big.Int) big.Int {
	var m, u big.Int
	fmt.Println("g: ", g)
	fmt.Println("lambda: ", lambda)
	u.Exp(&g, &lambda, nil)
	u.Sub(&u, big.NewInt(1))
	u.Div(&u, &n)
	u.ModInverse(&u, &n)
	m.Exp(em, &lambda, nil)
	m.Sub(&m, big.NewInt(1))
	m.Div(&m, &n)
	m.Mul(&m, &u)
	m.Mod(&m, &n)
	return m
}

func main() {
	KeyGeneration()
	m := big.NewInt(11)
	em := Encryption(m)
	dm := Decryption(&em)
	fmt.Println("Encryption: ", em)
	fmt.Println("Decryption: ", dm)

}
