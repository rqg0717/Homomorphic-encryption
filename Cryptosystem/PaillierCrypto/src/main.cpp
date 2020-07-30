/*============================================================================
 Name        : main.cpp
 Author      : James Ren
 Version     : 0.1
 Description : Paillier cryptosystem in C
============================================================================*/
#include <stdio.h>
#include <stdlib.h>
#include <string>
#include <iostream>
#include <time.h>

#include <gmp.h>
using namespace std;

#define BILLION 1E9
#define THOUSAND 1000.0

/** Private key
 *	p and q are two random primes.
 *	lambda = lcm(p-1, q-1).
 *	n = p * q.
 */

int bitLength = 256; 	/* bit length of n */
mpz_t lambda;			/* least common multiple of p-1 and q-1. */
mpz_t p, q;				/* prime numbers */
mpz_t n, nsqr;			/* Public key */
mpz_t g;				/* a random BigInteger in Z*_{n^2} where gcd (L(g^lambda mod n^2), n) = 1. */


string* ltrim(string* str, const string& chars = "\t\n\v\f\r ")
{
    str->erase(0, str->find_first_not_of(chars));
    return str;
}

string* rtrim(string* str, const string& chars = "\t\n\v\f\r ")
{
    str->erase(str->find_last_not_of(chars) + 1);
    return str;
}

string* trim(string* str, const string& chars = "\t\n\v\f\r ")
{
    return ltrim(rtrim(str, chars), chars);
}

/** Encrypts plaintext m. Ciphertext em = g^m * r^n mod n^2.
 *
 */


/** Generates the public key and private key.
 *
 */
void KeyGeneration()
{
	char buffer[bitLength] = { 0 };
	int i = 0;
	mpz_t temp;

	mpz_inits( lambda, p, q, n, g, nsqr, temp );

	/* Generates two positive BigIntegers that are probably prime with 256-bit. */
	buffer[0] |= 0xFF;
	for(i = 1; i < bitLength-1; i++) {
		buffer[i] = rand() % 0xFF;
	}
	/* Sets the bottom bit to 1, odd number (better chance for finding primes) */
	buffer[bitLength - 1] |= 0x01;
	/* Interprets this char buffer as an integer */
	mpz_import(temp, bitLength, 1, sizeof(buffer[0]), 0, 0, buffer);
	mpz_nextprime(p, temp);
	mpz_nextprime(q, p);
	/* public key */
	mpz_mul(n, p, q);
	mpz_mul(nsqr, n, n);
	/* If using p,q of equivalent length, */
	/* then  g = n + 1. */
	mpz_add_ui(g, n, 1);
	/* private key */
	/* lambda = lcm(p-1,q-1) */
	mpz_clrbit(p, 0);
	mpz_clrbit(q, 0);
	mpz_lcm(lambda, p, q);
}

int main(int argc, char *argv[])
{
	struct timespec ts_start, ts_end;

	KeyGeneration();


	printf("*********************** C performance test *********************** \n\n");

	clock_gettime(CLOCK_MONOTONIC, &ts_start);



	clock_gettime(CLOCK_MONOTONIC, &ts_end);
	printf("C time elapsed in microsecond: %.3f \n\n", ( ts_end.tv_nsec - ts_start.tv_nsec ) / THOUSAND);

	printf("*********************** End of test *********************** \n");

	return 0;
}
