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

int bitLength = 256; /* bit length of n */
int byteLength = 32; /* byte length of n */
mpz_t lambda; /* least common multiple of p-1 and q-1. */
mpz_t p, q; /* prime numbers */
mpz_t n, nsqr; /* Public key */
mpz_t g; /* a random BigInteger in Z*_{n^2} where gcd (L(g^lambda mod n^2), n) = 1. */

mpz_t msg, emsg;

string* ltrim(string* str, const string& chars = "\t\n\v\f\r ") {
	str->erase(0, str->find_first_not_of(chars));
	return str;
}

string* rtrim(string* str, const string& chars = "\t\n\v\f\r ") {
	str->erase(str->find_last_not_of(chars) + 1);
	return str;
}

string* trim(string* str, const string& chars = "\t\n\v\f\r ") {
	return ltrim(rtrim(str, chars), chars);
}

/** Generates the public key and private key.
 *
 */
void KeyGeneration() {
	uint8_t buffer[byteLength] = { 0 };
	uint8_t i = 0;
	mpz_t temp;

	mpz_init(lambda);
	mpz_init(p);
	mpz_init(q);
	mpz_init(n);
	mpz_init(g);
	mpz_init(nsqr);

	/* Generates two positive BigIntegers that are probably prime with 256-bit. */
	buffer[0] |= 0xFF;
	for (i = 1; i < byteLength - 1; i++) {
		buffer[i] = rand() % 0xFF;
	}
	/* Sets the bottom bit to 1, odd number (better chance for finding primes) */
	buffer[byteLength - 1] |= 0x01;
	/* Interprets this char buffer as an integer */
	mpz_import(temp, byteLength, 1, sizeof(buffer[0]), 0, 0, buffer);
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
	mpz_clear(temp);
}

/** Generates a random number with the specified number of bits
 *  such that gcd(number, this) = 1
 */
void genCoPrime(mpz_t r, mpz_t m) {
	uint8_t i = 0, done = 0;
	uint8_t buf[byteLength] = { 0 };
	mpz_t gcd;
	mpz_init(gcd);

	while (!done) {
		/* Generates random input r. */
		buf[0] |= 0x01;
		for (i = 1; i < byteLength - 1; i++) {
			buf[i] = rand() % 0xFF;
		}
		/* Sets the bottom bit to 1, odd number (better chance for finding primes) */
		buf[byteLength - 1] |= 0x01;
		/* Interprets this char buffer as an integer */
		mpz_import(r, byteLength, 1, sizeof(buf[0]), 0, 0, buf);
		mpz_nextprime(r, r);
		mpz_gcd(gcd, r, m);
		if (mpz_cmp_ui(gcd, 1) == 0) {
			done = 1;
		}
	}
	mpz_clear(gcd);

}

/** Encrypts plaintext m. Ciphertext em = g^m * r^n mod n^2.
 *
 */
void Encrypt(mpz_t m, mpz_t em) {
	mpz_t r, gm, rn;

	mpz_init(r);
	mpz_init(gm);
	mpz_init(rn);

	genCoPrime(r, m);
	/* r^n mod n^2 */
	mpz_powm(rn, r, n, nsqr);
	/* r^n mod n^2 */
	mpz_powm(gm, g, m, nsqr);
	mpz_mul(em, gm, rn);
	mpz_mod(em, em, nsqr);

	mpz_clear(r);
	mpz_clear(gm);
	mpz_clear(rn);

}

/** Decrypts ciphertext em. Plaintext m = L(c^lambda mod n^2) * u mod n
 *  where u = (L(g^lambda mod n^2))^(-1) mod n.
 */
void Decrypt(mpz_t m, mpz_t em) {
	mpz_t u;
	mpz_init(u);
	mpz_powm(u, g, lambda, nsqr);
	mpz_sub_ui(u, u, 1);
	mpz_div(u, u, n);
	mpz_invert(u, u, n);
	mpz_powm(m, em, lambda, nsqr);
	mpz_sub_ui(m, m, 1);
	mpz_div(m, m, n);
	mpz_mul(m, m, u);
	mpz_mod(m, m, n);
	mpz_clear(u);
}

void Cleanup() {
	mpz_clear(lambda);
	mpz_clear(p);
	mpz_clear(q);
	mpz_clear(n);
	mpz_clear(g);
	mpz_clear(nsqr);
	mpz_clear(msg);
	mpz_clear(emsg);
}

void Encryption() {
	mpz_init(msg);
	mpz_init(emsg);

	mpz_set_ui(msg, 1981);
	printf(" plain message = ");
	mpz_out_str(stdout, 10, msg);
	printf("\n");

	Encrypt(msg, emsg);
	printf(" encrypted message = ");
	mpz_out_str(stdout, 10, emsg);
	printf("\n");
}

void Decryption() {
	mpz_set_ui(msg, 0);

	Decrypt(msg, emsg);

	printf(" original message = ");
	mpz_out_str(stdout, 10, msg);
	printf("\n");

}

int main(int argc, char *argv[]) {
	struct timespec ts_start, ts_end;

	printf("*********************** C performance test *********************** \n\n");

	clock_gettime(CLOCK_MONOTONIC, &ts_start);

	KeyGeneration();

	Encryption();

	Decryption();

	Cleanup();

	clock_gettime(CLOCK_MONOTONIC, &ts_end);

	printf("C time elapsed in millisecond: %.3f \n\n",
			(ts_end.tv_nsec - ts_start.tv_nsec) / BILLION);

	printf("*********************** End of test *********************** \n");

	return 0;
}
