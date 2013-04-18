/***
 * Length extension attack against SHA1
 * Florian Weingarten <flo@hackvalue.de>
 *
 * Given SHA1(key+msg), key length and msg, compute
 * SHA1(key+msg+padding+suffix) without needing to
 * know the key.
 *
 * gcc sha1.c -lcrypto -std=c99 -o sha1
 ***/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <openssl/sha.h>

int main(int argc, char *argv[])
{
	if(argc != 5) {
		fprintf(stderr, "Usage: %s <keylen> <msg> <hash> <suffix>\n", argv[0]);
		exit(EXIT_FAILURE);
	}

	size_t keylen = atoi(argv[1]);
	char *msg = argv[2];
	char *hsh = argv[3];
	char *ext = argv[4];

	if(strlen(hsh) != 2*SHA_DIGEST_LENGTH) {
		fprintf(stderr, "Hash has invalid length (!= %d)\n", 2*SHA_DIGEST_LENGTH);
		exit(EXIT_FAILURE);
	}

	// Create padding for SHA1 block to next multiple of block length
	size_t len = ((keylen + strlen(msg)) / SHA_CBLOCK) + 1;
	size_t padlen = SHA_CBLOCK * len - keylen - strlen(msg);
	unsigned char *padding = malloc(padlen);
	padding[0] = 0x80;
	for(int i=0; i<padlen-2; i++) padding[1+i] = 0;
	size_t count = (keylen + strlen(msg)) * 8;
	padding[padlen-1] = count;
	if(count > 0xFF) {
		padding[padlen-2] = (count / 0xFF);
	}

	// Create new SHA1 state with keylen+msglen+padlen length
	SHA_CTX c;
	SHA1_Init(&c);
	c.Nl = (keylen + strlen(msg) + padlen) * 8;

	// Set SHA1 state to previous hash plus padding
	SHA_LONG *h = &c.h4;
	for(int i=0; i<5; i++) {
		int j = 2*SHA_DIGEST_LENGTH - (i+1)*8;
		*h = strtol(hsh+j, NULL, 16);
		h--;
		hsh[j] = 0;
	}

	// Print msg + padding + extension
	printf("newmsg = %s", msg);
	for(int i=0; i<padlen; i++) {
		printf("\\x%02x", padding[i]);
	}
	printf("%s\n", ext);

	// Print SHA1(key + msg + padding + extension)
	unsigned char digest[SHA_DIGEST_LENGTH];
	SHA1_Update(&c, ext, strlen(ext));
	SHA1_Final(digest, &c);
	printf("newhash = ");
	for(int i=0; i<SHA_DIGEST_LENGTH; i++) {
		printf("%02x", digest[i]);
	}
	puts("");

	return EXIT_SUCCESS;
}
