/*
 * NT/LM password hasher
 * generates samba-compatible hashes
 *
 * (C) 2005 Internet Connection, Inc.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 * 
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software Foundation,
 * Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.
 */
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <stdlib.h>

#include <openssl/des.h>
#include <openssl/md4.h>
#include <openssl/md5.h>
#include <openssl/rc4.h>
#define uchar u_char

static unsigned char *hx = "0123456789ABCDEF";
static void sh(unsigned char *out, const unsigned char *in,
				const unsigned char *key) 
{
	unsigned char key2[8];
	des_key_schedule dk;

	key2[0] = key[0] & 127;
	key2[1] = (((key[0] & 1) << 6) | (key[1] >> 2)) << 1;
	key2[2] = (((key[1] & 3) << 5) | (key[2] >> 3)) << 1;
	key2[3] = (((key[2] & 7) << 4) | (key[3] >> 4)) << 1;
	key2[4] = (((key[3] & 15) << 3) | (key[4] >> 5)) << 1;
	key2[5] = (((key[4] & 31) << 2) | (key[5] >> 6)) << 1;
	key2[6] = (((key[5] & 63) << 1) | (key[6] >> 7)) << 1;
	key2[7] = ((key[6] & 63)) << 1;
	DES_set_odd_parity((des_cblock*)key2);
	des_set_key((des_cblock *)key2, dk);
	des_ecb_encrypt((des_cblock*)in, (des_cblock *)out, dk, DES_ENCRYPT);
}

int main(int argc, char *argv[])
{
	static unsigned char dk[8] = {75,71,83,33,64,35,36,37};
	unsigned char out_lm[16];
	unsigned char out_nt[16];
	unsigned char in_nt[256];
	char in_lm[15];

	char *pw = 0;
	int c, i, len;

START:
	len = 0;
	while (((c=fgetc(stdin)) != EOF) && c != '\n' && c != '\r' && c != '\0') {
		pw = realloc(pw, len+2);
		if (!pw) {
			perror("realloc");
			exit(EXIT_FAILURE);
		}
		pw[len] = c;
		len++;
	}
	if (!pw || !len) {
		if (c == EOF) exit(EXIT_SUCCESS);
		goto START;
	}
	pw[len] = 0;

	/* lanman */
	memset(in_lm,0,sizeof(in_lm));
	for (i = 0; i < len && i < 14; i++) {
		if (pw[i] >= 'a' && pw[i] <= 'z') {
			in_lm[i] = (pw[i] - 'a') + 'A';
		} else {
			in_lm[i] = pw[i];
		}
	}
	in_lm[14] = 0;
	sh(out_lm, dk, in_lm);
	sh(out_lm+8, dk, in_lm+7);

	/* mdfour */
	for (i = 0; i < len && i < 128; i++) {
		in_nt[i*2] = pw[i];
		in_nt[(i*2)+1] = 0;
	}
	MD4(in_nt, i*2, out_nt);

	/* output */
	for (i = 0; i < 16; i++) {
		putchar(hx[out_lm[i]>>4]);
		putchar(hx[out_lm[i]&15]);
	}
	putchar(':');
	for (i = 0; i < 16; i++) {
		putchar(hx[out_nt[i]>>4]);
		putchar(hx[out_nt[i]&15]);
	}
	putchar('\n');

	if (c == EOF) exit(EXIT_SUCCESS);
	free(pw);
	pw = 0;
	goto START;
}
