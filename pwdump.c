#include <stdio.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <ctype.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <openssl/des.h>
#include <openssl/md4.h>
#include <openssl/md5.h>
#include <openssl/rc4.h>

#include "ntreg.h"
#include "sam.h"

int use_syskey = 0;

unsigned char syskey[0x10];
extern char *val_types[REG_MAX+1];

/* Global verbosity */
int gverbose = 0;


/* Array of loaded hives */
struct hive **hive;
int no_hives = 0;

/* Icky icky... globals used to refer to hives, will be
 * set when loading, so that hives can be loaded in any order
 */

int H_SAM = -1;
int H_SYS = -1;
int H_SEC = -1;
int H_SOF = -1;

void ucs2utf8(FILE *fp, char *vp, int len)
{
	unsigned char *p;
	/* NT always uses UCS16LE */
	int i;

	p = (unsigned char *)vp;
	for (i = 0; i < len; i += 2, p += 2) {
		if (!p[0] && !p[1]) break;
		if (p[1] & 0xF8) {
			fputc( (unsigned char) (0xE0 | (p[1] >> 4)), fp );
			fputc( (unsigned char) (0x80 | ((p[1] & 15) << 2) | (p[0] >> 6)) , fp);
			fputc( (unsigned char) (0x80 | (p[0] & 0x3F)), fp );
		} else if (p[1] | (p[0] & 0x80)) {
			fputc( (unsigned char) (0xC0 | (p[1] << 2)), fp );
			fputc( (unsigned char) (0x80 | (p[0] & 0x3F)), fp );
		} else {
			fputc( (unsigned char) p[0], fp );
		}
	}
}

/* ============================================================== */

/* Crypto-stuff & support for what we'll do in the V-value */

/*
 * Convert a 7 byte array into an 8 byte des key with odd parity.
 */

void str_to_key(unsigned char *str,unsigned char *key)
{
	int i;

	key[0] = str[0]>>1;
	key[1] = ((str[0]&0x01)<<6) | (str[1]>>2);
	key[2] = ((str[1]&0x03)<<5) | (str[2]>>3);
	key[3] = ((str[2]&0x07)<<4) | (str[3]>>4);
	key[4] = ((str[3]&0x0F)<<3) | (str[4]>>5);
	key[5] = ((str[4]&0x1F)<<2) | (str[5]>>6);
	key[6] = ((str[5]&0x3F)<<1) | (str[6]>>7);
	key[7] = str[6]&0x7F;
	for (i=0;i<8;i++) {
		key[i] = (key[i]<<1);
	}
	DES_set_odd_parity((des_cblock *)key);
}

/*
 * Function to convert the RID to the first decrypt key.
 */

void sid_to_key1(unsigned long sid,unsigned char deskey[8])
{
	unsigned char s[7];

	s[0] = (unsigned char)(sid & 0xFF);
	s[1] = (unsigned char)((sid>>8) & 0xFF);
	s[2] = (unsigned char)((sid>>16) & 0xFF);
	s[3] = (unsigned char)((sid>>24) & 0xFF);
	s[4] = s[0];
	s[5] = s[1];
	s[6] = s[2];

	str_to_key(s,deskey);
}

/*
 * Function to convert the RID to the second decrypt key.
 */

void sid_to_key2(unsigned long sid,unsigned char deskey[8])
{
	unsigned char s[7];
	
	s[0] = (unsigned char)((sid>>24) & 0xFF);
	s[1] = (unsigned char)(sid & 0xFF);
	s[2] = (unsigned char)((sid>>8) & 0xFF);
	s[3] = (unsigned char)((sid>>16) & 0xFF);
	s[4] = s[0];
	s[5] = s[1];
	s[6] = s[2];

	str_to_key(s,deskey);
}

int handle_syskey(void)
{
	/* This is \SAM\Domains\Account\F */
	struct samkeyf {
		char unknown[0x50];       /* 0x0000 - Unknown. May be machine SID */
		char unknown2[0x14];
		char syskeymode;          /* 0x0064 - Type/mode of syskey in use     */
		char syskeyflags1[0xb];   /* 0x0065 - More flags/settings            */
		char syskeyobf[0x30];     /* 0x0070 - This may very well be the obfuscated syskey */
	};    /* There may be more, usually 8 null-bytes? */

	/* Security\Policy\SecretEncryptionKey\@, only on NT5 */
	/* Probably contains some keyinfo for syskey. Second DWORD seems to be syskeymode */
	struct secpoldata {
		int  unknown1;             /* Some kind of flag? usually 1 */
		int  syskeymode;           /* Is this what we're looking for? */
		int  unknown2;             /* Usually 0? */
		char keydata[0x40];        /* Some kind of scrambled keydata? */
	};

	/* SYSTEM\CurrentControlSet\Control\Lsa\Data, only on NT5?? */
	/* Probably contains some keyinfo for syskey. Byte 0x34 seems to be mode */
	struct lsadata {
		char keydata[0x34];        /* Key information */
		int  syskeymode;           /* Is this what we're looking for? */
	};

	struct samkeyf *ff = NULL;
	struct secpoldata *sf = NULL;
	struct lsadata *ld = NULL;
	int secboot, samfmode, secmode , ldmode;
	struct keyval *samf, *secpol, *lsad;

	samf = get_val2buf(hive[H_SAM], NULL, 0, "\\SAM\\Domains\\Account\\F", REG_BINARY);

	if (samf && samf->len > 0xA0 ) {
		ff = (struct samkeyf *)&samf->data;
		samfmode = ff->syskeymode;
	} else {
		samfmode = -1;
	}

	secboot = get_dword(hive[H_SYS], 0, "\\ControlSet001\\Control\\Lsa\\SecureBoot");

	secmode = -1;
	secpol = get_val2buf(hive[H_SEC], NULL, 0, "\\Policy\\PolSecretEncryptionKey\\@", REG_NONE);
	if (secpol) {     /* Will not be found in NT 4, take care of that */
		sf = (struct secpoldata *)&secpol->data;
		secmode = sf->syskeymode;
	}

	lsad = get_val2buf(hive[H_SYS], NULL, 0, "\\ControlSet001\\Control\\Lsa\\Data\\Pattern", REG_BINARY);

	if (lsad && lsad->len >= 0x38) {
		ld = (struct lsadata *)&lsad->data;
		ldmode = ld->syskeymode;
	} else {
		ldmode = -1;
	}

	if (secboot == -1) {
		secboot = secmode = samfmode = 0;
	}

	if (lsad) FREE(lsad);
	if (secpol) FREE(secpol);
	if (samf) FREE(samf);

	if((secboot >= 2 && secboot <= 3)
	|| (samfmode >= 2 && samfmode <= 3)
	|| (secmode >= 2 && secmode <= 3)) {
		fprintf(stderr, "** SYSKEY is enabled but the key is not in the registry (%X:%X:%X). Can't continue.\n",
				secboot, samfmode, secmode);
		exit(1);
	}
	if (secboot > 3 || samfmode > 3 || secmode > 3) {
		fprintf(stderr, "** SYSKEY is enabled to an unknown setting (%X:%X:%X). Can't continue.\n",
				secboot, samfmode, secmode);
		exit(1);
	}
	/* no SYSKEY */
	if (secboot == 0 && samfmode == 0 && secmode == 0)
		return 0;

	/* YES syskey */
	if (secboot == 1 && samfmode == 1 && secmode == 1)
		return 1;

	fprintf(stderr, "** SYSKEY is enabled but the registry isn't in agreement about how (%X:%X:%X). Can't continue.\n",
			secboot, samfmode, secmode);
	exit(1);
}



void doit(char *buf, int rid, int vlen)
{
	unsigned char aqwerty[] = "!@#$%^&*()qwertyUIOPAzxcvbnmQQQQQQQQQQQQ)(*@&%";
	unsigned char anum[] = "0123456789012345678901234567890123456789";
	unsigned char antpassword[] = "NTPASSWORD";
	unsigned char almpassword[] = "LMPASSWORD";

	int i;
	unsigned char *vp, *kp, *qqp;
	char s[200];
	unsigned char md4[32],lanman[32];
	int username_offset,username_len;
	int fullname_offset,fullname_len;
	int comment_offset,comment_len;
	int homedir_offset,homedir_len;
	int ntpw_len,lmpw_len,ntpw_offs,lmpw_offs;
	struct keyval *fv;
	unsigned short acb;
	struct user_V *v;
	struct user_F *f;
	int is_disabled;
	int is_ignored;

	MD5_CTX md5c;
	unsigned char md5hash[0x10];
	RC4_KEY rc4k;
	unsigned char hbootkey[0x20];
	unsigned char ofbkey[0x10];
	
	des_key_schedule ks1, ks2;
	des_cblock deskey1, deskey2;
	struct keyval *samf;

	v = (struct user_V *)buf;
	vp = buf;
 
	username_offset = v->username_ofs;
	username_len    = v->username_len; 
	fullname_offset = v->fullname_ofs;
	fullname_len    = v->fullname_len;
	comment_offset  = v->comment_ofs;
	comment_len     = v->comment_len;
	homedir_offset  = v->homedir_ofs;
	homedir_len     = v->homedir_len;
	lmpw_offs       = v->lmpw_ofs;
	lmpw_len        = v->lmpw_len;
	ntpw_offs       = v->ntpw_ofs;
	ntpw_len        = v->ntpw_len;

	if(username_len <= 0 || username_len > vlen ||
     		username_offset <= 0 || username_offset >= vlen ||
		comment_len < 0 || comment_len > vlen   ||
		fullname_len < 0 || fullname_len > vlen ||
		homedir_offset < 0 || homedir_offset >= vlen ||
		comment_offset < 0 || comment_offset >= vlen ||
		lmpw_offs < 0 || lmpw_offs >= vlen) {

		fprintf(stderr, "SAM hive partially corrupt and %08X\\V is not usable, continuing...\n", rid);
		return;
	}

	/* Get users F value */
	snprintf(s,180,"\\SAM\\Domains\\Account\\Users\\%08X\\F",rid);
	fv = get_val2buf(hive[H_SAM], NULL, 0, s, REG_BINARY);
	if (!fv) {
		fprintf(stderr, "SAM hive partially corrupt and %08X\\F is not usable, continuing...\n", rid);
		is_disabled = 1;
	} else {
		if (fv->len != 0x50) {
			fprintf(stderr, "SAM hive partially corrupt and %08X\\F is of the wrong size (0x%02X), continuing...\n", rid, fv->len);
			is_disabled = 1;
		} else {
			f = (struct user_F *)&fv->data;
			acb = f->ACB_bits;
			is_disabled = (acb & ACB_DISABLED) ? 1 : 0;
		}
		FREE(fv);
	}
	username_offset += 0xCC;
	fullname_offset += 0xCC;
	comment_offset += 0xCC;
	homedir_offset += 0xCC;
	ntpw_offs += 0xCC;
	lmpw_offs += 0xCC;

	if (ntpw_len < 16) {
		if (!is_disabled) {
			fprintf(stderr, "** Problem with: ");
			ucs2utf8(stderr, vp+username_offset, username_len);
			fprintf(stderr, "\n** No NT MD4 hash found. This user probably has a BLANK password!\n");
			fprintf(stderr, "** LANMAN password IS however set. This is probably causing problems...\n");
			is_disabled = 1;
		}
		ntpw_offs = lmpw_offs;
		qqp = vp + 0xa8;
		*((unsigned int *)qqp) = ntpw_offs - 0xcc;
		ntpw_len = 16;
		lmpw_len = 0;
	}

	/* Get the two decrpt keys. */
	sid_to_key1(rid,(unsigned char *)deskey1);
	sid_to_key2(rid,(unsigned char *)deskey2);
	des_set_key((des_cblock *)deskey1,ks1);
	des_set_key((des_cblock *)deskey2,ks2);

	if (use_syskey) {
		/* setup SysKey decrypt round */

		samf = get_val2buf(hive[H_SAM], NULL, 0,
				"\\SAM\\Domains\\Account\\F", REG_BINARY);

		if (!samf || samf->len < 0xA0 ) {
			fprintf(stderr, "** SAM moved while working on it. Don't do that.\n");
			exit(1);
		}

		kp = (unsigned char *)&samf->data;

		MD5_Init(&md5c);
		MD5_Update( &md5c, &kp[0x70], 0x10);
		MD5_Update( &md5c, aqwerty, 0x2f );
		MD5_Update( &md5c, syskey, 0x10 );
		MD5_Update( &md5c, anum, 0x29 );
		MD5_Final( md5hash, &md5c );
	
		RC4_set_key( &rc4k, 0x10, md5hash );
		RC4( &rc4k, 0x20, &kp[0x80], hbootkey );

		/* decrypt and replace Lanman key */
		MD5_Init(&md5c);
		MD5_Update( &md5c, hbootkey, 0x10 );
		MD5_Update( &md5c, &rid, 0x4 );
		MD5_Update( &md5c, almpassword, 0xb );
		MD5_Final( md5hash, &md5c );        

		RC4_set_key( &rc4k, 0x10, md5hash );
		RC4( &rc4k, 0x10, (vp+lmpw_offs+4), ofbkey );

		memcpy(vp+lmpw_offs, ofbkey, 0x10);

		/* decrypt and replace NT key */
		MD5_Init(&md5c);
		MD5_Update( &md5c, hbootkey, 0x10 );
		MD5_Update( &md5c, &rid, 0x4 );
		MD5_Update( &md5c, antpassword, 0xb );
		MD5_Final( md5hash, &md5c );        

		RC4_set_key( &rc4k, 0x10, md5hash );
		RC4( &rc4k, 0x10, (vp+ntpw_offs+4), ofbkey );

		memcpy(vp+ntpw_offs, ofbkey, 0x10);
	}

	/* Decrypt the NT md4 password hash as two 8 byte blocks. */
	des_ecb_encrypt((des_cblock *)(vp+ntpw_offs ),
		   (des_cblock *)md4, ks1, DES_DECRYPT);
	des_ecb_encrypt((des_cblock *)(vp+ntpw_offs + 8),
		   (des_cblock *)&md4[8], ks2, DES_DECRYPT);

	/* Decrypt the lanman password hash as two 8 byte blocks. */
	des_ecb_encrypt((des_cblock *)(vp+lmpw_offs),
		   (des_cblock *)lanman, ks1, DES_DECRYPT);
	des_ecb_encrypt((des_cblock *)(vp+lmpw_offs + 8),
		   (des_cblock *)&lanman[8], ks2, DES_DECRYPT);

	/* write out username */
	ucs2utf8(stdout, vp+username_offset, username_len);
	
	printf(":%d:", rid);
	is_ignored = 0;
	if (lmpw_len >= 16) {
		for (i = 0; i < 16; i++) {
			printf("%02X", (unsigned int)lanman[i]);
		}
	} else {
		/* 32 x's */
		printf("XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX");
		is_ignored++;
	}
	putchar(':');
	if (ntpw_len >= 16) {
		for (i = 0; i < 16; i++) {
			printf("%02X", (unsigned int)md4[i]);
		}
	} else {
		/* 32 x's */
		printf("XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX");
		is_ignored++;
	}
	printf(":[U%c%c        ]:LCT-00000000:\n",
			is_disabled ? 'D' : ' ',
			is_ignored == 2 ? 'N' : ' ');
}

int main(int argc, char *argv[])
{
	int i, j;
	char s[200];
	struct keyval *v;
	int nkofs /* ,vkofs */ ;
	int rid;
	int count = 0, countri = 0;
	struct ex_data ex;
//	  int p[] = { 0x7, 0x3, 0xa, 0x8, 0xf, 0x9, 0x1, 0x2,0x4, 0xd, 0x5, 0x0, 0xe, 0xc, 0x6, 0xb };
	int p[] = { 0xb, 0x6, 0x7, 0x1, 0x8, 0xa, 0xe, 0x0,0x3, 0x5, 0x2, 0xf, 0xd, 0x9, 0xc, 0x4 };
	const char *kn[] = { "JD", "Skew1", "GBG", "Data" };
	unsigned char kv[9], *kp;
	unsigned char tmpkey[0x10];

	hive = (struct hive **)malloc(sizeof(struct hive *) * argc);
	if (!hive) {
		perror("malloc");
		exit(255);
	}
	for (i = 1; i < argc; i++) {
		hive[i-1]  = openHive(argv[i], HMODE_RO);
		if (!hive[i-1]) continue;
		switch(hive[i-1]->type) {
		case HTYPE_SAM:      H_SAM = i-1; break;
		case HTYPE_SOFTWARE: H_SOF = i-1; break;
		case HTYPE_SYSTEM:   H_SYS = i-1; break;
		case HTYPE_SECURITY: H_SEC = i-1; break;
		};
	}
	if (H_SAM == -1 || H_SYS == -1 || H_SEC == -1 || H_SOF == -1) {
		fprintf(stderr, "Usage: %s hives...\n", argv[0]);
		exit(1);
	}

	/* H_SYS H_SEC */
	if (handle_syskey()) {
		for (i = 0; i < 4; i++) {
			snprintf(s, 180, "\\ControlSet001\\Control\\Lsa\\%s",kn[i]);
			/* ??? maybe 0x1000 here ??? */
			v = get_class(hive[H_SYS], hive[H_SYS]->rootofs + 4, s);
			if (!v) {
				fprintf(stderr, "** Can't scan part of syskey from %s\n** Can't Continue\n", s);
				exit(1);
			}
	
			/* 4 bytes */
			kp = (unsigned char *)&v->data;
			for( j = 0; j*2 < v->len && j < 9; j++)
				kv[j] = kp[j*2];
			kv[8] = 0;
			if (sscanf(kv, "%x", ((int *)(&tmpkey[i*4]))) != 1) {
				fprintf(stderr, "** Can't scan part of syskey from %s\n** Can't Continue\n", s);
				exit(1);
			}
			FREE(v);
		}
		fprintf(stderr, "** Extracted SYSKEY: ");
		for (i = 0; i < 0x10; i++) {
			syskey[i] = tmpkey[p[i]];
			fprintf(stderr, "%02X", syskey[i]);
		}
		fprintf(stderr, "\n");
		use_syskey = 1;
	} else {
		use_syskey = 0;
	}

	/* H_SAM */
	nkofs = trav_path(hive[H_SAM], 0,"\\SAM\\Domains\\Account\\Users\\Names\\",0);
	if (!nkofs) {
		fprintf(stderr, "SAM hive invalid\n");
		return(1);
	}
	while ((ex_next_n(hive[H_SAM], nkofs+4, &count, &countri, &ex) > 0)) {
		snprintf(s,180,"\\SAM\\Domains\\Account\\Users\\Names\\%s\\@",ex.name);
		rid = get_dword(hive[H_SAM], 0, s);
		snprintf(s,180,"\\SAM\\Domains\\Account\\Users\\%08X\\V",rid);
		v = get_val2buf(hive[H_SAM], NULL, 0, s, REG_BINARY);
		if (!v) {
			fprintf(stderr, "SAM hive partially corrupt and %08X\\V is not available, continuing...\n", rid);
			free(ex.name);
			continue;
		}
		if (v->len < 0xcc) {
			fprintf(stderr, "SAM hive partially corrupt and %08X\\V is only %d bytes long, continuing...\n", rid, v->len);
			FREE(v);
			free(ex.name);
			continue;
		}
		doit( (char *)&v->data, rid, v->len);
		FREE(v);
		free(ex.name);
	}
	
	return 0;
}
