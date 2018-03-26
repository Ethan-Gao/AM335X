/*
 * Keystone crypto accelerator driver
 *
 * Copyright (C) 2015, 2016 Texas Instruments Incorporated - http://www.ti.com
 *
 * Authors:	Sandeep Nair
 *		Vitaly Andrianov
 *
 * Contributors:Tinku Mannan
 *		Hao Zhang
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * version 2 as published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 */

#include <linux/types.h>
#include <linux/crypto.h>
#include <linux/cryptohash.h>

#include <crypto/aes.h>
#include <crypto/sha.h>
#include <crypto/md5.h>

#include "keystone-sa.h"
#include "keystone-sa-hlp.h"

/* Byte offset for key in encryption security context */
#define SC_ENC_KEY_OFFSET (1 + 27 + 4)
/* Byte offset for Aux-1 in encryption security context */
#define SC_ENC_AUX1_OFFSET (1 + 27 + 4 + 32)

struct sa_eng_mci_tbl sa_mci_tbl;

/* Perform 16 byte swizzling */
void sa_swiz_128(u8 *in, u8 *out, u16 len)
{
	u8 data[16];
	int i, j;

	for (i = 0; i < len - 15; i += 16) {
		memcpy(data, &in[i], 16);
		for (j = 0; j < 16; j++)
			out[i + j] = data[15 - j];
	}
}

/* Convert CRA name to internal algorithm ID */
void sa_conv_calg_to_salg(const char *cra_name, int *ealg_id, int *aalg_id)
{
	*ealg_id = SA_EALG_ID_NONE;
	*aalg_id = SA_AALG_ID_NONE;

	if (!strcmp(cra_name, "authenc(hmac(sha1),cbc(aes))")) {
		*ealg_id = SA_EALG_ID_AES_CBC;
		*aalg_id = SA_AALG_ID_HMAC_SHA1;
	} else if (!strcmp(cra_name, "authenc(hmac(sha256),cbc(aes))")) {
		*ealg_id = SA_EALG_ID_AES_CBC;
		*aalg_id = SA_AALG_ID_HMAC_SHA2_256;
	} else if (!strcmp(cra_name, "authenc(hmac(sha1),ecb(cipher_null))")) {
		*ealg_id = SA_EALG_ID_NULL;
		*aalg_id = SA_AALG_ID_HMAC_SHA1;
	} else if (!strcmp(cra_name, "authenc(hmac(sha1),cbc(des3_ede))")) {
		*ealg_id = SA_EALG_ID_3DES_CBC;
		*aalg_id = SA_AALG_ID_HMAC_SHA1;
	} else if (!strcmp(cra_name, "authenc(xcbc(aes),cbc(aes))")) {
		*ealg_id = SA_EALG_ID_AES_CBC;
		*aalg_id = SA_AALG_ID_AES_XCBC;
	} else if (!strcmp(cra_name, "authenc(xcbc(aes),cbc(des3_ede))")) {
		*ealg_id = SA_EALG_ID_3DES_CBC;
		*aalg_id = SA_AALG_ID_AES_XCBC;
	} else if (!strcmp(cra_name, "rfc4106(gcm(aes))")) {
		*ealg_id = SA_EALG_ID_GCM;
	} else if (!strcmp(cra_name, "rfc4543(gcm(aes))")) {
		*aalg_id = SA_AALG_ID_GMAC;
	} else if (!strcmp(cra_name, "cbc(aes)")) {
		*ealg_id = SA_EALG_ID_AES_CBC;
	} else if (!strcmp(cra_name, "cbc(des3_ede)")) {
		*ealg_id = SA_EALG_ID_3DES_CBC;
	} else if (!strcmp(cra_name, "hmac(sha1)")) {
		*aalg_id = SA_AALG_ID_HMAC_SHA1;
	} else if (!strcmp(cra_name, "xcbc(aes)")) {
		*aalg_id = SA_AALG_ID_AES_XCBC;
	} else
		pr_err("%s - unsupported cra_name %s\n", __func__, cra_name);
}

struct sa_eng_info sa_eng_info_tbl[SA_ALG_ID_LAST] = {
	[SA_EALG_ID_NONE]	= { SA_ENG_ID_NONE, 0},
	[SA_EALG_ID_NULL]	= { SA_ENG_ID_NONE, 0},
	[SA_EALG_ID_AES_CTR]	= { SA_ENG_ID_NONE, 0},
	[SA_EALG_ID_AES_F8]	= { SA_ENG_ID_NONE, 0},
	[SA_EALG_ID_AES_CBC]	= { SA_ENG_ID_EM1, SA_CTX_ENC_TYPE1_SZ},
	[SA_EALG_ID_DES_CBC]	= { SA_ENG_ID_EM1, SA_CTX_ENC_TYPE1_SZ},
	[SA_EALG_ID_3DES_CBC]	= { SA_ENG_ID_EM1, SA_CTX_ENC_TYPE1_SZ},
	[SA_EALG_ID_CCM]	= { SA_ENG_ID_NONE, 0},
	[SA_EALG_ID_GCM]	= { SA_ENG_ID_EM1, SA_CTX_ENC_TYPE2_SZ},
	[SA_AALG_ID_NULL]	= { SA_ENG_ID_NONE, 0},
	[SA_AALG_ID_MD5]	= { SA_ENG_ID_NONE, 0},
	[SA_AALG_ID_SHA1]	= { SA_ENG_ID_NONE, 0},
	[SA_AALG_ID_SHA2_224]	= { SA_ENG_ID_NONE, 0},
	[SA_AALG_ID_SHA2_256]	= { SA_ENG_ID_NONE, 0},
	[SA_AALG_ID_HMAC_MD5]	= { SA_ENG_ID_AM1, SA_CTX_AUTH_TYPE2_SZ},
	[SA_AALG_ID_HMAC_SHA1]	= { SA_ENG_ID_AM1, SA_CTX_AUTH_TYPE2_SZ},
	[SA_AALG_ID_HMAC_SHA2_224] = { SA_ENG_ID_NONE, 0},
	[SA_AALG_ID_HMAC_SHA2_256] = { SA_ENG_ID_AM1, SA_CTX_AUTH_TYPE2_SZ},
	[SA_AALG_ID_GMAC]	= { SA_ENG_ID_EM1, SA_CTX_ENC_TYPE2_SZ},
	[SA_AALG_ID_CMAC]	= {SA_ENG_ID_EM1, SA_CTX_AUTH_TYPE1_SZ},
	[SA_AALG_ID_CBC_MAC]	= { SA_ENG_ID_NONE, 0},
	[SA_AALG_ID_AES_XCBC]	= {SA_ENG_ID_EM1, SA_CTX_AUTH_TYPE1_SZ}
};

/* Given an algorithm ID get the engine details */
struct sa_eng_info *sa_get_engine_info(int alg_id)
{
	if (alg_id < SA_ALG_ID_LAST)
		return &sa_eng_info_tbl[alg_id];

	pr_err("%s: unsupported algo\n", __func__);

	return &sa_eng_info_tbl[SA_EALG_ID_NONE];
}

/* Given an algorithm get the hash size */
int sa_get_hash_size(u16 aalg_id)
{
	int hash_size = 0;

	switch (aalg_id) {
	case SA_AALG_ID_MD5:
	case SA_AALG_ID_HMAC_MD5:
		hash_size = MD5_DIGEST_SIZE;
		break;

	case SA_AALG_ID_SHA1:
	case SA_AALG_ID_HMAC_SHA1:
		hash_size = SHA1_DIGEST_SIZE;
		break;

	case SA_AALG_ID_SHA2_224:
	case SA_AALG_ID_HMAC_SHA2_224:
		hash_size = SHA224_DIGEST_SIZE;
		break;

	case SA_AALG_ID_SHA2_256:
	case SA_AALG_ID_HMAC_SHA2_256:
		hash_size = SHA256_DIGEST_SIZE;
		break;

	case SA_AALG_ID_AES_XCBC:
	case SA_AALG_ID_CMAC:
	case SA_AALG_ID_GMAC:
		hash_size = AES_BLOCK_SIZE;
		break;

	default:
		pr_err("%s: unsupported hash\n", __func__);
		break;
	}

	return hash_size;
}

/* Initialize MD5 digest */
static inline void md5_init(u32 *hash)
{
	/* Load magic initialization constants */
	hash[0] = 0x67452301;
	hash[1] = 0xefcdab89;
	hash[2] = 0x98badcfe;
	hash[3] = 0x10325476;
}

/* Generate HMAC-MD5 intermediate Hash */
static void sa_hmac_md5_get_pad(const u8 *key, u16 key_sz, u32 *ipad, u32 *opad)
{
	u8 k_ipad[MD5_MESSAGE_BYTES];
	u8 k_opad[MD5_MESSAGE_BYTES];
	int i;

	for (i = 0; i < key_sz; i++) {
		k_ipad[i] = key[i] ^ 0x36;
		k_opad[i] = key[i] ^ 0x5c;
	}
	/* Instead of XOR with 0 */
	for (; i < SHA_MESSAGE_BYTES; i++) {
		k_ipad[i] = 0x36;
		k_opad[i] = 0x5c;
	}

	/* SHA-1 on k_ipad */
	md5_init(ipad);
	md5_transform(ipad, (u32 *)k_ipad);

	/* SHA-1 on k_opad */
	md5_init(opad);
	md5_transform(ipad, (u32 *)k_opad);
}

/* Generate HMAC-SHA1 intermediate Hash */
static
void sa_hmac_sha1_get_pad(const u8 *key, u16 key_sz, u32 *ipad, u32 *opad)
{
	u32 ws[SHA_WORKSPACE_WORDS];
	u8 k_ipad[SHA_MESSAGE_BYTES];
	u8 k_opad[SHA_MESSAGE_BYTES];
	int i;

	for (i = 0; i < key_sz; i++) {
		k_ipad[i] = key[i] ^ 0x36;
		k_opad[i] = key[i] ^ 0x5c;
	}
	/* Instead of XOR with 0 */
	for (; i < SHA_MESSAGE_BYTES; i++) {
		k_ipad[i] = 0x36;
		k_opad[i] = 0x5c;
	}

	/* SHA-1 on k_ipad */
	sha_init(ipad);
	sha_transform(ipad, k_ipad, ws);

	for (i = 0; i < SHA_DIGEST_WORDS; i++)
		ipad[i] = cpu_to_be32(ipad[i]);

	/* SHA-1 on k_opad */
	sha_init(opad);
	sha_transform(opad, k_opad, ws);

	for (i = 0; i < SHA_DIGEST_WORDS; i++)
		opad[i] = cpu_to_be32(opad[i]);
}

#define ROTATE(a, n)     (((a)<<(n))|(((a)&0xffffffff)>>(32-(n))))

/*
 * FIPS specification refers to right rotations, while our ROTATE macro
 * is left one. This is why you might notice that rotation coefficients
 * differ from those observed in FIPS document by 32-N...
 */
#define Sigma0(x)	(ROTATE((x), 30) ^ ROTATE((x), 19) ^ ROTATE((x), 10))
#define Sigma1(x)	(ROTATE((x), 26) ^ ROTATE((x), 21) ^ ROTATE((x), 7))
#define sigma0(x)	(ROTATE((x), 25) ^ ROTATE((x), 14) ^ ((x)>>3))
#define sigma1(x)	(ROTATE((x), 15) ^ ROTATE((x), 13) ^ ((x)>>10))

#define CH(x, y, z)	(((x) & (y)) ^ ((~(x)) & (z)))
#define MAJ(x, y, z)	(((x) & (y)) ^ ((x) & (z)) ^ ((y) & (z)))

/* SHA256 constants. Values obtained from RFC4634. */
static const u32 K256[64] = {
	0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5,
	0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
	0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
	0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
	0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc,
	0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
	0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
	0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
	0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
	0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
	0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3,
	0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
	0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5,
	0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
	0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
	0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
};

/* Obtained from TI SA-LLD */
static const u32 mac_last_word_mask[3] = {0xff000000, 0xffff0000, 0xffffff00};

/* Structure used by SHA2 algorithm */
struct sa_sha2_inst_t {
	u32 h[8];		/* H Buffers */
	u32 nl, nh;
	u32 data[16];	/* 32 bit words in a BLOCK */
	u16 num;
	u16 md_len;
};

/* Initialize SHA2-256 context. */
static inline void sa_sha256_init(struct sa_sha2_inst_t *inst)
{
	/* SHA256 initial hash values. Values obtained from RFC4634. */
	inst->h[0]   = 0x6a09e667;
	inst->h[1]   = 0xbb67ae85;
	inst->h[2]   = 0x3c6ef372;
	inst->h[3]   = 0xa54ff53a;
	inst->h[4]   = 0x510e527f;
	inst->h[5]   = 0x9b05688c;
	inst->h[6]   = 0x1f83d9ab;
	inst->h[7]   = 0x5be0cd19;
	inst->nl     = 0;
	inst->nh     = 0;
	inst->num    = 0;
	inst->md_len = SHA256_DIGEST_SIZE;
}

/* SHA2 block processing function. */
static inline void sha256_block(struct sa_sha2_inst_t *inst, u32 *p)
{
	u32 a, b, c, d, e, f, g, h, s0, s1, T1, T2;
	u32	X[16];
	int i;

	a = inst->h[0];
	b = inst->h[1];
	c = inst->h[2];
	d = inst->h[3];
	e = inst->h[4];
	f = inst->h[5];
	g = inst->h[6];
	h = inst->h[7];

	for (i = 0; i < 16; i++) {
		T1 = X[i] = p[i];
		T1 += h + Sigma1(e) + CH(e, f, g) + K256[i];
		T2 = Sigma0(a) + MAJ(a, b, c);
		h = g;
		g = f;
		f = e;
		e = d + T1;
		d = c;
		c = b;
		b = a;
		a = T1 + T2;
	}

	for (; i < 64; i++) {
		s0 = X[(i + 1) & 0x0f];
		s0 = sigma0(s0);
		s1 = X[(i + 14) & 0x0f];
		s1 = sigma1(s1);

		T1 = X[i & 0xf] += s0 + s1 + X[(i + 9) & 0xf];
		T1 += h + Sigma1(e) + CH(e, f, g) + K256[i];
		T2 = Sigma0(a) + MAJ(a, b, c);
		h = g;
		g = f;
		f = e;
		e = d + T1;
		d = c;
		c = b;
		b = a;
		a = T1 + T2;
	}

	inst->h[0] += a;
	inst->h[1] += b;
	inst->h[2] += c;
	inst->h[3] += d;
	inst->h[4] += e;
	inst->h[5] += f;
	inst->h[6] += g;
	inst->h[7] += h;
}

/* SHA2-256 update function. */
static inline void sa_sha256_update(struct sa_sha2_inst_t *inst,
		u8 *data, u32 len)
{
	u32 *p;
	u16 ew, ec, sw;
	u32 l;
	u32 offset = 0;

	if (len == 0)
		return;

	l = (inst->nl + (len << 3)) & 0xffffffff;
	if (l < inst->nl) /* overflow */
		inst->nh++;

	inst->nh += (len >> 29);
	inst->nl = l;
	/*
	 * We now can process the input data in blocks of SHA_CBLOCK
	 * chars and save the leftovers to inst->data.
	 */
	p = inst->data;
	while (len >= SHA256_BLOCK_SIZE) {
		for (sw = (SHA256_BLOCK_SIZE/4); sw; sw--, offset += 4) {
			*p++ = SA_MK_U32(data[offset], data[offset + 1],
					data[offset + 2], data[offset + 3]);
		}
		p = inst->data;
		sha256_block(inst, p);
		len -= SHA256_BLOCK_SIZE;
	}
	ec = (s16)len;
	inst->num = ec;
	ew = (ec >> 2);
	ec &= 0x03;

	for (sw = 0; sw < ew; sw++) {
		p[sw] = SA_MK_U32(data[offset], data[offset + 1],
				data[offset + 2], data[offset + 3]);
	}

	if (ec) {
		p[sw] = (SA_MK_U32(data[offset], data[offset + 1],
				data[offset + 2], data[offset + 3])) &
			mac_last_word_mask[ec - 1];
	}
}

/* Generate HMAC-SHA256 intermediate Hash */
static inline void sa_hmac_sha256_get_pad(const u8 *key, u16 key_sz,
		u32 *ipad, u32 *opad)
{
	u16 i;
	struct sa_sha2_inst_t sha2_inst;
	u8 k_ipad[SHA256_BLOCK_SIZE];
	u8 k_opad[SHA256_BLOCK_SIZE];
	u8 *key1 = (u8 *)key;

	/* assumption is that key_sz will be even number always */
	/* set up key xor ipad, opad */
	for (i = 0; i < key_sz; i++) {
		k_ipad[i] = key1[i] ^ 0x36;
		k_opad[i] = key1[i] ^ 0x5c;
	}

	/* Instead of XOR with zero */
	for (; i < SHA256_BLOCK_SIZE; i++) {
		k_ipad[i] = 0x36;
		k_opad[i] = 0x5c;
	}

	/*
	 * Perform sha1 on K_ipad
	 */
	/*Init the SHA1 state for 1st pass */
	sa_sha256_init(&sha2_inst);

	/* start with inner pad k_ipad */
	sa_sha256_update(&sha2_inst, (u8 *)k_ipad, SHA256_BLOCK_SIZE);

	/* Output the intermediate hash */
	for (i = 0; i < 8; i++)
		ipad[i] = cpu_to_be32(sha2_inst.h[i]);

	/*
	 * Perform sha1 on K_opad
	 */
	/*Init the SHA1 state for 2nd pass */
	sa_sha256_init(&sha2_inst);

	/* start with outer pad k_opad */
	sa_sha256_update(&sha2_inst, (u8 *)k_opad, SHA256_BLOCK_SIZE);

	/* Output the intermediate hash */
	for (i = 0; i < 8; i++)
		opad[i] = cpu_to_be32(sha2_inst.h[i]);
}

/* Derive GHASH to be used in the GCM algorithm */
static inline void sa_calc_ghash(const u8 *key, u16 key_sz, u8 *ghash)
{
	struct AES_KEY enc_key;

	if (private_AES_set_encrypt_key(key, key_sz, &enc_key) == -1) {
		pr_err("ERROR (%s): failed to set enc key\n", __func__);
		return;
	}

	memset(ghash, 0x00, AES_BLOCK_SIZE);
	AES_encrypt(ghash, ghash, &enc_key);
}

/* Derive the inverse key used in AES-CBC decryption operation */
static inline int sa_aes_inv_key(u8 *inv_key, const u8 *key, u16 key_sz)
{
	struct crypto_aes_ctx ctx;
	int key_pos;

	if (crypto_aes_expand_key(&ctx, key, key_sz)) {
		pr_err("%s: bad key len(%d)\n", __func__, key_sz);
		return -1;
	}

	/* Refer the implementation of crypto_aes_expand_key()
	 * to understand the below logic
	 */
	switch (key_sz) {
	case AES_KEYSIZE_128:
	case AES_KEYSIZE_192:
		key_pos = key_sz + 24;
		break;

	case AES_KEYSIZE_256:
		key_pos = key_sz + 24 - 4;
		break;

	default:
		pr_err("%s: bad key len(%d)\n", __func__, key_sz);
		return -1;
	}

	memcpy(inv_key, &ctx.key_enc[key_pos], key_sz);
	return 0;
}

/* Set Security context for the encryption engine */
int sa_set_sc_enc(u16 alg_id, const u8 *key, u16 key_sz,
		  u16 aad_len, u8 enc, u8 *sc_buf)
{
	u8 ghash[16]; /* AES block size */
	const u8 *mci = NULL;
	/* Convert the key size (16/24/32) to the key size index (0/1/2) */
	int key_idx = (key_sz >> 3) - 2;

	/* Set Encryption mode selector to crypto processing */
	sc_buf[0] = 0;

	/* Select the mode control instruction */
	switch (alg_id) {
	case SA_EALG_ID_AES_CBC:
		mci = (enc) ? sa_mci_tbl.aes_enc[SA_ENG_ALGO_CBC][key_idx] :
			sa_mci_tbl.aes_dec[SA_ENG_ALGO_CBC][key_idx];
		break;

	case SA_EALG_ID_CCM:
		mci = (enc) ? sa_mci_tbl.aes_enc[SA_ENG_ALGO_CCM][key_idx] :
			sa_mci_tbl.aes_dec[SA_ENG_ALGO_CCM][key_idx];
		break;

	case SA_EALG_ID_AES_F8:
		mci = sa_mci_tbl.aes_enc[SA_ENG_ALGO_F8][key_idx];
		break;

	case SA_EALG_ID_AES_CTR:
		mci = sa_mci_tbl.aes_enc[SA_ENG_ALGO_CTR][key_idx];
		break;

	case SA_EALG_ID_GCM:
		aad_len = 8;	/* Default AAD size is 8 */

		mci = (enc) ? sa_mci_tbl.aes_enc[SA_ENG_ALGO_GCM][key_idx] :
			sa_mci_tbl.aes_dec[SA_ENG_ALGO_GCM][key_idx];
		/* Set AAD length at byte offset 23 in Aux-1 */
		sc_buf[SC_ENC_AUX1_OFFSET + 23] = (aad_len << 3);
		/* fall through to GMAC for hash */

	case SA_AALG_ID_GMAC:
		if (alg_id == SA_AALG_ID_GMAC)
			mci = sa_mci_tbl.aes_enc[SA_ENG_ALGO_GMAC][key_idx];

		sa_calc_ghash(key, (key_sz << 3), ghash);
		/* copy GCM Hash in Aux-1 */
		memcpy(&sc_buf[SC_ENC_AUX1_OFFSET], ghash, 16);
		break;

	case SA_AALG_ID_AES_XCBC:
	case SA_AALG_ID_CMAC:
		mci = sa_mci_tbl.aes_enc[SA_ENG_ALGO_CMAC][key_idx];
		break;

	case SA_AALG_ID_CBC_MAC:
		mci = sa_mci_tbl.aes_enc[SA_ENG_ALGO_CBCMAC][key_idx];
		break;

	case SA_EALG_ID_3DES_CBC:
		mci = (enc) ? sa_mci_tbl._3des_enc[SA_ENG_ALGO_CBC] :
			sa_mci_tbl._3des_dec[SA_ENG_ALGO_CBC];
		break;
	}

	/* Set the mode control instructions in security context */
	if (mci)
		memcpy(&sc_buf[1], mci, 27);

	/* For AES-CBC decryption get the inverse key */
	if ((alg_id == SA_EALG_ID_AES_CBC) && !enc) {
		if (sa_aes_inv_key(&sc_buf[SC_ENC_KEY_OFFSET], key, key_sz))
			return -1;
	}
	/* For AES-XCBC-MAC get the subkey */
	else if (alg_id == SA_AALG_ID_AES_XCBC) {
		if (sa_aes_xcbc_subkey(&sc_buf[SC_ENC_KEY_OFFSET], NULL,
				       NULL, key, key_sz))
			return -1;
	}
	/* For all other cases: key is used */
	else
		memcpy(&sc_buf[SC_ENC_KEY_OFFSET], key, key_sz);

	return 0;
}

/* Set Security context for the authentication engine */
void sa_set_sc_auth(u16 alg_id, const u8 *key, u16 key_sz, u8 *sc_buf)
{
	u32 ipad[8], opad[8];
	u8 mac_sz, keyed_mac = 0;

	/* Set Authentication mode selector to hash processing */
	sc_buf[0] = 0;

	/* Auth SW ctrl word: bit[6]=1 (upload computed hash to TLR section) */
	sc_buf[1] = 0x40;

	switch (alg_id) {
	case SA_AALG_ID_MD5:
		/*
		 * Auth SW ctrl word: bit[4]=1 (basic hash)
		 * bit[3:0]=1 (MD5 operation)
		 */
		sc_buf[1] |= (0x10 | 0x1);
		break;

	case SA_AALG_ID_SHA1:
		/*
		 * Auth SW ctrl word: bit[4]=1 (basic hash)
		 * bit[3:0]=2 (SHA1 operation)
		 */
		sc_buf[1] |= (0x10 | 0x2);
		break;

	case SA_AALG_ID_SHA2_224:
		/*
		 * Auth SW ctrl word: bit[4]=1 (basic hash)
		 * bit[3:0]=3 (SHA2-224 operation)
		 */
		sc_buf[1] |= (0x10 | 0x3);
		break;

	case SA_AALG_ID_SHA2_256:
		/*
		 * Auth SW ctrl word: bit[4]=1 (basic hash)
		 * bit[3:0]=4 (SHA2-256 operation)
		 */
		sc_buf[1] |= (0x10 | 0x4);
		break;

	case SA_AALG_ID_HMAC_MD5:
		/*
		 * Auth SW ctrl word: bit[4]=0 (HMAC)
		 * bit[3:0]=1 (MD5 operation)
		 */
		sc_buf[1] |= 0x1;
		keyed_mac = 1;
		mac_sz = MD5_DIGEST_SIZE;
		sa_hmac_md5_get_pad(key, key_sz, ipad, opad);
		break;

	case SA_AALG_ID_HMAC_SHA1:
		/*
		 * Auth SW ctrl word: bit[4]=0 (HMAC)
		 * bit[3:0]=2 (SHA1 operation)
		 */
		sc_buf[1] |= 0x2;
		keyed_mac = 1;
		mac_sz = SHA1_DIGEST_SIZE;
		sa_hmac_sha1_get_pad(key, key_sz, ipad, opad);
		break;

	case SA_AALG_ID_HMAC_SHA2_224:
		/*
		 * Auth SW ctrl word: bit[4]=0 (HMAC)
		 * bit[3:0]=3 (SHA2-224 operation)
		 */
		sc_buf[1] |= 0x3;
		keyed_mac = 1;
		mac_sz = SHA224_DIGEST_SIZE;
		break;

	case SA_AALG_ID_HMAC_SHA2_256:
		/*
		 * Auth SW ctrl word: bit[4]=0 (HMAC)
		 * bit[3:0]=4 (SHA2-256 operation)
		 */
		sc_buf[1] |= 0x4;
		keyed_mac = 1;
		mac_sz = SHA256_DIGEST_SIZE;
		sa_hmac_sha256_get_pad(key, key_sz, ipad, opad);
		break;
	}

	/* Copy the keys or ipad/opad */
	if (keyed_mac) {
		/* Copy ipad to AuthKey */
		memcpy(&sc_buf[32], ipad, mac_sz);
		/* Copy opad to Aux-1 */
		memcpy(&sc_buf[64], opad, mac_sz);
	}
}
