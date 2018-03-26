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

#include <linux/interrupt.h>
#include <linux/dmapool.h>
#include <linux/delay.h>
#include <linux/platform_device.h>
#include <linux/soc/ti/knav_dma.h>
#include <linux/soc/ti/knav_qmss.h>

#include <linux/crypto.h>
#include <crypto/algapi.h>
#include <crypto/aead.h>
#include <crypto/internal/aead.h>
#include <crypto/authenc.h>
#include <crypto/des.h>
#include <crypto/sha.h>
#include <crypto/scatterwalk.h>

#include "keystone-sa.h"
#include "keystone-sa-hlp.h"

#define SA_SW0_EVICT_FL_SHIFT	16
#define SA_SW0_TEAR_FL_SHIFT	17
#define SA_SW0_NOPAYLD_FL_SHIFT	18
#define SA_SW0_CMDL_INFO_SHIFT	20
#define SA_SW0_ENG_ID_SHIFT	25
#define SA_SW0_CPPI_DST_INFO_PRESENT	BIT(30)
#define SA_CMDL_PRESENT		BIT(4)

#define SA_SW2_EGRESS_CPPI_FLOW_ID_SHIFT	16
#define SA_SW2_EGRESS_CPPI_STATUS_LEN_SHIFT	24

#define SA_CMDL_UPD_ENC		0x0001
#define SA_CMDL_UPD_AUTH	0x0002
#define SA_CMDL_UPD_ENC_IV	0x0004
#define SA_CMDL_UPD_AUTH_IV	0x0008
#define SA_CMDL_UPD_AUX_KEY	0x0010

/* Command label parameters for GCM */
#define SA_CMDL_UPD_ENC_SIZE	0x0080
#define SA_CMDL_UPD_AAD			0x0010

/* size of SCCTL structure in bytes */
#define SA_SCCTL_SZ 8

/* Tear down the Security Context */
#define SA_SC_TEAR_RETRIES	5
#define SA_SC_TEAR_DELAY	20 /* msecs */

/*	Algorithm interface functions & templates	*/
struct sa_alg_tmpl {
	u32 type; /* CRYPTO_ALG_TYPE from <linux/crypto.h> */
	union {
		struct crypto_alg crypto;
		struct aead_alg aead;
	} alg;
	bool registered;
};

/* Number of elements in scatterlist */
static int sg_count(struct scatterlist *sg, int len)
{
	int sg_nents = 0;

	while (sg && (len > 0)) {
		sg_nents++;
		len -= sg->length;
		sg = sg_next(sg);
	}
	return sg_nents;
}

/* buffer capacity of scatterlist */
static int sg_len(struct scatterlist *sg)
{
	int len = 0;

	while (sg) {
		len += sg->length;
		sg = sg_next(sg);
	}
	return len;
}
/* Copy buffer content from list of hwdesc-s to DST SG list */
static int sa_hwdesc2sg_copy(struct knav_dma_desc **hwdesc,
			     struct scatterlist *dst,
			     unsigned int src_offset, unsigned int dst_offset,
			     size_t len, int num)
{
	struct scatter_walk walk;
	int sglen, cplen;
	int j = 0;

	sglen = hwdesc[0]->desc_info & KNAV_DMA_DESC_PKT_LEN_MASK;

	if (unlikely(len + src_offset > sglen)) {
		pr_err("[%s] src len(%d) less than (%d)\n", __func__,
		       sglen, len + src_offset);
		return -EINVAL;
	}

	sglen = sg_len(dst);
	if (unlikely(len + dst_offset > sglen)) {
		pr_err("[%s] dst len(%d) less than (%d)\n", __func__,
		       sglen, len + dst_offset);
		return -EINVAL;
	}

	scatterwalk_start(&walk, dst);
	scatterwalk_advance(&walk, dst_offset);
	while ((j < num) && (len > 0)) {
		cplen = min((int)len, (int)(hwdesc[j]->buff_len - src_offset));
		if (likely(cplen)) {
			scatterwalk_copychunks(((char *)hwdesc[j]->sw_data[0] +
						   src_offset),
						  &walk, cplen, 1);
		}
		len -= cplen;
		j++;
		src_offset = 0;
	}
	return 0;
}

static void scatterwalk_copy(void *buf, struct scatterlist *sg,
			     unsigned int start, unsigned int nbytes, int out)
{
	struct scatter_walk walk;
	unsigned int offset = 0;

	if (!nbytes)
		return;

	for (;;) {
		scatterwalk_start(&walk, sg);

		if (start < offset + sg->length)
			break;

		offset += sg->length;
		sg = sg_next(sg);
	}

	scatterwalk_advance(&walk, start - offset);
	scatterwalk_copychunks(buf, &walk, nbytes, out);
}

/* Command Label Definitions and utility functions */
struct sa_cmdl_cfg {
	int	enc1st;
	int	aalg;
	u8	enc_eng_id;
	u8	auth_eng_id;
	u8	iv_size;
	const u8 *akey;
	u16	akey_len;
	u32	salt;
};

/* Format general command label */
static int sa_format_cmdl_gen(struct sa_cmdl_cfg *cfg, u8 *cmdl,
			      struct sa_cmdl_upd_info *upd_info)
{
	u8 offset = 0;
	u32 *word_ptr = (u32 *)cmdl;
	int i;
	int ret = 0;

	/* Clear the command label */
	memset(cmdl, 0, (SA_MAX_CMDL_WORDS * sizeof(u32)));

	/* Iniialize the command update structure */
	memset(upd_info, 0, sizeof(*upd_info));
	upd_info->enc_size.offset = 2;
	upd_info->enc_size.size = 2;
	upd_info->enc_offset.size = 1;
	upd_info->enc_size2.size = 4;
	upd_info->auth_size.offset = 2;
	upd_info->auth_size.size = 2;
	upd_info->auth_offset.size = 1;

	if (cfg->aalg == SA_AALG_ID_AES_XCBC) {
		/* Derive K2/K3 subkeys */
		ret = sa_aes_xcbc_subkey(NULL, (u8 *)&upd_info->aux_key[0],
					 (u8 *)&upd_info->aux_key[AES_BLOCK_SIZE
					 / sizeof(u32)],
					 cfg->akey, cfg->akey_len);
		if (ret)
			return ret;

		/*
		 * Format the key into 32bit CPU words
		 * from a big-endian stream
		 */
		for (i = 0; i < SA_MAX_AUX_DATA_WORDS; i++)
			upd_info->aux_key[i] =
				be32_to_cpu(upd_info->aux_key[i]);
	}

	if (cfg->enc1st) {
		if (cfg->enc_eng_id != SA_ENG_ID_NONE) {
			upd_info->flags |= SA_CMDL_UPD_ENC;
			upd_info->enc_size.index = 0;
			upd_info->enc_offset.index = 1;

			if ((cfg->enc_eng_id == SA_ENG_ID_EM1) &&
			    (cfg->auth_eng_id == SA_ENG_ID_EM1))
				cfg->auth_eng_id = SA_ENG_ID_EM2;

			/* Encryption command label */
			if (cfg->auth_eng_id != SA_ENG_ID_NONE)
				cmdl[SA_CMDL_OFFSET_NESC] = cfg->auth_eng_id;
			else
				cmdl[SA_CMDL_OFFSET_NESC] = SA_ENG_ID_OUTPORT2;

			/* Encryption modes requiring IV */
			if (cfg->iv_size) {
				upd_info->flags |= SA_CMDL_UPD_ENC_IV;
				upd_info->enc_iv.index =
					SA_CMDL_HEADER_SIZE_BYTES >> 2;
				upd_info->enc_iv.size = cfg->iv_size;

				cmdl[SA_CMDL_OFFSET_LABEL_LEN] =
					SA_CMDL_HEADER_SIZE_BYTES +
					cfg->iv_size;

				cmdl[SA_CMDL_OFFSET_OPTION_CTRL1] =
					(SA_CTX_ENC_AUX2_OFFSET |
					 (cfg->iv_size >> 3));

				offset = SA_CMDL_HEADER_SIZE_BYTES +
						cfg->iv_size;
			} else {
				cmdl[SA_CMDL_OFFSET_LABEL_LEN] =
					SA_CMDL_HEADER_SIZE_BYTES;
				offset = SA_CMDL_HEADER_SIZE_BYTES;
			}
		}

		if (cfg->auth_eng_id != SA_ENG_ID_NONE) {
			upd_info->flags |= SA_CMDL_UPD_AUTH;
			upd_info->auth_size.index = offset >> 2;
			upd_info->auth_offset.index =
				upd_info->auth_size.index + 1;

			cmdl[offset + SA_CMDL_OFFSET_NESC] = SA_ENG_ID_OUTPORT2;

			/* Algorithm with subkeys */
			if ((cfg->aalg == SA_AALG_ID_AES_XCBC) ||
			    (cfg->aalg == SA_AALG_ID_CMAC)) {
				upd_info->flags |= SA_CMDL_UPD_AUX_KEY;
				upd_info->aux_key_info.index =
				(offset + SA_CMDL_HEADER_SIZE_BYTES) >> 2;

				cmdl[offset + SA_CMDL_OFFSET_LABEL_LEN] =
					SA_CMDL_HEADER_SIZE_BYTES + 16;
				cmdl[offset + SA_CMDL_OFFSET_OPTION_CTRL1] =
					(SA_CTX_ENC_AUX1_OFFSET | (16 >> 3));

				offset += SA_CMDL_HEADER_SIZE_BYTES + 16;
			} else {
				cmdl[offset + SA_CMDL_OFFSET_LABEL_LEN] =
					SA_CMDL_HEADER_SIZE_BYTES;
				offset += SA_CMDL_HEADER_SIZE_BYTES;
			}
		}
	} else {
		/* Auth first */
		if (cfg->auth_eng_id != SA_ENG_ID_NONE) {
			upd_info->flags |= SA_CMDL_UPD_AUTH;
			upd_info->auth_size.index = 0;
			upd_info->auth_offset.index = 1;

			if ((cfg->auth_eng_id == SA_ENG_ID_EM1) &&
			    (cfg->enc_eng_id == SA_ENG_ID_EM1))
				cfg->enc_eng_id = SA_ENG_ID_EM2;

			/* Authentication command label */
			if (cfg->enc_eng_id != SA_ENG_ID_NONE)
				cmdl[SA_CMDL_OFFSET_NESC] = cfg->enc_eng_id;
			else
				cmdl[SA_CMDL_OFFSET_NESC] = SA_ENG_ID_OUTPORT2;

			/* Algorithm with subkeys */
			if ((cfg->aalg == SA_AALG_ID_AES_XCBC) ||
			    (cfg->aalg == SA_AALG_ID_CMAC)) {
				upd_info->flags |= SA_CMDL_UPD_AUX_KEY;
				upd_info->aux_key_info.index =
					(SA_CMDL_HEADER_SIZE_BYTES) >> 2;

				cmdl[SA_CMDL_OFFSET_LABEL_LEN] =
					SA_CMDL_HEADER_SIZE_BYTES + 16;
				cmdl[offset + SA_CMDL_OFFSET_OPTION_CTRL1] =
					(SA_CTX_ENC_AUX1_OFFSET | (16 >> 3));

				offset = SA_CMDL_HEADER_SIZE_BYTES + 16;
			} else {
				cmdl[SA_CMDL_OFFSET_LABEL_LEN] =
					SA_CMDL_HEADER_SIZE_BYTES;
				offset = SA_CMDL_HEADER_SIZE_BYTES;
			}
		}

		if (cfg->enc_eng_id != SA_ENG_ID_NONE) {
			upd_info->flags |= SA_CMDL_UPD_ENC;
			upd_info->enc_size.index = offset >> 2;
			upd_info->enc_offset.index =
				upd_info->enc_size.index + 1;

			cmdl[offset + SA_CMDL_OFFSET_NESC] = SA_ENG_ID_OUTPORT2;

			/* Encryption modes requiring IV */
			if (cfg->iv_size) {
				upd_info->flags |= SA_CMDL_UPD_ENC_IV;
				upd_info->enc_iv.index =
				(offset + SA_CMDL_HEADER_SIZE_BYTES) >> 2;
				upd_info->enc_iv.size = cfg->iv_size;

				cmdl[offset + SA_CMDL_OFFSET_LABEL_LEN] =
				SA_CMDL_HEADER_SIZE_BYTES + cfg->iv_size;

				cmdl[offset + SA_CMDL_OFFSET_OPTION_CTRL1] =
				(SA_CTX_ENC_AUX2_OFFSET | (cfg->iv_size >> 3));

				offset += SA_CMDL_HEADER_SIZE_BYTES +
						cfg->iv_size;
			} else {
				cmdl[offset + SA_CMDL_OFFSET_LABEL_LEN] =
					SA_CMDL_HEADER_SIZE_BYTES;
				offset += SA_CMDL_HEADER_SIZE_BYTES;
			}
		}
	}

	offset = roundup(offset, 8);

	for (i = 0; i < offset / 4; i++)
		word_ptr[i] = be32_to_cpu(word_ptr[i]);

	return offset;
}

/*
 * Format GCM command label
 *
 *   1-Command Header (4 Bytes)
 *              -  NESC (1 byte)
 *              -  Cmdl Len (1 byte)
 *              -  Payload Size (2 bytes)
 *
 *   2 - Control information (4 bytes)
 *               - Offset (1 bytes)
 *               - Opt Ctrl1 (1 bytes)
 *               - Opt Ctrl2 (1 byte)
 *               - Opt Ctrl3 (1 byte)
 *
 *   3 - Option 1  - Total Encryption Length (8 bytes)
 *
 *   4 - Option 2: AAD (16 bytes)
 *
 *   5 - Option 3: AES-CTR IV (salt (4 bytes) | IV (16 bytes) | 1)
 */
static int sa_format_cmdl_gcm(struct sa_cmdl_cfg *cfg, u8 *cmdl,
			      struct sa_cmdl_upd_info *upd_info)
{
	u8 offset = 0;
	u32 *word_ptr = (u32 *)cmdl;
	int i;

	/* Clear the command label */
	memset(cmdl, 0, (SA_MAX_CMDL_WORDS * sizeof(u32)));

	if (upd_info->submode == SA_MODE_GCM) {
		/* Construct Command label header */
		cmdl[SA_CMDL_OFFSET_NESC] = SA_ENG_ID_FINAL;
		cmdl[SA_CMDL_OFFSET_LABEL_LEN] = SA_GCM_SIZE;
		cmdl[SA_CMDL_OFFSET_OPTION_CTRL1] = SA_GCM_OPT1;
		cmdl[SA_CMDL_OFFSET_OPTION_CTRL2] = SA_GCM_OPT2;
		cmdl[SA_CMDL_OFFSET_OPTION_CTRL3] = SA_GCM_OPT3;

		/* Option 1: Total Encryption Length (8 bytes) */

		/* Option 2: AAD (16 bytes) */

		/* Option 3: AES-CTR IV (salt (4 bytes) | IV (8 bytes) | 0x1) */
		/* Fill in the Salt Value */
		word_ptr[8] = cfg->salt;

		/*
		 * Format the Command label into 32bit CPU words
		 * from a big-endian stream
		 */
		offset = roundup(SA_GCM_SIZE, 8);

		for (i = 0; i < offset/4; i++)
			word_ptr[i] = be32_to_cpu(word_ptr[i]);

		word_ptr[11] = 1;
		return offset;
	} else if (upd_info->submode == SA_MODE_GMAC) {
		/* Construct Command label header */
		cmdl[SA_CMDL_OFFSET_NESC]         = SA_ENG_ID_FINAL;
		cmdl[SA_CMDL_OFFSET_LABEL_LEN]    = SA_GMAC_SIZE;
		cmdl[SA_CMDL_OFFSET_OPTION_CTRL1] = SA_GMAC_OPT1;
		cmdl[SA_CMDL_OFFSET_OPTION_CTRL2] = SA_GMAC_OPT2;
		cmdl[SA_CMDL_OFFSET_OPTION_CTRL3] = SA_GMAC_OPT3;

		/* Option 1: Total Authentication + Payload Length (8 bytes) */

		/* Option 2: AAD | Payload (16 bytes) */

		/* Option 3: AES-CTR IV (salt (4 bytes) | IV (8 bytes) | 0x1) */
		/* Fill in the Salt Value */
		word_ptr[8] = cfg->salt;

		/*
		 * Format the Command label into 32bit CPU words
		 * from a big-endian stream
		 */
		offset = roundup(SA_GMAC_SIZE, 8);
		for (i = 0; i < offset/4; i++)
			word_ptr[i] = be32_to_cpu(word_ptr[i]);

		word_ptr[11] = 1;
		return offset;
	}

	dev_err(sa_ks2_dev, "(%s): Unsupported mode\n", __func__);
	return -1;
}

static inline void sa_copy_iv(u32 *out, const u8 *iv, bool size16)
{
	int j;

	for (j = 0; j < ((size16) ? 4 : 2); j++) {
		*out = cpu_to_be32(*((u32 *)iv));
		iv += 4;
		out++;
	}
}

/* Update Command label */
static inline void
sa_update_cmdl(struct device *dev, u8 enc_offset, u16 enc_size,	u8 *enc_iv,
	       u16 auth_size, u8 *auth_iv, u8 aad_size,
	       u8 *aad,	struct sa_cmdl_upd_info	*upd_info, u32 *cmdl)
{
	switch (upd_info->submode) {
	case SA_MODE_GEN:
		if (likely(upd_info->flags & SA_CMDL_UPD_ENC)) {
			cmdl[upd_info->enc_size.index] &= 0xffff0000;
			cmdl[upd_info->enc_size.index] |= enc_size;
			cmdl[upd_info->enc_offset.index] &= 0x00ffffff;
			cmdl[upd_info->enc_offset.index] |=
						((u32)enc_offset << 24);

			if (likely(upd_info->flags & SA_CMDL_UPD_ENC_IV)) {
				sa_copy_iv(&cmdl[upd_info->enc_iv.index],
					   enc_iv,
					   (upd_info->enc_iv.size > 8));
			}
		}

		if (likely(upd_info->flags & SA_CMDL_UPD_AUTH)) {
			cmdl[upd_info->auth_size.index] &= 0xffff0000;
			cmdl[upd_info->auth_size.index] |= auth_size;
			cmdl[upd_info->auth_offset.index] &= 0x00ffffff;
			cmdl[upd_info->auth_offset.index] |= 0;

			if (upd_info->flags & SA_CMDL_UPD_AUTH_IV) {
				sa_copy_iv(&cmdl[upd_info->auth_iv.index],
					   auth_iv,
					   (upd_info->auth_iv.size > 8));
			}

			if (upd_info->flags & SA_CMDL_UPD_AUX_KEY) {
				int offset = (auth_size & 0xF) ? 4 : 0;

				memcpy(&cmdl[upd_info->aux_key_info.index],
				       &upd_info->aux_key[offset], 16);
			}
		}
		break;

	case SA_MODE_GCM:
		/* Update  Command label header (8 bytes) */
		cmdl[0] |= enc_size;
		cmdl[1] |= (enc_offset << 24);

		/* Option 1: Store encryption length (8 byte) */
		cmdl[3] |= (enc_size << 3);

		/* Option 2: Store AAD with zero padding (16 bytes) */
		cmdl[4] = SA_MK_U32(aad[0], aad[1], aad[2], aad[3]);
		cmdl[5] = SA_MK_U32(aad[4], aad[5], aad[6], aad[7]);

		/* ESN */
		if (aad_size == 12) {
			cmdl[6] =
				SA_MK_U32(aad[8], aad[9], aad[10], aad[11]);
		}

		/* Option 3: AES CTR IV (salt|IV|1) */
		cmdl[9] = SA_MK_U32(enc_iv[0], enc_iv[1], enc_iv[2], enc_iv[3]);
		cmdl[10] = SA_MK_U32(enc_iv[4], enc_iv[5], enc_iv[6], enc_iv[7]);
		break;

	case SA_MODE_GMAC:
		/* Update  Command label header (8 bytes) */

		/* Auth offset - 16 bytes */
		cmdl[1] |= (16 << 24);

		/* Option 1: Store Authentication length (8 byte) */
		cmdl[3] |= (auth_size << 3);/* Payload Length + AAD + IV */

		/* Option 2: Store AAD with zero padding (16 bytes) */
		cmdl[4] = SA_MK_U32(aad[0], aad[1], aad[2], aad[3]);
		cmdl[5] = SA_MK_U32(aad[4], aad[5], aad[6], aad[7]);

		/* ESN */
		if (aad_size == 12) {

			/* Payload Length + Remaining IV Size */
			cmdl[0] |= enc_size + 4;

			cmdl[6] = SA_MK_U32(aad[8], aad[9], aad[10], aad[11]);
			cmdl[7] = SA_MK_U32(enc_iv[0], enc_iv[1],
					    enc_iv[2], enc_iv[3]);
		} else {

			/* Payload Length */
			cmdl[0] |= enc_size;

			/* Append IV */
			cmdl[6] = SA_MK_U32(enc_iv[0], enc_iv[1],
					enc_iv[2], enc_iv[3]);
			cmdl[7] = SA_MK_U32(enc_iv[4], enc_iv[5],
					enc_iv[6], enc_iv[7]);
		}

		/* Option 3: AES CTR IV (salt|IV|1) */
		cmdl[9] = SA_MK_U32(enc_iv[0], enc_iv[1],
				    enc_iv[2], enc_iv[3]);
		cmdl[10] = SA_MK_U32(enc_iv[4], enc_iv[5],
				     enc_iv[6], enc_iv[7]);
		break;

	case SA_MODE_CCM:
	default:
		dev_err(dev, "unsupported mode(%d)\n", upd_info->submode);
		break;
	}
}

/* Format SWINFO words to be sent to SA */
static
void sa_set_swinfo(u8 eng_id, u16 sc_id, dma_addr_t sc_phys,
		   u8 cmdl_present, u8 cmdl_offset, u8 flags, u16 queue_id,
		   u8 flow_id, u8 hash_size, u32 *swinfo)
{
	swinfo[0] = sc_id;
	swinfo[0] |= (flags << SA_SW0_EVICT_FL_SHIFT);
	if (likely(cmdl_present))
		swinfo[0] |= ((cmdl_offset | SA_CMDL_PRESENT) <<
			      SA_SW0_CMDL_INFO_SHIFT);
	swinfo[0] |= (eng_id << SA_SW0_ENG_ID_SHIFT);
	swinfo[0] |= SA_SW0_CPPI_DST_INFO_PRESENT;
	swinfo[1] = sc_phys;
	swinfo[2] = (queue_id | (flow_id << SA_SW2_EGRESS_CPPI_FLOW_ID_SHIFT) |
		     (hash_size << SA_SW2_EGRESS_CPPI_STATUS_LEN_SHIFT));
}

/* Security context creation functions */

/* Dump the security context */
static void sa_dump_sc(u8 *buf, u32 dma_addr)
{
#ifdef DEBUG
	dev_info(sa_ks2_dev, "Security context dump for %p:\n",
		 (void *)dma_addr);
	print_hex_dump(KERN_CONT, "", DUMP_PREFIX_OFFSET,
		       16, 1, buf, SA_CTX_MAX_SZ, false);
#endif
}

/* Initialize Security context */
static
int sa_init_sc(struct sa_ctx_info *ctx, const u8 *enc_key,
	       u16 enc_key_sz, const u8 *auth_key, u16 auth_key_sz,
	       const char *cra_name, u8 enc,
	       u32 *swinfo)
{
	struct sa_eng_info *enc_eng, *auth_eng;
	int ealg_id, aalg_id, use_enc = 0;
	int enc_sc_offset, auth_sc_offset;
	u8 php_f, php_e, eng0_f, eng1_f;
	u8 *sc_buf = ctx->sc;
	u16 sc_id = ctx->sc_id;
	u16 aad_len = 0; /* Currently not supporting AEAD algo */
	u8 first_engine;
	u8 hash_size;
	int ret = 0;

	memset(sc_buf, 0, SA_CTX_MAX_SZ);
	sa_conv_calg_to_salg(cra_name, &ealg_id, &aalg_id);
	enc_eng = sa_get_engine_info(ealg_id);
	auth_eng = sa_get_engine_info(aalg_id);

	if (!enc_eng->sc_size && !auth_eng->sc_size)
		return -EINVAL;

	if (auth_eng->eng_id <= SA_ENG_ID_EM2)
		use_enc = 1;

	/* Determine the order of encryption & Authentication contexts */
	if (enc || !use_enc) {
		if (aalg_id == SA_AALG_ID_GMAC) {
			eng0_f = SA_CTX_SIZE_TO_DMA_SIZE(auth_eng->sc_size);
			eng1_f = SA_CTX_SIZE_TO_DMA_SIZE(enc_eng->sc_size);
		} else {
			eng0_f = SA_CTX_SIZE_TO_DMA_SIZE(enc_eng->sc_size);
			eng1_f = SA_CTX_SIZE_TO_DMA_SIZE(auth_eng->sc_size);
		}
		enc_sc_offset = SA_CTX_PHP_PE_CTX_SZ;
		auth_sc_offset = enc_sc_offset + enc_eng->sc_size;
	} else {
		eng0_f = SA_CTX_SIZE_TO_DMA_SIZE(auth_eng->sc_size);
		eng1_f = SA_CTX_SIZE_TO_DMA_SIZE(enc_eng->sc_size);
		auth_sc_offset = SA_CTX_PHP_PE_CTX_SZ;
		enc_sc_offset = auth_sc_offset + auth_eng->sc_size;
	}

	php_f = SA_CTX_DMA_SIZE_64;
	php_e = SA_CTX_DMA_SIZE_64;

	/* SCCTL Owner info: 0=host, 1=CP_ACE */
	sc_buf[SA_CTX_SCCTL_OWNER_OFFSET] = 0;
	/* SCCTL F/E control */
	sc_buf[1] = SA_CTX_SCCTL_MK_DMA_INFO(php_f, eng0_f, eng1_f, php_e);

	memcpy(&sc_buf[2], &sc_id, 2);
	memcpy(&sc_buf[4], &ctx->sc_phys, 4);

	/* Initialize the rest of PHP context */
	memset(sc_buf + SA_SCCTL_SZ, 0, SA_CTX_PHP_PE_CTX_SZ - SA_SCCTL_SZ);

	/* Prepare context for encryption engine */
	if (enc_eng->sc_size) {
		ret = sa_set_sc_enc(ealg_id, enc_key, enc_key_sz, aad_len,
				    enc, &sc_buf[enc_sc_offset]);
		if (ret)
			return ret;
	}

	/* Prepare context for authentication engine */
	if (auth_eng->sc_size) {
		if (use_enc) {
			if (sa_set_sc_enc(aalg_id, auth_key, auth_key_sz,
					  aad_len, 0, &sc_buf[auth_sc_offset]))
				return -1;
		} else
			sa_set_sc_auth(aalg_id, auth_key, auth_key_sz,
				       &sc_buf[auth_sc_offset]);
	}

	/* Set the ownership of context to CP_ACE */
	sc_buf[SA_CTX_SCCTL_OWNER_OFFSET] = 0x80;

	/* swizzle the security context */
	sa_swiz_128(sc_buf, sc_buf, SA_CTX_MAX_SZ);

	/* Setup SWINFO */
	if (ealg_id == SA_EALG_ID_GCM) {
		/* For GCM enc and dec performed by same engine */
		first_engine = enc_eng->eng_id;
	} else if ((ealg_id == SA_EALG_ID_NULL) ||
				(ealg_id == SA_EALG_ID_NONE))
		first_engine = auth_eng->eng_id;
	else
		first_engine = enc ? enc_eng->eng_id : auth_eng->eng_id;

	hash_size = AES_BLOCK_SIZE;
	if (aalg_id != SA_AALG_ID_NONE) {
		hash_size = sa_get_hash_size(aalg_id);
		if (!hash_size)
			return -EINVAL;
	}

	/* Round up the tag size to multiple of 8 */
	hash_size = roundup(hash_size, 8);

	sa_set_swinfo(first_engine, ctx->sc_id, ctx->sc_phys, 1, 0,
	/*
	 * For run-time self tests in the cryptographic
	 * algorithm manager framework the EVICT flag is required.
	 * EVICT is also required if the key gets changed for the context.
	 */
		      SA_SW_INFO_FLAG_EVICT,
		      ctx->rx_compl_qid, ctx->rx_flow, hash_size, swinfo);

	sa_dump_sc(sc_buf, ctx->sc_phys);

	return 0;
}

static int sa_tear_sc(struct sa_ctx_info *ctx,
		      struct keystone_crypto_data *pdata)
{
	struct device *dev = &pdata->pdev->dev;
	int own_off, cnt = SA_SC_TEAR_RETRIES;
	struct knav_dma_desc *hwdesc;
	struct sa_dma_req_ctx *dma_ctx;
	int ret = 0;
	u32 packet_info;
	int j;
	dma_addr_t dma_addr;
	u32 dma_sz;

	dma_ctx = kmem_cache_alloc(pdata->dma_req_ctx_cache, GFP_KERNEL);
	if (!dma_ctx) {
		ret = -ENOMEM;
		goto err;
	}

	dma_ctx->dev_data = pdata;
	dma_ctx->pkt = false;

	sa_set_swinfo(SA_ENG_ID_OUTPORT2, ctx->sc_id, ctx->sc_phys, 0, 0,
		      (SA_SW_INFO_FLAG_TEAR | SA_SW_INFO_FLAG_EVICT |
		       SA_SW_INFO_FLAG_NOPD),
		      ctx->rx_compl_qid, ctx->rx_flow, 0, &ctx->epib[1]);

	ctx->epib[0] = 0;

	/* map the packet */
	packet_info = KNAV_DMA_DESC_HAS_EPIB |
		(pdata->tx_compl_qid << KNAV_DMA_DESC_RETQ_SHIFT);

	hwdesc = knav_pool_desc_get(pdata->tx_pool);
	if (IS_ERR_OR_NULL(hwdesc)) {
		dev_dbg(dev, "out of tx pool desc\n");
		ret = -ENOBUFS;
		goto err;
	}

	memset(hwdesc, 0, sizeof(struct knav_dma_desc));
	for (j = 0; j < 4; j++)
		hwdesc->epib[j] = ctx->epib[j];

	hwdesc->packet_info  = packet_info;

	knav_pool_desc_map(pdata->tx_pool, hwdesc, sizeof(hwdesc),
			   &dma_addr, &dma_sz);

	hwdesc->sw_data[0] = (u32)dma_addr;
	hwdesc->sw_data[1] = dma_sz;
	hwdesc->sw_data[2] = (u32)dma_ctx;

	knav_queue_push(pdata->tx_submit_q, dma_addr,
			sizeof(struct knav_dma_desc), 0);

	/*
	 * Check that CP_ACE has released the context
	 * by making sure that the owner bit is 0
	 */
	/*
	 * Security context had been swizzled by 128 bits
	 * before handing to CP_ACE
	 */
	own_off = ((SA_CTX_SCCTL_OWNER_OFFSET / 16) * 16)
		+ (15 - (SA_CTX_SCCTL_OWNER_OFFSET % 16));
	while (__raw_readb(&ctx->sc[own_off])) {
		if (!--cnt)
			return -EAGAIN;
		msleep_interruptible(SA_SC_TEAR_DELAY);
	}
	return 0;

err:
	atomic_inc(&pdata->stats.sc_tear_dropped);
	if (dma_ctx)
		kmem_cache_free(pdata->dma_req_ctx_cache, dma_ctx);
	return ret;
}

/* Free the per direction context memory */
static int sa_free_ctx_info(struct sa_ctx_info *ctx,
			     struct keystone_crypto_data *data)
{
	unsigned long bn;
	int	ret = 0;

	ret = sa_tear_sc(ctx, data);
	if (ret) {
		dev_err(sa_ks2_dev,
			"Failed to tear down context id(%x)\n", ctx->sc_id);
		return ret;
	}

	bn = ctx->sc_id - data->sc_id_start;
	spin_lock(&data->scid_lock);
	__clear_bit(bn, data->ctx_bm);
	data->sc_id--;
	spin_unlock(&data->scid_lock);

	if (ctx->sc) {
		dma_pool_free(data->sc_pool, ctx->sc, ctx->sc_phys);
		ctx->sc = NULL;
	}

	return 0;
}

/* Initialize the per direction context memory */
static int sa_init_ctx_info(struct sa_ctx_info *ctx,
			    struct keystone_crypto_data *data)
{
	unsigned long bn;
	int err;

	spin_lock(&data->scid_lock);
	if (data->sc_id > data->sc_id_end) {
		spin_unlock(&data->scid_lock);
		dev_err(&data->pdev->dev, "Out of SC IDs\n");
		return -ENOMEM;
	}
	bn = find_first_zero_bit(data->ctx_bm, SA_MAX_NUM_CTX);
	__set_bit(bn, data->ctx_bm);
	data->sc_id++;
	spin_unlock(&data->scid_lock);

	ctx->sc_id = (u16)(data->sc_id_start + bn);

	ctx->rx_flow = knav_dma_get_flow(data->rx_chan);
	ctx->rx_compl_qid = data->rx_compl_qid;

	ctx->sc = dma_pool_alloc(data->sc_pool, GFP_KERNEL, &ctx->sc_phys);
	if (!ctx->sc) {
		dev_err(&data->pdev->dev, "Failed to allocate SC memory\n");
		err = -ENOMEM;
		goto scid_rollback;
	}

	return 0;

scid_rollback:
	spin_lock(&data->scid_lock);
	__clear_bit(bn, data->ctx_bm);
	data->sc_id--;
	spin_unlock(&data->scid_lock);

	return err;
}

/* Initialize TFM context */
static int sa_init_tfm(struct crypto_tfm *tfm)
{
	struct crypto_alg *alg = tfm->__crt_alg;
	struct sa_tfm_ctx *ctx = crypto_tfm_ctx(tfm);
	struct keystone_crypto_data *data = dev_get_drvdata(sa_ks2_dev);
	int ret;

	if ((alg->cra_flags & CRYPTO_ALG_TYPE_MASK) == CRYPTO_ALG_TYPE_AEAD) {
		memset(ctx, 0, sizeof(*ctx));
		ctx->dev_data = data;

		ret = sa_init_ctx_info(&ctx->enc, data);
		if (ret)
			return ret;
		ret = sa_init_ctx_info(&ctx->dec, data);
		if (ret) {
			sa_free_ctx_info(&ctx->enc, data);
			return ret;
		}
	}

	dev_dbg(sa_ks2_dev, "%s(0x%p) sc-ids(0x%x(0x%x), 0x%x(0x%x))\n",
		__func__, tfm, ctx->enc.sc_id, ctx->enc.sc_phys,
		ctx->dec.sc_id, ctx->dec.sc_phys);
	return 0;
}

static int sa_gcm_get_aad(struct aead_request *req, u8 *aad, u8 *aad_len)
{
	struct scatter_walk walk;
	int ret = 0;

	*aad_len = req->assoclen - crypto_aead_ivsize(crypto_aead_reqtfm(req));

	scatterwalk_start(&walk, req->src);
	scatterwalk_copychunks(aad, &walk, *aad_len, 0);
	scatterwalk_done(&walk, 0, 0);

	return ret;
}

/* Algorithm init */
static int sa_cra_init_aead(struct crypto_aead *tfm)
{
	return sa_init_tfm(crypto_aead_tfm(tfm));
}

/* Algorithm context teardown */
static void sa_exit_tfm(struct crypto_tfm *tfm)
{
	struct crypto_alg *alg = tfm->__crt_alg;
	struct sa_tfm_ctx *ctx = crypto_tfm_ctx(tfm);
	struct keystone_crypto_data *data = dev_get_drvdata(sa_ks2_dev);

	dev_dbg(sa_ks2_dev, "%s(0x%p) sc-ids(0x%x(0x%x), 0x%x(0x%x))\n",
		__func__, tfm, ctx->enc.sc_id, ctx->enc.sc_phys,
		ctx->dec.sc_id, ctx->dec.sc_phys);

	if ((alg->cra_flags & CRYPTO_ALG_TYPE_MASK)
	    == CRYPTO_ALG_TYPE_AEAD) {
		sa_free_ctx_info(&ctx->enc, data);
		sa_free_ctx_info(&ctx->dec, data);
	}
}

static void sa_exit_tfm_aead(struct crypto_aead *tfm)
{
	return sa_exit_tfm(crypto_aead_tfm(tfm));
}

/* AEAD algorithm configuration interface function */
static int sa_aead_setkey(struct crypto_aead *authenc,
			  const u8 *key, unsigned int keylen)
{
	struct sa_tfm_ctx *ctx = crypto_aead_ctx(authenc);
	struct crypto_authenc_keys keys;

	const char *cra_name;
	struct sa_eng_info *enc_eng, *auth_eng;
	int ealg_id, aalg_id, cmdl_len;
	struct sa_cmdl_cfg cfg;

	if (crypto_authenc_extractkeys(&keys, key, keylen) != 0)
		goto badkey;

	cra_name = crypto_tfm_alg_name(crypto_aead_tfm(authenc));

	sa_conv_calg_to_salg(cra_name, &ealg_id, &aalg_id);
	enc_eng = sa_get_engine_info(ealg_id);
	auth_eng = sa_get_engine_info(aalg_id);

	memset(&cfg, 0, sizeof(cfg));
	cfg.enc1st = 1;
	cfg.aalg = aalg_id;
	cfg.enc_eng_id = enc_eng->eng_id;
	cfg.auth_eng_id = auth_eng->eng_id;
	cfg.iv_size = crypto_aead_ivsize(authenc);
	cfg.akey = keys.authkey;
	cfg.akey_len = keys.authkeylen;

	/* Setup Encryption Security Context & Command label template */
	if (sa_init_sc(&ctx->enc, keys.enckey, keys.enckeylen,
		       keys.authkey, keys.authkeylen,
		       cra_name, 1, &ctx->enc.epib[1]))
		goto badkey;

	cmdl_len = sa_format_cmdl_gen(&cfg,
				      (u8 *)ctx->enc.cmdl,
				      &ctx->enc.cmdl_upd_info);
	if ((cmdl_len <= 0) || (cmdl_len > SA_MAX_CMDL_WORDS * sizeof(u32)))
		goto badkey;

	ctx->enc.cmdl_size = cmdl_len;

	/* Setup Decryption Security Context & Command label template */
	if (sa_init_sc(&ctx->dec, keys.enckey, keys.enckeylen,
		       keys.authkey, keys.authkeylen,
		       cra_name, 0, &ctx->dec.epib[1]))
		goto badkey;

	cfg.enc1st = 0;
	cfg.enc_eng_id = enc_eng->eng_id;
	cfg.auth_eng_id = auth_eng->eng_id;
	cmdl_len = sa_format_cmdl_gen(&cfg, (u8 *)ctx->dec.cmdl,
				      &ctx->dec.cmdl_upd_info);

	if ((cmdl_len <= 0) || (cmdl_len > SA_MAX_CMDL_WORDS * sizeof(u32)))
		goto badkey;

	ctx->dec.cmdl_size = cmdl_len;
	return 0;

badkey:
	dev_err(sa_ks2_dev, "%s: badkey\n", __func__);
	crypto_aead_set_flags(authenc, CRYPTO_TFM_RES_BAD_KEY_LEN);
	return -EINVAL;
}

/**
 * sa_prepare_tx_desc() - prepare a chain of tx descriptors
 * @pdata:	struct keystone_crypto_data pinter
 * @_sg:	struct scatterlist source list
 * @num_sg:	number of buffers in the _sg list
 * @pslen:	length of protocol specific data
 * @psdata:	pointer to the protocol specific data
 * @epiblen:	EPIB length
 * @epib:	pointer to EPIB (extended packet info block)
 * @ctx:	struct sa_dma_req_ctx pointer
 *
 * For each buffer in the source _sg list the function gets a hardware
 * descriptor from tx_pool and fills the buffer descriptor fields and maps the
 * descriptor. For the first descriptor (packet descriptor) it also sets the
 * psinfo and epib fields.
 *
 * Returns dma address of the first descripto on success, NULL otherwise.
 */
static dma_addr_t
sa_prepare_tx_desc(struct keystone_crypto_data *pdata, struct scatterlist *_sg,
		   int num_sg, u32 pslen, u32 *psdata,
		   u32 epiblen, u32 *epib, struct sa_dma_req_ctx *ctx)
{
	struct device *dev = &pdata->pdev->dev;
	struct knav_dma_desc *hwdesc = NULL;
	struct scatterlist *sg = _sg;
	u32 packet_len = 0;
	u32 nsg;
	u32 next_desc = 0;
	u32 packet_info;

	packet_info = KNAV_DMA_DESC_HAS_EPIB |
		((pslen / sizeof(u32)) << KNAV_DMA_DESC_PSLEN_SHIFT) |
		(pdata->tx_compl_qid << KNAV_DMA_DESC_RETQ_SHIFT);

	for (sg += num_sg - 1, nsg = num_sg; nsg > 0; sg--, nsg--) {
		u32 buflen, orig_len;
		int i;
		dma_addr_t dma_addr;
		u32 dma_sz;
		u32 *out, *in;

		hwdesc = knav_pool_desc_get(pdata->tx_pool);
		if (IS_ERR_OR_NULL(hwdesc)) {
			dev_dbg(dev, "out of tx pool desc\n");
			return 0;
		}

		buflen = sg_dma_len(sg) & KNAV_DMA_DESC_PKT_LEN_MASK;
		orig_len = buflen;
		packet_len += buflen;
		if (nsg == 1) { /* extra fileds for packed descriptor */
			for (out = hwdesc->epib, in = epib, i = 0;
			     i < epiblen / sizeof(u32); i++)
				*out++ = *in++;
			for (out = hwdesc->psdata, in = psdata, i = 0;
			     i < pslen / sizeof(u32); i++)
				*out++ = *in++;


		}

		hwdesc->desc_info    = packet_len;
		hwdesc->tag_info     = 0;
		hwdesc->packet_info  = packet_info;
		hwdesc->buff_len     = buflen;
		hwdesc->buff         = sg_dma_address(sg);
		hwdesc->next_desc    = next_desc;
		hwdesc->orig_len     = orig_len;
		hwdesc->orig_buff    = sg_dma_address(sg);

		knav_pool_desc_map(pdata->tx_pool, hwdesc, sizeof(hwdesc),
				   &dma_addr, &dma_sz);

		hwdesc->sw_data[0] = (u32)dma_addr;
		hwdesc->sw_data[1] = dma_sz;
		hwdesc->sw_data[2] = (u32)ctx;

		next_desc = (u32)dma_addr;
	}

	return (unlikely(!hwdesc)) ? 0 : hwdesc->sw_data[0];
}

void sa_tx_completion_process(struct keystone_crypto_data *dev_data)
{
	struct knav_dma_desc *hwdesc = NULL;
	dma_addr_t dma;
	struct sa_dma_req_ctx *ctx = NULL;
	u32	pkt_len;
	u32	calc_pkt_len;

	for (;;) {
		dma = knav_queue_pop(dev_data->tx_compl_q, NULL);
		if (!dma) {
			dev_dbg(sa_ks2_dev, "no desc in the queue %d\n",
				dev_data->tx_compl_qid);
			break;
		}

		ctx = NULL;
		pkt_len = 0;
		calc_pkt_len = 0;

		do {
			hwdesc = knav_pool_desc_unmap(dev_data->tx_pool, dma,
						      sizeof(hwdesc));
			if (!hwdesc) {
				pr_err("failed to unmap descriptor 0x%08x\n",
				       dma);
				break;
			}
			/* take the req_ctx from the first descriptor */
			if (!ctx) {
				ctx = (struct sa_dma_req_ctx
					   *)hwdesc->sw_data[2];
				pkt_len = hwdesc->desc_info &
					KNAV_DMA_DESC_PKT_LEN_MASK;
			}
			calc_pkt_len += hwdesc->buff_len;
			dma = hwdesc->next_desc;

			knav_pool_desc_put(dev_data->tx_pool, hwdesc);
		} while (dma);

#ifdef DEBUG
		if (pkt_len != calc_pkt_len)
			pr_err("[%s] calculated packet length doesn't match %d/%d\n",
			       __func__, calc_pkt_len, pkt_len);
#endif

		if ((pkt_len > 0) && ctx) {
			dma_unmap_sg(&ctx->dev_data->pdev->dev, ctx->src,
				     ctx->src_nents, DMA_TO_DEVICE);

			if (likely(ctx->pkt)) {
				atomic_add(ctx->src_nents,
					   &ctx->dev_data->tx_dma_desc_cnt);
				atomic_inc(&ctx->dev_data->stats.tx_pkts);
			}
		}

		if (ctx)
			kmem_cache_free(ctx->dev_data->dma_req_ctx_cache, ctx);
	}
}

/**
 * sa_rx_desc_process() - proccess descriptors related
 *			  to one trasnsformation received from SA
 *
 * @dev_data:	struct keystone_crypto_data pointer
 * @hwdesc:	array of pointers to descriptors
 * @num:	number descriptors in the array
 *
 * From the first descriptor, which is a packer descriptor, the function
 * retrieves all algorithm parameters including pointer to original request.
 * If the transformation was an encryption, it copies calculated authentication
 * tag to the destination list, otherwise compare received tag with calculated.
 *
 * After that it copies all buffers from hw descriptors to the destination list
 * and call aead_request_complete() callback.
 *
 * At the end the function frees all buffers.
 */
static
void sa_rx_desc_process(struct keystone_crypto_data *dev_data,
			struct knav_dma_desc **hwdesc, int num)
{
	int			j;
	unsigned int		alg_type;
	u32			req_sub_type;

	alg_type = hwdesc[0]->psdata[0] & CRYPTO_ALG_TYPE_MASK;
	req_sub_type = hwdesc[0]->psdata[0] >> SA_REQ_SUBTYPE_SHIFT;

	if (likely(alg_type == CRYPTO_ALG_TYPE_AEAD)) {
		int auth_words, auth_size, enc_len, enc_offset, i;
		struct aead_request *req;
		struct crypto_aead *tfm;
		int enc, err = 0;
		unsigned int ivsize;

		req = (struct aead_request *)hwdesc[0]->psdata[1];
		tfm = crypto_aead_reqtfm(req);
		auth_size = crypto_aead_authsize(tfm);
		ivsize = crypto_aead_ivsize(tfm);

		if (req_sub_type == SA_REQ_SUBTYPE_ENC) {
			enc_offset = req->assoclen;
			enc_len = req->cryptlen;
			enc = 1;
		} else if (req_sub_type == SA_REQ_SUBTYPE_DEC) {
			enc_offset = req->assoclen;
			enc_len = req->cryptlen - auth_size;
			enc = 0;
		} else {
			err = -EBADMSG;
			goto aead_err;
		}

		/* NOTE: We receive the tag as host endian 32bit words */
		auth_words = auth_size / sizeof(u32);

		for (i = 2; i < (auth_words + SA_PSDATA_CTX_WORDS); i++)
			hwdesc[0]->psdata[i] = htonl(hwdesc[0]->psdata[i]);

		/* if encryption, copy the authentication tag */
		if (enc) {
			scatterwalk_copy(
				&hwdesc[0]->psdata[SA_PSDATA_CTX_WORDS],
				req->dst, enc_offset + enc_len, auth_size, 1);
		} else  {
			/* Verify the authentication tag */
			u8 auth_tag[SA_MAX_AUTH_TAG_SZ];

			scatterwalk_copy(auth_tag, req->src,
					    enc_len + req->assoclen,
					    auth_size, 0);

			err = memcmp(&hwdesc[0]->psdata[SA_PSDATA_CTX_WORDS],
				     auth_tag, auth_size) ? -EBADMSG : 0;
			if (unlikely(err))
				goto aead_err;
		}

		/* Copy the encrypted/decrypted data */
		if (unlikely(sa_hwdesc2sg_copy(hwdesc, req->dst, enc_offset,
					       enc_offset, enc_len, num)))
			err = -EBADMSG;

aead_err:
		aead_request_complete(req, err);
	}

	/* free buffers here */
	for (j = 0; j < num; j++) {
		if (hwdesc[j]->orig_len == PAGE_SIZE) {
			__free_page((struct page *)hwdesc[j]->sw_data[1]);
			atomic_dec(&dev_data->rx_dma_page_cnt);
		} else {
			kfree((void *)hwdesc[j]->sw_data[0]);
		}
	}

	atomic_inc(&dev_data->stats.rx_pkts);
}

/**
 * sa_rx_completion_process() - processes received from SA buffers
 *
 * @dev_data:	struct keystone_crypto_data pointer
 *
 * The function is called from rx tasklet. It retreives one or multiple
 * chained hw descriptors and calls sa_rx_desc_process(). After that it
 * returns all descriptors into the rx_pool.
 */
void sa_rx_completion_process(struct keystone_crypto_data *dev_data)
{
	struct knav_dma_desc	*hwdesc[MAX_SKB_FRAGS];
	int			j, desc_num;
	dma_addr_t		dma;
	u32			pkt_len;
	u32			calc_pkt_len;
	int			wait4pkt = 1;

	for (;;) {
		dma = knav_queue_pop(dev_data->rx_compl_q, NULL);
		if (!dma) {
			dev_dbg(sa_ks2_dev, "no desc in the queue %d\n",
				dev_data->rx_compl_qid);
			break;
		}

		pkt_len = 0;
		calc_pkt_len = 0;
		wait4pkt = 1;
		desc_num = 0;

		do {
			hwdesc[desc_num] =
				knav_pool_desc_unmap(dev_data->rx_pool, dma,
						     sizeof(hwdesc));
			if (!hwdesc[desc_num]) {
				pr_err("failed to unmap descriptor 0x%08x\n",
				       dma);
				break;
			}

			if (hwdesc[desc_num]->orig_len == PAGE_SIZE) {
				dma_unmap_page(sa_ks2_dev,
					       hwdesc[desc_num]->orig_buff,
					       PAGE_SIZE,
					       DMA_FROM_DEVICE);
			} else {
				dma_unmap_single(sa_ks2_dev,
						 hwdesc[desc_num]->orig_buff,
						 SA_RX_BUF0_SIZE,
						 DMA_FROM_DEVICE);
			}

			/* take the req_ctx from the first descriptor */
			if (wait4pkt) {
				pkt_len = hwdesc[desc_num]->desc_info &
					KNAV_DMA_DESC_PKT_LEN_MASK;
				wait4pkt = 0;
			}
			calc_pkt_len += hwdesc[desc_num]->buff_len;

			dma = hwdesc[desc_num]->next_desc;
			desc_num++;
		} while (dma);

#ifdef DEBUG
		if (pkt_len != calc_pkt_len)
			pr_err("[%s] calculated packet length doesn't match %d/%d\n",
			       __func__, calc_pkt_len, pkt_len);
#endif

		/* retrieve data and copy it to the destination sg list */
		sa_rx_desc_process(dev_data, hwdesc, desc_num);

		/* return descriptor to the pool */
		for (j = 0; j < desc_num; j++)
			knav_pool_desc_put(dev_data->rx_pool, hwdesc[j]);
	}
}

/**
 * sa_aead_perform() - perform AEAD transformation
 * @req:	struct aead_request pointer
 * @iv:		initial vector
 * enc:		boolean flag true for encryption, false for decryption
 *
 * This function prepare
 *
 * 1) checks whether the driver has enought buffers to receive transformed
 *    data.
 * 2) allocates request context and fills appropriate fields in it.
 * 3) maps source list
 * 4) prepare tx dma desctiprors and submits them to the SA queue.
 *
 * Return: -EINPROGRESS on success, appropriate error code
 */
static int sa_aead_perform(struct aead_request *req, u8 *iv, bool enc)
{
	struct crypto_aead *tfm = crypto_aead_reqtfm(req);
	struct sa_tfm_ctx *ctx = crypto_aead_ctx(tfm);
	struct sa_ctx_info *sa_ctx = enc ? &ctx->enc : &ctx->dec;
	dma_addr_t desc_dma_addr;
	struct keystone_crypto_data *pdata = dev_get_drvdata(sa_ks2_dev);
	struct sa_dma_req_ctx *req_ctx = NULL;
	u8 enc_offset;
	int sg_nents;
	int psdata_offset, ret = 0;
	u8 *auth_iv = NULL;
	u8 aad[16];
	u8 aad_len = 0;
	u16 enc_len;
	u16 auth_len;
	u32 req_type;
	int n_bufs;

	gfp_t flags = req->base.flags & CRYPTO_TFM_REQ_MAY_SLEEP ?
			GFP_KERNEL : GFP_ATOMIC;

	if (enc) {
		iv = req->iv;
		enc_offset = req->assoclen;
		enc_len = req->cryptlen;
		auth_len = req->assoclen + req->cryptlen;
	} else {
		enc_offset = req->assoclen;
		enc_len = req->cryptlen - crypto_aead_authsize(tfm);
		auth_len = req->assoclen + req->cryptlen -
			crypto_aead_authsize(tfm);
	}

	/* Parse out AAD values */
	if (sa_ctx->cmdl_upd_info.submode == SA_MODE_GCM) {
		sa_gcm_get_aad(req, aad, &aad_len);

		/*
		 * Set the AAD size to the configured
		 * AAD size when first packet is received.
		 * AAD size CANNOT be changed after this.
		 */
		if (sa_ctx->cmdl_upd_info.aad.index == 0) {
			sa_ctx->cmdl_upd_info.aad.index = 0xFF;
			sa_ctx->cmdl_upd_info.aad.size = aad_len;
			sa_ctx->sc[SA_CTX_PHP_PE_CTX_SZ + 64 + 24] =
				(aad_len << 3);
		}

		if (sa_ctx->cmdl_upd_info.aad.size != aad_len) {
			atomic_inc(&pdata->stats.tx_dropped);
			dev_err(sa_ks2_dev, "ERROR: AAD Size Mismatch (%d, %d)\n",
				aad_len,
				sa_ctx->cmdl_upd_info.aad.size);
			return -EPERM;
		}
	} else if (sa_ctx->cmdl_upd_info.submode == SA_MODE_GMAC) {
		sa_gcm_get_aad(req, aad, &aad_len);
	}

	/* Allocate descriptor & submit packet */
	sg_nents = sg_count(req->src, auth_len);

	if (unlikely(atomic_sub_return(sg_nents, &pdata->tx_dma_desc_cnt)
		     < 0)) {
		ret = -EBUSY;
		goto err_0;
	}

	n_bufs = auth_len - SA_RX_BUF0_SIZE;

	n_bufs = (n_bufs <= 0) ? 0 :
		DIV_ROUND_UP(n_bufs, PAGE_SIZE);

	if (unlikely(atomic_read(&pdata->rx_dma_page_cnt) < n_bufs)) {
		ret = -EBUSY;
		goto err_0;
	}

	req_ctx = kmem_cache_alloc(pdata->dma_req_ctx_cache, flags);

	if (unlikely(!req_ctx)) {
		ret = -ENOMEM;
		goto err_0;
	}

	memcpy(req_ctx->cmdl, sa_ctx->cmdl, sa_ctx->cmdl_size);

	/* Update Command Label */
	sa_update_cmdl(sa_ks2_dev, enc_offset, enc_len,
		       iv, auth_len, auth_iv, aad_len, aad,
		       &sa_ctx->cmdl_upd_info, req_ctx->cmdl);

	/*
	 * Last 2 words in PSDATA will have the crypto alg type &
	 * crypto request pointer
	 */
	req_type = CRYPTO_ALG_TYPE_AEAD;
	if (enc)
		req_type |= (SA_REQ_SUBTYPE_ENC << SA_REQ_SUBTYPE_SHIFT);
	else
		req_type |= (SA_REQ_SUBTYPE_DEC << SA_REQ_SUBTYPE_SHIFT);

	psdata_offset = sa_ctx->cmdl_size / sizeof(u32);
	req_ctx->cmdl[psdata_offset++] = req_type;
	req_ctx->cmdl[psdata_offset] = (u32)req;

	/* map the packet */
	req_ctx->src = req->src;
	req_ctx->src_nents = dma_map_sg(sa_ks2_dev, req_ctx->src,
					   sg_nents, DMA_TO_DEVICE);

	if (unlikely(req_ctx->src_nents != sg_nents)) {
		dev_warn_ratelimited(sa_ks2_dev, "failed to map tx pkt\n");
		ret = -EIO;
		goto err;
	}

	req_ctx->dev_data = pdata;
	req_ctx->pkt = true;

	desc_dma_addr = sa_prepare_tx_desc(pdata, req_ctx->src,
					   sg_nents,
					   (sa_ctx->cmdl_size +
					    (SA_PSDATA_CTX_WORDS *
					     sizeof(u32))),
					   req_ctx->cmdl,
					   sizeof(sa_ctx->epib),
					   sa_ctx->epib,
					   req_ctx);

	if (desc_dma_addr == 0) {
		ret = -EIO;
		goto err;
	}

	knav_queue_push(pdata->tx_submit_q, desc_dma_addr,
			sizeof(struct knav_dma_desc), 0);

	return -EINPROGRESS;

err:
	if (req_ctx)
		kmem_cache_free(pdata->dma_req_ctx_cache, req_ctx);
err_0:
	atomic_add(sg_nents, &pdata->tx_dma_desc_cnt);
	return ret;
}

/* AEAD algorithm encrypt interface function */
static int sa_aead_encrypt(struct aead_request *req)
{
	return sa_aead_perform(req, req->iv, true);
}

/* AEAD algorithm decrypt interface function */
static int sa_aead_decrypt(struct aead_request *req)
{
	return sa_aead_perform(req, req->iv, false);
}

/* GCM algorithm configuration interface function */
static int sa_aead_gcm_setkey(struct crypto_aead *authenc,
								const u8 *key, unsigned int keylen)
{
	struct sa_tfm_ctx *ctx = crypto_aead_ctx(authenc);
	unsigned int enckey_len;
	struct sa_eng_info *enc_eng, *auth_eng;
	int ealg_id, aalg_id, cmdl_len;
	struct sa_cmdl_cfg cfg;
	u8 const *enc_key;
	const char *cra_name;
	u32 *temp_key;

	cra_name = crypto_tfm_alg_name(crypto_aead_tfm(authenc));

	sa_conv_calg_to_salg(cra_name, &ealg_id, &aalg_id);

	if (ealg_id != SA_EALG_ID_NONE) {
		/*  GCM  */
		enc_eng = sa_get_engine_info(ealg_id);
		enckey_len = keylen - 4;
		enc_key = key;

		memset(&cfg, 0, sizeof(cfg));
		cfg.enc_eng_id = enc_eng->eng_id;
		cfg.iv_size = crypto_aead_ivsize(authenc);

		/* Prpoerties not applicable to GCM */
		cfg.aalg = SA_EALG_ID_NONE;
		cfg.auth_eng_id = SA_ENG_ID_NONE;
		cfg.akey = NULL;
		cfg.akey_len = 0;

		/* Iniialize the command update structure */
		memset(&ctx->enc.cmdl_upd_info, 0,
				sizeof(struct sa_cmdl_upd_info));
		ctx->enc.cmdl_upd_info.submode = SA_MODE_GCM;
		/* Default AAD size to 8 */
		ctx->enc.cmdl_upd_info.aad.size = 8;
		ctx->enc.cmdl_upd_info.aad.index = 0;

		memset(&ctx->dec.cmdl_upd_info, 0,
				sizeof(struct sa_cmdl_upd_info));
		ctx->dec.cmdl_upd_info.submode = SA_MODE_GCM;
		/* Default AAD size to 8 */
		ctx->dec.cmdl_upd_info.aad.size = 8;
		ctx->dec.cmdl_upd_info.aad.index = 0;
	} else {
		/*  GMAC  */
		auth_eng = sa_get_engine_info(aalg_id);

		memset(&cfg, 0, sizeof(cfg));
		cfg.iv_size = crypto_aead_ivsize(authenc);
		cfg.aalg = aalg_id;
		cfg.auth_eng_id = auth_eng->eng_id;
		cfg.akey = key;
		cfg.akey_len = keylen - 4;

		cfg.enc_eng_id = SA_ENG_ID_NONE;
		enckey_len = 0;
		enc_key = NULL;

		/* Iniialize the command update structure */
		memset(&ctx->enc.cmdl_upd_info, 0,
				sizeof(struct sa_cmdl_upd_info));
		ctx->enc.cmdl_upd_info.submode = SA_MODE_GMAC;
		memset(&ctx->dec.cmdl_upd_info, 0,
				sizeof(struct sa_cmdl_upd_info));
		ctx->dec.cmdl_upd_info.submode = SA_MODE_GMAC;
	}

	/* Store Salt/NONCE value */
	temp_key = (u32 *) &key[keylen - 4];
	cfg.salt = *temp_key;

	/* Setup Encryption Security Context & Command label template */
	if (sa_init_sc(&ctx->enc, enc_key, enckey_len, cfg.akey,
		       cfg.akey_len, cra_name, 1, &ctx->enc.epib[1]))
		goto badkey;

	cmdl_len = sa_format_cmdl_gcm(&cfg,
				      (u8 *)ctx->enc.cmdl,
				      &ctx->enc.cmdl_upd_info);
	if ((cmdl_len <= 0) || (cmdl_len > SA_MAX_CMDL_WORDS * sizeof(u32)))
		goto badkey;

	ctx->enc.cmdl_size = cmdl_len;

	/* Setup Decryption Security Context & Command label template */
	if (sa_init_sc(&ctx->dec, enc_key, enckey_len, cfg.akey,
		       cfg.akey_len, cra_name, 0, &ctx->dec.epib[1]))
		goto badkey;

	cmdl_len = sa_format_cmdl_gcm(&cfg,
				      (u8 *)ctx->dec.cmdl,
				      &ctx->dec.cmdl_upd_info);
	if ((cmdl_len <= 0) || (cmdl_len > SA_MAX_CMDL_WORDS * sizeof(u32)))
		goto badkey;

	ctx->dec.cmdl_size = cmdl_len;

	return 0;

badkey:
	dev_err(sa_ks2_dev, "%s: badkey\n", __func__);
	crypto_aead_set_flags(authenc, CRYPTO_TFM_RES_BAD_KEY_LEN);
	return -EINVAL;
}

static struct sa_alg_tmpl sa_algs[] = {
	/* AEAD algorithms */
	{	.type = CRYPTO_ALG_TYPE_AEAD,
		.alg.aead = {
			.base = {
				.cra_name = "authenc(hmac(sha1),cbc(aes))",
				.cra_driver_name =
					"authenc(hmac(sha1),cbc(aes))-keystone-sa",
				.cra_blocksize = AES_BLOCK_SIZE,
				.cra_flags = CRYPTO_ALG_TYPE_AEAD |
					CRYPTO_ALG_KERN_DRIVER_ONLY |
					CRYPTO_ALG_ASYNC,
				.cra_ctxsize = sizeof(struct sa_tfm_ctx),
				.cra_module = THIS_MODULE,
				.cra_alignmask = 0,
				.cra_priority = 3000,
			},
			.ivsize = AES_BLOCK_SIZE,
			.maxauthsize = SHA1_DIGEST_SIZE,

			.init = sa_cra_init_aead,
			.exit = sa_exit_tfm_aead,
			.setkey	= sa_aead_setkey,
			.encrypt = sa_aead_encrypt,
			.decrypt = sa_aead_decrypt,
		}
	},
	{	.type = CRYPTO_ALG_TYPE_AEAD,
		.alg.aead = {
			.base = {
				.cra_name = "authenc(hmac(sha1),cbc(des3_ede))",
				.cra_driver_name =
					"authenc(hmac(sha1),cbc(des3_ede))-keystone-sa",
				.cra_blocksize = DES3_EDE_BLOCK_SIZE,
				.cra_flags = CRYPTO_ALG_TYPE_AEAD |
					CRYPTO_ALG_KERN_DRIVER_ONLY |
					CRYPTO_ALG_ASYNC,
				.cra_ctxsize = sizeof(struct sa_tfm_ctx),
				.cra_module = THIS_MODULE,
				.cra_alignmask = 0,
				.cra_priority = 3000,
			},
			.ivsize = DES3_EDE_BLOCK_SIZE,
			.maxauthsize = SHA1_DIGEST_SIZE,
			.init = sa_cra_init_aead,
			.exit = sa_exit_tfm_aead,
			.setkey	= sa_aead_setkey,
			.encrypt = sa_aead_encrypt,
			.decrypt = sa_aead_decrypt,
		}
	},
	{       .type = CRYPTO_ALG_TYPE_AEAD,
		.alg.aead = {
			.base = {
				.cra_name = "authenc(xcbc(aes),cbc(aes))",
				.cra_driver_name =
					"authenc(xcbc(aes),cbc(aes))-keystone-sa",
				.cra_blocksize = AES_BLOCK_SIZE,
				.cra_flags = CRYPTO_ALG_TYPE_AEAD |
					CRYPTO_ALG_KERN_DRIVER_ONLY |
					CRYPTO_ALG_ASYNC,
				.cra_ctxsize = sizeof(struct sa_tfm_ctx),
				.cra_module = THIS_MODULE,
				.cra_alignmask = 0,
				.cra_priority = 3000,
			},
			.ivsize = AES_BLOCK_SIZE,
			.maxauthsize = AES_XCBC_DIGEST_SIZE,
			.init = sa_cra_init_aead,
			.exit = sa_exit_tfm_aead,
			.setkey	= sa_aead_setkey,
			.encrypt = sa_aead_encrypt,
			.decrypt = sa_aead_decrypt,
		}
	},
	{	.type = CRYPTO_ALG_TYPE_AEAD,
		.alg.aead = {
			.base = {
				.cra_name = "authenc(xcbc(aes),cbc(des3_ede))",
				.cra_driver_name =
					"authenc(xcbc(aes),cbc(des3_ede))-keystone-sa",
				.cra_blocksize = DES3_EDE_BLOCK_SIZE,
				.cra_flags = CRYPTO_ALG_TYPE_AEAD |
					CRYPTO_ALG_KERN_DRIVER_ONLY |
					CRYPTO_ALG_ASYNC,
				.cra_ctxsize = sizeof(struct sa_tfm_ctx),
				.cra_module = THIS_MODULE,
				.cra_alignmask = 0,
				.cra_priority = 3000,
			},
			.ivsize = DES3_EDE_BLOCK_SIZE,
			.maxauthsize = AES_XCBC_DIGEST_SIZE,
			.init = sa_cra_init_aead,
			.exit = sa_exit_tfm_aead,
			.setkey	= sa_aead_setkey,
			.encrypt = sa_aead_encrypt,
			.decrypt = sa_aead_decrypt,
		}
	},
	{	.type = CRYPTO_ALG_TYPE_AEAD,
		.alg.aead = {
			.base = {
				.cra_name = "authenc(hmac(sha1),ecb(cipher_null))",
				.cra_driver_name =
					"authenc-hmac-sha1-cipher_null-keystone-sa",
				.cra_blocksize = NULL_BLOCK_SIZE,
				.cra_flags = CRYPTO_ALG_TYPE_AEAD |
					CRYPTO_ALG_KERN_DRIVER_ONLY |
					CRYPTO_ALG_ASYNC,
				.cra_ctxsize = sizeof(struct sa_tfm_ctx),
				.cra_module = THIS_MODULE,
				.cra_alignmask = 0,
				.cra_priority = 3000,
			},
			.ivsize = NULL_IV_SIZE,
			.maxauthsize = SHA1_DIGEST_SIZE,
			.init = sa_cra_init_aead,
			.exit = sa_exit_tfm_aead,
			.setkey	= sa_aead_setkey,
			.encrypt = sa_aead_encrypt,
			.decrypt = sa_aead_decrypt,
		}
	},
	{	.type = CRYPTO_ALG_TYPE_AEAD,
		.alg.aead = {
			.base = {
				.cra_name = "rfc4106(gcm(aes))",
				.cra_driver_name =
					"rfc4106-gcm-aes-keystone-sa",
				.cra_blocksize = AES_BLOCK_SIZE,
				.cra_flags = CRYPTO_ALG_TYPE_AEAD |
					CRYPTO_ALG_KERN_DRIVER_ONLY |
					CRYPTO_ALG_ASYNC,
				.cra_ctxsize = sizeof(struct sa_tfm_ctx),
				.cra_module = THIS_MODULE,
				.cra_alignmask = 0,
				.cra_priority = 3000,
			},
			.ivsize = 8,
			.maxauthsize = AES_BLOCK_SIZE,
			.init = sa_cra_init_aead,
			.exit = sa_exit_tfm_aead,
			.setkey	= sa_aead_gcm_setkey,
			.encrypt = sa_aead_encrypt,
			.decrypt = sa_aead_decrypt,
		}
	},
	{	.type = CRYPTO_ALG_TYPE_AEAD,
		.alg.aead = {
			.base = {
				.cra_name = "rfc4543(gcm(aes))",
				.cra_driver_name =
					"rfc4543-gcm-aes-keystone-sa",
				.cra_blocksize = AES_BLOCK_SIZE,
				.cra_flags = CRYPTO_ALG_TYPE_AEAD |
					CRYPTO_ALG_KERN_DRIVER_ONLY |
					CRYPTO_ALG_ASYNC,
				.cra_ctxsize = sizeof(struct sa_tfm_ctx),
				.cra_module = THIS_MODULE,
				.cra_alignmask = 0,
				.cra_priority = 3000,
			},
			.ivsize = 8,
			.maxauthsize = AES_BLOCK_SIZE,
			.init = sa_cra_init_aead,
			.exit = sa_exit_tfm_aead,
			.setkey	= sa_aead_gcm_setkey,
			.encrypt = sa_aead_encrypt,
			.decrypt = sa_aead_decrypt,
		}
	},
	{	.type = CRYPTO_ALG_TYPE_AEAD,
		.alg.aead = {
			.base = {
				.cra_name = "authenc(hmac(sha256),cbc(aes))",
				.cra_driver_name =
					"authenc-hmac-sha256-cbc-aes-keystone-sa",
				.cra_blocksize = AES_BLOCK_SIZE,
				.cra_flags = CRYPTO_ALG_TYPE_AEAD |
					CRYPTO_ALG_KERN_DRIVER_ONLY |
					CRYPTO_ALG_ASYNC,
				.cra_ctxsize = sizeof(struct sa_tfm_ctx),
				.cra_module = THIS_MODULE,
				.cra_alignmask = 0,
				.cra_priority = 3000,
			},
			.ivsize = AES_BLOCK_SIZE,
			.maxauthsize = SHA256_DIGEST_SIZE,
			.init = sa_cra_init_aead,
			.exit = sa_exit_tfm_aead,
			.setkey	= sa_aead_setkey,
			.encrypt = sa_aead_encrypt,
			.decrypt = sa_aead_decrypt,
		}
	},
};

/* Register the algorithms in crypto framework */
void sa_register_algos(const struct device *dev)
{
	char *alg_name;
	u32 type;
	int i, err, num_algs = ARRAY_SIZE(sa_algs);

	for (i = 0; i < num_algs; i++) {
		type = sa_algs[i].type;
		if (type == CRYPTO_ALG_TYPE_AEAD) {
			alg_name = sa_algs[i].alg.aead.base.cra_name;
			err = crypto_register_aead(&sa_algs[i].alg.aead);
		} else {
			dev_err(dev,
				"un-supported crypto algorithm (%d)",
				sa_algs[i].type);
			continue;
		}

		if (err)
			dev_err(dev, "Failed to register '%s'\n", alg_name);
		else
			sa_algs[i].registered = true;
	}
}

/* un-register the algorithms from crypto framework */
void sa_unregister_algos(const struct device *dev)
{
	char *alg_name;
	int err = 0, i, num_algs = ARRAY_SIZE(sa_algs);

	for (i = 0; i < num_algs; i++) {
		if (sa_algs[i].registered) {
			if (sa_algs[i].type == CRYPTO_ALG_TYPE_AEAD) {
				alg_name = sa_algs[i].alg.aead.base.cra_name;
				crypto_unregister_aead(&sa_algs[i].alg.aead);
				err = 0;
			} else {
				alg_name = sa_algs[i].alg.crypto.cra_name;
				err = crypto_unregister_alg(&sa_algs[i].alg.crypto);
			}
			sa_algs[i].registered = false;
		}

		if (err)
			dev_err(dev, "Failed to unregister '%s'", alg_name);
	}
}
