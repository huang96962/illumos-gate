/*
 * CDDL HEADER START
 *
 * The contents of this file are subject to the terms of the
 * Common Development and Distribution License (the "License").
 * You may not use this file except in compliance with the License.
 *
 * You can obtain a copy of the license at usr/src/OPENSOLARIS.LICENSE
 * or http://www.opensolaris.org/os/licensing.
 * See the License for the specific language governing permissions
 * and limitations under the License.
 *
 * When distributing Covered Code, include this CDDL HEADER in each
 * file and include the License file at usr/src/OPENSOLARIS.LICENSE.
 * If applicable, add the following below this CDDL HEADER, with the
 * fields enclosed by brackets "[]" replaced with your own identifying
 * information: Portions Copyright [yyyy] [name of copyright owner]
 *
 * CDDL HEADER END
 */
/*
 * Copyright (c) 2003, 2010, Oracle and/or its affiliates. All rights reserved.
 * Copyright 2017 Nexenta Systems, Inc.  All rights reserved.
 * Copyright 2018, Joyent, Inc.
 * Copyright 2019 Beijing Asia Creation Technology Co.Ltd.
 */

/*
 * SM4 provider for the Kernel Cryptographic Framework (KCF)
 */

#include <sys/types.h>
#include <sys/systm.h>
#include <sys/modctl.h>
#include <sys/ddi.h>
#include <sys/crypto/common.h>
#include <sys/crypto/impl.h>
#include <sys/crypto/spi.h>
#include <sys/sysmacros.h>
#include <sys/strsun.h>
#include <modes/modes.h>
#include <sys/cmn_err.h>
#define	_SM4_IMPL
#include <sm4/sm4_impl.h>

extern struct mod_ops mod_cryptoops;

/*
 * Module linkage information for the kernel.
 */
static struct modlcrypto modlcrypto = {
	&mod_cryptoops,
	"SM4 Kernel SW Provider"
};

static struct modlinkage modlinkage = {
	MODREV_1,
	(void *)&modlcrypto,
	NULL
};

/*
 * Mechanism info structure passed to KCF during registration.
 */
static crypto_mech_info_t sm4_mech_info_tab[] = {
	/* SM4_ECB */
	{SUN_CKM_SM4_ECB, SM4_ECB_MECH_INFO_TYPE,
	    CRYPTO_FG_ENCRYPT | CRYPTO_FG_ENCRYPT_ATOMIC |
	    CRYPTO_FG_DECRYPT | CRYPTO_FG_DECRYPT_ATOMIC,
	    SM4_MIN_KEY_BYTES, SM4_MAX_KEY_BYTES, CRYPTO_KEYSIZE_UNIT_IN_BYTES},
	/* SM4_CBC */
	{SUN_CKM_SM4_CBC, SM4_CBC_MECH_INFO_TYPE,
	    CRYPTO_FG_ENCRYPT | CRYPTO_FG_ENCRYPT_ATOMIC |
	    CRYPTO_FG_DECRYPT | CRYPTO_FG_DECRYPT_ATOMIC,
	    SM4_MIN_KEY_BYTES, SM4_MAX_KEY_BYTES, CRYPTO_KEYSIZE_UNIT_IN_BYTES},
	/* SM4_CBC_MAC */
	{SUN_CKM_SM4_CBC_MAC, SM4_CBCMAC_MECH_INFO_TYPE,
	    CRYPTO_FG_ENCRYPT | CRYPTO_FG_ENCRYPT_ATOMIC |
	    CRYPTO_FG_MAC | CRYPTO_FG_MAC_ATOMIC,
	    SM4_MIN_KEY_BYTES, SM4_MAX_KEY_BYTES, CRYPTO_KEYSIZE_UNIT_IN_BYTES},
	/* SM4_CTR */
	{SUN_CKM_SM4_CTR, SM4_CTR_MECH_INFO_TYPE,
	    CRYPTO_FG_ENCRYPT | CRYPTO_FG_ENCRYPT_ATOMIC |
	    CRYPTO_FG_DECRYPT | CRYPTO_FG_DECRYPT_ATOMIC,
	    SM4_MIN_KEY_BYTES, SM4_MAX_KEY_BYTES, CRYPTO_KEYSIZE_UNIT_IN_BYTES},
	/* SM4_CFB */
	{SUN_CKM_SM4_CFB, SM4_CFB_MECH_INFO_TYPE,
	    CRYPTO_FG_ENCRYPT | CRYPTO_FG_ENCRYPT_ATOMIC |
	    CRYPTO_FG_DECRYPT | CRYPTO_FG_DECRYPT_ATOMIC,
	    SM4_MIN_KEY_BYTES, SM4_MAX_KEY_BYTES, CRYPTO_KEYSIZE_UNIT_IN_BYTES},
	/* SM4_OFB */
	{SUN_CKM_SM4_OFB, SM4_OFB_MECH_INFO_TYPE,
	    CRYPTO_FG_ENCRYPT | CRYPTO_FG_ENCRYPT_ATOMIC |
	    CRYPTO_FG_DECRYPT | CRYPTO_FG_DECRYPT_ATOMIC,
	    SM4_MIN_KEY_BYTES, SM4_MAX_KEY_BYTES, CRYPTO_KEYSIZE_UNIT_IN_BYTES},
	/* SM4_CFB_MAC */
	{SUN_CKM_SM4_CFB_MAC, SM4_CFBMAC_MECH_INFO_TYPE,
	    CRYPTO_FG_ENCRYPT | CRYPTO_FG_ENCRYPT_ATOMIC |
	    CRYPTO_FG_MAC | CRYPTO_FG_MAC_ATOMIC,
	    SM4_MIN_KEY_BYTES, SM4_MAX_KEY_BYTES, CRYPTO_KEYSIZE_UNIT_IN_BYTES},
	/* SM4_OFB_MAC */
	{SUN_CKM_SM4_OFB_MAC, SM4_OFBMAC_MECH_INFO_TYPE,
	    CRYPTO_FG_ENCRYPT | CRYPTO_FG_ENCRYPT_ATOMIC |
	    CRYPTO_FG_MAC | CRYPTO_FG_MAC_ATOMIC,
	    SM4_MIN_KEY_BYTES, SM4_MAX_KEY_BYTES, CRYPTO_KEYSIZE_UNIT_IN_BYTES},
};

/* operations are in-place if the output buffer is NULL */
#define	SM4_ARG_INPLACE(input, output)				\
	if ((output) == NULL)					\
		(output) = (input);

static void sm4_provider_status(crypto_provider_handle_t, uint_t *);

static crypto_control_ops_t sm4_control_ops = {
	sm4_provider_status
};

static int sm4_encrypt_init(crypto_ctx_t *, crypto_mechanism_t *,
    crypto_key_t *, crypto_spi_ctx_template_t, crypto_req_handle_t);
static int sm4_decrypt_init(crypto_ctx_t *, crypto_mechanism_t *,
    crypto_key_t *, crypto_spi_ctx_template_t, crypto_req_handle_t);
static int sm4_common_init(crypto_ctx_t *, crypto_mechanism_t *,
    crypto_key_t *, crypto_spi_ctx_template_t, crypto_req_handle_t);
static int sm4_common_init_ctx(sm4_ctx_t *, crypto_spi_ctx_template_t *,
    crypto_mechanism_t *, crypto_key_t *, int kmflag);
static int sm4_encrypt_final(crypto_ctx_t *, crypto_data_t *,
    crypto_req_handle_t);
static int sm4_decrypt_final(crypto_ctx_t *, crypto_data_t *,
    crypto_req_handle_t);

static int sm4_encrypt(crypto_ctx_t *, crypto_data_t *, crypto_data_t *,
    crypto_req_handle_t);
static int sm4_encrypt_update(crypto_ctx_t *, crypto_data_t *,
    crypto_data_t *, crypto_req_handle_t);
static int sm4_encrypt_atomic(crypto_provider_handle_t, crypto_session_id_t,
    crypto_mechanism_t *, crypto_key_t *, crypto_data_t *,
    crypto_data_t *, crypto_spi_ctx_template_t, crypto_req_handle_t);

static int sm4_decrypt(crypto_ctx_t *, crypto_data_t *, crypto_data_t *,
    crypto_req_handle_t);
static int sm4_decrypt_update(crypto_ctx_t *, crypto_data_t *,
    crypto_data_t *, crypto_req_handle_t);
static int sm4_decrypt_atomic(crypto_provider_handle_t, crypto_session_id_t,
    crypto_mechanism_t *, crypto_key_t *, crypto_data_t *,
    crypto_data_t *, crypto_spi_ctx_template_t, crypto_req_handle_t);

static crypto_cipher_ops_t sm4_cipher_ops = {
	sm4_encrypt_init,
	sm4_encrypt,
	sm4_encrypt_update,
	sm4_encrypt_final,
	sm4_encrypt_atomic,
	sm4_decrypt_init,
	sm4_decrypt,
	sm4_decrypt_update,
	sm4_decrypt_final,
	sm4_decrypt_atomic
};

static int sm4_mac_mode_final(sm4_ctx_t *, crypto_data_t *);
static int sm4_mac_init(crypto_ctx_t *, crypto_mechanism_t *,
    crypto_key_t *, crypto_spi_ctx_template_t, crypto_req_handle_t);
static int sm4_mac(crypto_ctx_t *, crypto_data_t *, crypto_data_t *,
    crypto_req_handle_t);
static int sm4_mac_update(crypto_ctx_t *, crypto_data_t *,
    crypto_req_handle_t);
static int sm4_mac_final(crypto_ctx_t *, crypto_data_t *,
    crypto_req_handle_t);
static int sm4_mac_atomic(crypto_provider_handle_t, crypto_session_id_t,
    crypto_mechanism_t *, crypto_key_t *, crypto_data_t *, crypto_data_t *,
    crypto_spi_ctx_template_t, crypto_req_handle_t);
static int sm4_mac_verify_atomic(crypto_provider_handle_t, crypto_session_id_t,
    crypto_mechanism_t *, crypto_key_t *, crypto_data_t *, crypto_data_t *,
    crypto_spi_ctx_template_t, crypto_req_handle_t);

static crypto_mac_ops_t sm4_mac_ops = {
	sm4_mac_init,
	sm4_mac,
	sm4_mac_update,
	sm4_mac_final,
	sm4_mac_atomic,
	sm4_mac_verify_atomic
};

static int sm4_create_ctx_template(crypto_provider_handle_t,
    crypto_mechanism_t *, crypto_key_t *, crypto_spi_ctx_template_t *,
    size_t *, crypto_req_handle_t);
static int sm4_free_context(crypto_ctx_t *);

static crypto_ctx_ops_t sm4_ctx_ops = {
	sm4_create_ctx_template,
	sm4_free_context
};

static crypto_ops_t sm4_crypto_ops = {
	&sm4_control_ops,
	NULL,
	&sm4_cipher_ops,
	&sm4_mac_ops,
	NULL,
	NULL,
	NULL,
	NULL,
	NULL,
	NULL,
	NULL,
	NULL,
	NULL,
	&sm4_ctx_ops,
	NULL,
	NULL,
	NULL,
};

static crypto_provider_info_t sm4_prov_info = {
	CRYPTO_SPI_VERSION_4,
	"SM4 Software Provider",
	CRYPTO_SW_PROVIDER,
	{&modlinkage},
	NULL,
	&sm4_crypto_ops,
	sizeof (sm4_mech_info_tab)/sizeof (crypto_mech_info_t),
	sm4_mech_info_tab
};

static crypto_kcf_provider_handle_t sm4_prov_handle = 0;
static crypto_data_t null_crypto_data = { CRYPTO_DATA_RAW };

#ifdef _KERNEL
#if defined(__amd64)
extern int detect_gmi();
extern void gmi_sm4_encrypt(unsigned char *out, const unsigned char *in, 
    sm4_key_t *key, size_t len);
extern int gmi_sm4_enabled;
extern int gmi_sm4_mech_enabled;
#endif
#endif

#define	CK_SM4_CTR_PARAMS CK_AES_CTR_PARAMS

#define SM4_MECH_IS_CBC mechanism->cm_type == SM4_CBC_MECH_INFO_TYPE

kmutex_t wait_lock;

int
_init(void)
{
	int ret;

	if ((ret = mod_install(&modlinkage)) != 0)
		return (ret);

	/* Register with KCF.  If the registration fails, remove the module. */
	if (crypto_register_provider(&sm4_prov_info, &sm4_prov_handle)) {
		(void) mod_remove(&modlinkage);
		return (EACCES);
	}

	mutex_init(&wait_lock, NULL, MUTEX_DRIVER, NULL);

#ifdef _KERNEL
#if defined(__amd64)
	int r = detect_gmi();
	cmn_err(CE_NOTE, "!detect_gmi gmi_sm4_enabled = %d", r);
#endif
#endif

	return (0);
}

int
_fini(void)
{
	/* Unregister from KCF if module is registered */
	if (sm4_prov_handle != 0) {
		if (crypto_unregister_provider(sm4_prov_handle))
			return (EBUSY);

		sm4_prov_handle = 0;
	}
	mutex_destroy(&wait_lock);

	return (mod_remove(&modlinkage));
}

int
_info(struct modinfo *modinfop)
{
	return (mod_info(&modlinkage, modinfop));
}


static int
sm4_check_mech_param(crypto_mechanism_t *mechanism, sm4_ctx_t **ctx, int kmflag)
{
	void *p = NULL;
	boolean_t param_required = B_TRUE;
	size_t param_len;
	void *(*alloc_fun)(int);
	int rv = CRYPTO_SUCCESS;

	switch (mechanism->cm_type) {
	case SM4_ECB_MECH_INFO_TYPE:
		param_required = B_FALSE;
		alloc_fun = ecb_alloc_ctx;
		break;
	case SM4_CBC_MECH_INFO_TYPE:
		param_len = SM4_BLOCK_LEN;
		alloc_fun = cbc_alloc_ctx;
		break;
	case SM4_CFB_MECH_INFO_TYPE:
		param_len = SM4_BLOCK_LEN;
		alloc_fun = cfb_alloc_ctx;
		break;
	case SM4_OFB_MECH_INFO_TYPE:
		param_len = SM4_BLOCK_LEN;
		alloc_fun = ofb_alloc_ctx;
		break;
	case SM4_CBCMAC_MECH_INFO_TYPE:
		param_len = SM4_BLOCK_LEN;
		alloc_fun = cmac_alloc_ctx;
		break;
	case SM4_CFBMAC_MECH_INFO_TYPE:
		param_len = SM4_BLOCK_LEN;
		alloc_fun = cfb_mac_alloc_ctx;
		break;
	case SM4_OFBMAC_MECH_INFO_TYPE:
		param_len = SM4_BLOCK_LEN;
		alloc_fun = ofb_mac_alloc_ctx;
		break;
	case SM4_CTR_MECH_INFO_TYPE:
		param_len = sizeof (CK_SM4_CTR_PARAMS);
		alloc_fun = ctr_alloc_ctx;
		break;
	default:
		rv = CRYPTO_MECHANISM_INVALID;
		return (rv);
	}
	if (param_required && mechanism->cm_param != NULL &&
	    mechanism->cm_param_len != param_len) {
		rv = CRYPTO_MECHANISM_PARAM_INVALID;
	}
	if (ctx != NULL) {
		p = (alloc_fun)(kmflag);
		*ctx = p;
	}
	return (rv);
}

/*
 * Initialize key schedules for SM4
 */
static int
init_keysched(crypto_key_t *key, void *newbie, boolean_t init_decrypt_key)
{
	/*
	 * Only keys by value are supported by this module.
	 */
	switch (key->ck_format) {
	case CRYPTO_KEY_RAW:
		if ((key->ck_length & 63) != 0) {
			return (CRYPTO_KEY_SIZE_RANGE);
		}
		break;
	default:
		return (CRYPTO_KEY_TYPE_INCONSISTENT);
	}

	sm4_init_keysched(key->ck_data, newbie, init_decrypt_key);
	return (CRYPTO_SUCCESS);
}

/*
 * KCF software provider control entry points.
 */
/* ARGSUSED */
static void
sm4_provider_status(crypto_provider_handle_t provider, uint_t *status)
{
	*status = CRYPTO_PROVIDER_READY;
}

static int
sm4_encrypt_init(crypto_ctx_t *ctx, crypto_mechanism_t *mechanism,
    crypto_key_t *key, crypto_spi_ctx_template_t template,
    crypto_req_handle_t req)
{
	return (sm4_common_init(ctx, mechanism, key, template, req));
}

static int
sm4_decrypt_init(crypto_ctx_t *ctx, crypto_mechanism_t *mechanism,
    crypto_key_t *key, crypto_spi_ctx_template_t template,
    crypto_req_handle_t req)
{
	return (sm4_common_init(ctx, mechanism, key, template, req));
}

/*
 * KCF software provider encrypt entry points.
 */
static int
sm4_common_init(crypto_ctx_t *ctx, crypto_mechanism_t *mechanism,
    crypto_key_t *key, crypto_spi_ctx_template_t template,
    crypto_req_handle_t req)
{
	sm4_ctx_t *sm4_ctx;
	int rv;
	int kmflag;

	/*
	 * Only keys by value are supported by this module.
	 */
	if (key->ck_format != CRYPTO_KEY_RAW) {
		return (CRYPTO_KEY_TYPE_INCONSISTENT);
	}

	kmflag = crypto_kmflag(req);
	if ((rv = sm4_check_mech_param(mechanism, &sm4_ctx, kmflag))
	    != CRYPTO_SUCCESS)
		return (rv);

	rv = sm4_common_init_ctx(sm4_ctx, template, mechanism, key, kmflag);
	if (rv != CRYPTO_SUCCESS) {
		crypto_free_mode_ctx(sm4_ctx);
		return (rv);
	}

	ctx->cc_provider_private = sm4_ctx;

	return (CRYPTO_SUCCESS);
}

#ifdef _KERNEL
#if defined(__amd64)

static void
sm4_init_control_word(sm4_key_t * key, sm4_ctx_t *sm4_ctx, boolean_t encrypt)
{
	bcopy(sm4_ctx->sc_keysched, key, sizeof(sm4_key_t));
	
	key->q.op.encdec = encrypt ? 0 : 1;
	
	key->q.op.func = GMI_SM4_FUNC_CODE;
	key->q.op.digest = 0;
	
	if (sm4_ctx->sc_flags & ECB_MODE) {
		key->q.op.mode = 0x1;
	} else if (sm4_ctx->sc_flags & (CBC_MODE | CMAC_MODE)){
		key->q.op.mode = 0x2;
	} else if (sm4_ctx->sc_flags & (CFB_MODE | CFB_MAC_MODE)){
		key->q.op.mode = 0x4;
	} else if (sm4_ctx->sc_flags & (OFB_MODE | OFB_MAC_MODE)){
		key->q.op.mode = 0x8;
	} else if (sm4_ctx->sc_flags & CTR_MODE){
		key->q.op.mode = 0x10;
	}
	
	if (sm4_ctx->sc_flags & (CMAC_MODE | CFB_MAC_MODE | OFB_MAC_MODE)) {
		key->q.op.digest = 1;
	}
	
	key->q.op.reserved = 0;
	
	if (sm4_ctx->sc_iv != NULL) {
		bcopy((uint8_t *)sm4_ctx->sc_iv, key->iv, SM4_BLOCK_SIZE);
	}
}

static void
sm4_free_cache(sm4_buff_t * cache)
{
	if (cache->freeptr != NULL) {
		if (cache->length > 0) {
			kmem_free(cache->freeptr, cache->length);
		}
		cache->freeptr = NULL;
		cache->data = NULL;
	}
}

static void
sm4_alloc_buff_from_crypto(sm4_buff_t * cache, crypto_data_t * data)
{
	int rv;

	cache->data = NULL;
	cache->freeptr = NULL;
	if (data == NULL)
		return;
	if (data->cd_length == 0)
		return;

	cache->length = data->cd_length;

	if (data->cd_format == CRYPTO_DATA_RAW) {
		if ((rv = crypto_get_input_data(data, &cache->data, NULL)) != CRYPTO_SUCCESS) {
			cache->data = NULL;
			return;
		}
	} else {
		cache->freeptr = kmem_zalloc(cache->length, KM_SLEEP);
		if ((rv = crypto_get_input_data(data, &cache->data, cache->freeptr)) != CRYPTO_SUCCESS) {
			sm4_free_cache(cache);
			return;
		}
	}
}

static void
sm4_alloc_buff(sm4_buff_t * cache, size_t length)
{
	cache->freeptr = kmem_zalloc(length, KM_SLEEP);
	cache->length = length;
	cache->data = cache->freeptr;
}

static void 
sm4_put_output_data(sm4_buff_t * cache, crypto_data_t * cd)
{
	int rv = 0;
	if (cache->data != NULL && cd != NULL && cache->length > 0) {
		rv = crypto_put_output_data(cache->data, cd, cache->length);
	}
}

#endif
#endif

static int
sm4_zx_encrypt(sm4_ctx_t *sm4_ctx, crypto_data_t *cd_in, crypto_data_t *cd_out,
    size_t length_needed, boolean_t encrypt, char *func)
{
	sm4_buff_t in = {0}, out = {0};
	sm4_key_t gmi_key;
	int ret = CRYPTO_FAILED;
	size_t remain;

#ifdef _KERNEL
#if defined(__amd64)
	if (GMI_SM4_MECH_ENABLED) {
		sm4_alloc_buff_from_crypto(&in, cd_in);
		sm4_alloc_buff(&out, length_needed);

		if (in.data == NULL || out.data == NULL) {
			sm4_free_cache(&in);
			sm4_free_cache(&out);
			return (ret);
		}

		sm4_ctx->zx_done = 1;
		sm4_init_control_word(&gmi_key, sm4_ctx, encrypt);
		kpreempt_disable();
		gmi_sm4_encrypt(out.data, in.data, &gmi_key,
		    cd_in->cd_length);
		kpreempt_enable();

		//buffer not aligned, copy the remain buffer
		remain = cd_in->cd_length & (SM4_BLOCK_SIZE - 1);
		if (remain !=0) {
			bcopy(in.data + cd_in->cd_length - remain,
			    out.data + cd_in->cd_length - remain,
			    remain);
		}
		ret = CRYPTO_SUCCESS;
		sm4_put_output_data(&out, cd_out);

		sm4_free_cache(&in);
		sm4_free_cache(&out);
	}
#endif
#endif
	return (ret);
}

static void
sm4_align_output(crypto_data_t *cd_in, crypto_data_t *cd_out,
    size_t length_needed)
{
	sm4_buff_t in = {0}, aout = {0};
	size_t offset_in, offset_out;
	size_t length_in;

	if (cd_out->cd_length >= length_needed)
		return;

	//save offset
	offset_in = cd_in->cd_offset;
	offset_out = cd_out->cd_offset;
	length_in = cd_in->cd_length;

	//offset to the remain
	cd_in->cd_offset = cd_out->cd_length;
	cd_out->cd_offset = cd_out->cd_length;
	cd_in->cd_length = length_needed - cd_out->cd_length;

	//get remain buff
	sm4_alloc_buff_from_crypto(&in, cd_in);
	sm4_alloc_buff(&aout, length_needed - cd_out->cd_length);
	if (in.data == NULL || aout.data == NULL)
		goto out;

	//copy remain buff
	bcopy(in.data, aout.data, length_needed - cd_out->cd_length);

	//output remain buff
	cd_out->cd_length = length_needed;
	sm4_put_output_data(&aout, cd_out);

out:
	//restore offset
	cd_in->cd_offset = offset_in;
	cd_out->cd_offset = offset_out;
	cd_in->cd_length = length_in;

	sm4_free_cache(&in);
	sm4_free_cache(&aout);
}
static int
sm4_encrypt(crypto_ctx_t *ctx, crypto_data_t *plaintext,
    crypto_data_t *ciphertext, crypto_req_handle_t req)
{
	int ret = CRYPTO_FAILED;

	sm4_ctx_t *sm4_ctx;
	size_t saved_length, saved_offset, length_needed;

	ASSERT(ctx->cc_provider_private != NULL);
	sm4_ctx = ctx->cc_provider_private;

	/*
	 * For block ciphers, plaintext must be a multiple of SM4 block size.
	 * This test is only valid for ciphers whose blocksize is a power of 2.
	 */
	if (((sm4_ctx->sc_flags & (CTR_MODE|CMAC_MODE|CFB_MAC_MODE|
	    OFB_MAC_MODE)) == 0) &&
	    (plaintext->cd_length & (SM4_BLOCK_LEN - 1)) != 0)
		return (CRYPTO_DATA_LEN_RANGE);

	SM4_ARG_INPLACE(plaintext, ciphertext);

	/*
	 * We need to just return the length needed to store the output.
	 * We should not destroy the context for the following case.
	 */
	switch (sm4_ctx->sc_flags &
	    (CMAC_MODE | CFB_MAC_MODE | OFB_MAC_MODE)) {
	case CMAC_MODE:
	case CFB_MAC_MODE:
	case OFB_MAC_MODE:
		length_needed = SM4_BLOCK_LEN;
		break;
	default:
		length_needed = plaintext->cd_length;
	}

	if (ciphertext->cd_length < length_needed) {
		ciphertext->cd_length = length_needed;
		return (CRYPTO_BUFFER_TOO_SMALL);
	}

	saved_length = ciphertext->cd_length;
	saved_offset = ciphertext->cd_offset;

	ret = sm4_zx_encrypt(sm4_ctx, plaintext, ciphertext, length_needed,
	    B_TRUE, "sm4_encrypt");
	if (ret == CRYPTO_SUCCESS) {
		(void) sm4_free_context(ctx);
		return (ret);
	}

	/*
	 * Do an update on the specified input data.
	 */
	ret = sm4_encrypt_update(ctx, plaintext, ciphertext, req);
	if (ret != CRYPTO_SUCCESS) {
		(void) sm4_free_context(ctx);
		return (ret);
	}

	if (sm4_ctx->sc_flags & (CMAC_MODE | CFB_MAC_MODE | OFB_MAC_MODE)) {
		ciphertext->cd_length = length_needed;
		ret = sm4_mac_mode_final(sm4_ctx, ciphertext);
		sm4_ctx->sc_remainder_len = 0;
	}
	
	ASSERT(sm4_ctx->sc_remainder_len == 0);
	(void) sm4_free_context(ctx);

	return (ret);
}

static int
sm4_decrypt(crypto_ctx_t *ctx, crypto_data_t *ciphertext,
    crypto_data_t *plaintext, crypto_req_handle_t req)
{
	int ret = CRYPTO_FAILED;

	sm4_ctx_t *sm4_ctx;
	off_t saved_offset;
	size_t saved_length, length_needed;

	ASSERT(ctx->cc_provider_private != NULL);
	sm4_ctx = ctx->cc_provider_private;

	/*
	 * For block ciphers, plaintext must be a multiple of SM4 block size.
	 * This test is only valid for ciphers whose blocksize is a power of 2.
	 */
	if (((sm4_ctx->sc_flags & (CTR_MODE|CMAC_MODE|CFB_MAC_MODE|
	    OFB_MAC_MODE)) == 0) &&
	    (ciphertext->cd_length & (SM4_BLOCK_LEN - 1)) != 0) {
		return (CRYPTO_ENCRYPTED_DATA_LEN_RANGE);
	}

	SM4_ARG_INPLACE(ciphertext, plaintext);

	saved_offset = plaintext->cd_offset;
	saved_length = plaintext->cd_length;
	length_needed = ciphertext->cd_length;

	ret = sm4_zx_encrypt(sm4_ctx, ciphertext, plaintext, length_needed,
	    B_FALSE, "sm4_decrypt");
	if (ret == CRYPTO_SUCCESS) {
		(void) sm4_free_context(ctx);
		return (ret);
	}

	/*
	 * Do an update on the specified input data.
	 */
	ret = sm4_decrypt_update(ctx, ciphertext, plaintext, req);

	ASSERT(sm4_ctx->sc_remainder_len == 0);
	(void) sm4_free_context(ctx);

	return (ret);
}


/* ARGSUSED */
static int
sm4_encrypt_update(crypto_ctx_t *ctx, crypto_data_t *plaintext,
    crypto_data_t *ciphertext, crypto_req_handle_t req)
{
	off_t saved_offset;
	size_t saved_length, out_len;
	int ret = CRYPTO_SUCCESS;
	sm4_ctx_t *sm4_ctx;

	ASSERT(ctx->cc_provider_private != NULL);
	sm4_ctx = ctx->cc_provider_private;

	SM4_ARG_INPLACE(plaintext, ciphertext);

	/*
	 * CTR mode does not accumulate plaintext across xx_update() calls --
	 * it always outputs the same number of bytes as the input (so
	 * sc_remainder_len is always 0).  Other modes _do_ accumulate
	 * plaintext, and output only full blocks. For non-CTR modes, adjust
	 * the output size to reflect this.
	 */
	out_len = plaintext->cd_length + sm4_ctx->sc_remainder_len;
	if ((sm4_ctx->sc_flags & CTR_MODE) == 0)
		out_len &= ~(SM4_BLOCK_LEN - 1);

	/*
	 * return length needed to store the output.
	 * CMAC stores its output in a local buffer until *_final.
	 */
	if ((sm4_ctx->sc_flags & 
	    (CMAC_MODE | CFB_MAC_MODE | OFB_MAC_MODE)) == 0 &&
	    ciphertext->cd_length < out_len) {
		ciphertext->cd_length = out_len;
		return (CRYPTO_BUFFER_TOO_SMALL);
	}

	saved_offset = ciphertext->cd_offset;
	saved_length = ciphertext->cd_length;

	/*
	 * Do the SM4 update on the specified input data.
	 */
	switch (plaintext->cd_format) {
	case CRYPTO_DATA_RAW:		
		ret = crypto_update_iov(ctx->cc_provider_private,
		    plaintext, ciphertext, sm4_encrypt_contiguous_blocks,
		    sm4_copy_block64);
		break;
	case CRYPTO_DATA_UIO:
		ret = crypto_update_uio(ctx->cc_provider_private,
		    plaintext, ciphertext, sm4_encrypt_contiguous_blocks,
		    sm4_copy_block64);
		break;
	case CRYPTO_DATA_MBLK:
		ret = crypto_update_mp(ctx->cc_provider_private,
		    plaintext, ciphertext, sm4_encrypt_contiguous_blocks,
		    sm4_copy_block64);
		break;
	default:
		ret = CRYPTO_ARGUMENTS_BAD;
	}

	if (ret == CRYPTO_SUCCESS) {
		if (plaintext != ciphertext)
			ciphertext->cd_length =
			    ciphertext->cd_offset - saved_offset;
	} else {
		ciphertext->cd_length = saved_length;
	}
	ciphertext->cd_offset = saved_offset;

	return (ret);
}

static int
sm4_decrypt_update(crypto_ctx_t *ctx, crypto_data_t *ciphertext,
    crypto_data_t *plaintext, crypto_req_handle_t req)
{
	off_t saved_offset;
	size_t saved_length, out_len;
	int ret = CRYPTO_SUCCESS;
	sm4_ctx_t *sm4_ctx;

	ASSERT(ctx->cc_provider_private != NULL);
	sm4_ctx = ctx->cc_provider_private;

	SM4_ARG_INPLACE(ciphertext, plaintext);

	/*
	 * Adjust the number of bytes that will hold the plaintext (out_len).
	 * MAC mechanisms never return plaintext for update
	 * operations, so we set out_len to 0 for those.
	 *
	 * CTR mode does not accumulate any ciphertext across xx_decrypt
	 * calls, and always outputs as many bytes of plaintext as
	 * ciphertext.
	 *
	 * The remaining mechanisms output full blocks of plaintext, so
	 * we round out_len down to the closest multiple of SM4_BLOCK_LEN.
	 */
	out_len = sm4_ctx->sc_remainder_len + ciphertext->cd_length;
	if ((sm4_ctx->sc_flags & (CMAC_MODE|CFB_MAC_MODE|OFB_MAC_MODE)) != 0) {
		out_len = 0;
	} else if ((sm4_ctx->sc_flags & CTR_MODE) == 0) {
		out_len &= ~(SM4_BLOCK_LEN - 1);
	}

	/* return length needed to store the output */
	if (plaintext->cd_length < out_len) {
		plaintext->cd_length = out_len;
		return (CRYPTO_BUFFER_TOO_SMALL);
	}

	saved_offset = plaintext->cd_offset;
	saved_length = plaintext->cd_length;

	/*
	 * Do the AES update on the specified input data.
	 */
	switch (ciphertext->cd_format) {
	case CRYPTO_DATA_RAW:
		ret = crypto_update_iov(ctx->cc_provider_private,
		    ciphertext, plaintext, sm4_decrypt_contiguous_blocks,
		    sm4_copy_block64);
		break;
	case CRYPTO_DATA_UIO:
		ret = crypto_update_uio(ctx->cc_provider_private,
		    ciphertext, plaintext, sm4_decrypt_contiguous_blocks,
		    sm4_copy_block64);
		break;
	case CRYPTO_DATA_MBLK:
		ret = crypto_update_mp(ctx->cc_provider_private,
		    ciphertext, plaintext, sm4_decrypt_contiguous_blocks,
		    sm4_copy_block64);
		break;
	default:
		ret = CRYPTO_ARGUMENTS_BAD;
	}

	if (ret == CRYPTO_SUCCESS) {
		if (ciphertext != plaintext)
			plaintext->cd_length =
			    plaintext->cd_offset - saved_offset;
	} else {
		plaintext->cd_length = saved_length;
	}
	plaintext->cd_offset = saved_offset;

	return (ret);
}

/* ARGSUSED */
static int
sm4_encrypt_final(crypto_ctx_t *ctx, crypto_data_t *data,
    crypto_req_handle_t req)
{
	sm4_ctx_t *sm4_ctx;
	int ret;

	ASSERT(ctx->cc_provider_private != NULL);
	sm4_ctx = ctx->cc_provider_private;

	if (data->cd_format != CRYPTO_DATA_RAW &&
	    data->cd_format != CRYPTO_DATA_UIO &&
	    data->cd_format != CRYPTO_DATA_MBLK) {
		return (CRYPTO_ARGUMENTS_BAD);
	}
	
	if (sm4_ctx->zx_done == 1) {
		(void) sm4_free_context(ctx);
		return (CRYPTO_SUCCESS);
	}

	if (sm4_ctx->sc_flags &
	    (CMAC_MODE | CFB_MAC_MODE | OFB_MAC_MODE)) {
		ret = sm4_mac_mode_final(sm4_ctx, data);
		if (ret != CRYPTO_SUCCESS)
			return (ret);
		data->cd_length = SM4_BLOCK_LEN;
	} else if ((sm4_ctx->sc_flags & CTR_MODE) == 0){
		/*
		 * There must be no unprocessed plaintext.
		 * This happens if the length of the last data is
		 * not a multiple of the AES block length.
		 */
		if (sm4_ctx->sc_remainder_len > 0) {
			return (CRYPTO_DATA_LEN_RANGE);
		}
		data->cd_length = 0;
	}

	(void) sm4_free_context(ctx);

	return (CRYPTO_SUCCESS);
}

/* ARGSUSED */
static int
sm4_decrypt_final(crypto_ctx_t *ctx, crypto_data_t *data,
    crypto_req_handle_t req)
{
	sm4_ctx_t *sm4_ctx;
	int ret;
	off_t saved_offset;
	size_t saved_length;

	ASSERT(ctx->cc_provider_private != NULL);
	sm4_ctx = ctx->cc_provider_private;

	if (data->cd_format != CRYPTO_DATA_RAW &&
	    data->cd_format != CRYPTO_DATA_UIO &&
	    data->cd_format != CRYPTO_DATA_MBLK) {
		return (CRYPTO_ARGUMENTS_BAD);
	}

	if (sm4_ctx->zx_done == 1) {
		(void) sm4_free_context(ctx);
		return (CRYPTO_SUCCESS);
	}

	/*
	 * There must be no unprocessed ciphertext.
	 * This happens if the length of the last ciphertext is
	 * not a multiple of the SM4 block length.
	 *
	 * For CTR mode, sc_remainder_len is always zero (we never
	 * accumulate ciphertext across update calls with CTR mode).
	 */
	if (sm4_ctx->sc_remainder_len > 0 &&
	    (sm4_ctx->sc_flags & CTR_MODE) == 0) {
		return (CRYPTO_ENCRYPTED_DATA_LEN_RANGE);
	}

	if ((sm4_ctx->sc_flags & (CTR_MODE|CMAC_MODE|CFB_MAC_MODE|
	    OFB_MAC_MODE)) == 0) {
		data->cd_length = 0;
	}

	(void) sm4_free_context(ctx);

	return (CRYPTO_SUCCESS);
}

/* ARGSUSED */
static int
sm4_encrypt_atomic(crypto_provider_handle_t provider,
    crypto_session_id_t session_id, crypto_mechanism_t *mechanism,
    crypto_key_t *key, crypto_data_t *plaintext, crypto_data_t *ciphertext,
    crypto_spi_ctx_template_t template, crypto_req_handle_t req)
{
	sm4_ctx_t sm4_ctx;	/* on the stack */
	off_t saved_offset;
	size_t saved_length;
	size_t length_needed;
	int ret;

	SM4_ARG_INPLACE(plaintext, ciphertext);

	/*
	 * CTR, CCM, CMAC, GCM, and GMAC modes do not require that plaintext
	 * be a multiple of SM4 block size.
	 */
	/*switch (mechanism->cm_type) {
	case SM4_CTR_MECH_INFO_TYPE:
	case SM4_CFB_MECH_INFO_TYPE:
	case SM4_OFB_MECH_INFO_TYPE:
	case SM4_CFBMAC_MECH_INFO_TYPE:
	case SM4_CBCMAC_MECH_INFO_TYPE:	
	case SM4_OFBMAC_MECH_INFO_TYPE:
		break;
	default:
		if ((plaintext->cd_length & (SM4_BLOCK_LEN - 1)) != 0)
			return (CRYPTO_DATA_LEN_RANGE);
	}*/

	if ((ret = sm4_check_mech_param(mechanism, NULL, 0)) != CRYPTO_SUCCESS)
		return (ret);

	bzero(&sm4_ctx, sizeof (sm4_ctx_t));

	ret = sm4_common_init_ctx(&sm4_ctx, template, mechanism, key,
	    crypto_kmflag(req));
	if (ret != CRYPTO_SUCCESS)
		return (ret);

	switch (mechanism->cm_type) {
	case SM4_CBCMAC_MECH_INFO_TYPE:
	case SM4_CFBMAC_MECH_INFO_TYPE:
	case SM4_OFBMAC_MECH_INFO_TYPE:
		length_needed = SM4_BLOCK_LEN;
		break;
	default:
		length_needed = plaintext->cd_length;
	}

	/* return size of buffer needed to store output */
	if (ciphertext->cd_length < length_needed) {
		ciphertext->cd_length = length_needed;
		ret = CRYPTO_BUFFER_TOO_SMALL;
		goto out;
	}

	saved_offset = ciphertext->cd_offset;
	saved_length = ciphertext->cd_length;

	ret = sm4_zx_encrypt(&sm4_ctx, plaintext, ciphertext, length_needed,
	    B_TRUE, "sm4_encrypt_atomic");
	if (ret == CRYPTO_SUCCESS) {
		goto out;
	}

	/*
	 * Do an update on the specified input data.
	 */
	switch (plaintext->cd_format) {
	case CRYPTO_DATA_RAW:
		ret = crypto_update_iov(&sm4_ctx, plaintext, ciphertext,
		    sm4_encrypt_contiguous_blocks, sm4_copy_block64);
		break;
	case CRYPTO_DATA_UIO:
		ret = crypto_update_uio(&sm4_ctx, plaintext, ciphertext,
		    sm4_encrypt_contiguous_blocks, sm4_copy_block64);
		break;
	case CRYPTO_DATA_MBLK:
		ret = crypto_update_mp(&sm4_ctx, plaintext, ciphertext,
		    sm4_encrypt_contiguous_blocks, sm4_copy_block64);
		break;
	default:
		ret = CRYPTO_ARGUMENTS_BAD;
	}

	if (ret == CRYPTO_SUCCESS) {
		switch (mechanism->cm_type) {
		case SM4_CTR_MECH_INFO_TYPE:
			/*
			 * Note that this use of the ASSERT3U has a slightly
			 * different meaning than the other uses in the
			 * switch statement. The other uses are to ensure
			 * no unprocessed plaintext remains after encryption
			 * (and that the input plaintext was an exact multiple
			 * of AES_BLOCK_LEN).
			 *
			 * For CTR mode, it is ensuring that no input
			 * plaintext was ever segmented and buffered during
			 * processing (since it's a stream cipher).
			 */
			ASSERT3U(sm4_ctx.sc_remainder_len, ==, 0);
			break;
		case SM4_CBCMAC_MECH_INFO_TYPE:
		case SM4_CFBMAC_MECH_INFO_TYPE:
		case SM4_OFBMAC_MECH_INFO_TYPE:
			ret = sm4_mac_mode_final(&sm4_ctx, ciphertext);
			if (ret != CRYPTO_SUCCESS)
				goto out;
			break;
		default:
			ASSERT3U(sm4_ctx.sc_remainder_len, ==, 0);
			break;
		}

		if (plaintext != ciphertext) {
			ciphertext->cd_length =
			    ciphertext->cd_offset - saved_offset;
		}
		sm4_align_output(plaintext, ciphertext, length_needed);
	} else {
		ciphertext->cd_length = saved_length;
	}
	ciphertext->cd_offset = saved_offset;

out:
	if (sm4_ctx.sc_flags & PROVIDER_OWNS_KEY_SCHEDULE) {
		bzero(sm4_ctx.sc_keysched, sm4_ctx.sc_keysched_len);
		kmem_free(sm4_ctx.sc_keysched, sm4_ctx.sc_keysched_len);
	}

	return (ret);
}

/* ARGSUSED */
static int
sm4_decrypt_atomic(crypto_provider_handle_t provider,
    crypto_session_id_t session_id, crypto_mechanism_t *mechanism,
    crypto_key_t *key, crypto_data_t *ciphertext, crypto_data_t *plaintext,
    crypto_spi_ctx_template_t template, crypto_req_handle_t req)
{
	sm4_ctx_t sm4_ctx;	/* on the stack */
	off_t saved_offset;
	size_t saved_length;
	size_t length_needed;
	int ret;
	
	SM4_ARG_INPLACE(ciphertext, plaintext);

	/*
	 * CCM, GCM, CTR, and GMAC modes do not require that ciphertext
	 * be a multiple of AES block size.
	 */
	/*switch (mechanism->cm_type) {
	case SM4_CTR_MECH_INFO_TYPE:
		break;
	default:
		if ((ciphertext->cd_length & (SM4_BLOCK_LEN - 1)) != 0)
			return (CRYPTO_ENCRYPTED_DATA_LEN_RANGE);
	}*/

	if ((ret = sm4_check_mech_param(mechanism, NULL, 0)) != CRYPTO_SUCCESS)
		return (ret);

	bzero(&sm4_ctx, sizeof (sm4_ctx_t));

	ret = sm4_common_init_ctx(&sm4_ctx, template, mechanism, key,
	    crypto_kmflag(req));
	if (ret != CRYPTO_SUCCESS)
		return (ret);

	switch (mechanism->cm_type) {
	default:
		length_needed = ciphertext->cd_length;
	}

	/* return size of buffer needed to store output */
	if (plaintext->cd_length < length_needed) {
		plaintext->cd_length = length_needed;
		ret = CRYPTO_BUFFER_TOO_SMALL;
		goto out;
	}

	saved_offset = plaintext->cd_offset;
	saved_length = plaintext->cd_length;

	ret = sm4_zx_encrypt(&sm4_ctx, ciphertext, plaintext, length_needed,
	    B_FALSE, "sm4_decrypt_atomic");
	if (ret == CRYPTO_SUCCESS) {
		goto out;
	}

	/*
	 * Do an update on the specified input data.
	 */
	switch (ciphertext->cd_format) {
	case CRYPTO_DATA_RAW:
		ret = crypto_update_iov(&sm4_ctx, ciphertext, plaintext,
		    sm4_decrypt_contiguous_blocks, sm4_copy_block64);
		break;
	case CRYPTO_DATA_UIO:
		ret = crypto_update_uio(&sm4_ctx, ciphertext, plaintext,
		    sm4_decrypt_contiguous_blocks, sm4_copy_block64);
		break;
	case CRYPTO_DATA_MBLK:
		ret = crypto_update_mp(&sm4_ctx, ciphertext, plaintext,
		    sm4_decrypt_contiguous_blocks, sm4_copy_block64);
		break;
	default:
		ret = CRYPTO_ARGUMENTS_BAD;
	}

	if (ret == CRYPTO_SUCCESS) {
		switch (mechanism->cm_type) {
		case SM4_CTR_MECH_INFO_TYPE:
			if (ciphertext != plaintext) {
				plaintext->cd_length =
				    plaintext->cd_offset - saved_offset;
			}
			break;
		default:
			ASSERT3U(sm4_ctx.sc_remainder_len, ==, 0);
			if (ciphertext != plaintext) {
				plaintext->cd_length =
				    plaintext->cd_offset - saved_offset;
			}
			break;
		}
		sm4_align_output(ciphertext, plaintext, length_needed);
	} else {
		plaintext->cd_length = saved_length;
	}
	plaintext->cd_offset = saved_offset;

out:
	if (sm4_ctx.sc_flags & PROVIDER_OWNS_KEY_SCHEDULE) {
		bzero(sm4_ctx.sc_keysched, sm4_ctx.sc_keysched_len);
		kmem_free(sm4_ctx.sc_keysched, sm4_ctx.sc_keysched_len);
	}

	return (ret);
}

/*
 * KCF software provider context template entry points.
 */
/* ARGSUSED */
static int
sm4_create_ctx_template(crypto_provider_handle_t provider,
    crypto_mechanism_t *mechanism, crypto_key_t *key,
    crypto_spi_ctx_template_t *tmpl, size_t *tmpl_size,
    crypto_req_handle_t req)
{
	void *keysched;
	size_t size;
	int rv;

	if (mechanism->cm_type != SM4_ECB_MECH_INFO_TYPE &&
	    mechanism->cm_type != SM4_CBC_MECH_INFO_TYPE &&
	    mechanism->cm_type != SM4_CTR_MECH_INFO_TYPE &&
	    mechanism->cm_type != SM4_CFB_MECH_INFO_TYPE &&
	    mechanism->cm_type != SM4_OFB_MECH_INFO_TYPE &&
	    mechanism->cm_type != SM4_CBCMAC_MECH_INFO_TYPE &&
	    mechanism->cm_type != SM4_CFBMAC_MECH_INFO_TYPE &&
	    mechanism->cm_type != SM4_OFBMAC_MECH_INFO_TYPE)
		return (CRYPTO_MECHANISM_INVALID);

	if ((keysched = sm4_alloc_keysched(&size,
	    crypto_kmflag(req))) == NULL) {
		return (CRYPTO_HOST_MEMORY);
	}

	/*
	 * Initialize key schedule.  Key length information is stored
	 * in the key.
	 */
	if ((rv = init_keysched(key, keysched, SM4_MECH_IS_CBC))
	    != CRYPTO_SUCCESS) {
		bzero(keysched, size);
		kmem_free(keysched, size);
		return (rv);
	}

	*tmpl = keysched;
	*tmpl_size = size;

	return (CRYPTO_SUCCESS);
}


static int
sm4_free_context(crypto_ctx_t *ctx)
{
	sm4_ctx_t *sm4_ctx = ctx->cc_provider_private;

	if (sm4_ctx != NULL) {
		if (sm4_ctx->sc_flags & PROVIDER_OWNS_KEY_SCHEDULE) {
			ASSERT(sm4_ctx->sc_keysched_len != 0);
			bzero(sm4_ctx->sc_keysched, sm4_ctx->sc_keysched_len);
			kmem_free(sm4_ctx->sc_keysched,
			    sm4_ctx->sc_keysched_len);
		}
		crypto_free_mode_ctx(sm4_ctx);
		ctx->cc_provider_private = NULL;
	}

	return (CRYPTO_SUCCESS);
}

static int
sm4_mac_mode_final(sm4_ctx_t *sm4_ctx, crypto_data_t *out)
{
	cbc_ctx_t * cbc_ctx = (cbc_ctx_t *)sm4_ctx;
	int i = 0;
	uint8_t * mac_ptr = (uint8_t *)cbc_ctx->cbc_iv;

	if (cbc_ctx->cbc_flags & OFB_MAC_MODE) {
		mac_ptr = (uint8_t *)cbc_ctx->cbc_lastblock;
	}

	int rv = crypto_put_output_data(mac_ptr, out, SM4_BLOCK_LEN);

	return (0);
}

static int
sm4_mac_init_ctx(cbc_ctx_t *cbc_ctx, char *param, size_t param_len,
    size_t block_size, void (*copy_block)(uint8_t *, uint64_t *),
    uint32_t mode)
{
	if (param != NULL) {
#ifdef _KERNEL
		ASSERT(param_len == block_size);
#else
		assert(param_len == block_size);
#endif
		copy_block((uchar_t *)param, cbc_ctx->cbc_iv);
	}

	cbc_ctx->cbc_lastp = (uint8_t *)&cbc_ctx->cbc_iv[0];
	cbc_ctx->cbc_flags |= mode;
	cbc_ctx->max_remain = block_size;// + 1;
	return (CRYPTO_SUCCESS);
}

static int
sm4_cbc_mac_init_ctx(cbc_ctx_t *cbc_ctx, char *param, size_t param_len,
    size_t block_size, void (*copy_block)(uint8_t *, uint64_t *))
{
	return (sm4_mac_init_ctx(cbc_ctx, param, param_len, block_size,
	    copy_block, CMAC_MODE));
}

static int
sm4_cfb_mac_init_ctx(cbc_ctx_t *cbc_ctx, char *param, size_t param_len,
    size_t block_size, void (*copy_block)(uint8_t *, uint64_t *))
{
	return (sm4_mac_init_ctx(cbc_ctx, param, param_len, block_size,
	    copy_block, CFB_MAC_MODE));
}

static int
sm4_ofb_mac_init_ctx(cbc_ctx_t *cbc_ctx, char *param, size_t param_len,
    size_t block_size, void (*copy_block)(uint8_t *, uint64_t *))
{
	return (sm4_mac_init_ctx(cbc_ctx, param, param_len, block_size,
	    copy_block, OFB_MAC_MODE));
}

static int
sm4_cbc_common_init_ctx(sm4_ctx_t *sm4_ctx, void *param, size_t paramlen,
    int (*init_ctx) (cbc_ctx_t *, char *, size_t, size_t block_size,
        void (*copy_block)(uint8_t *, uint64_t *)))
{
	int rv = CRYPTO_SUCCESS;	
	rv = init_ctx((cbc_ctx_t *)sm4_ctx, (char *)param,
	    paramlen, SM4_BLOCK_LEN, sm4_copy_block64);
	return (rv);
}

static int
sm4_ctr_common_init_ctx(sm4_ctx_t *sm4_ctx, void *param, size_t paramlen,
    int (*init_ctx) (ctr_ctx_t *, ulong_t , uint8_t *,
        int (*cipher)(const void *ks, const uint8_t *pt, uint8_t *ct),
        void (*copy_block)(uint8_t *, uint8_t *)))
{
	CK_SM4_CTR_PARAMS *ctrp;
	int rv = CRYPTO_SUCCESS;
	
	if (param == NULL || paramlen != sizeof (CK_SM4_CTR_PARAMS)) {
		return (CRYPTO_MECHANISM_PARAM_INVALID);
	}
	
	ctrp = (CK_SM4_CTR_PARAMS *)param;
	rv = init_ctx((ctr_ctx_t *)sm4_ctx, (uint32_t)ctrp->ulCounterBits,
	    ctrp->cb, sm4_encrypt_block, sm4_copy_block);
	
	return (rv);
}

static int
sm4_common_init_ctx(sm4_ctx_t *sm4_ctx, crypto_spi_ctx_template_t *template,
    crypto_mechanism_t *mechanism, crypto_key_t *key, int kmflag)
{
	int rv = CRYPTO_SUCCESS;
	void *keysched;
	size_t size;

	if (template == NULL) {
		if ((keysched = sm4_alloc_keysched(&size, kmflag)) == NULL)
			return (CRYPTO_HOST_MEMORY);
		/*
		 * Initialize key schedule.
		 * Key length is stored in the key.
		 */
		if ((rv = init_keysched(key, keysched, SM4_MECH_IS_CBC))
		    != CRYPTO_SUCCESS) {
			kmem_free(keysched, size);
			return (rv);
		}

		sm4_ctx->sc_flags |= PROVIDER_OWNS_KEY_SCHEDULE;
		sm4_ctx->sc_keysched_len = size;
	} else {
		keysched = template;
	}
	sm4_ctx->sc_keysched = keysched;
	sm4_ctx->zx_done = 0;

	switch (mechanism->cm_type) {
	case SM4_ECB_MECH_INFO_TYPE:
		sm4_ctx->sc_flags |= ECB_MODE;
		break;
	case SM4_CBC_MECH_INFO_TYPE:
		rv = sm4_cbc_common_init_ctx(sm4_ctx,
		    (void *)mechanism->cm_param, mechanism->cm_param_len,
		    cbc_init_ctx);
		break;
	case SM4_CFB_MECH_INFO_TYPE:
		rv = sm4_cbc_common_init_ctx(sm4_ctx,
		    (void *)mechanism->cm_param, mechanism->cm_param_len,
		    cfb_init_ctx);
		break;
	case SM4_OFB_MECH_INFO_TYPE:
		rv = sm4_cbc_common_init_ctx(sm4_ctx,
		    (void *)mechanism->cm_param, mechanism->cm_param_len,
		    ofb_init_ctx);
		break;
	case SM4_CTR_MECH_INFO_TYPE:		
		rv = sm4_ctr_common_init_ctx(sm4_ctx,
		    (void *)mechanism->cm_param, mechanism->cm_param_len,
		    ctr_init_ctx);
		break;
	case SM4_CBCMAC_MECH_INFO_TYPE:
		rv = sm4_cbc_common_init_ctx(sm4_ctx,
		    (void *)mechanism->cm_param, mechanism->cm_param_len,
		    sm4_cbc_mac_init_ctx);
		break;
	case SM4_CFBMAC_MECH_INFO_TYPE:
		rv = sm4_cbc_common_init_ctx(sm4_ctx,
		    (void *)mechanism->cm_param, mechanism->cm_param_len,
		    sm4_cfb_mac_init_ctx);
		break;
	case SM4_OFBMAC_MECH_INFO_TYPE:
		rv = sm4_cbc_common_init_ctx(sm4_ctx,
		    (void *)mechanism->cm_param, mechanism->cm_param_len,
		    sm4_ofb_mac_init_ctx);
		break;
	}

	if (rv != CRYPTO_SUCCESS) {
		if (sm4_ctx->sc_flags & PROVIDER_OWNS_KEY_SCHEDULE) {
			bzero(keysched, size);
			kmem_free(keysched, size);
		}
	}

	return (rv);
}

static int
sm4_mac_init(crypto_ctx_t *ctx, crypto_mechanism_t *mechanism,
    crypto_key_t *key, crypto_spi_ctx_template_t template,
    crypto_req_handle_t req)
{
	return (sm4_encrypt_init(ctx, mechanism,
	    key, template, req));
}

static int
sm4_mac(crypto_ctx_t *ctx, crypto_data_t *plaintext, crypto_data_t *ciphertext,
    crypto_req_handle_t req)
{
	return (sm4_encrypt(ctx, plaintext, ciphertext, req));
}

static int
sm4_mac_update(crypto_ctx_t *ctx, crypto_data_t *data,
    crypto_req_handle_t req)
{
	crypto_data_t out;
	uint8_t block[SM4_BLOCK_LEN];
	out.cd_format = CRYPTO_DATA_RAW;
	out.cd_offset = 0;
	out.cd_length = sizeof (block);
	out.cd_miscdata = NULL;
	out.cd_raw.iov_base = (void *)block;
	out.cd_raw.iov_len = sizeof (block);

	return (sm4_encrypt_update(ctx, data, &out, req));
}

static int
sm4_mac_final(crypto_ctx_t *ctx, crypto_data_t *mac, crypto_req_handle_t req)
{
	return (sm4_encrypt_final(ctx, mac, req));
}

static int
sm4_mac_atomic(crypto_provider_handle_t provider,
    crypto_session_id_t session_id, crypto_mechanism_t *mechanism,
    crypto_key_t *key, crypto_data_t *data, crypto_data_t *mac,
    crypto_spi_ctx_template_t template, crypto_req_handle_t req)
{
	/* CMAC */
	return (sm4_encrypt_atomic(provider, session_id, mechanism,
	    key, data, mac, template, req));
}

static int
sm4_mac_verify_atomic(crypto_provider_handle_t provider,
    crypto_session_id_t session_id, crypto_mechanism_t *mechanism,
    crypto_key_t *key, crypto_data_t *data, crypto_data_t *mac,
    crypto_spi_ctx_template_t template, crypto_req_handle_t req)
{
	crypto_mechanism_t gcm_mech;
	crypto_data_t data_mac;
	char buf[SM4_BLOCK_LEN];
	int rv;

	/* CMAC */
	data_mac.cd_format = CRYPTO_DATA_RAW;
	data_mac.cd_offset = 0;
	data_mac.cd_length = SM4_BLOCK_LEN;
	data_mac.cd_miscdata = NULL;
	data_mac.cd_raw.iov_base = (void *) buf;
	data_mac.cd_raw.iov_len = SM4_BLOCK_LEN;

	rv = sm4_encrypt_atomic(provider, session_id, &gcm_mech,
	    key, data, &data_mac, template, req);

	if (rv != CRYPTO_SUCCESS)
		return (rv);

	/* should use get_input_data for mac? */
	if (bcmp(buf, mac->cd_raw.iov_base + mac->cd_offset,
	    SM4_BLOCK_LEN) != 0)
		return (CRYPTO_INVALID_MAC);

	return (CRYPTO_SUCCESS);
}
