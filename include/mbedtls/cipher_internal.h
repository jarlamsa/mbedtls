/**
 * \file cipher_internal.h
 *
 * \brief Cipher wrappers.
 *
 * \author Adriaan de Jong <dejong@fox-it.com>
 */
/*
 *  Copyright (C) 2006-2015, ARM Limited, All Rights Reserved
 *  SPDX-License-Identifier: Apache-2.0
 *
 *  Licensed under the Apache License, Version 2.0 (the "License"); you may
 *  not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
 *  WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 *
 *  This file is part of mbed TLS (https://tls.mbed.org)
 */
#ifndef MBEDTLS_CIPHER_WRAP_H
#define MBEDTLS_CIPHER_WRAP_H

#if !defined(MBEDTLS_CONFIG_FILE)
#include "config.h"
#else
#include MBEDTLS_CONFIG_FILE
#endif

#include "cipher.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * Cipher information macro definition
 */

#if defined(MBEDTLS_CCM_C) && defined(MBEDTLS_AES_C)
/* Dummy definition to keep check-names.sh happy - don't uncomment */
//#define MBEDTLS_CIPHER_INFO_AES_128_CCM
//#define MBEDTLS_CIPHER_BASE_AES_128_CCM

#define MBEDTLS_CIPHER_INFO_AES_128_CCM_TYPE            MBEDTLS_CIPHER_AES_128_CCM
#define MBEDTLS_CIPHER_INFO_AES_128_CCM_MODE            MBEDTLS_MODE_CCM
#define MBEDTLS_CIPHER_INFO_AES_128_CCM_KEY_BITLEN      128
#define MBEDTLS_CIPHER_INFO_AES_128_CCM_NAME            "AES-128-CCM"
#define MBEDTLS_CIPHER_INFO_AES_128_CCM_IV_SIZE         12
#define MBEDTLS_CIPHER_INFO_AES_128_CCM_FLAGS           MBEDTLS_CIPHER_VARIABLE_IV_LEN
#define MBEDTLS_CIPHER_INFO_AES_128_CCM_BLOCK_SIZE      16
#define MBEDTLS_CIPHER_INFO_AES_128_CCM_BASE            &ccm_aes_info

#define MBEDTLS_CIPHER_BASE_AES_128_CCM_CIPHER          MBEDTLS_CIPHER_ID_AES
#define MBEDTLS_CIPHER_BASE_AES_128_CCM_ECB_FUNC        NULL
#define MBEDTLS_CIPHER_BASE_AES_128_CCM_CBC_FUNC        NULL
#define MBEDTLS_CIPHER_BASE_AES_128_CCM_CFB_FUNC        NULL
#define MBEDTLS_CIPHER_BASE_AES_128_CCM_OFB_FUNC        NULL
#define MBEDTLS_CIPHER_BASE_AES_128_CCM_CTR_FUNC        NULL
#define MBEDTLS_CIPHER_BASE_AES_128_CCM_XTS_FUNC        NULL
#define MBEDTLS_CIPHER_BASE_AES_128_CCM_STREAM_FUNC     NULL
#define MBEDTLS_CIPHER_BASE_AES_128_CCM_SETKEY_ENC_FUNC ccm_aes_setkey_wrap
#define MBEDTLS_CIPHER_BASE_AES_128_CCM_SETKEY_DEC_FUNC ccm_aes_setkey_wrap
#define MBEDTLS_CIPHER_BASE_AES_128_CCM_ALLOC_FUNC      ccm_ctx_alloc
#define MBEDTLS_CIPHER_BASE_AES_128_CCM_FREE_FUNC       ccm_ctx_free
#endif /* MBEDTLS_CCM_C && MBEDTLS_AES_C */

/**
 * Helper macros to extract fields from cipher types
 */
#define MBEDTLS_CIPHER_INFO_TYPE_T( CIPHER )            CIPHER ## _TYPE
#define MBEDTLS_CIPHER_INFO_MODE_T( CIPHER )            CIPHER ## _MODE
#define MBEDTLS_CIPHER_INFO_KEY_BITLEN_T( CIPHER )      CIPHER ## _KEY_BITLEN
#define MBEDTLS_CIPHER_INFO_NAME_T( CIPHER )            CIPHER ## _NAME
#define MBEDTLS_CIPHER_INFO_IV_SIZE_T( CIPHER )         CIPHER ## _IV_SIZE
#define MBEDTLS_CIPHER_INFO_FLAGS_T( CIPHER )           CIPHER ## _FLAGS
#define MBEDTLS_CIPHER_INFO_BLOCK_SIZE_T( CIPHER )      CIPHER ## _BLOCK_SIZE
#define MBEDTLS_CIPHER_INFO_BASE_T( CIPHER )            CIPHER ## _BASE

#define MBEDTLS_CIPHER_BASE_CIPHER_T( CIPHER )          CIPHER ## _CIPHER
#define MBEDTLS_CIPHER_BASE_ECB_FUNC_T( CIPHER )        CIPHER ## _ECB_FUNC
#define MBEDTLS_CIPHER_BASE_CBC_FUNC_T( CIPHER )        CIPHER ## _CBC_FUNC
#define MBEDTLS_CIPHER_BASE_CFB_FUNC_T( CIPHER )        CIPHER ## _CFB_FUNC
#define MBEDTLS_CIPHER_BASE_OFB_FUNC_T( CIPHER )        CIPHER ## _OFB_FUNC
#define MBEDTLS_CIPHER_BASE_CTR_FUNC_T( CIPHER )        CIPHER ## _CTR_FUNC
#define MBEDTLS_CIPHER_BASE_XTS_FUNC_T( CIPHER )        CIPHER ## _XTS_FUNC
#define MBEDTLS_CIPHER_BASE_STREAM_FUNC_T( CIPHER )     CIPHER ## _STREAM_FUNC
#define MBEDTLS_CIPHER_BASE_SETKEY_ENC_FUNC_T( CIPHER ) CIPHER ## _SETKEY_ENC_FUNC
#define MBEDTLS_CIPHER_BASE_SETKEY_DEC_FUNC_T( CIPHER ) CIPHER ## _SETKEY_DEC_FUNC
#define MBEDTLS_CIPHER_BASE_ALLOC_FUNC_T( CIPHER )      CIPHER ## _ALLOC_FUNC
#define MBEDTLS_CIPHER_BASE_FREE_FUNC_T( CIPHER )       CIPHER ## _FREE_FUNC

/* Wrappers around MBEDTLS_CIPHER_INFO_{FIELD}_T() which makes sure that
 * the argument is macro-expandend before concatenating with the field name.
 * This allows to call these macros as
 * MBEDTLS_CIPHER_INFO_{FIELD}( MBEDTLS_CIPHER_SINGLE_TYPE ).
 * where MBEDTLS_CIPHER_SINGLE_TYPE expands to MBEDTLS_CIPHER_INFO_{TYPE}.
 */
#define MBEDTLS_CIPHER_INFO_TYPE( CIPHER )              MBEDTLS_CIPHER_INFO_TYPE_T( CIPHER )
#define MBEDTLS_CIPHER_INFO_MODE( CIPHER )              MBEDTLS_CIPHER_INFO_MODE_T( CIPHER )
#define MBEDTLS_CIPHER_INFO_KEY_BITLEN( CIPHER )        MBEDTLS_CIPHER_INFO_KEY_BITLEN_T( CIPHER )
#define MBEDTLS_CIPHER_INFO_NAME( CIPHER )              MBEDTLS_CIPHER_INFO_NAME_T( CIPHER )
#define MBEDTLS_CIPHER_INFO_IV_SIZE( CIPHER )           MBEDTLS_CIPHER_INFO_IV_SIZE_T( CIPHER )
#define MBEDTLS_CIPHER_INFO_FLAGS( CIPHER )             MBEDTLS_CIPHER_INFO_FLAGS_T( CIPHER )
#define MBEDTLS_CIPHER_INFO_BLOCK_SIZE( CIPHER )        MBEDTLS_CIPHER_INFO_BLOCK_SIZE_T( CIPHER )
#define MBEDTLS_CIPHER_INFO_BASE( CIPHER )              MBEDTLS_CIPHER_INFO_BASE_T( CIPHER )

#define MBEDTLS_CIPHER_BASE_CIPHER( CIPHER )            MBEDTLS_CIPHER_BASE_CIPHER_T( CIPHER )
#define MBEDTLS_CIPHER_BASE_ECB_FUNC( CIPHER )          MBEDTLS_CIPHER_BASE_ECB_FUNC_T( CIPHER )
#define MBEDTLS_CIPHER_BASE_CBC_FUNC( CIPHER )          MBEDTLS_CIPHER_BASE_CBC_FUNC_T( CIPHER )
#define MBEDTLS_CIPHER_BASE_CFB_FUNC( CIPHER )          MBEDTLS_CIPHER_BASE_CFB_FUNC_T( CIPHER )
#define MBEDTLS_CIPHER_BASE_OFB_FUNC( CIPHER )          MBEDTLS_CIPHER_BASE_OFB_FUNC_T( CIPHER )
#define MBEDTLS_CIPHER_BASE_CTR_FUNC( CIPHER )          MBEDTLS_CIPHER_BASE_CTR_FUNC_T( CIPHER )
#define MBEDTLS_CIPHER_BASE_XTS_FUNC( CIPHER )          MBEDTLS_CIPHER_BASE_XTS_FUNC_T( CIPHER )
#define MBEDTLS_CIPHER_BASE_STREAM_FUNC( CIPHER )       MBEDTLS_CIPHER_BASE_STREAM_FUNC_T( CIPHER )
#define MBEDTLS_CIPHER_BASE_SETKEY_ENC_FUNC( CIPHER )   MBEDTLS_CIPHER_BASE_SETKEY_ENC_FUNC_T( CIPHER )
#define MBEDTLS_CIPHER_BASE_SETKEY_DEC_FUNC( CIPHER )   MBEDTLS_CIPHER_BASE_SETKEY_DEC_FUNC_T( CIPHER )
#define MBEDTLS_CIPHER_BASE_ALLOC_FUNC( CIPHER )        MBEDTLS_CIPHER_BASE_ALLOC_FUNC_T( CIPHER )
#define MBEDTLS_CIPHER_BASE_FREE_FUNC( CIPHER )         MBEDTLS_CIPHER_BASE_FREE_FUNC_T( CIPHER )

/**
 * Base cipher information. The non-mode specific functions and values.
 */
struct mbedtls_cipher_base_t
{
    /** Base Cipher type (e.g. MBEDTLS_CIPHER_ID_AES) */
    mbedtls_cipher_id_t cipher;

    /** Encrypt using ECB */
    int (*ecb_func)( void *ctx, mbedtls_operation_t mode,
                     const unsigned char *input, unsigned char *output );

#if defined(MBEDTLS_CIPHER_MODE_CBC)
    /** Encrypt using CBC */
    int (*cbc_func)( void *ctx, mbedtls_operation_t mode, size_t length,
                     unsigned char *iv, const unsigned char *input,
                     unsigned char *output );
#endif

#if defined(MBEDTLS_CIPHER_MODE_CFB)
    /** Encrypt using CFB (Full length) */
    int (*cfb_func)( void *ctx, mbedtls_operation_t mode, size_t length, size_t *iv_off,
                     unsigned char *iv, const unsigned char *input,
                     unsigned char *output );
#endif

#if defined(MBEDTLS_CIPHER_MODE_OFB)
    /** Encrypt using OFB (Full length) */
    int (*ofb_func)( void *ctx, size_t length, size_t *iv_off,
                     unsigned char *iv,
                     const unsigned char *input,
                     unsigned char *output );
#endif

#if defined(MBEDTLS_CIPHER_MODE_CTR)
    /** Encrypt using CTR */
    int (*ctr_func)( void *ctx, size_t length, size_t *nc_off,
                     unsigned char *nonce_counter, unsigned char *stream_block,
                     const unsigned char *input, unsigned char *output );
#endif

#if defined(MBEDTLS_CIPHER_MODE_XTS)
    /** Encrypt or decrypt using XTS. */
    int (*xts_func)( void *ctx, mbedtls_operation_t mode, size_t length,
                     const unsigned char data_unit[16],
                     const unsigned char *input, unsigned char *output );
#endif

#if defined(MBEDTLS_CIPHER_MODE_STREAM)
    /** Encrypt using STREAM */
    int (*stream_func)( void *ctx, size_t length,
                        const unsigned char *input, unsigned char *output );
#endif

    /** Set key for encryption purposes */
    int (*setkey_enc_func)( void *ctx, const unsigned char *key,
                            unsigned int key_bitlen );

    /** Set key for decryption purposes */
    int (*setkey_dec_func)( void *ctx, const unsigned char *key,
                            unsigned int key_bitlen);

    /** Allocate a new context */
    void * (*ctx_alloc_func)( void );

    /** Free the given context */
    void (*ctx_free_func)( void *ctx );

};

/**
 * \brief   This macro builds an instance of ::mbedtls_cipher_info_t
 *          from an \c MBEDTLS_CIPHER_INFO_XXX identifier.
 */
#define MBEDTLS_CIPHER_INFO( CIPHER )                   \
    { MBEDTLS_CIPHER_INFO_TYPE( CIPHER ),               \
      MBEDTLS_CIPHER_INFO_MODE( CIPHER ),               \
      MBEDTLS_CIPHER_INFO_KEY_BITLEN( CIPHER ),         \
      MBEDTLS_CIPHER_INFO_NAME( CIPHER ),               \
      MBEDTLS_CIPHER_INFO_IV_SIZE( CIPHER ),            \
      MBEDTLS_CIPHER_INFO_FLAGS( CIPHER ),              \
      MBEDTLS_CIPHER_INFO_BLOCK_SIZE( CIPHER ),         \
      MBEDTLS_CIPHER_INFO_BASE( CIPHER ) }

#define MBEDTLS_CIPHER_BASE( CIPHER )                   \
    { MBEDTLS_CIPHER_BASE_CIPHER( CIPHER ),             \
      MBEDTLS_CIPHER_BASE_ECB_FUNC( CIPHER ),           \
      MBEDTLS_CIPHER_BASE_CBC_FUNC( CIPHER ),           \
      MBEDTLS_CIPHER_BASE_CFB_FUNC( CIPHER ),           \
      MBEDTLS_CIPHER_BASE_OFB_FUNC( CIPHER ),           \
      MBEDTLS_CIPHER_BASE_CTR_FUNC( CIPHER ),           \
      MBEDTLS_CIPHER_BASE_XTS_FUNC( CIPHER ),           \
      MBEDTLS_CIPHER_BASE_STREAM_FUNC( CIPHER ),        \
      MBEDTLS_CIPHER_BASE_SETKEY_ENC_FUNC( CIPHER ),    \
      MBEDTLS_CIPHER_BASE_SETKEY_DEC_FUNC( CIPHER ),    \
      MBEDTLS_CIPHER_BASE_ALLOC_FUNC( CIPHER ),         \
      MBEDTLS_CIPHER_BASE_FREE_FUNC( CIPHER ) }

typedef struct
{
    mbedtls_cipher_type_t type;
    const mbedtls_cipher_info_t *info;
} mbedtls_cipher_definition_t;

extern const mbedtls_cipher_definition_t mbedtls_cipher_definitions[];

extern int mbedtls_cipher_supported[];

#ifdef __cplusplus
}
#endif

#endif /* MBEDTLS_CIPHER_WRAP_H */
