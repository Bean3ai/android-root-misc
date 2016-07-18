#ifndef POLARSSL_CONFIG_H
#define POLARSSL_CONFIG_H
#if defined(_MSC_VER) && !defined(_CRT_SECURE_NO_DEPRECATE)
#define _CRT_SECURE_NO_DEPRECATE 1
#endif
#define POLARSSL_HAVE_LONGLONG
#define POLARSSL_HAVE_ASM
#define POLARSSL_HAVE_READDIR_R
#define POLARSSL_HAVE_TIME
#define POLARSSL_CIPHER_MODE_CBC
#define POLARSSL_CIPHER_MODE_CFB
#define POLARSSL_CIPHER_MODE_CTR
#define POLARSSL_CIPHER_NULL_CIPHER
#define POLARSSL_CIPHER_PADDING_PKCS7
#define POLARSSL_CIPHER_PADDING_ONE_AND_ZEROS
#define POLARSSL_CIPHER_PADDING_ZEROS_AND_LEN
#define POLARSSL_CIPHER_PADDING_ZEROS
#define POLARSSL_ENABLE_WEAK_CIPHERSUITES
#define POLARSSL_ECP_NIST_OPTIM
#define POLARSSL_ERROR_STRERROR_BC
#define POLARSSL_ERROR_STRERROR_DUMMY
#define POLARSSL_FS_IO
#define POLARSSL_PKCS1_V15
// #define POLARSSL_SELF_TEST
#define POLARSSL_SSL_ALERT_MESSAGES
#define POLARSSL_SSL_SRV_SUPPORT_SSLV2_CLIENT_HELLO
#define POLARSSL_SSL_MAX_FRAGMENT_LENGTH
#define POLARSSL_SSL_SESSION_TICKETS
#define POLARSSL_SSL_SERVER_NAME_INDICATION
#define POLARSSL_SSL_TRUNCATED_HMAC
// #define POLARSSL_AES_C
// #define POLARSSL_ASN1_PARSE_C
#define POLARSSL_BIGNUM_C
// #define POLARSSL_CTR_DRBG_C
#define POLARSSL_MD_C
#define POLARSSL_OID_C
// #define POLARSSL_PK_C
#define POLARSSL_RSA_C

#if defined(POLARSSL_CONFIG_OPTIONS)
#define POLARSSL_MPI_WINDOW_SIZE            6 /**< Maximum windows size used. */
#define POLARSSL_MPI_MAX_SIZE             512 /**< Maximum number of bytes for usable MPIs. */
#define CTR_DRBG_ENTROPY_LEN               48 /**< Amount of entropy used per seed by default (48 with SHA-512, 32 with SHA-256) */
#define CTR_DRBG_RESEED_INTERVAL        10000 /**< Interval before reseed is performed by default */
#define CTR_DRBG_MAX_INPUT                256 /**< Maximum number of additional input bytes */
#define CTR_DRBG_MAX_REQUEST             1024 /**< Maximum number of requested bytes per call */
#define CTR_DRBG_MAX_SEED_INPUT           384 /**< Maximum size of (re)seed buffer */
#define ENTROPY_MAX_SOURCES                20 /**< Maximum number of sources supported */
#define ENTROPY_MAX_GATHER                128 /**< Maximum amount requested from entropy sources */
#define MEMORY_ALIGN_MULTIPLE               4 /**< Align on multiples of this value */
#define POLARSSL_MEMORY_STDMALLOC      malloc /**< Default allocator to use, can be undefined */
#define POLARSSL_MEMORY_STDFREE          free /**< Default free to use, can be undefined */
#define SSL_CACHE_DEFAULT_TIMEOUT       86400 /**< 1 day  */
#define SSL_CACHE_DEFAULT_MAX_ENTRIES      50 /**< Maximum entries in cache */
#define SSL_MAX_CONTENT_LEN             16384 /**< Size of the input / output buffer */
#define SSL_DEFAULT_TICKET_LIFETIME     86400 /**< Lifetime of session tickets (if enabled) */
#endif /* POLARSSL_CONFIG_OPTIONS */

/*
 * Sanity checks on defines and dependencies
 */
#if defined(POLARSSL_CERTS_C) && !defined(POLARSSL_PEM_PARSE_C)
#error "POLARSSL_CERTS_C defined, but not all prerequisites"
#endif

#if defined(POLARSSL_CTR_DRBG_C) && !defined(POLARSSL_AES_C)
#error "POLARSSL_CTR_DRBG_C defined, but not all prerequisites"
#endif

#if defined(POLARSSL_DHM_C) && !defined(POLARSSL_BIGNUM_C)
#error "POLARSSL_DHM_C defined, but not all prerequisites"
#endif

#if defined(POLARSSL_ECDH_C) && !defined(POLARSSL_ECP_C)
#error "POLARSSL_ECDH_C defined, but not all prerequisites"
#endif

#if defined(POLARSSL_ECDSA_C) &&            \
    ( !defined(POLARSSL_ECP_C) ||           \
      !defined(POLARSSL_ASN1_PARSE_C) ||    \
      !defined(POLARSSL_ASN1_WRITE_C) )
#error "POLARSSL_ECDSA_C defined, but not all prerequisites"
#endif

#if defined(POLARSSL_ECP_C) && ( !defined(POLARSSL_BIGNUM_C) || (   \
    !defined(POLARSSL_ECP_DP_SECP192R1_ENABLED) &&                  \
    !defined(POLARSSL_ECP_DP_SECP224R1_ENABLED) &&                  \
    !defined(POLARSSL_ECP_DP_SECP256R1_ENABLED) &&                  \
    !defined(POLARSSL_ECP_DP_SECP384R1_ENABLED) &&                  \
    !defined(POLARSSL_ECP_DP_SECP521R1_ENABLED) &&                  \
    !defined(POLARSSL_ECP_DP_BP256R1_ENABLED)   &&                  \
    !defined(POLARSSL_ECP_DP_BP384R1_ENABLED)   &&                  \
    !defined(POLARSSL_ECP_DP_BP512R1_ENABLED) ) )
#error "POLARSSL_ECP_C defined, but not all prerequisites"
#endif

#if defined(POLARSSL_ENTROPY_C) && (!defined(POLARSSL_SHA512_C) &&      \
                                    !defined(POLARSSL_SHA256_C))
#error "POLARSSL_ENTROPY_C defined, but not all prerequisites"
#endif
#if defined(POLARSSL_ENTROPY_C) && defined(POLARSSL_SHA512_C) &&         \
    defined(POLARSSL_CONFIG_OPTIONS) && (CTR_DRBG_ENTROPY_LEN > 64)
#error "CTR_DRBG_ENTROPY_LEN value too high"
#endif
#if defined(POLARSSL_ENTROPY_C) && !defined(POLARSSL_SHA512_C) &&        \
    defined(POLARSSL_CONFIG_OPTIONS) && (CTR_DRBG_ENTROPY_LEN > 32)
#error "CTR_DRBG_ENTROPY_LEN value too high"
#endif

#if defined(POLARSSL_GCM_C) && (                                        \
        !defined(POLARSSL_AES_C) && !defined(POLARSSL_CAMELLIA_C) )
#error "POLARSSL_GCM_C defined, but not all prerequisites"
#endif

#if defined(POLARSSL_HAVEGE_C) && !defined(POLARSSL_TIMING_C)
#error "POLARSSL_HAVEGE_C defined, but not all prerequisites"
#endif

#if defined(POLARSSL_KEY_EXCHANGE_DHE_PSK_ENABLED) && !defined(POLARSSL_DHM_C)
#error "POLARSSL_KEY_EXCHANGE_DHE_PSK_ENABLED defined, but not all prerequisites"
#endif

#if defined(POLARSSL_KEY_EXCHANGE_ECDHE_PSK_ENABLED) &&                     \
    !defined(POLARSSL_ECDH_C)
#error "POLARSSL_KEY_EXCHANGE_ECDHE_PSK_ENABLED defined, but not all prerequisites"
#endif

#if defined(POLARSSL_KEY_EXCHANGE_DHE_RSA_ENABLED) &&                   \
    ( !defined(POLARSSL_DHM_C) || !defined(POLARSSL_RSA_C) ||           \
      !defined(POLARSSL_X509_CRT_PARSE_C) || !defined(POLARSSL_PKCS1_V15) )
#error "POLARSSL_KEY_EXCHANGE_DHE_RSA_ENABLED defined, but not all prerequisites"
#endif

#if defined(POLARSSL_KEY_EXCHANGE_ECDHE_RSA_ENABLED) &&                 \
    ( !defined(POLARSSL_ECDH_C) || !defined(POLARSSL_RSA_C) ||          \
      !defined(POLARSSL_X509_CRT_PARSE_C) || !defined(POLARSSL_PKCS1_V15) )
#error "POLARSSL_KEY_EXCHANGE_ECDHE_RSA_ENABLED defined, but not all prerequisites"
#endif

#if defined(POLARSSL_KEY_EXCHANGE_ECDHE_ECDSA_ENABLED) &&                 \
    ( !defined(POLARSSL_ECDH_C) || !defined(POLARSSL_ECDSA_C) ||          \
      !defined(POLARSSL_X509_CRT_PARSE_C) )
#error "POLARSSL_KEY_EXCHANGE_ECDHE_ECDSA_ENABLED defined, but not all prerequisites"
#endif

#if defined(POLARSSL_KEY_EXCHANGE_RSA_PSK_ENABLED) &&                   \
    ( !defined(POLARSSL_RSA_C) || !defined(POLARSSL_X509_CRT_PARSE_C) ||\
      !defined(POLARSSL_PKCS1_V15) )
#error "POLARSSL_KEY_EXCHANGE_RSA_PSK_ENABLED defined, but not all prerequisites"
#endif

#if defined(POLARSSL_KEY_EXCHANGE_RSA_ENABLED) &&                       \
    ( !defined(POLARSSL_RSA_C) || !defined(POLARSSL_X509_CRT_PARSE_C) ||\
      !defined(POLARSSL_PKCS1_V15) )
#error "POLARSSL_KEY_EXCHANGE_RSA_ENABLED defined, but not all prerequisites"
#endif

#if defined(POLARSSL_MEMORY_BUFFER_ALLOC_C) && !defined(POLARSSL_MEMORY_C)
#error "POLARSSL_MEMORY_BUFFER_ALLOC_C defined, but not all prerequisites"
#endif

#if defined(POLARSSL_PBKDF2_C) && !defined(POLARSSL_MD_C)
#error "POLARSSL_PBKDF2_C defined, but not all prerequisites"
#endif

#if defined(POLARSSL_PEM_PARSE_C) && !defined(POLARSSL_BASE64_C)
#error "POLARSSL_PEM_PARSE_C defined, but not all prerequisites"
#endif

#if defined(POLARSSL_PEM_WRITE_C) && !defined(POLARSSL_BASE64_C)
#error "POLARSSL_PEM_WRITE_C defined, but not all prerequisites"
#endif

#if defined(POLARSSL_PK_PARSE_C) && !defined(POLARSSL_PK_C)
#error "POLARSSL_PK_PARSE_C defined, but not all prerequisites"
#endif

#if defined(POLARSSL_PK_WRITE_C) && !defined(POLARSSL_PK_C)
#error "POLARSSL_PK_WRITE_C defined, but not all prerequisites"
#endif

#if defined(POLARSSL_PKCS11_C) && !defined(POLARSSL_PK_C)
#error "POLARSSL_PKCS11_C defined, but not all prerequisites"
#endif

#if defined(POLARSSL_RSA_C) && ( !defined(POLARSSL_BIGNUM_C) ||         \
    !defined(POLARSSL_OID_C) )
#error "POLARSSL_RSA_C defined, but not all prerequisites"
#endif

#if defined(POLARSSL_SSL_PROTO_SSL3) && ( !defined(POLARSSL_MD5_C) ||     \
    !defined(POLARSSL_SHA1_C) )
#error "POLARSSL_SSL_PROTO_SSL3 defined, but not all prerequisites"
#endif

#if defined(POLARSSL_SSL_PROTO_TLS1) && ( !defined(POLARSSL_MD5_C) ||     \
    !defined(POLARSSL_SHA1_C) )
#error "POLARSSL_SSL_PROTO_TLS1 defined, but not all prerequisites"
#endif

#if defined(POLARSSL_SSL_PROTO_TLS1_1) && ( !defined(POLARSSL_MD5_C) ||     \
    !defined(POLARSSL_SHA1_C) )
#error "POLARSSL_SSL_PROTO_TLS1_1 defined, but not all prerequisites"
#endif

#if defined(POLARSSL_SSL_PROTO_TLS1_2) && ( !defined(POLARSSL_SHA1_C) &&     \
    !defined(POLARSSL_SHA256_C) && !defined(POLARSSL_SHA512_C) )
#error "POLARSSL_SSL_PROTO_TLS1_2 defined, but not all prerequisites"
#endif

#if defined(POLARSSL_SSL_CLI_C) && !defined(POLARSSL_SSL_TLS_C)
#error "POLARSSL_SSL_CLI_C defined, but not all prerequisites"
#endif

#if defined(POLARSSL_SSL_TLS_C) && ( !defined(POLARSSL_CIPHER_C) ||     \
    !defined(POLARSSL_MD_C) )
#error "POLARSSL_SSL_TLS_C defined, but not all prerequisites"
#endif

#if defined(POLARSSL_SSL_SRV_C) && !defined(POLARSSL_SSL_TLS_C)
#error "POLARSSL_SSL_SRV_C defined, but not all prerequisites"
#endif

#if defined(POLARSSL_SSL_TLS_C) && (!defined(POLARSSL_SSL_PROTO_SSL3) && \
    !defined(POLARSSL_SSL_PROTO_TLS1) && !defined(POLARSSL_SSL_PROTO_TLS1_1) && \
    !defined(POLARSSL_SSL_PROTO_TLS1_2))
#error "POLARSSL_SSL_TLS_C defined, but no protocols are active"
#endif

#if defined(POLARSSL_SSL_TLS_C) && (defined(POLARSSL_SSL_PROTO_SSL3) && \
    defined(POLARSSL_SSL_PROTO_TLS1_1) && !defined(POLARSSL_SSL_PROTO_TLS1))
#error "Illegal protocol selection"
#endif

#if defined(POLARSSL_SSL_TLS_C) && (defined(POLARSSL_SSL_PROTO_TLS1) && \
    defined(POLARSSL_SSL_PROTO_TLS1_2) && !defined(POLARSSL_SSL_PROTO_TLS1_1))
#error "Illegal protocol selection"
#endif

#if defined(POLARSSL_SSL_TLS_C) && (defined(POLARSSL_SSL_PROTO_SSL3) && \
    defined(POLARSSL_SSL_PROTO_TLS1_2) && (!defined(POLARSSL_SSL_PROTO_TLS1) || \
    !defined(POLARSSL_SSL_PROTO_TLS1_1)))
#error "Illegal protocol selection"
#endif

#if defined(POLARSSL_SSL_SESSION_TICKETS) && defined(POLARSSL_SSL_TLS_C) && \
    ( !defined(POLARSSL_AES_C) || !defined(POLARSSL_SHA256_C) ||            \
      !defined(POLARSSL_CIPHER_MODE_CBC) )
#error "POLARSSL_SSL_SESSION_TICKETS_C defined, but not all prerequisites"
#endif

#if defined(POLARSSL_THREADING_DUMMY)
#if !defined(POLARSSL_THREADING_C) || defined(POLARSSL_THREADING_IMPL)
#error "POLARSSL_THREADING_DUMMY defined, but not all prerequisites"
#endif
#define POLARSSL_THREADING_IMPL
#endif

#if defined(POLARSSL_THREADING_PTHREAD)
#if !defined(POLARSSL_THREADING_C) || defined(POLARSSL_THREADING_IMPL)
#error "POLARSSL_THREADING_PTHREAD defined, but not all prerequisites"
#endif
#define POLARSSL_THREADING_IMPL
#endif

#if defined(POLARSSL_THREADING_ALT)
#if !defined(POLARSSL_THREADING_C) || defined(POLARSSL_THREADING_IMPL)
#error "POLARSSL_THREADING_ALT defined, but not all prerequisites"
#endif
#define POLARSSL_THREADING_IMPL
#endif

#if defined(POLARSSL_THREADING_C) && !defined(POLARSSL_THREADING_IMPL)
#error "POLARSSL_THREADING_C defined, single threading implementation required"
#endif
#undef POLARSSL_THREADING_IMPL

#if defined(POLARSSL_X509_USE_C) && ( !defined(POLARSSL_BIGNUM_C) ||  \
    !defined(POLARSSL_OID_C) || !defined(POLARSSL_ASN1_PARSE_C) ||      \
    !defined(POLARSSL_PK_PARSE_C) )
#error "POLARSSL_X509_USE_C defined, but not all prerequisites"
#endif

#if defined(POLARSSL_X509_CREATE_C) && ( !defined(POLARSSL_BIGNUM_C) ||  \
    !defined(POLARSSL_OID_C) || !defined(POLARSSL_ASN1_WRITE_C) ||       \
    !defined(POLARSSL_PK_WRITE_C) )
#error "POLARSSL_X509_CREATE_C defined, but not all prerequisites"
#endif

#if defined(POLARSSL_X509_CRT_PARSE_C) && ( !defined(POLARSSL_X509_USE_C) )
#error "POLARSSL_X509_CRT_PARSE_C defined, but not all prerequisites"
#endif

#if defined(POLARSSL_X509_CRL_PARSE_C) && ( !defined(POLARSSL_X509_USE_C) )
#error "POLARSSL_X509_CRL_PARSE_C defined, but not all prerequisites"
#endif

#if defined(POLARSSL_X509_CSR_PARSE_C) && ( !defined(POLARSSL_X509_USE_C) )
#error "POLARSSL_X509_CSR_PARSE_C defined, but not all prerequisites"
#endif

#if defined(POLARSSL_X509_CRT_WRITE_C) && ( !defined(POLARSSL_X509_CREATE_C) )
#error "POLARSSL_X509_CRT_WRITE_C defined, but not all prerequisites"
#endif

#if defined(POLARSSL_X509_CSR_WRITE_C) && ( !defined(POLARSSL_X509_CREATE_C) )
#error "POLARSSL_X509_CSR_WRITE_C defined, but not all prerequisites"
#endif

#endif /* config.h */
