/* packet-tls-utils.c
 * ssl manipulation functions
 * By Paolo Abeni <paolo.abeni@email.com>
 *
 * Copyright (c) 2013, Hauke Mehrtens <hauke@hauke-m.de>
 * Copyright (c) 2014, Peter Wu <peter@lekensteyn.nl>
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "config.h"

#if defined(HAVE_ZLIB) && !defined(HAVE_ZLIBNG)
#define ZLIB_CONST
#define ZLIB_PREFIX(x) x
#include <zlib.h>
typedef z_stream zlib_stream;
#endif /* HAVE_ZLIB */

#ifdef HAVE_ZLIBNG
#define ZLIB_PREFIX(x) zng_ ## x
#include <zlib-ng.h>
typedef zng_stream zlib_stream;
#endif /* HAVE_ZLIBNG */

#include <stdlib.h>
#include <errno.h>

#include <epan/packet.h>
#include <epan/strutil.h>
#include <epan/addr_resolv.h>
#include <epan/expert.h>
#include <epan/asn1.h>
#include <epan/proto_data.h>
#include <epan/oids.h>
#include <epan/secrets.h>

#include <wsutil/inet_cidr.h>
#include <wsutil/filesystem.h>
#include <wsutil/file_util.h>
#include <wsutil/str_util.h>
#include <wsutil/report_message.h>
#include <wsutil/pint.h>
#include <wsutil/strtoi.h>
#include <wsutil/wsgcrypt.h>
#include <wsutil/rsa.h>
#include <wsutil/ws_assert.h>
#include "packet-ber.h"
#include "packet-x509af.h"
#include "packet-x509if.h"
#include "packet-tls-utils.h"
#include "packet-ocsp.h"
#include "packet-tls.h"
#include "packet-dtls.h"
#include "packet-quic.h"
#if defined(HAVE_LIBGNUTLS)
#include <gnutls/abstract.h>
#endif

/* JA3/JA3S calculations must ignore GREASE values
 * as described in RFC 8701.
 */
#define IS_GREASE_TLS(x) ((((x) & 0x0f0f) == 0x0a0a) && \
                        (((x) & 0xff) == (((x)>>8) & 0xff)))

/* Section 22.3 of RFC 9000 (QUIC) reserves values of this
 * form for a similar purpose as GREASE.
 */
#define IS_GREASE_QUIC(x) ((x) > 27 ? ((((x) - 27) % 31) == 0) : 0)

#define DTLS13_MAX_EPOCH 10

/* Lookup tables {{{ */
const value_string ssl_version_short_names[] = {
    { SSLV2_VERSION,        "SSLv2" },
    { SSLV3_VERSION,        "SSLv3" },
    { TLSV1_VERSION,        "TLSv1" },
    { TLCPV1_VERSION,       "TLCP" },
    { TLSV1DOT1_VERSION,    "TLSv1.1" },
    { TLSV1DOT2_VERSION,    "TLSv1.2" },
    { TLSV1DOT3_VERSION,    "TLSv1.3" },
    { DTLSV1DOT0_VERSION,   "DTLSv1.0" },
    { DTLSV1DOT2_VERSION,   "DTLSv1.2" },
    { DTLSV1DOT3_VERSION,   "DTLSv1.3" },
    { DTLSV1DOT0_OPENSSL_VERSION, "DTLS 1.0 (OpenSSL pre 0.9.8f)" },
    { 0x00, NULL }
};

const value_string ssl_versions[] = {
    { SSLV2_VERSION,        "SSL 2.0" },
    { SSLV3_VERSION,        "SSL 3.0" },
    { TLSV1_VERSION,        "TLS 1.0" },
    { TLCPV1_VERSION,       "TLCP" },
    { TLSV1DOT1_VERSION,    "TLS 1.1" },
    { TLSV1DOT2_VERSION,    "TLS 1.2" },
    { TLSV1DOT3_VERSION,    "TLS 1.3" },
    { 0x7F0E,               "TLS 1.3 (draft 14)" },
    { 0x7F0F,               "TLS 1.3 (draft 15)" },
    { 0x7F10,               "TLS 1.3 (draft 16)" },
    { 0x7F11,               "TLS 1.3 (draft 17)" },
    { 0x7F12,               "TLS 1.3 (draft 18)" },
    { 0x7F13,               "TLS 1.3 (draft 19)" },
    { 0x7F14,               "TLS 1.3 (draft 20)" },
    { 0x7F15,               "TLS 1.3 (draft 21)" },
    { 0x7F16,               "TLS 1.3 (draft 22)" },
    { 0x7F17,               "TLS 1.3 (draft 23)" },
    { 0x7F18,               "TLS 1.3 (draft 24)" },
    { 0x7F19,               "TLS 1.3 (draft 25)" },
    { 0x7F1A,               "TLS 1.3 (draft 26)" },
    { 0x7F1B,               "TLS 1.3 (draft 27)" },
    { 0x7F1C,               "TLS 1.3 (draft 28)" },
    { 0xFB17,               "TLS 1.3 (Facebook draft 23)" },
    { 0xFB1A,               "TLS 1.3 (Facebook draft 26)" },
    { DTLSV1DOT0_OPENSSL_VERSION, "DTLS 1.0 (OpenSSL pre 0.9.8f)" },
    { DTLSV1DOT0_VERSION,   "DTLS 1.0" },
    { DTLSV1DOT2_VERSION,   "DTLS 1.2" },
    { DTLSV1DOT3_VERSION,   "DTLS 1.3" },
    { 0x0A0A,               "Reserved (GREASE)" }, /* RFC 8701 */
    { 0x1A1A,               "Reserved (GREASE)" }, /* RFC 8701 */
    { 0x2A2A,               "Reserved (GREASE)" }, /* RFC 8701 */
    { 0x3A3A,               "Reserved (GREASE)" }, /* RFC 8701 */
    { 0x4A4A,               "Reserved (GREASE)" }, /* RFC 8701 */
    { 0x5A5A,               "Reserved (GREASE)" }, /* RFC 8701 */
    { 0x6A6A,               "Reserved (GREASE)" }, /* RFC 8701 */
    { 0x7A7A,               "Reserved (GREASE)" }, /* RFC 8701 */
    { 0x8A8A,               "Reserved (GREASE)" }, /* RFC 8701 */
    { 0x9A9A,               "Reserved (GREASE)" }, /* RFC 8701 */
    { 0xAAAA,               "Reserved (GREASE)" }, /* RFC 8701 */
    { 0xBABA,               "Reserved (GREASE)" }, /* RFC 8701 */
    { 0xCACA,               "Reserved (GREASE)" }, /* RFC 8701 */
    { 0xDADA,               "Reserved (GREASE)" }, /* RFC 8701 */
    { 0xEAEA,               "Reserved (GREASE)" }, /* RFC 8701 */
    { 0xFAFA,               "Reserved (GREASE)" }, /* RFC 8701 */
    { 0x00, NULL }
};

static const value_string ssl_version_ja4_names[] = {
    { 0x0100,               "s1" },
    { SSLV2_VERSION,        "s2" },
    { SSLV3_VERSION,        "s3" },
    { TLSV1_VERSION,        "10" },
    { TLSV1DOT1_VERSION,    "11" },
    { TLSV1DOT2_VERSION,    "12" },
    { TLSV1DOT3_VERSION,    "13" },
    { DTLSV1DOT0_VERSION,   "d1" },
    { DTLSV1DOT2_VERSION,   "d2" },
    { DTLSV1DOT3_VERSION,   "d3" },
    { 0x00, NULL }
};

const value_string ssl_20_msg_types[] = {
    { SSL2_HND_ERROR,               "Error" },
    { SSL2_HND_CLIENT_HELLO,        "Client Hello" },
    { SSL2_HND_CLIENT_MASTER_KEY,   "Client Master Key" },
    { SSL2_HND_CLIENT_FINISHED,     "Client Finished" },
    { SSL2_HND_SERVER_HELLO,        "Server Hello" },
    { SSL2_HND_SERVER_VERIFY,       "Server Verify" },
    { SSL2_HND_SERVER_FINISHED,     "Server Finished" },
    { SSL2_HND_REQUEST_CERTIFICATE, "Request Certificate" },
    { SSL2_HND_CLIENT_CERTIFICATE,  "Client Certificate" },
    { 0x00, NULL }
};
/* http://www.iana.org/assignments/tls-parameters/tls-parameters.xhtml */
/* Note: sorted by ascending value so value_string-ext can do a binary search */
static const value_string ssl_20_cipher_suites[] = {
    { 0x000000, "TLS_NULL_WITH_NULL_NULL" },
    { 0x000001, "TLS_RSA_WITH_NULL_MD5" },
    { 0x000002, "TLS_RSA_WITH_NULL_SHA" },
    { 0x000003, "TLS_RSA_EXPORT_WITH_RC4_40_MD5" },
    { 0x000004, "TLS_RSA_WITH_RC4_128_MD5" },
    { 0x000005, "TLS_RSA_WITH_RC4_128_SHA" },
    { 0x000006, "TLS_RSA_EXPORT_WITH_RC2_CBC_40_MD5" },
    { 0x000007, "TLS_RSA_WITH_IDEA_CBC_SHA" },
    { 0x000008, "TLS_RSA_EXPORT_WITH_DES40_CBC_SHA" },
    { 0x000009, "TLS_RSA_WITH_DES_CBC_SHA" },
    { 0x00000a, "TLS_RSA_WITH_3DES_EDE_CBC_SHA" },
    { 0x00000b, "TLS_DH_DSS_EXPORT_WITH_DES40_CBC_SHA" },
    { 0x00000c, "TLS_DH_DSS_WITH_DES_CBC_SHA" },
    { 0x00000d, "TLS_DH_DSS_WITH_3DES_EDE_CBC_SHA" },
    { 0x00000e, "TLS_DH_RSA_EXPORT_WITH_DES40_CBC_SHA" },
    { 0x00000f, "TLS_DH_RSA_WITH_DES_CBC_SHA" },
    { 0x000010, "TLS_DH_RSA_WITH_3DES_EDE_CBC_SHA" },
    { 0x000011, "TLS_DHE_DSS_EXPORT_WITH_DES40_CBC_SHA" },
    { 0x000012, "TLS_DHE_DSS_WITH_DES_CBC_SHA" },
    { 0x000013, "TLS_DHE_DSS_WITH_3DES_EDE_CBC_SHA" },
    { 0x000014, "TLS_DHE_RSA_EXPORT_WITH_DES40_CBC_SHA" },
    { 0x000015, "TLS_DHE_RSA_WITH_DES_CBC_SHA" },
    { 0x000016, "TLS_DHE_RSA_WITH_3DES_EDE_CBC_SHA" },
    { 0x000017, "TLS_DH_anon_EXPORT_WITH_RC4_40_MD5" },
    { 0x000018, "TLS_DH_anon_WITH_RC4_128_MD5" },
    { 0x000019, "TLS_DH_anon_EXPORT_WITH_DES40_CBC_SHA" },
    { 0x00001a, "TLS_DH_anon_WITH_DES_CBC_SHA" },
    { 0x00001b, "TLS_DH_anon_WITH_3DES_EDE_CBC_SHA" },
    { 0x00001c, "SSL_FORTEZZA_KEA_WITH_NULL_SHA" },
    { 0x00001d, "SSL_FORTEZZA_KEA_WITH_FORTEZZA_CBC_SHA" },
#if 0
    { 0x00001e, "SSL_FORTEZZA_KEA_WITH_RC4_128_SHA" },
#endif
    /* RFC 2712 */
    { 0x00001E, "TLS_KRB5_WITH_DES_CBC_SHA" },
    { 0x00001F, "TLS_KRB5_WITH_3DES_EDE_CBC_SHA" },
    { 0x000020, "TLS_KRB5_WITH_RC4_128_SHA" },
    { 0x000021, "TLS_KRB5_WITH_IDEA_CBC_SHA" },
    { 0x000022, "TLS_KRB5_WITH_DES_CBC_MD5" },
    { 0x000023, "TLS_KRB5_WITH_3DES_EDE_CBC_MD5" },
    { 0x000024, "TLS_KRB5_WITH_RC4_128_MD5" },
    { 0x000025, "TLS_KRB5_WITH_IDEA_CBC_MD5" },
    { 0x000026, "TLS_KRB5_EXPORT_WITH_DES_CBC_40_SHA" },
    { 0x000027, "TLS_KRB5_EXPORT_WITH_RC2_CBC_40_SHA" },
    { 0x000028, "TLS_KRB5_EXPORT_WITH_RC4_40_SHA" },
    { 0x000029, "TLS_KRB5_EXPORT_WITH_DES_CBC_40_MD5" },
    { 0x00002A, "TLS_KRB5_EXPORT_WITH_RC2_CBC_40_MD5" },
    { 0x00002B, "TLS_KRB5_EXPORT_WITH_RC4_40_MD5" },
    /* RFC 4785 */
    { 0x00002C, "TLS_PSK_WITH_NULL_SHA" },
    { 0x00002D, "TLS_DHE_PSK_WITH_NULL_SHA" },
    { 0x00002E, "TLS_RSA_PSK_WITH_NULL_SHA" },
    /* RFC 5246 */
    { 0x00002f, "TLS_RSA_WITH_AES_128_CBC_SHA" },
    { 0x000030, "TLS_DH_DSS_WITH_AES_128_CBC_SHA" },
    { 0x000031, "TLS_DH_RSA_WITH_AES_128_CBC_SHA" },
    { 0x000032, "TLS_DHE_DSS_WITH_AES_128_CBC_SHA" },
    { 0x000033, "TLS_DHE_RSA_WITH_AES_128_CBC_SHA" },
    { 0x000034, "TLS_DH_anon_WITH_AES_128_CBC_SHA" },
    { 0x000035, "TLS_RSA_WITH_AES_256_CBC_SHA" },
    { 0x000036, "TLS_DH_DSS_WITH_AES_256_CBC_SHA" },
    { 0x000037, "TLS_DH_RSA_WITH_AES_256_CBC_SHA" },
    { 0x000038, "TLS_DHE_DSS_WITH_AES_256_CBC_SHA" },
    { 0x000039, "TLS_DHE_RSA_WITH_AES_256_CBC_SHA" },
    { 0x00003A, "TLS_DH_anon_WITH_AES_256_CBC_SHA" },
    { 0x00003B, "TLS_RSA_WITH_NULL_SHA256" },
    { 0x00003C, "TLS_RSA_WITH_AES_128_CBC_SHA256" },
    { 0x00003D, "TLS_RSA_WITH_AES_256_CBC_SHA256" },
    { 0x00003E, "TLS_DH_DSS_WITH_AES_128_CBC_SHA256" },
    { 0x00003F, "TLS_DH_RSA_WITH_AES_128_CBC_SHA256" },
    { 0x000040, "TLS_DHE_DSS_WITH_AES_128_CBC_SHA256" },
    { 0x000041, "TLS_RSA_WITH_CAMELLIA_128_CBC_SHA" },
    { 0x000042, "TLS_DH_DSS_WITH_CAMELLIA_128_CBC_SHA" },
    { 0x000043, "TLS_DH_RSA_WITH_CAMELLIA_128_CBC_SHA" },
    { 0x000044, "TLS_DHE_DSS_WITH_CAMELLIA_128_CBC_SHA" },
    { 0x000045, "TLS_DHE_RSA_WITH_CAMELLIA_128_CBC_SHA" },
    { 0x000046, "TLS_DH_anon_WITH_CAMELLIA_128_CBC_SHA" },
    { 0x000047, "TLS_ECDH_ECDSA_WITH_NULL_SHA" },
    { 0x000048, "TLS_ECDH_ECDSA_WITH_RC4_128_SHA" },
    { 0x000049, "TLS_ECDH_ECDSA_WITH_DES_CBC_SHA" },
    { 0x00004A, "TLS_ECDH_ECDSA_WITH_3DES_EDE_CBC_SHA" },
    { 0x00004B, "TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA" },
    { 0x00004C, "TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA" },
    { 0x000060, "TLS_RSA_EXPORT1024_WITH_RC4_56_MD5" },
    { 0x000061, "TLS_RSA_EXPORT1024_WITH_RC2_CBC_56_MD5" },
    { 0x000062, "TLS_RSA_EXPORT1024_WITH_DES_CBC_SHA" },
    { 0x000063, "TLS_DHE_DSS_EXPORT1024_WITH_DES_CBC_SHA" },
    { 0x000064, "TLS_RSA_EXPORT1024_WITH_RC4_56_SHA" },
    { 0x000065, "TLS_DHE_DSS_EXPORT1024_WITH_RC4_56_SHA" },
    { 0x000066, "TLS_DHE_DSS_WITH_RC4_128_SHA" },
    { 0x000067, "TLS_DHE_RSA_WITH_AES_128_CBC_SHA256" },
    { 0x000068, "TLS_DH_DSS_WITH_AES_256_CBC_SHA256" },
    { 0x000069, "TLS_DH_RSA_WITH_AES_256_CBC_SHA256" },
    { 0x00006A, "TLS_DHE_DSS_WITH_AES_256_CBC_SHA256" },
    { 0x00006B, "TLS_DHE_RSA_WITH_AES_256_CBC_SHA256" },
    { 0x00006C, "TLS_DH_anon_WITH_AES_128_CBC_SHA256" },
    { 0x00006D, "TLS_DH_anon_WITH_AES_256_CBC_SHA256" },
    /* 0x00,0x6E-83 Unassigned  */
    { 0x000084, "TLS_RSA_WITH_CAMELLIA_256_CBC_SHA" },
    { 0x000085, "TLS_DH_DSS_WITH_CAMELLIA_256_CBC_SHA" },
    { 0x000086, "TLS_DH_RSA_WITH_CAMELLIA_256_CBC_SHA" },
    { 0x000087, "TLS_DHE_DSS_WITH_CAMELLIA_256_CBC_SHA" },
    { 0x000088, "TLS_DHE_RSA_WITH_CAMELLIA_256_CBC_SHA" },
    { 0x000089, "TLS_DH_anon_WITH_CAMELLIA_256_CBC_SHA" },
    /* RFC 4279 */
    { 0x00008A, "TLS_PSK_WITH_RC4_128_SHA" },
    { 0x00008B, "TLS_PSK_WITH_3DES_EDE_CBC_SHA" },
    { 0x00008C, "TLS_PSK_WITH_AES_128_CBC_SHA" },
    { 0x00008D, "TLS_PSK_WITH_AES_256_CBC_SHA" },
    { 0x00008E, "TLS_DHE_PSK_WITH_RC4_128_SHA" },
    { 0x00008F, "TLS_DHE_PSK_WITH_3DES_EDE_CBC_SHA" },
    { 0x000090, "TLS_DHE_PSK_WITH_AES_128_CBC_SHA" },
    { 0x000091, "TLS_DHE_PSK_WITH_AES_256_CBC_SHA" },
    { 0x000092, "TLS_RSA_PSK_WITH_RC4_128_SHA" },
    { 0x000093, "TLS_RSA_PSK_WITH_3DES_EDE_CBC_SHA" },
    { 0x000094, "TLS_RSA_PSK_WITH_AES_128_CBC_SHA" },
    { 0x000095, "TLS_RSA_PSK_WITH_AES_256_CBC_SHA" },
    /* RFC 4162 */
    { 0x000096, "TLS_RSA_WITH_SEED_CBC_SHA" },
    { 0x000097, "TLS_DH_DSS_WITH_SEED_CBC_SHA" },
    { 0x000098, "TLS_DH_RSA_WITH_SEED_CBC_SHA" },
    { 0x000099, "TLS_DHE_DSS_WITH_SEED_CBC_SHA" },
    { 0x00009A, "TLS_DHE_RSA_WITH_SEED_CBC_SHA" },
    { 0x00009B, "TLS_DH_anon_WITH_SEED_CBC_SHA" },
    /* RFC 5288 */
    { 0x00009C, "TLS_RSA_WITH_AES_128_GCM_SHA256" },
    { 0x00009D, "TLS_RSA_WITH_AES_256_GCM_SHA384" },
    { 0x00009E, "TLS_DHE_RSA_WITH_AES_128_GCM_SHA256" },
    { 0x00009F, "TLS_DHE_RSA_WITH_AES_256_GCM_SHA384" },
    { 0x0000A0, "TLS_DH_RSA_WITH_AES_128_GCM_SHA256" },
    { 0x0000A1, "TLS_DH_RSA_WITH_AES_256_GCM_SHA384" },
    { 0x0000A2, "TLS_DHE_DSS_WITH_AES_128_GCM_SHA256" },
    { 0x0000A3, "TLS_DHE_DSS_WITH_AES_256_GCM_SHA384" },
    { 0x0000A4, "TLS_DH_DSS_WITH_AES_128_GCM_SHA256" },
    { 0x0000A5, "TLS_DH_DSS_WITH_AES_256_GCM_SHA384" },
    { 0x0000A6, "TLS_DH_anon_WITH_AES_128_GCM_SHA256" },
    { 0x0000A7, "TLS_DH_anon_WITH_AES_256_GCM_SHA384" },
    /* RFC 5487 */
    { 0x0000A8, "TLS_PSK_WITH_AES_128_GCM_SHA256" },
    { 0x0000A9, "TLS_PSK_WITH_AES_256_GCM_SHA384" },
    { 0x0000AA, "TLS_DHE_PSK_WITH_AES_128_GCM_SHA256" },
    { 0x0000AB, "TLS_DHE_PSK_WITH_AES_256_GCM_SHA384" },
    { 0x0000AC, "TLS_RSA_PSK_WITH_AES_128_GCM_SHA256" },
    { 0x0000AD, "TLS_RSA_PSK_WITH_AES_256_GCM_SHA384" },
    { 0x0000AE, "TLS_PSK_WITH_AES_128_CBC_SHA256" },
    { 0x0000AF, "TLS_PSK_WITH_AES_256_CBC_SHA384" },
    { 0x0000B0, "TLS_PSK_WITH_NULL_SHA256" },
    { 0x0000B1, "TLS_PSK_WITH_NULL_SHA384" },
    { 0x0000B2, "TLS_DHE_PSK_WITH_AES_128_CBC_SHA256" },
    { 0x0000B3, "TLS_DHE_PSK_WITH_AES_256_CBC_SHA384" },
    { 0x0000B4, "TLS_DHE_PSK_WITH_NULL_SHA256" },
    { 0x0000B5, "TLS_DHE_PSK_WITH_NULL_SHA384" },
    { 0x0000B6, "TLS_RSA_PSK_WITH_AES_128_CBC_SHA256" },
    { 0x0000B7, "TLS_RSA_PSK_WITH_AES_256_CBC_SHA384" },
    { 0x0000B8, "TLS_RSA_PSK_WITH_NULL_SHA256" },
    { 0x0000B9, "TLS_RSA_PSK_WITH_NULL_SHA384" },
    /* From RFC 5932 */
    { 0x0000BA, "TLS_RSA_WITH_CAMELLIA_128_CBC_SHA256" },
    { 0x0000BB, "TLS_DH_DSS_WITH_CAMELLIA_128_CBC_SHA256" },
    { 0x0000BC, "TLS_DH_RSA_WITH_CAMELLIA_128_CBC_SHA256" },
    { 0x0000BD, "TLS_DHE_DSS_WITH_CAMELLIA_128_CBC_SHA256" },
    { 0x0000BE, "TLS_DHE_RSA_WITH_CAMELLIA_128_CBC_SHA256" },
    { 0x0000BF, "TLS_DH_anon_WITH_CAMELLIA_128_CBC_SHA256" },
    { 0x0000C0, "TLS_RSA_WITH_CAMELLIA_256_CBC_SHA256" },
    { 0x0000C1, "TLS_DH_DSS_WITH_CAMELLIA_256_CBC_SHA256" },
    { 0x0000C2, "TLS_DH_RSA_WITH_CAMELLIA_256_CBC_SHA256" },
    { 0x0000C3, "TLS_DHE_DSS_WITH_CAMELLIA_256_CBC_SHA256" },
    { 0x0000C4, "TLS_DHE_RSA_WITH_CAMELLIA_256_CBC_SHA256" },
    { 0x0000C5, "TLS_DH_anon_WITH_CAMELLIA_256_CBC_SHA256" },
    /* 0x00,0xC6-FE Unassigned  */
    { 0x0000FF, "TLS_EMPTY_RENEGOTIATION_INFO_SCSV" },
    /* 0x01-BF,* Unassigned  */
    /* From RFC 4492 */
    { 0x00c001, "TLS_ECDH_ECDSA_WITH_NULL_SHA" },
    { 0x00c002, "TLS_ECDH_ECDSA_WITH_RC4_128_SHA" },
    { 0x00c003, "TLS_ECDH_ECDSA_WITH_3DES_EDE_CBC_SHA" },
    { 0x00c004, "TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA" },
    { 0x00c005, "TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA" },
    { 0x00c006, "TLS_ECDHE_ECDSA_WITH_NULL_SHA" },
    { 0x00c007, "TLS_ECDHE_ECDSA_WITH_RC4_128_SHA" },
    { 0x00c008, "TLS_ECDHE_ECDSA_WITH_3DES_EDE_CBC_SHA" },
    { 0x00c009, "TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA" },
    { 0x00c00a, "TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA" },
    { 0x00c00b, "TLS_ECDH_RSA_WITH_NULL_SHA" },
    { 0x00c00c, "TLS_ECDH_RSA_WITH_RC4_128_SHA" },
    { 0x00c00d, "TLS_ECDH_RSA_WITH_3DES_EDE_CBC_SHA" },
    { 0x00c00e, "TLS_ECDH_RSA_WITH_AES_128_CBC_SHA" },
    { 0x00c00f, "TLS_ECDH_RSA_WITH_AES_256_CBC_SHA" },
    { 0x00c010, "TLS_ECDHE_RSA_WITH_NULL_SHA" },
    { 0x00c011, "TLS_ECDHE_RSA_WITH_RC4_128_SHA" },
    { 0x00c012, "TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA" },
    { 0x00c013, "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA" },
    { 0x00c014, "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA" },
    { 0x00c015, "TLS_ECDH_anon_WITH_NULL_SHA" },
    { 0x00c016, "TLS_ECDH_anon_WITH_RC4_128_SHA" },
    { 0x00c017, "TLS_ECDH_anon_WITH_3DES_EDE_CBC_SHA" },
    { 0x00c018, "TLS_ECDH_anon_WITH_AES_128_CBC_SHA" },
    { 0x00c019, "TLS_ECDH_anon_WITH_AES_256_CBC_SHA" },
    /* RFC 5054 */
    { 0x00C01A, "TLS_SRP_SHA_WITH_3DES_EDE_CBC_SHA" },
    { 0x00C01B, "TLS_SRP_SHA_RSA_WITH_3DES_EDE_CBC_SHA" },
    { 0x00C01C, "TLS_SRP_SHA_DSS_WITH_3DES_EDE_CBC_SHA" },
    { 0x00C01D, "TLS_SRP_SHA_WITH_AES_128_CBC_SHA" },
    { 0x00C01E, "TLS_SRP_SHA_RSA_WITH_AES_128_CBC_SHA" },
    { 0x00C01F, "TLS_SRP_SHA_DSS_WITH_AES_128_CBC_SHA" },
    { 0x00C020, "TLS_SRP_SHA_WITH_AES_256_CBC_SHA" },
    { 0x00C021, "TLS_SRP_SHA_RSA_WITH_AES_256_CBC_SHA" },
    { 0x00C022, "TLS_SRP_SHA_DSS_WITH_AES_256_CBC_SHA" },
    /* RFC 5589 */
    { 0x00C023, "TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256" },
    { 0x00C024, "TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384" },
    { 0x00C025, "TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA256" },
    { 0x00C026, "TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA384" },
    { 0x00C027, "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256" },
    { 0x00C028, "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384" },
    { 0x00C029, "TLS_ECDH_RSA_WITH_AES_128_CBC_SHA256" },
    { 0x00C02A, "TLS_ECDH_RSA_WITH_AES_256_CBC_SHA384" },
    { 0x00C02B, "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256" },
    { 0x00C02C, "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384" },
    { 0x00C02D, "TLS_ECDH_ECDSA_WITH_AES_128_GCM_SHA256" },
    { 0x00C02E, "TLS_ECDH_ECDSA_WITH_AES_256_GCM_SHA384" },
    { 0x00C02F, "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256" },
    { 0x00C030, "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384" },
    { 0x00C031, "TLS_ECDH_RSA_WITH_AES_128_GCM_SHA256" },
    { 0x00C032, "TLS_ECDH_RSA_WITH_AES_256_GCM_SHA384" },
    /* RFC 5489 */
    { 0x00C033, "TLS_ECDHE_PSK_WITH_RC4_128_SHA" },
    { 0x00C034, "TLS_ECDHE_PSK_WITH_3DES_EDE_CBC_SHA" },
    { 0x00C035, "TLS_ECDHE_PSK_WITH_AES_128_CBC_SHA" },
    { 0x00C036, "TLS_ECDHE_PSK_WITH_AES_256_CBC_SHA" },
    { 0x00C037, "TLS_ECDHE_PSK_WITH_AES_128_CBC_SHA256" },
    { 0x00C038, "TLS_ECDHE_PSK_WITH_AES_256_CBC_SHA384" },
    { 0x00C039, "TLS_ECDHE_PSK_WITH_NULL_SHA" },
    { 0x00C03A, "TLS_ECDHE_PSK_WITH_NULL_SHA256" },
    { 0x00C03B, "TLS_ECDHE_PSK_WITH_NULL_SHA384" },
    /* 0xC0,0x3C-FF Unassigned
            0xC1-FD,* Unassigned
            0xFE,0x00-FD Unassigned
            0xFE,0xFE-FF Reserved to avoid conflicts with widely deployed implementations [Pasi_Eronen]
            0xFF,0x00-FF Reserved for Private Use [RFC5246]
            */

    /* old numbers used in the beginning
     * https://tools.ietf.org/html/draft-agl-tls-chacha20poly1305 */
    { 0x00CC13, "TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256" },
    { 0x00CC14, "TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256" },
    { 0x00CC15, "TLS_DHE_RSA_WITH_CHACHA20_POLY1305_SHA256" },

    /* https://tools.ietf.org/html/rfc7905 */
    { 0x00CCA8, "TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256" },
    { 0x00CCA9, "TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256" },
    { 0x00CCAA, "TLS_DHE_RSA_WITH_CHACHA20_POLY1305_SHA256" },
    { 0x00CCAB, "TLS_PSK_WITH_CHACHA20_POLY1305_SHA256" },
    { 0x00CCAC, "TLS_ECDHE_PSK_WITH_CHACHA20_POLY1305_SHA256" },
    { 0x00CCAD, "TLS_DHE_PSK_WITH_CHACHA20_POLY1305_SHA256" },
    { 0x00CCAE, "TLS_RSA_PSK_WITH_CHACHA20_POLY1305_SHA256" },

    /* GM/T 0024-2014 */
    { 0x00e001, "ECDHE_SM1_SM3"},
    { 0x00e003, "ECC_SM1_SM3"},
    { 0x00e005, "IBSDH_SM1_SM3"},
    { 0x00e007, "IBC_SM1_SM3"},
    { 0x00e009, "RSA_SM1_SM3"},
    { 0x00e00a, "RSA_SM1_SHA1"},
    { 0x00e011, "ECDHE_SM4_CBC_SM3"},
    { 0x00e013, "ECC_SM4_CBC_SM3"},
    { 0x00e015, "IBSDH_SM4_CBC_SM3"},
    { 0x00e017, "IBC_SM4_CBC_SM3"},
    { 0x00e019, "RSA_SM4_CBC_SM3"},
    { 0x00e01a, "RSA_SM4_CBC_SHA1"},
    { 0x00e01c, "RSA_SM4_CBC_SHA256"},
    { 0x00e051, "ECDHE_SM4_GCM_SM3"},
    { 0x00e053, "ECC_SM4_GCM_SM3"},
    { 0x00e055, "IBSDH_SM4_GCM_SM3"},
    { 0x00e057, "IBC_SM4_GCM_SM3"},
    { 0x00e059, "RSA_SM4_GCM_SM3"},
    { 0x00e05a, "RSA_SM4_GCM_SHA256"},

    /* https://tools.ietf.org/html/draft-josefsson-salsa20-tls */
    { 0x00E410, "TLS_RSA_WITH_ESTREAM_SALSA20_SHA1" },
    { 0x00E411, "TLS_RSA_WITH_SALSA20_SHA1" },
    { 0x00E412, "TLS_ECDHE_RSA_WITH_ESTREAM_SALSA20_SHA1" },
    { 0x00E413, "TLS_ECDHE_RSA_WITH_SALSA20_SHA1" },
    { 0x00E414, "TLS_ECDHE_ECDSA_WITH_ESTREAM_SALSA20_SHA1" },
    { 0x00E415, "TLS_ECDHE_ECDSA_WITH_SALSA20_SHA1" },
    { 0x00E416, "TLS_PSK_WITH_ESTREAM_SALSA20_SHA1" },
    { 0x00E417, "TLS_PSK_WITH_SALSA20_SHA1" },
    { 0x00E418, "TLS_ECDHE_PSK_WITH_ESTREAM_SALSA20_SHA1" },
    { 0x00E419, "TLS_ECDHE_PSK_WITH_SALSA20_SHA1" },
    { 0x00E41A, "TLS_RSA_PSK_WITH_ESTREAM_SALSA20_SHA1" },
    { 0x00E41B, "TLS_RSA_PSK_WITH_SALSA20_SHA1" },
    { 0x00E41C, "TLS_DHE_PSK_WITH_ESTREAM_SALSA20_SHA1" },
    { 0x00E41D, "TLS_DHE_PSK_WITH_SALSA20_SHA1" },
    { 0x00E41E, "TLS_DHE_RSA_WITH_ESTREAM_SALSA20_SHA1" },
    { 0x00E41F, "TLS_DHE_RSA_WITH_SALSA20_SHA1" },

    /* these from http://www.mozilla.org/projects/
         security/pki/nss/ssl/fips-ssl-ciphersuites.html */
    { 0x00fefe, "SSL_RSA_FIPS_WITH_DES_CBC_SHA"},
    { 0x00feff, "SSL_RSA_FIPS_WITH_3DES_EDE_CBC_SHA" },
    { 0x00ffe0, "SSL_RSA_FIPS_WITH_3DES_EDE_CBC_SHA" },
    { 0x00ffe1, "SSL_RSA_FIPS_WITH_DES_CBC_SHA"},
    /* note that ciphersuites of {0x00????} are TLS cipher suites in
     * a sslv2 client hello message; the ???? above is the two-byte
     * tls cipher suite id
     */

    { 0x010080, "SSL2_RC4_128_WITH_MD5" },
    { 0x020080, "SSL2_RC4_128_EXPORT40_WITH_MD5" },
    { 0x030080, "SSL2_RC2_128_CBC_WITH_MD5" },
    { 0x040080, "SSL2_RC2_128_CBC_EXPORT40_WITH_MD5" },
    { 0x050080, "SSL2_IDEA_128_CBC_WITH_MD5" },
    { 0x060040, "SSL2_DES_64_CBC_WITH_MD5" },
    { 0x0700c0, "SSL2_DES_192_EDE3_CBC_WITH_MD5" },
    { 0x080080, "SSL2_RC4_64_WITH_MD5" },

    { 0x00, NULL }
};

value_string_ext ssl_20_cipher_suites_ext = VALUE_STRING_EXT_INIT(ssl_20_cipher_suites);


/*
 * Supported Groups (formerly named "EC Named Curve").
 * https://www.iana.org/assignments/tls-parameters/tls-parameters.xhtml#tls-parameters-8
 */
const value_string ssl_extension_curves[] = {
    {  1, "sect163k1" },
    {  2, "sect163r1" },
    {  3, "sect163r2" },
    {  4, "sect193r1" },
    {  5, "sect193r2" },
    {  6, "sect233k1" },
    {  7, "sect233r1" },
    {  8, "sect239k1" },
    {  9, "sect283k1" },
    { 10, "sect283r1" },
    { 11, "sect409k1" },
    { 12, "sect409r1" },
    { 13, "sect571k1" },
    { 14, "sect571r1" },
    { 15, "secp160k1" },
    { 16, "secp160r1" },
    { 17, "secp160r2" },
    { 18, "secp192k1" },
    { 19, "secp192r1" },
    { 20, "secp224k1" },
    { 21, "secp224r1" },
    { 22, "secp256k1" },
    { 23, "secp256r1" },
    { 24, "secp384r1" },
    { 25, "secp521r1" },
    { 26, "brainpoolP256r1" }, /* RFC 7027 */
    { 27, "brainpoolP384r1" }, /* RFC 7027 */
    { 28, "brainpoolP512r1" }, /* RFC 7027 */
    { 29, "x25519" }, /* RFC 8446 / RFC 8422 */
    { 30, "x448" }, /* RFC 8446 / RFC 8422 */
    { 31, "brainpoolP256r1tls13" }, /* RFC8734 */
    { 32, "brainpoolP384r1tls13" }, /* RFC8734 */
    { 33, "brainpoolP512r1tls13" }, /* RFC8734 */
    { 34, "GC256A" }, /* RFC9189 */
    { 35, "GC256B" }, /* RFC9189 */
    { 36, "GC256C" }, /* RFC9189 */
    { 37, "GC256D" }, /* RFC9189 */
    { 38, "GC512A" }, /* RFC9189 */
    { 39, "GC512B" }, /* RFC9189 */
    { 40, "GC512C" }, /* RFC9189 */
    { 41, "curveSM2" }, /* RFC 8998 */
    { 256, "ffdhe2048" }, /* RFC 7919 */
    { 257, "ffdhe3072" }, /* RFC 7919 */
    { 258, "ffdhe4096" }, /* RFC 7919 */
    { 259, "ffdhe6144" }, /* RFC 7919 */
    { 260, "ffdhe8192" }, /* RFC 7919 */
    /* PQC key exchange algorithms from OQS-OpenSSL,
        see https://github.com/open-quantum-safe/openssl/blob/OQS-OpenSSL_1_1_1-stable/oqs-template/oqs-kem-info.md */
    { 0x0200, "frodo640aes" },
    { 0x2F00, "p256_frodo640aes" },
    { 0x0201, "frodo640shake" },
    { 0x2F01, "p256_frodo640shake" },
    { 0x0202, "frodo976aes" },
    { 0x2F02, "p384_frodo976aes" },
    { 0x0203, "frodo976shake" },
    { 0x2F03, "p384_frodo976shake" },
    { 0x0204, "frodo1344aes" },
    { 0x2F04, "p521_frodo1344aes" },
    { 0x0205, "frodo1344shake" },
    { 0x2F05, "p521_frodo1344shake" },
    { 0x023A, "kyber512" },
    { 0x2F3A, "p256_kyber512" },
    { 0x023C, "kyber768" },
    { 0x2F3C, "p384_kyber768" },
    { 0x023D, "kyber1024" },
    { 0x2F3D, "p521_kyber1024" },
    { 0x0214, "ntru_hps2048509" },
    { 0x2F14, "p256_ntru_hps2048509" },
    { 0x0215, "ntru_hps2048677" },
    { 0x2F15, "p384_ntru_hps2048677" },
    { 0x0216, "ntru_hps4096821" },
    { 0x2F16, "p521_ntru_hps4096821" },
    { 0x0245, "ntru_hps40961229" },
    { 0x2F45, "p521_ntru_hps40961229" },
    { 0x0217, "ntru_hrss701" },
    { 0x2F17, "p384_ntru_hrss701" },
    { 0x0246, "ntru_hrss1373" },
    { 0x2F46, "p521_ntru_hrss1373" },
    { 0x0218, "lightsaber" },
    { 0x2F18, "p256_lightsaber" },
    { 0x0219, "saber" },
    { 0x2F19, "p384_saber" },
    { 0x021A, "firesaber" },
    { 0x2F1A, "p521_firesaber" },
    { 0x021B, "sidhp434" },
    { 0x2F1B, "p256_sidhp434" },
    { 0x021C, "sidhp503" },
    { 0x2F1C, "p256_sidhp503" },
    { 0x021D, "sidhp610" },
    { 0x2F1D, "p384_sidhp610" },
    { 0x021E, "sidhp751" },
    { 0x2F1E, "p521_sidhp751" },
    { 0x021F, "sikep434" },
    { 0x2F1F, "p256_sikep434" },
    { 0x0220, "sikep503" },
    { 0x2F20, "p256_sikep503" },
    { 0x0221, "sikep610" },
    { 0x2F21, "p384_sikep610" },
    { 0x0222, "sikep751" },
    { 0x2F22, "p521_sikep751" },
    { 0x0238, "bikel1" },
    { 0x2F38, "p256_bikel1" },
    { 0x023B, "bikel3" },
    { 0x2F3B, "p384_bikel3" },
    { 0x023E, "kyber90s512" },
    { 0x2F3E, "p256_kyber90s512" },
    { 0x023F, "kyber90s768" },
    { 0x2F3F, "p384_kyber90s768" },
    { 0x0240, "kyber90s1024" },
    { 0x2F40, "p521_kyber90s1024" },
    { 0x022C, "hqc128" },
    { 0x2F2C, "p256_hqc128" },
    { 0x022D, "hqc192" },
    { 0x2F2D, "p384_hqc192" },
    { 0x022E, "hqc256" },
    { 0x2F2E, "p521_hqc256" },
    { 0x022F, "ntrulpr653" },
    { 0x2F2F, "p256_ntrulpr653" },
    { 0x0230, "ntrulpr761" },
    { 0x2F43, "p256_ntrulpr761" },
    { 0x0231, "ntrulpr857" },
    { 0x2F31, "p384_ntrulpr857" },
    { 0x0241, "ntrulpr1277" },
    { 0x2F41, "p521_ntrulpr1277" },
    { 0x0232, "sntrup653" },
    { 0x2F32, "p256_sntrup653" },
    { 0x0233, "sntrup761" },
    { 0x2F44, "p256_sntrup761" },
    { 0x0234, "sntrup857" },
    { 0x2F34, "p384_sntrup857" },
    { 0x0242, "sntrup1277" },
    { 0x2F42, "p521_sntrup1277" },
    /* Other PQ key exchange algorithms:
        https://blog.cloudflare.com/post-quantum-for-all
	https://www.ietf.org/archive/id/draft-tls-westerbaan-xyber768d00-02.txt */
    { 0xFE30, "X25519Kyber512Draft00" },
    { 0xFE31, "X25519Kyber768Draft00 (obsolete value)" },
    { 0x6399, "X25519Kyber768Draft00" },
    { 2570, "Reserved (GREASE)" }, /* RFC 8701 */
    { 6682, "Reserved (GREASE)" }, /* RFC 8701 */
    { 10794, "Reserved (GREASE)" }, /* RFC 8701 */
    { 14906, "Reserved (GREASE)" }, /* RFC 8701 */
    { 19018, "Reserved (GREASE)" }, /* RFC 8701 */
    { 23130, "Reserved (GREASE)" }, /* RFC 8701 */
    { 27242, "Reserved (GREASE)" }, /* RFC 8701 */
    { 31354, "Reserved (GREASE)" }, /* RFC 8701 */
    { 35466, "Reserved (GREASE)" }, /* RFC 8701 */
    { 39578, "Reserved (GREASE)" }, /* RFC 8701 */
    { 43690, "Reserved (GREASE)" }, /* RFC 8701 */
    { 47802, "Reserved (GREASE)" }, /* RFC 8701 */
    { 51914, "Reserved (GREASE)" }, /* RFC 8701 */
    { 56026, "Reserved (GREASE)" }, /* RFC 8701 */
    { 60138, "Reserved (GREASE)" }, /* RFC 8701 */
    { 64250, "Reserved (GREASE)" }, /* RFC 8701 */
    { 0xFF01, "arbitrary_explicit_prime_curves" },
    { 0xFF02, "arbitrary_explicit_char2_curves" },
    { 0x00, NULL }
};

const value_string ssl_curve_types[] = {
    { 1, "explicit_prime" },
    { 2, "explicit_char2" },
    { 3, "named_curve" },
    { 0x00, NULL }
};

const value_string ssl_extension_ec_point_formats[] = {
    { 0, "uncompressed" },
    { 1, "ansiX962_compressed_prime" },
    { 2, "ansiX962_compressed_char2" },
    { 0x00, NULL }
};

const value_string ssl_20_certificate_type[] = {
    { 0x00, "N/A" },
    { 0x01, "X.509 Certificate" },
    { 0x00, NULL }
};

const value_string ssl_31_content_type[] = {
    { 20, "Change Cipher Spec" },
    { 21, "Alert" },
    { 22, "Handshake" },
    { 23, "Application Data" },
    { 24, "Heartbeat" },
    { 25, "Connection ID" },
    { 0x00, NULL }
};

#if 0
/* XXX - would be used if we dissected the body of a Change Cipher Spec
   message. */
const value_string ssl_31_change_cipher_spec[] = {
    { 1, "Change Cipher Spec" },
    { 0x00, NULL }
};
#endif

const value_string ssl_31_alert_level[] = {
    { 1, "Warning" },
    { 2, "Fatal" },
    { 0x00, NULL }
};

const value_string ssl_31_alert_description[] = {
    {   0,  "Close Notify" },
    {   1,  "End of Early Data" },
    {  10,  "Unexpected Message" },
    {  20,  "Bad Record MAC" },
    {  21,  "Decryption Failed" },
    {  22,  "Record Overflow" },
    {  30,  "Decompression Failure" },
    {  40,  "Handshake Failure" },
    {  41,  "No Certificate" },
    {  42,  "Bad Certificate" },
    {  43,  "Unsupported Certificate" },
    {  44,  "Certificate Revoked" },
    {  45,  "Certificate Expired" },
    {  46,  "Certificate Unknown" },
    {  47,  "Illegal Parameter" },
    {  48,  "Unknown CA" },
    {  49,  "Access Denied" },
    {  50,  "Decode Error" },
    {  51,  "Decrypt Error" },
    {  60,  "Export Restriction" },
    {  70,  "Protocol Version" },
    {  71,  "Insufficient Security" },
    {  80,  "Internal Error" },
    {  86,  "Inappropriate Fallback" },
    {  90,  "User Canceled" },
    { 100, "No Renegotiation" },
    { 109, "Missing Extension" },
    { 110, "Unsupported Extension" },
    { 111, "Certificate Unobtainable" },
    { 112, "Unrecognized Name" },
    { 113, "Bad Certificate Status Response" },
    { 114, "Bad Certificate Hash Value" },
    { 115, "Unknown PSK Identity" },
    { 116, "Certificate Required" },
    { 120, "No application Protocol" },
    { 121, "ECH Required" },
    { 0x00, NULL }
};

const value_string ssl_31_handshake_type[] = {
    { SSL_HND_HELLO_REQUEST,     "Hello Request" },
    { SSL_HND_CLIENT_HELLO,      "Client Hello" },
    { SSL_HND_SERVER_HELLO,      "Server Hello" },
    { SSL_HND_HELLO_VERIFY_REQUEST, "Hello Verify Request"},
    { SSL_HND_NEWSESSION_TICKET, "New Session Ticket" },
    { SSL_HND_END_OF_EARLY_DATA, "End of Early Data" },
    { SSL_HND_HELLO_RETRY_REQUEST, "Hello Retry Request" },
    { SSL_HND_ENCRYPTED_EXTENSIONS, "Encrypted Extensions" },
    { SSL_HND_CERTIFICATE,       "Certificate" },
    { SSL_HND_SERVER_KEY_EXCHG,  "Server Key Exchange" },
    { SSL_HND_CERT_REQUEST,      "Certificate Request" },
    { SSL_HND_SVR_HELLO_DONE,    "Server Hello Done" },
    { SSL_HND_CERT_VERIFY,       "Certificate Verify" },
    { SSL_HND_CLIENT_KEY_EXCHG,  "Client Key Exchange" },
    { SSL_HND_FINISHED,          "Finished" },
    { SSL_HND_CERT_URL,          "Client Certificate URL" },
    { SSL_HND_CERT_STATUS,       "Certificate Status" },
    { SSL_HND_SUPPLEMENTAL_DATA, "Supplemental Data" },
    { SSL_HND_KEY_UPDATE,        "Key Update" },
    { SSL_HND_COMPRESSED_CERTIFICATE, "Compressed Certificate" },
    { SSL_HND_ENCRYPTED_EXTS,    "Encrypted Extensions" },
    { 0x00, NULL }
};

const value_string tls_heartbeat_type[] = {
    { 1, "Request" },
    { 2, "Response" },
    { 0x00, NULL }
};

const value_string tls_heartbeat_mode[] = {
    { 1, "Peer allowed to send requests" },
    { 2, "Peer not allowed to send requests" },
    { 0x00, NULL }
};

const value_string ssl_31_compression_method[] = {
    {  0, "null" },
    {  1, "DEFLATE" },
    { 64, "LZS" },
    { 0x00, NULL }
};

#if 0
/* XXX - would be used if we dissected a Signature, as would be
   seen in a server key exchange or certificate verify message. */
const value_string ssl_31_key_exchange_algorithm[] = {
    { 0, "RSA" },
    { 1, "Diffie Hellman" },
    { 0x00, NULL }
};

const value_string ssl_31_signature_algorithm[] = {
    { 0, "Anonymous" },
    { 1, "RSA" },
    { 2, "DSA" },
    { 0x00, NULL }
};
#endif

const value_string ssl_31_client_certificate_type[] = {
    { 1, "RSA Sign" },
    { 2, "DSS Sign" },
    { 3, "RSA Fixed DH" },
    { 4, "DSS Fixed DH" },
    /* GOST certificate types */
    /* Section 3.5 of draft-chudov-cryptopro-cptls-04 */
    { 21, "GOST R 34.10-94" },
    { 22, "GOST R 34.10-2001" },
    /* END GOST certificate types */
    { 64, "ECDSA Sign" },
    { 65, "RSA Fixed ECDH" },
    { 66, "ECDSA Fixed ECDH" },
    { 80, "IBC Params" },
    { 0x00, NULL }
};

#if 0
/* XXX - would be used if we dissected exchange keys, as would be
   seen in a client key exchange message. */
const value_string ssl_31_public_value_encoding[] = {
    { 0, "Implicit" },
    { 1, "Explicit" },
    { 0x00, NULL }
};
#endif

/* http://www.iana.org/assignments/tls-parameters/tls-parameters.xhtml */
/* Note: sorted by ascending value so value_string_ext fcns can do a binary search */
static const value_string ssl_31_ciphersuite[] = {
    /* RFC 2246, RFC 4346, RFC 5246 */
    { 0x0000, "TLS_NULL_WITH_NULL_NULL" },
    { 0x0001, "TLS_RSA_WITH_NULL_MD5" },
    { 0x0002, "TLS_RSA_WITH_NULL_SHA" },
    { 0x0003, "TLS_RSA_EXPORT_WITH_RC4_40_MD5" },
    { 0x0004, "TLS_RSA_WITH_RC4_128_MD5" },
    { 0x0005, "TLS_RSA_WITH_RC4_128_SHA" },
    { 0x0006, "TLS_RSA_EXPORT_WITH_RC2_CBC_40_MD5" },
    { 0x0007, "TLS_RSA_WITH_IDEA_CBC_SHA" },
    { 0x0008, "TLS_RSA_EXPORT_WITH_DES40_CBC_SHA" },
    { 0x0009, "TLS_RSA_WITH_DES_CBC_SHA" },
    { 0x000a, "TLS_RSA_WITH_3DES_EDE_CBC_SHA" },
    { 0x000b, "TLS_DH_DSS_EXPORT_WITH_DES40_CBC_SHA" },
    { 0x000c, "TLS_DH_DSS_WITH_DES_CBC_SHA" },
    { 0x000d, "TLS_DH_DSS_WITH_3DES_EDE_CBC_SHA" },
    { 0x000e, "TLS_DH_RSA_EXPORT_WITH_DES40_CBC_SHA" },
    { 0x000f, "TLS_DH_RSA_WITH_DES_CBC_SHA" },
    { 0x0010, "TLS_DH_RSA_WITH_3DES_EDE_CBC_SHA" },
    { 0x0011, "TLS_DHE_DSS_EXPORT_WITH_DES40_CBC_SHA" },
    { 0x0012, "TLS_DHE_DSS_WITH_DES_CBC_SHA" },
    { 0x0013, "TLS_DHE_DSS_WITH_3DES_EDE_CBC_SHA" },
    { 0x0014, "TLS_DHE_RSA_EXPORT_WITH_DES40_CBC_SHA" },
    { 0x0015, "TLS_DHE_RSA_WITH_DES_CBC_SHA" },
    { 0x0016, "TLS_DHE_RSA_WITH_3DES_EDE_CBC_SHA" },
    { 0x0017, "TLS_DH_anon_EXPORT_WITH_RC4_40_MD5" },
    { 0x0018, "TLS_DH_anon_WITH_RC4_128_MD5" },
    { 0x0019, "TLS_DH_anon_EXPORT_WITH_DES40_CBC_SHA" },
    { 0x001a, "TLS_DH_anon_WITH_DES_CBC_SHA" },
    { 0x001b, "TLS_DH_anon_WITH_3DES_EDE_CBC_SHA" },

    { 0x001c, "SSL_FORTEZZA_KEA_WITH_NULL_SHA" },
    { 0x001d, "SSL_FORTEZZA_KEA_WITH_FORTEZZA_CBC_SHA" },
#if 0 /* Because it clashes with KRB5, is never used any more, and is safe
         to remove according to David Hopwood <david.hopwood@zetnet.co.uk>
         of the ietf-tls list */
    { 0x001e, "SSL_FORTEZZA_KEA_WITH_RC4_128_SHA" },
#endif
    /* RFC 2712 */
    { 0x001E, "TLS_KRB5_WITH_DES_CBC_SHA" },
    { 0x001F, "TLS_KRB5_WITH_3DES_EDE_CBC_SHA" },
    { 0x0020, "TLS_KRB5_WITH_RC4_128_SHA" },
    { 0x0021, "TLS_KRB5_WITH_IDEA_CBC_SHA" },
    { 0x0022, "TLS_KRB5_WITH_DES_CBC_MD5" },
    { 0x0023, "TLS_KRB5_WITH_3DES_EDE_CBC_MD5" },
    { 0x0024, "TLS_KRB5_WITH_RC4_128_MD5" },
    { 0x0025, "TLS_KRB5_WITH_IDEA_CBC_MD5" },
    { 0x0026, "TLS_KRB5_EXPORT_WITH_DES_CBC_40_SHA" },
    { 0x0027, "TLS_KRB5_EXPORT_WITH_RC2_CBC_40_SHA" },
    { 0x0028, "TLS_KRB5_EXPORT_WITH_RC4_40_SHA" },
    { 0x0029, "TLS_KRB5_EXPORT_WITH_DES_CBC_40_MD5" },
    { 0x002A, "TLS_KRB5_EXPORT_WITH_RC2_CBC_40_MD5" },
    { 0x002B, "TLS_KRB5_EXPORT_WITH_RC4_40_MD5" },
    /* RFC 4785 */
    { 0x002C, "TLS_PSK_WITH_NULL_SHA" },
    { 0x002D, "TLS_DHE_PSK_WITH_NULL_SHA" },
    { 0x002E, "TLS_RSA_PSK_WITH_NULL_SHA" },
    /* RFC 5246 */
    { 0x002F, "TLS_RSA_WITH_AES_128_CBC_SHA" },
    { 0x0030, "TLS_DH_DSS_WITH_AES_128_CBC_SHA" },
    { 0x0031, "TLS_DH_RSA_WITH_AES_128_CBC_SHA" },
    { 0x0032, "TLS_DHE_DSS_WITH_AES_128_CBC_SHA" },
    { 0x0033, "TLS_DHE_RSA_WITH_AES_128_CBC_SHA" },
    { 0x0034, "TLS_DH_anon_WITH_AES_128_CBC_SHA" },
    { 0x0035, "TLS_RSA_WITH_AES_256_CBC_SHA" },
    { 0x0036, "TLS_DH_DSS_WITH_AES_256_CBC_SHA" },
    { 0x0037, "TLS_DH_RSA_WITH_AES_256_CBC_SHA" },
    { 0x0038, "TLS_DHE_DSS_WITH_AES_256_CBC_SHA" },
    { 0x0039, "TLS_DHE_RSA_WITH_AES_256_CBC_SHA" },
    { 0x003A, "TLS_DH_anon_WITH_AES_256_CBC_SHA" },
    { 0x003B, "TLS_RSA_WITH_NULL_SHA256" },
    { 0x003C, "TLS_RSA_WITH_AES_128_CBC_SHA256" },
    { 0x003D, "TLS_RSA_WITH_AES_256_CBC_SHA256" },
    { 0x003E, "TLS_DH_DSS_WITH_AES_128_CBC_SHA256" },
    { 0x003F, "TLS_DH_RSA_WITH_AES_128_CBC_SHA256" },
    { 0x0040, "TLS_DHE_DSS_WITH_AES_128_CBC_SHA256" },
    /* RFC 4132 */
    { 0x0041, "TLS_RSA_WITH_CAMELLIA_128_CBC_SHA" },
    { 0x0042, "TLS_DH_DSS_WITH_CAMELLIA_128_CBC_SHA" },
    { 0x0043, "TLS_DH_RSA_WITH_CAMELLIA_128_CBC_SHA" },
    { 0x0044, "TLS_DHE_DSS_WITH_CAMELLIA_128_CBC_SHA" },
    { 0x0045, "TLS_DHE_RSA_WITH_CAMELLIA_128_CBC_SHA" },
    { 0x0046, "TLS_DH_anon_WITH_CAMELLIA_128_CBC_SHA" },
    /* 0x00,0x60-66 Reserved to avoid conflicts with widely deployed implementations  */
    /* --- ??? --- */
    { 0x0060, "TLS_RSA_EXPORT1024_WITH_RC4_56_MD5" },
    { 0x0061, "TLS_RSA_EXPORT1024_WITH_RC2_CBC_56_MD5" },
    /* draft-ietf-tls-56-bit-ciphersuites-01.txt */
    { 0x0062, "TLS_RSA_EXPORT1024_WITH_DES_CBC_SHA" },
    { 0x0063, "TLS_DHE_DSS_EXPORT1024_WITH_DES_CBC_SHA" },
    { 0x0064, "TLS_RSA_EXPORT1024_WITH_RC4_56_SHA" },
    { 0x0065, "TLS_DHE_DSS_EXPORT1024_WITH_RC4_56_SHA" },
    { 0x0066, "TLS_DHE_DSS_WITH_RC4_128_SHA" },
    /* --- ??? ---*/
    { 0x0067, "TLS_DHE_RSA_WITH_AES_128_CBC_SHA256" },
    { 0x0068, "TLS_DH_DSS_WITH_AES_256_CBC_SHA256" },
    { 0x0069, "TLS_DH_RSA_WITH_AES_256_CBC_SHA256" },
    { 0x006A, "TLS_DHE_DSS_WITH_AES_256_CBC_SHA256" },
    { 0x006B, "TLS_DHE_RSA_WITH_AES_256_CBC_SHA256" },
    { 0x006C, "TLS_DH_anon_WITH_AES_128_CBC_SHA256" },
    { 0x006D, "TLS_DH_anon_WITH_AES_256_CBC_SHA256" },
    /* draft-chudov-cryptopro-cptls-04.txt */
    { 0x0080,  "TLS_GOSTR341094_WITH_28147_CNT_IMIT" },
    { 0x0081,  "TLS_GOSTR341001_WITH_28147_CNT_IMIT" },
    { 0x0082,  "TLS_GOSTR341094_WITH_NULL_GOSTR3411" },
    { 0x0083,  "TLS_GOSTR341001_WITH_NULL_GOSTR3411" },
    /* RFC 4132 */
    { 0x0084, "TLS_RSA_WITH_CAMELLIA_256_CBC_SHA" },
    { 0x0085, "TLS_DH_DSS_WITH_CAMELLIA_256_CBC_SHA" },
    { 0x0086, "TLS_DH_RSA_WITH_CAMELLIA_256_CBC_SHA" },
    { 0x0087, "TLS_DHE_DSS_WITH_CAMELLIA_256_CBC_SHA" },
    { 0x0088, "TLS_DHE_RSA_WITH_CAMELLIA_256_CBC_SHA" },
    { 0x0089, "TLS_DH_anon_WITH_CAMELLIA_256_CBC_SHA" },
    /* RFC 4279 */
    { 0x008A, "TLS_PSK_WITH_RC4_128_SHA" },
    { 0x008B, "TLS_PSK_WITH_3DES_EDE_CBC_SHA" },
    { 0x008C, "TLS_PSK_WITH_AES_128_CBC_SHA" },
    { 0x008D, "TLS_PSK_WITH_AES_256_CBC_SHA" },
    { 0x008E, "TLS_DHE_PSK_WITH_RC4_128_SHA" },
    { 0x008F, "TLS_DHE_PSK_WITH_3DES_EDE_CBC_SHA" },
    { 0x0090, "TLS_DHE_PSK_WITH_AES_128_CBC_SHA" },
    { 0x0091, "TLS_DHE_PSK_WITH_AES_256_CBC_SHA" },
    { 0x0092, "TLS_RSA_PSK_WITH_RC4_128_SHA" },
    { 0x0093, "TLS_RSA_PSK_WITH_3DES_EDE_CBC_SHA" },
    { 0x0094, "TLS_RSA_PSK_WITH_AES_128_CBC_SHA" },
    { 0x0095, "TLS_RSA_PSK_WITH_AES_256_CBC_SHA" },
    /* RFC 4162 */
    { 0x0096, "TLS_RSA_WITH_SEED_CBC_SHA" },
    { 0x0097, "TLS_DH_DSS_WITH_SEED_CBC_SHA" },
    { 0x0098, "TLS_DH_RSA_WITH_SEED_CBC_SHA" },
    { 0x0099, "TLS_DHE_DSS_WITH_SEED_CBC_SHA" },
    { 0x009A, "TLS_DHE_RSA_WITH_SEED_CBC_SHA" },
    { 0x009B, "TLS_DH_anon_WITH_SEED_CBC_SHA" },
    /* RFC 5288 */
    { 0x009C, "TLS_RSA_WITH_AES_128_GCM_SHA256" },
    { 0x009D, "TLS_RSA_WITH_AES_256_GCM_SHA384" },
    { 0x009E, "TLS_DHE_RSA_WITH_AES_128_GCM_SHA256" },
    { 0x009F, "TLS_DHE_RSA_WITH_AES_256_GCM_SHA384" },
    { 0x00A0, "TLS_DH_RSA_WITH_AES_128_GCM_SHA256" },
    { 0x00A1, "TLS_DH_RSA_WITH_AES_256_GCM_SHA384" },
    { 0x00A2, "TLS_DHE_DSS_WITH_AES_128_GCM_SHA256" },
    { 0x00A3, "TLS_DHE_DSS_WITH_AES_256_GCM_SHA384" },
    { 0x00A4, "TLS_DH_DSS_WITH_AES_128_GCM_SHA256" },
    { 0x00A5, "TLS_DH_DSS_WITH_AES_256_GCM_SHA384" },
    { 0x00A6, "TLS_DH_anon_WITH_AES_128_GCM_SHA256" },
    { 0x00A7, "TLS_DH_anon_WITH_AES_256_GCM_SHA384" },
    /* RFC 5487 */
    { 0x00A8, "TLS_PSK_WITH_AES_128_GCM_SHA256" },
    { 0x00A9, "TLS_PSK_WITH_AES_256_GCM_SHA384" },
    { 0x00AA, "TLS_DHE_PSK_WITH_AES_128_GCM_SHA256" },
    { 0x00AB, "TLS_DHE_PSK_WITH_AES_256_GCM_SHA384" },
    { 0x00AC, "TLS_RSA_PSK_WITH_AES_128_GCM_SHA256" },
    { 0x00AD, "TLS_RSA_PSK_WITH_AES_256_GCM_SHA384" },
    { 0x00AE, "TLS_PSK_WITH_AES_128_CBC_SHA256" },
    { 0x00AF, "TLS_PSK_WITH_AES_256_CBC_SHA384" },
    { 0x00B0, "TLS_PSK_WITH_NULL_SHA256" },
    { 0x00B1, "TLS_PSK_WITH_NULL_SHA384" },
    { 0x00B2, "TLS_DHE_PSK_WITH_AES_128_CBC_SHA256" },
    { 0x00B3, "TLS_DHE_PSK_WITH_AES_256_CBC_SHA384" },
    { 0x00B4, "TLS_DHE_PSK_WITH_NULL_SHA256" },
    { 0x00B5, "TLS_DHE_PSK_WITH_NULL_SHA384" },
    { 0x00B6, "TLS_RSA_PSK_WITH_AES_128_CBC_SHA256" },
    { 0x00B7, "TLS_RSA_PSK_WITH_AES_256_CBC_SHA384" },
    { 0x00B8, "TLS_RSA_PSK_WITH_NULL_SHA256" },
    { 0x00B9, "TLS_RSA_PSK_WITH_NULL_SHA384" },
    /* From RFC 5932 */
    { 0x00BA, "TLS_RSA_WITH_CAMELLIA_128_CBC_SHA256" },
    { 0x00BB, "TLS_DH_DSS_WITH_CAMELLIA_128_CBC_SHA256" },
    { 0x00BC, "TLS_DH_RSA_WITH_CAMELLIA_128_CBC_SHA256" },
    { 0x00BD, "TLS_DHE_DSS_WITH_CAMELLIA_128_CBC_SHA256" },
    { 0x00BE, "TLS_DHE_RSA_WITH_CAMELLIA_128_CBC_SHA256" },
    { 0x00BF, "TLS_DH_anon_WITH_CAMELLIA_128_CBC_SHA256" },
    { 0x00C0, "TLS_RSA_WITH_CAMELLIA_256_CBC_SHA256" },
    { 0x00C1, "TLS_DH_DSS_WITH_CAMELLIA_256_CBC_SHA256" },
    { 0x00C2, "TLS_DH_RSA_WITH_CAMELLIA_256_CBC_SHA256" },
    { 0x00C3, "TLS_DHE_DSS_WITH_CAMELLIA_256_CBC_SHA256" },
    { 0x00C4, "TLS_DHE_RSA_WITH_CAMELLIA_256_CBC_SHA256" },
    { 0x00C5, "TLS_DH_anon_WITH_CAMELLIA_256_CBC_SHA256" },
    /* RFC 8998 */
    { 0x00C6, "TLS_SM4_GCM_SM3" },
    { 0x00C7, "TLS_SM4_CCM_SM3" },
    /* 0x00,0xC8-FE Unassigned */
    /* From RFC 5746 */
    { 0x00FF, "TLS_EMPTY_RENEGOTIATION_INFO_SCSV" },
    /* RFC 8701 */
    { 0x0A0A, "Reserved (GREASE)" },
    /* RFC 8446 */
    { 0x1301, "TLS_AES_128_GCM_SHA256" },
    { 0x1302, "TLS_AES_256_GCM_SHA384" },
    { 0x1303, "TLS_CHACHA20_POLY1305_SHA256" },
    { 0x1304, "TLS_AES_128_CCM_SHA256" },
    { 0x1305, "TLS_AES_128_CCM_8_SHA256" },
    /* RFC 8701 */
    { 0x1A1A, "Reserved (GREASE)" },
    { 0x2A2A, "Reserved (GREASE)" },
    { 0x3A3A, "Reserved (GREASE)" },
    { 0x4A4A, "Reserved (GREASE)" },
    /* From RFC 7507 */
    { 0x5600, "TLS_FALLBACK_SCSV" },
    /* RFC 8701 */
    { 0x5A5A, "Reserved (GREASE)" },
    { 0x6A6A, "Reserved (GREASE)" },
    { 0x7A7A, "Reserved (GREASE)" },
    { 0x8A8A, "Reserved (GREASE)" },
    { 0x9A9A, "Reserved (GREASE)" },
    { 0xAAAA, "Reserved (GREASE)" },
    { 0xBABA, "Reserved (GREASE)" },
    /* From RFC 4492 */
    { 0xc001, "TLS_ECDH_ECDSA_WITH_NULL_SHA" },
    { 0xc002, "TLS_ECDH_ECDSA_WITH_RC4_128_SHA" },
    { 0xc003, "TLS_ECDH_ECDSA_WITH_3DES_EDE_CBC_SHA" },
    { 0xc004, "TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA" },
    { 0xc005, "TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA" },
    { 0xc006, "TLS_ECDHE_ECDSA_WITH_NULL_SHA" },
    { 0xc007, "TLS_ECDHE_ECDSA_WITH_RC4_128_SHA" },
    { 0xc008, "TLS_ECDHE_ECDSA_WITH_3DES_EDE_CBC_SHA" },
    { 0xc009, "TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA" },
    { 0xc00a, "TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA" },
    { 0xc00b, "TLS_ECDH_RSA_WITH_NULL_SHA" },
    { 0xc00c, "TLS_ECDH_RSA_WITH_RC4_128_SHA" },
    { 0xc00d, "TLS_ECDH_RSA_WITH_3DES_EDE_CBC_SHA" },
    { 0xc00e, "TLS_ECDH_RSA_WITH_AES_128_CBC_SHA" },
    { 0xc00f, "TLS_ECDH_RSA_WITH_AES_256_CBC_SHA" },
    { 0xc010, "TLS_ECDHE_RSA_WITH_NULL_SHA" },
    { 0xc011, "TLS_ECDHE_RSA_WITH_RC4_128_SHA" },
    { 0xc012, "TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA" },
    { 0xc013, "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA" },
    { 0xc014, "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA" },
    { 0xc015, "TLS_ECDH_anon_WITH_NULL_SHA" },
    { 0xc016, "TLS_ECDH_anon_WITH_RC4_128_SHA" },
    { 0xc017, "TLS_ECDH_anon_WITH_3DES_EDE_CBC_SHA" },
    { 0xc018, "TLS_ECDH_anon_WITH_AES_128_CBC_SHA" },
    { 0xc019, "TLS_ECDH_anon_WITH_AES_256_CBC_SHA" },
    /* RFC 5054 */
    { 0xC01A, "TLS_SRP_SHA_WITH_3DES_EDE_CBC_SHA" },
    { 0xC01B, "TLS_SRP_SHA_RSA_WITH_3DES_EDE_CBC_SHA" },
    { 0xC01C, "TLS_SRP_SHA_DSS_WITH_3DES_EDE_CBC_SHA" },
    { 0xC01D, "TLS_SRP_SHA_WITH_AES_128_CBC_SHA" },
    { 0xC01E, "TLS_SRP_SHA_RSA_WITH_AES_128_CBC_SHA" },
    { 0xC01F, "TLS_SRP_SHA_DSS_WITH_AES_128_CBC_SHA" },
    { 0xC020, "TLS_SRP_SHA_WITH_AES_256_CBC_SHA" },
    { 0xC021, "TLS_SRP_SHA_RSA_WITH_AES_256_CBC_SHA" },
    { 0xC022, "TLS_SRP_SHA_DSS_WITH_AES_256_CBC_SHA" },
    /* RFC 5589 */
    { 0xC023, "TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256" },
    { 0xC024, "TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384" },
    { 0xC025, "TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA256" },
    { 0xC026, "TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA384" },
    { 0xC027, "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256" },
    { 0xC028, "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384" },
    { 0xC029, "TLS_ECDH_RSA_WITH_AES_128_CBC_SHA256" },
    { 0xC02A, "TLS_ECDH_RSA_WITH_AES_256_CBC_SHA384" },
    { 0xC02B, "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256" },
    { 0xC02C, "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384" },
    { 0xC02D, "TLS_ECDH_ECDSA_WITH_AES_128_GCM_SHA256" },
    { 0xC02E, "TLS_ECDH_ECDSA_WITH_AES_256_GCM_SHA384" },
    { 0xC02F, "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256" },
    { 0xC030, "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384" },
    { 0xC031, "TLS_ECDH_RSA_WITH_AES_128_GCM_SHA256" },
    { 0xC032, "TLS_ECDH_RSA_WITH_AES_256_GCM_SHA384" },
    /* RFC 5489 */
    { 0xC033, "TLS_ECDHE_PSK_WITH_RC4_128_SHA" },
    { 0xC034, "TLS_ECDHE_PSK_WITH_3DES_EDE_CBC_SHA" },
    { 0xC035, "TLS_ECDHE_PSK_WITH_AES_128_CBC_SHA" },
    { 0xC036, "TLS_ECDHE_PSK_WITH_AES_256_CBC_SHA" },
    { 0xC037, "TLS_ECDHE_PSK_WITH_AES_128_CBC_SHA256" },
    { 0xC038, "TLS_ECDHE_PSK_WITH_AES_256_CBC_SHA384" },
    { 0xC039, "TLS_ECDHE_PSK_WITH_NULL_SHA" },
    { 0xC03A, "TLS_ECDHE_PSK_WITH_NULL_SHA256" },
    { 0xC03B, "TLS_ECDHE_PSK_WITH_NULL_SHA384" },
    /* RFC 6209 */
    { 0xC03C, "TLS_RSA_WITH_ARIA_128_CBC_SHA256" },
    { 0xC03D, "TLS_RSA_WITH_ARIA_256_CBC_SHA384" },
    { 0xC03E, "TLS_DH_DSS_WITH_ARIA_128_CBC_SHA256" },
    { 0xC03F, "TLS_DH_DSS_WITH_ARIA_256_CBC_SHA384" },
    { 0xC040, "TLS_DH_RSA_WITH_ARIA_128_CBC_SHA256" },
    { 0xC041, "TLS_DH_RSA_WITH_ARIA_256_CBC_SHA384" },
    { 0xC042, "TLS_DHE_DSS_WITH_ARIA_128_CBC_SHA256" },
    { 0xC043, "TLS_DHE_DSS_WITH_ARIA_256_CBC_SHA384" },
    { 0xC044, "TLS_DHE_RSA_WITH_ARIA_128_CBC_SHA256" },
    { 0xC045, "TLS_DHE_RSA_WITH_ARIA_256_CBC_SHA384" },
    { 0xC046, "TLS_DH_anon_WITH_ARIA_128_CBC_SHA256" },
    { 0xC047, "TLS_DH_anon_WITH_ARIA_256_CBC_SHA384" },
    { 0xC048, "TLS_ECDHE_ECDSA_WITH_ARIA_128_CBC_SHA256" },
    { 0xC049, "TLS_ECDHE_ECDSA_WITH_ARIA_256_CBC_SHA384" },
    { 0xC04A, "TLS_ECDH_ECDSA_WITH_ARIA_128_CBC_SHA256" },
    { 0xC04B, "TLS_ECDH_ECDSA_WITH_ARIA_256_CBC_SHA384" },
    { 0xC04C, "TLS_ECDHE_RSA_WITH_ARIA_128_CBC_SHA256" },
    { 0xC04D, "TLS_ECDHE_RSA_WITH_ARIA_256_CBC_SHA384" },
    { 0xC04E, "TLS_ECDH_RSA_WITH_ARIA_128_CBC_SHA256" },
    { 0xC04F, "TLS_ECDH_RSA_WITH_ARIA_256_CBC_SHA384" },
    { 0xC050, "TLS_RSA_WITH_ARIA_128_GCM_SHA256" },
    { 0xC051, "TLS_RSA_WITH_ARIA_256_GCM_SHA384" },
    { 0xC052, "TLS_DHE_RSA_WITH_ARIA_128_GCM_SHA256" },
    { 0xC053, "TLS_DHE_RSA_WITH_ARIA_256_GCM_SHA384" },
    { 0xC054, "TLS_DH_RSA_WITH_ARIA_128_GCM_SHA256" },
    { 0xC055, "TLS_DH_RSA_WITH_ARIA_256_GCM_SHA384" },
    { 0xC056, "TLS_DHE_DSS_WITH_ARIA_128_GCM_SHA256" },
    { 0xC057, "TLS_DHE_DSS_WITH_ARIA_256_GCM_SHA384" },
    { 0xC058, "TLS_DH_DSS_WITH_ARIA_128_GCM_SHA256" },
    { 0xC059, "TLS_DH_DSS_WITH_ARIA_256_GCM_SHA384" },
    { 0xC05A, "TLS_DH_anon_WITH_ARIA_128_GCM_SHA256" },
    { 0xC05B, "TLS_DH_anon_WITH_ARIA_256_GCM_SHA384" },
    { 0xC05C, "TLS_ECDHE_ECDSA_WITH_ARIA_128_GCM_SHA256" },
    { 0xC05D, "TLS_ECDHE_ECDSA_WITH_ARIA_256_GCM_SHA384" },
    { 0xC05E, "TLS_ECDH_ECDSA_WITH_ARIA_128_GCM_SHA256" },
    { 0xC05F, "TLS_ECDH_ECDSA_WITH_ARIA_256_GCM_SHA384" },
    { 0xC060, "TLS_ECDHE_RSA_WITH_ARIA_128_GCM_SHA256" },
    { 0xC061, "TLS_ECDHE_RSA_WITH_ARIA_256_GCM_SHA384" },
    { 0xC062, "TLS_ECDH_RSA_WITH_ARIA_128_GCM_SHA256" },
    { 0xC063, "TLS_ECDH_RSA_WITH_ARIA_256_GCM_SHA384" },
    { 0xC064, "TLS_PSK_WITH_ARIA_128_CBC_SHA256" },
    { 0xC065, "TLS_PSK_WITH_ARIA_256_CBC_SHA384" },
    { 0xC066, "TLS_DHE_PSK_WITH_ARIA_128_CBC_SHA256" },
    { 0xC067, "TLS_DHE_PSK_WITH_ARIA_256_CBC_SHA384" },
    { 0xC068, "TLS_RSA_PSK_WITH_ARIA_128_CBC_SHA256" },
    { 0xC069, "TLS_RSA_PSK_WITH_ARIA_256_CBC_SHA384" },
    { 0xC06A, "TLS_PSK_WITH_ARIA_128_GCM_SHA256" },
    { 0xC06B, "TLS_PSK_WITH_ARIA_256_GCM_SHA384" },
    { 0xC06C, "TLS_DHE_PSK_WITH_ARIA_128_GCM_SHA256" },
    { 0xC06D, "TLS_DHE_PSK_WITH_ARIA_256_GCM_SHA384" },
    { 0xC06E, "TLS_RSA_PSK_WITH_ARIA_128_GCM_SHA256" },
    { 0xC06F, "TLS_RSA_PSK_WITH_ARIA_256_GCM_SHA384" },
    { 0xC070, "TLS_ECDHE_PSK_WITH_ARIA_128_CBC_SHA256" },
    { 0xC071, "TLS_ECDHE_PSK_WITH_ARIA_256_CBC_SHA384" },
    /* RFC 6367 */
    { 0xC072, "TLS_ECDHE_ECDSA_WITH_CAMELLIA_128_CBC_SHA256" },
    { 0xC073, "TLS_ECDHE_ECDSA_WITH_CAMELLIA_256_CBC_SHA384" },
    { 0xC074, "TLS_ECDH_ECDSA_WITH_CAMELLIA_128_CBC_SHA256" },
    { 0xC075, "TLS_ECDH_ECDSA_WITH_CAMELLIA_256_CBC_SHA384" },
    { 0xC076, "TLS_ECDHE_RSA_WITH_CAMELLIA_128_CBC_SHA256" },
    { 0xC077, "TLS_ECDHE_RSA_WITH_CAMELLIA_256_CBC_SHA384" },
    { 0xC078, "TLS_ECDH_RSA_WITH_CAMELLIA_128_CBC_SHA256" },
    { 0xC079, "TLS_ECDH_RSA_WITH_CAMELLIA_256_CBC_SHA384" },
    { 0xC07A, "TLS_RSA_WITH_CAMELLIA_128_GCM_SHA256" },
    { 0xC07B, "TLS_RSA_WITH_CAMELLIA_256_GCM_SHA384" },
    { 0xC07C, "TLS_DHE_RSA_WITH_CAMELLIA_128_GCM_SHA256" },
    { 0xC07D, "TLS_DHE_RSA_WITH_CAMELLIA_256_GCM_SHA384" },
    { 0xC07E, "TLS_DH_RSA_WITH_CAMELLIA_128_GCM_SHA256" },
    { 0xC07F, "TLS_DH_RSA_WITH_CAMELLIA_256_GCM_SHA384" },
    { 0xC080, "TLS_DHE_DSS_WITH_CAMELLIA_128_GCM_SHA256" },
    { 0xC081, "TLS_DHE_DSS_WITH_CAMELLIA_256_GCM_SHA384" },
    { 0xC082, "TLS_DH_DSS_WITH_CAMELLIA_128_GCM_SHA256" },
    { 0xC083, "TLS_DH_DSS_WITH_CAMELLIA_256_GCM_SHA384" },
    { 0xC084, "TLS_DH_anon_WITH_CAMELLIA_128_GCM_SHA256" },
    { 0xC085, "TLS_DH_anon_WITH_CAMELLIA_256_GCM_SHA384" },
    { 0xC086, "TLS_ECDHE_ECDSA_WITH_CAMELLIA_128_GCM_SHA256" },
    { 0xC087, "TLS_ECDHE_ECDSA_WITH_CAMELLIA_256_GCM_SHA384" },
    { 0xC088, "TLS_ECDH_ECDSA_WITH_CAMELLIA_128_GCM_SHA256" },
    { 0xC089, "TLS_ECDH_ECDSA_WITH_CAMELLIA_256_GCM_SHA384" },
    { 0xC08A, "TLS_ECDHE_RSA_WITH_CAMELLIA_128_GCM_SHA256" },
    { 0xC08B, "TLS_ECDHE_RSA_WITH_CAMELLIA_256_GCM_SHA384" },
    { 0xC08C, "TLS_ECDH_RSA_WITH_CAMELLIA_128_GCM_SHA256" },
    { 0xC08D, "TLS_ECDH_RSA_WITH_CAMELLIA_256_GCM_SHA384" },
    { 0xC08E, "TLS_PSK_WITH_CAMELLIA_128_GCM_SHA256" },
    { 0xC08F, "TLS_PSK_WITH_CAMELLIA_256_GCM_SHA384" },
    { 0xC090, "TLS_DHE_PSK_WITH_CAMELLIA_128_GCM_SHA256" },
    { 0xC091, "TLS_DHE_PSK_WITH_CAMELLIA_256_GCM_SHA384" },
    { 0xC092, "TLS_RSA_PSK_WITH_CAMELLIA_128_GCM_SHA256" },
    { 0xC093, "TLS_RSA_PSK_WITH_CAMELLIA_256_GCM_SHA384" },
    { 0xC094, "TLS_PSK_WITH_CAMELLIA_128_CBC_SHA256" },
    { 0xC095, "TLS_PSK_WITH_CAMELLIA_256_CBC_SHA384" },
    { 0xC096, "TLS_DHE_PSK_WITH_CAMELLIA_128_CBC_SHA256" },
    { 0xC097, "TLS_DHE_PSK_WITH_CAMELLIA_256_CBC_SHA384" },
    { 0xC098, "TLS_RSA_PSK_WITH_CAMELLIA_128_CBC_SHA256" },
    { 0xC099, "TLS_RSA_PSK_WITH_CAMELLIA_256_CBC_SHA384" },
    { 0xC09A, "TLS_ECDHE_PSK_WITH_CAMELLIA_128_CBC_SHA256" },
    { 0xC09B, "TLS_ECDHE_PSK_WITH_CAMELLIA_256_CBC_SHA384" },
    /* RFC 6655 */
    { 0xC09C, "TLS_RSA_WITH_AES_128_CCM" },
    { 0xC09D, "TLS_RSA_WITH_AES_256_CCM" },
    { 0xC09E, "TLS_DHE_RSA_WITH_AES_128_CCM" },
    { 0xC09F, "TLS_DHE_RSA_WITH_AES_256_CCM" },
    { 0xC0A0, "TLS_RSA_WITH_AES_128_CCM_8" },
    { 0xC0A1, "TLS_RSA_WITH_AES_256_CCM_8" },
    { 0xC0A2, "TLS_DHE_RSA_WITH_AES_128_CCM_8" },
    { 0xC0A3, "TLS_DHE_RSA_WITH_AES_256_CCM_8" },
    { 0xC0A4, "TLS_PSK_WITH_AES_128_CCM" },
    { 0xC0A5, "TLS_PSK_WITH_AES_256_CCM" },
    { 0xC0A6, "TLS_DHE_PSK_WITH_AES_128_CCM" },
    { 0xC0A7, "TLS_DHE_PSK_WITH_AES_256_CCM" },
    { 0xC0A8, "TLS_PSK_WITH_AES_128_CCM_8" },
    { 0xC0A9, "TLS_PSK_WITH_AES_256_CCM_8" },
    { 0xC0AA, "TLS_PSK_DHE_WITH_AES_128_CCM_8" },
    { 0xC0AB, "TLS_PSK_DHE_WITH_AES_256_CCM_8" },
    /* RFC 7251 */
    { 0xC0AC, "TLS_ECDHE_ECDSA_WITH_AES_128_CCM" },
    { 0xC0AD, "TLS_ECDHE_ECDSA_WITH_AES_256_CCM" },
    { 0xC0AE, "TLS_ECDHE_ECDSA_WITH_AES_128_CCM_8" },
    { 0xC0AF, "TLS_ECDHE_ECDSA_WITH_AES_256_CCM_8" },
    /* RFC 8492 */
    { 0xC0B0, "TLS_ECCPWD_WITH_AES_128_GCM_SHA256" },
    { 0xC0B1, "TLS_ECCPWD_WITH_AES_256_GCM_SHA384" },
    { 0xC0B2, "TLS_ECCPWD_WITH_AES_128_CCM_SHA256" },
    { 0xC0B3, "TLS_ECCPWD_WITH_AES_256_CCM_SHA384" },
    /* draft-camwinget-tls-ts13-macciphersuites */
    { 0xC0B4, "TLS_SHA256_SHA256" },
    { 0xC0B5, "TLS_SHA384_SHA384" },
    /* https://www.ietf.org/archive/id/draft-cragie-tls-ecjpake-01.txt */
    { 0xC0FF, "TLS_ECJPAKE_WITH_AES_128_CCM_8" },
    /* draft-smyshlyaev-tls12-gost-suites */
    { 0xC100, "TLS_GOSTR341112_256_WITH_KUZNYECHIK_CTR_OMAC" },
    { 0xC101, "TLS_GOSTR341112_256_WITH_MAGMA_CTR_OMAC" },
    { 0xC102, "TLS_GOSTR341112_256_WITH_28147_CNT_IMIT" },
    /* draft-smyshlyaev-tls13-gost-suites */
    { 0xC103, "TLS_GOSTR341112_256_WITH_KUZNYECHIK_MGM_L" },
    { 0xC104, "TLS_GOSTR341112_256_WITH_MAGMA_MGM_L" },
    { 0xC105, "TLS_GOSTR341112_256_WITH_KUZNYECHIK_MGM_S" },
    { 0xC106, "TLS_GOSTR341112_256_WITH_MAGMA_MGM_S" },
    /* RFC 8701 */
    { 0xCACA, "Reserved (GREASE)" },
/*
0xC0,0xAB-FF Unassigned
0xC1,0x03-FD,* Unassigned
0xFE,0x00-FD Unassigned
0xFE,0xFE-FF Reserved to avoid conflicts with widely deployed implementations [Pasi_Eronen]
0xFF,0x00-FF Reserved for Private Use [RFC5246]
*/
    /* old numbers used in the beginning
     * https://tools.ietf.org/html/draft-agl-tls-chacha20poly1305 */
    { 0xCC13, "TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256" },
    { 0xCC14, "TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256" },
    { 0xCC15, "TLS_DHE_RSA_WITH_CHACHA20_POLY1305_SHA256" },
    /* RFC 7905 */
    { 0xCCA8, "TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256" },
    { 0xCCA9, "TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256" },
    { 0xCCAA, "TLS_DHE_RSA_WITH_CHACHA20_POLY1305_SHA256" },
    { 0xCCAB, "TLS_PSK_WITH_CHACHA20_POLY1305_SHA256" },
    { 0xCCAC, "TLS_ECDHE_PSK_WITH_CHACHA20_POLY1305_SHA256" },
    { 0xCCAD, "TLS_DHE_PSK_WITH_CHACHA20_POLY1305_SHA256" },
    { 0xCCAE, "TLS_RSA_PSK_WITH_CHACHA20_POLY1305_SHA256" },
    /* RFC 8442 */
    { 0xD001, "TLS_ECDHE_PSK_WITH_AES_128_GCM_SHA256" },
    { 0xD002, "TLS_ECDHE_PSK_WITH_AES_256_GCM_SHA384" },
    { 0xD003, "TLS_ECDHE_PSK_WITH_AES_128_CCM_8_SHA256" },
    { 0xD005, "TLS_ECDHE_PSK_WITH_AES_128_CCM_SHA256" },
    /* RFC 8701 */
    { 0xDADA, "Reserved (GREASE)" },
    /* GM/T 0024-2014 */
    { 0xe001, "ECDHE_SM1_SM3"},
    { 0xe003, "ECC_SM1_SM3"},
    { 0xe005, "IBSDH_SM1_SM3"},
    { 0xe007, "IBC_SM1_SM3"},
    { 0xe009, "RSA_SM1_SM3"},
    { 0xe00a, "RSA_SM1_SHA1"},
    { 0xe011, "ECDHE_SM4_CBC_SM3"},
    { 0xe013, "ECC_SM4_CBC_SM3"},
    { 0xe015, "IBSDH_SM4_CBC_SM3"},
    { 0xe017, "IBC_SM4_CBC_SM3"},
    { 0xe019, "RSA_SM4_CBC_SM3"},
    { 0xe01a, "RSA_SM4_CBC_SHA1"},
    { 0xe01c, "RSA_SM4_CBC_SHA256"},
    { 0xe051, "ECDHE_SM4_GCM_SM3"},
    { 0xe053, "ECC_SM4_GCM_SM3"},
    { 0xe055, "IBSDH_SM4_GCM_SM3"},
    { 0xe057, "IBC_SM4_GCM_SM3"},
    { 0xe059, "RSA_SM4_GCM_SM3"},
    { 0xe05a, "RSA_SM4_GCM_SHA256"},
    /* https://tools.ietf.org/html/draft-josefsson-salsa20-tls */
    { 0xE410, "TLS_RSA_WITH_ESTREAM_SALSA20_SHA1" },
    { 0xE411, "TLS_RSA_WITH_SALSA20_SHA1" },
    { 0xE412, "TLS_ECDHE_RSA_WITH_ESTREAM_SALSA20_SHA1" },
    { 0xE413, "TLS_ECDHE_RSA_WITH_SALSA20_SHA1" },
    { 0xE414, "TLS_ECDHE_ECDSA_WITH_ESTREAM_SALSA20_SHA1" },
    { 0xE415, "TLS_ECDHE_ECDSA_WITH_SALSA20_SHA1" },
    { 0xE416, "TLS_PSK_WITH_ESTREAM_SALSA20_SHA1" },
    { 0xE417, "TLS_PSK_WITH_SALSA20_SHA1" },
    { 0xE418, "TLS_ECDHE_PSK_WITH_ESTREAM_SALSA20_SHA1" },
    { 0xE419, "TLS_ECDHE_PSK_WITH_SALSA20_SHA1" },
    { 0xE41A, "TLS_RSA_PSK_WITH_ESTREAM_SALSA20_SHA1" },
    { 0xE41B, "TLS_RSA_PSK_WITH_SALSA20_SHA1" },
    { 0xE41C, "TLS_DHE_PSK_WITH_ESTREAM_SALSA20_SHA1" },
    { 0xE41D, "TLS_DHE_PSK_WITH_SALSA20_SHA1" },
    { 0xE41E, "TLS_DHE_RSA_WITH_ESTREAM_SALSA20_SHA1" },
    { 0xE41F, "TLS_DHE_RSA_WITH_SALSA20_SHA1" },
    /* RFC 8701 */
    { 0xEAEA, "Reserved (GREASE)" },
    { 0xFAFA, "Reserved (GREASE)" },
    /* these from http://www.mozilla.org/projects/
         security/pki/nss/ssl/fips-ssl-ciphersuites.html */
    { 0xfefe, "SSL_RSA_FIPS_WITH_DES_CBC_SHA"},
    { 0xfeff, "SSL_RSA_FIPS_WITH_3DES_EDE_CBC_SHA" },
    { 0xffe0, "SSL_RSA_FIPS_WITH_3DES_EDE_CBC_SHA" },
    { 0xffe1, "SSL_RSA_FIPS_WITH_DES_CBC_SHA" },
    /* note that ciphersuites 0xff00 - 0xffff are private */
    { 0x00, NULL }
};

value_string_ext ssl_31_ciphersuite_ext = VALUE_STRING_EXT_INIT(ssl_31_ciphersuite);

/* http://www.iana.org/assignments/tls-extensiontype-values/tls-extensiontype-values.xhtml#tls-extensiontype-values-1 */
const value_string tls_hello_extension_types[] = {
    { SSL_HND_HELLO_EXT_SERVER_NAME, "server_name" }, /* RFC 6066 */
    { SSL_HND_HELLO_EXT_MAX_FRAGMENT_LENGTH, "max_fragment_length" },/* RFC 6066 */
    { SSL_HND_HELLO_EXT_CLIENT_CERTIFICATE_URL, "client_certificate_url" }, /* RFC 6066 */
    { SSL_HND_HELLO_EXT_TRUSTED_CA_KEYS, "trusted_ca_keys" }, /* RFC 6066 */
    { SSL_HND_HELLO_EXT_TRUNCATED_HMAC, "truncated_hmac" }, /* RFC 6066 */
    { SSL_HND_HELLO_EXT_STATUS_REQUEST, "status_request" }, /* RFC 6066 */
    { SSL_HND_HELLO_EXT_USER_MAPPING, "user_mapping" }, /* RFC 4681 */
    { SSL_HND_HELLO_EXT_CLIENT_AUTHZ, "client_authz" }, /* RFC 5878 */
    { SSL_HND_HELLO_EXT_SERVER_AUTHZ, "server_authz" }, /* RFC 5878 */
    { SSL_HND_HELLO_EXT_CERT_TYPE, "cert_type" }, /* RFC 6091 */
    { SSL_HND_HELLO_EXT_SUPPORTED_GROUPS, "supported_groups" }, /* RFC 4492, RFC 7919 */
    { SSL_HND_HELLO_EXT_EC_POINT_FORMATS, "ec_point_formats" }, /* RFC 4492 */
    { SSL_HND_HELLO_EXT_SRP, "srp" }, /* RFC 5054 */
    { SSL_HND_HELLO_EXT_SIGNATURE_ALGORITHMS, "signature_algorithms" }, /* RFC 5246 */
    { SSL_HND_HELLO_EXT_USE_SRTP, "use_srtp" }, /* RFC 5764 */
    { SSL_HND_HELLO_EXT_HEARTBEAT, "heartbeat" }, /* RFC 6520 */
    { SSL_HND_HELLO_EXT_ALPN, "application_layer_protocol_negotiation" }, /* RFC 7301 */
    { SSL_HND_HELLO_EXT_STATUS_REQUEST_V2, "status_request_v2" }, /* RFC 6961 */
    { SSL_HND_HELLO_EXT_SIGNED_CERTIFICATE_TIMESTAMP, "signed_certificate_timestamp" }, /* RFC 6962 */
    { SSL_HND_HELLO_EXT_CLIENT_CERT_TYPE, "client_certificate_type" }, /* RFC 7250 */
    { SSL_HND_HELLO_EXT_SERVER_CERT_TYPE, "server_certificate_type" }, /* RFC 7250 */
    { SSL_HND_HELLO_EXT_PADDING, "padding" }, /* RFC 7685 */
    { SSL_HND_HELLO_EXT_ENCRYPT_THEN_MAC, "encrypt_then_mac" }, /* RFC 7366 */
    { SSL_HND_HELLO_EXT_EXTENDED_MASTER_SECRET, "extended_master_secret" }, /* RFC 7627 */
    { SSL_HND_HELLO_EXT_TOKEN_BINDING, "token_binding" }, /* https://tools.ietf.org/html/draft-ietf-tokbind-negotiation */
    { SSL_HND_HELLO_EXT_CACHED_INFO, "cached_info" }, /* RFC 7924 */
    { SSL_HND_HELLO_EXT_COMPRESS_CERTIFICATE, "compress_certificate" }, /* https://tools.ietf.org/html/draft-ietf-tls-certificate-compression-03 */
    { SSL_HND_HELLO_EXT_RECORD_SIZE_LIMIT, "record_size_limit" }, /* RFC 8449 */
    { SSL_HND_HELLO_EXT_DELEGATED_CREDENTIALS, "delegated_credentials" }, /* draft-ietf-tls-subcerts-10.txt */
    { SSL_HND_HELLO_EXT_SESSION_TICKET_TLS, "session_ticket" }, /* RFC 5077 / RFC 8447 */
    { SSL_HND_HELLO_EXT_KEY_SHARE_OLD, "Reserved (key_share)" }, /* https://tools.ietf.org/html/draft-ietf-tls-tls13-22 (removed in -23) */
    { SSL_HND_HELLO_EXT_PRE_SHARED_KEY, "pre_shared_key" }, /* RFC 8446 */
    { SSL_HND_HELLO_EXT_EARLY_DATA, "early_data" }, /* RFC 8446 */
    { SSL_HND_HELLO_EXT_SUPPORTED_VERSIONS, "supported_versions" }, /* RFC 8446 */
    { SSL_HND_HELLO_EXT_COOKIE, "cookie" }, /* RFC 8446 */
    { SSL_HND_HELLO_EXT_PSK_KEY_EXCHANGE_MODES, "psk_key_exchange_modes" }, /* RFC 8446 */
    { SSL_HND_HELLO_EXT_TICKET_EARLY_DATA_INFO, "Reserved (ticket_early_data_info)" }, /* draft-ietf-tls-tls13-18 (removed in -19) */
    { SSL_HND_HELLO_EXT_CERTIFICATE_AUTHORITIES, "certificate_authorities" }, /* RFC 8446 */
    { SSL_HND_HELLO_EXT_OID_FILTERS, "oid_filters" }, /* RFC 8446 */
    { SSL_HND_HELLO_EXT_POST_HANDSHAKE_AUTH, "post_handshake_auth" }, /* RFC 8446 */
    { SSL_HND_HELLO_EXT_SIGNATURE_ALGORITHMS_CERT, "signature_algorithms_cert" }, /* RFC 8446 */
    { SSL_HND_HELLO_EXT_KEY_SHARE, "key_share" }, /* RFC 8446 */
    { SSL_HND_HELLO_EXT_TRANSPARENCY_INFO, "transparency_info" }, /* draft-ietf-trans-rfc6962-bis-41 */
    { SSL_HND_HELLO_EXT_CONNECTION_ID_DEPRECATED, "connection_id (deprecated)" }, /* draft-ietf-tls-dtls-connection-id-07 */
    { SSL_HND_HELLO_EXT_CONNECTION_ID, "connection_id" }, /* RFC 9146 */
    { SSL_HND_HELLO_EXT_EXTERNAL_ID_HASH, "external_id_hash" }, /* RFC 8844 */
    { SSL_HND_HELLO_EXT_EXTERNAL_SESSION_ID, "external_session_id" }, /* RFC 8844 */
    { SSL_HND_HELLO_EXT_QUIC_TRANSPORT_PARAMETERS_V1, "quic_transport_parameters" }, /* draft-ietf-quic-tls-33 */
    { SSL_HND_HELLO_EXT_TICKET_REQUEST, "ticket_request" }, /* draft-ietf-tls-ticketrequests-07 */
    { SSL_HND_HELLO_EXT_DNSSEC_CHAIN, "dnssec_chain" }, /* RFC 9102 */
    { SSL_HND_HELLO_EXT_GREASE_0A0A, "Reserved (GREASE)" }, /* RFC 8701 */
    { SSL_HND_HELLO_EXT_GREASE_1A1A, "Reserved (GREASE)" }, /* RFC 8701 */
    { SSL_HND_HELLO_EXT_GREASE_2A2A, "Reserved (GREASE)" }, /* RFC 8701 */
    { SSL_HND_HELLO_EXT_NPN, "next_protocol_negotiation"}, /* https://tools.ietf.org/id/draft-agl-tls-nextprotoneg-03.html */
    { SSL_HND_HELLO_EXT_GREASE_3A3A, "Reserved (GREASE)" }, /* RFC 8701 */
    { SSL_HND_HELLO_EXT_ALPS, "application_settings" }, /* draft-vvv-tls-alps-01 */
    { SSL_HND_HELLO_EXT_GREASE_4A4A, "Reserved (GREASE)" }, /* RFC 8701 */
    { SSL_HND_HELLO_EXT_GREASE_5A5A, "Reserved (GREASE)" }, /* RFC 8701 */
    { SSL_HND_HELLO_EXT_GREASE_6A6A, "Reserved (GREASE)" }, /* RFC 8701 */
    { SSL_HND_HELLO_EXT_CHANNEL_ID_OLD, "channel_id_old" }, /* https://tools.ietf.org/html/draft-balfanz-tls-channelid-00
       https://twitter.com/ericlaw/status/274237352531083264 */
    { SSL_HND_HELLO_EXT_CHANNEL_ID, "channel_id" }, /* https://tools.ietf.org/html/draft-balfanz-tls-channelid-01
       https://code.google.com/p/chromium/codesearch#chromium/src/net/third_party/nss/ssl/sslt.h&l=209 */
    { SSL_HND_HELLO_EXT_RENEGOTIATION_INFO, "renegotiation_info" }, /* RFC 5746 */
    { SSL_HND_HELLO_EXT_GREASE_7A7A, "Reserved (GREASE)" }, /* RFC 8701 */
    { SSL_HND_HELLO_EXT_GREASE_8A8A, "Reserved (GREASE)" }, /* RFC 8701 */
    { SSL_HND_HELLO_EXT_GREASE_9A9A, "Reserved (GREASE)" }, /* RFC 8701 */
    { SSL_HND_HELLO_EXT_GREASE_AAAA, "Reserved (GREASE)" }, /* RFC 8701 */
    { SSL_HND_HELLO_EXT_GREASE_BABA, "Reserved (GREASE)" }, /* RFC 8701 */
    { SSL_HND_HELLO_EXT_GREASE_CACA, "Reserved (GREASE)" }, /* RFC 8701 */
    { SSL_HND_HELLO_EXT_GREASE_DADA, "Reserved (GREASE)" }, /* RFC 8701 */
    { SSL_HND_HELLO_EXT_GREASE_EAEA, "Reserved (GREASE)" }, /* RFC 8701 */
    { SSL_HND_HELLO_EXT_GREASE_FAFA, "Reserved (GREASE)" }, /* RFC 8701 */
    { SSL_HND_HELLO_EXT_QUIC_TRANSPORT_PARAMETERS, "quic_transport_parameters (drafts version)" }, /* https://tools.ietf.org/html/draft-ietf-quic-tls */
    { SSL_HND_HELLO_EXT_ENCRYPTED_SERVER_NAME, "encrypted_server_name" }, /* https://tools.ietf.org/html/draft-ietf-tls-esni-01 */
    { SSL_HND_HELLO_EXT_ENCRYPTED_CLIENT_HELLO, "encrypted_client_hello" }, /* https://datatracker.ietf.org/doc/draft-ietf-tls-esni/17/ */
    { 0, NULL }
};

const value_string tls_hello_ext_server_name_type_vs[] = {
    { 0, "host_name" },
    { 0, NULL }
};

/* RFC 6066 Section 4 */
const value_string tls_hello_ext_max_fragment_length[] = {
    { 1, "512" },  // 2^9
    { 2, "1024" }, // 2^10
    { 3, "2048" }, // 2^11
    { 4, "4096" }, // 2^12
    { 0, NULL }
};

/* RFC 8446 Section 4.2.9 */
const value_string tls_hello_ext_psk_ke_mode[] = {
    { 0, "PSK-only key establishment (psk_ke)" },
    { 1, "PSK with (EC)DHE key establishment (psk_dhe_ke)" },
    { 0, NULL }
};

const value_string tls13_key_update_request[] = {
    { 0, "update_not_requested" },
    { 1, "update_requested" },
    { 0, NULL }
};

/* RFC 5246 7.4.1.4.1 */
/* https://www.iana.org/assignments/tls-parameters/tls-parameters.xhtml */
/* Note that the TLS 1.3 SignatureScheme registry reserves all values
 * with first octet 0x00-0x06 and all values with second octet 0x00-0x03
 * for backwards compatibility with TLS 1.2 SignatureAndHashAlgorithm.
 *
 * RFC 8422 and RFC 9189 add official support in TLS 1.2 for some algorithms
 * originally defined for TLS 1.3, and extend the TLS SignatureAlgorithm
 * and TLS HashAlgorithm registries, but the new values are not compatible
 * with all of the TLS 1.3-only SignatureSchemes. Adding those values could
 * cause confusion if used to interpret one of those schemes in a
 * signature_algorithms extension offered in a TLS 1.3 ClientHello.
 */
const value_string tls_hash_algorithm[] = {
    { 0, "None" },
    { 1, "MD5" },
    { 2, "SHA1" },
    { 3, "SHA224" },
    { 4, "SHA256" },
    { 5, "SHA384" },
    { 6, "SHA512" },
#if 0
    /* RFC 8422 adds this to the HashAlgorithm registry, but it really
     * only applies to 0x0807 and 0x0808, not for other TLS 1.3
     * SignatureSchemes with 0x08 in the octet used for Hash in TLS 1.2.
     * E.g., we don't want to display this for 0x0806 rsa_pss_rsae_sha512.
     */
    { 8, "Intrinsic" },
#endif
    { 0, NULL }
};

const value_string tls_signature_algorithm[] = {
    { 0, "Anonymous" },
    { 1, "RSA" },
    { 2, "DSA" },
    { 3, "ECDSA" },
#if 0
    /* As above. */
    { 7, "ED25519" },
    { 8, "ED448" },
    { 64, "GOSTR34102012_256" },
    { 65, "GOSTR34102012_512" },
#endif
    { 0, NULL }
};

/* RFC 8446 Section 4.2.3 */
const value_string tls13_signature_algorithm[] = {
    { 0x0201, "rsa_pkcs1_sha1" },
    { 0x0203, "ecdsa_sha1" },
    { 0x0401, "rsa_pkcs1_sha256" },
    { 0x0403, "ecdsa_secp256r1_sha256" },
    { 0x0420, "rsa_pkcs1_sha256_legacy" }, /* draft-davidben-tls13-pkcs1-01 */
    { 0x0501, "rsa_pkcs1_sha384" },
    { 0x0503, "ecdsa_secp384r1_sha384" },
    { 0x0520, "rsa_pkcs1_sha384_legacy" }, /* draft-davidben-tls13-pkcs1-01 */
    { 0x0601, "rsa_pkcs1_sha512" },
    { 0x0603, "ecdsa_secp521r1_sha512" },
    { 0x0620, "rsa_pkcs1_sha512_legacy" }, /* draft-davidben-tls13-pkcs1-01 */
    { 0x0708, "sm2sig_sm3" },
    { 0x0709, "gostr34102012_256a" }, /* RFC9367 */
    { 0x070a, "gostr34102012_256b" }, /* RFC9367 */
    { 0x070b, "gostr34102012_256c" }, /* RFC9367 */
    { 0x070c, "gostr34102012_256d" }, /* RFC9367 */
    { 0x070d, "gostr34102012_512a" }, /* RFC9367 */
    { 0x070e, "gostr34102012_512b" }, /* RFC9367 */
    { 0x070f, "gostr34102012_512c" }, /* RFC9367 */
    { 0x0804, "rsa_pss_rsae_sha256" },
    { 0x0805, "rsa_pss_rsae_sha384" },
    { 0x0806, "rsa_pss_rsae_sha512" },
    { 0x0807, "ed25519" },
    { 0x0808, "ed448" },
    { 0x0809, "rsa_pss_pss_sha256" },
    { 0x080a, "rsa_pss_pss_sha384" },
    { 0x080b, "rsa_pss_pss_sha512" },
    { 0x081a, "ecdsa_brainpoolP256r1tls13_sha256" }, /* RFC8734 */
    { 0x081b, "ecdsa_brainpoolP384r1tls13_sha384" }, /* RFC8734 */
    { 0x081c, "ecdsa_brainpoolP512r1tls13_sha512" }, /* RFC8734 */
    /* PQC digital signature algorithms from OQS-OpenSSL,
        see https://github.com/open-quantum-safe/openssl/blob/OQS-OpenSSL_1_1_1-stable/oqs-template/oqs-sig-info.md */
    { 0xfea0, "dilithium2" },
    { 0xfea1, "p256_dilithium2" },
    { 0xfea2, "rsa3072_dilithium2" },
    { 0xfea3, "dilithium3" },
    { 0xfea4, "p384_dilithium3" },
    { 0xfea5, "dilithium5" },
    { 0xfea6, "p521_dilithium5" },
    { 0xfea7, "dilithium2_aes" },
    { 0xfea8, "p256_dilithium2_aes" },
    { 0xfea9, "rsa3072_dilithium2_aes" },
    { 0xfeaa, "dilithium3_aes" },
    { 0xfeab, "p384_dilithium3_aes" },
    { 0xfeac, "dilithium5_aes" },
    { 0xfead, "p521_dilithium5_aes" },
    { 0xfe0b, "falcon512" },
    { 0xfe0c, "p256_falcon512" },
    { 0xfe0d, "rsa3072_falcon512" },
    { 0xfe0e, "falcon1024" },
    { 0xfe0f, "p521_falcon1024" },
    { 0xfe96, "picnicl1full" },
    { 0xfe97, "p256_picnicl1full" },
    { 0xfe98, "rsa3072_picnicl1full" },
    { 0xfe1b, "picnic3l1" },
    { 0xfe1c, "p256_picnic3l1" },
    { 0xfe1d, "rsa3072_picnic3l1" },
    { 0xfe27, "rainbowIclassic" },
    { 0xfe28, "p256_rainbowIclassic" },
    { 0xfe29, "rsa3072_rainbowIclassic" },
    { 0xfe3c, "rainbowVclassic" },
    { 0xfe3d, "p521_rainbowVclassic" },
    { 0xfe42, "sphincsharaka128frobust" },
    { 0xfe43, "p256_sphincsharaka128frobust" },
    { 0xfe44, "rsa3072_sphincsharaka128frobust" },
    { 0xfe5e, "sphincssha256128frobust" },
    { 0xfe5f, "p256_sphincssha256128frobust" },
    { 0xfe60, "rsa3072_sphincssha256128frobust" },
    { 0xfe7a, "sphincsshake256128frobust" },
    { 0xfe7b, "p256_sphincsshake256128frobust" },
    { 0xfe7c, "rsa3072_sphincsshake256128frobust" },
    { 0, NULL }
};

/* RFC 6091 3.1 */
const value_string tls_certificate_type[] = {
    { 0, "X.509" },
    { 1, "OpenPGP" },
    { SSL_HND_CERT_TYPE_RAW_PUBLIC_KEY, "Raw Public Key" }, /* RFC 7250 */
    { 0, NULL }
};

const value_string tls_cert_chain_type[] = {
    { SSL_HND_CERT_URL_TYPE_INDIVIDUAL_CERT,    "Individual Certificates" },
    { SSL_HND_CERT_URL_TYPE_PKIPATH,            "PKI Path" },
    { 0, NULL }
};

const value_string tls_cert_status_type[] = {
    { SSL_HND_CERT_STATUS_TYPE_OCSP,            "OCSP" },
    { SSL_HND_CERT_STATUS_TYPE_OCSP_MULTI,      "OCSP Multi" },
    { 0, NULL }
};

/* Generated by tools/make-tls-ct-logids.py
 * Last-Modified Sun, 18 Aug 2024 13:38:00 GMT, 163 entries. */
static const bytes_string ct_logids[] = {
    { (const uint8_t[]){
          0xb2, 0x1e, 0x05, 0xcc, 0x8b, 0xa2, 0xcd, 0x8a, 0x20, 0x4e, 0x87,
          0x66, 0xf9, 0x2b, 0xb9, 0x8a, 0x25, 0x20, 0x67, 0x6b, 0xda, 0xfa,
          0x70, 0xe7, 0xb2, 0x49, 0x53, 0x2d, 0xef, 0x8b, 0x90, 0x5e,
      },
      32, "Google 'Argon2020' log" },
    { (const uint8_t[]){
          0xf6, 0x5c, 0x94, 0x2f, 0xd1, 0x77, 0x30, 0x22, 0x14, 0x54, 0x18,
          0x08, 0x30, 0x94, 0x56, 0x8e, 0xe3, 0x4d, 0x13, 0x19, 0x33, 0xbf,
          0xdf, 0x0c, 0x2f, 0x20, 0x0b, 0xcc, 0x4e, 0xf1, 0x64, 0xe3,
      },
      32, "Google 'Argon2021' log" },
    { (const uint8_t[]){
          0x29, 0x79, 0xbe, 0xf0, 0x9e, 0x39, 0x39, 0x21, 0xf0, 0x56, 0x73,
          0x9f, 0x63, 0xa5, 0x77, 0xe5, 0xbe, 0x57, 0x7d, 0x9c, 0x60, 0x0a,
          0xf8, 0xf9, 0x4d, 0x5d, 0x26, 0x5c, 0x25, 0x5d, 0xc7, 0x84,
      },
      32, "Google 'Argon2022' log" },
    { (const uint8_t[]){
          0xe8, 0x3e, 0xd0, 0xda, 0x3e, 0xf5, 0x06, 0x35, 0x32, 0xe7, 0x57,
          0x28, 0xbc, 0x89, 0x6b, 0xc9, 0x03, 0xd3, 0xcb, 0xd1, 0x11, 0x6b,
          0xec, 0xeb, 0x69, 0xe1, 0x77, 0x7d, 0x6d, 0x06, 0xbd, 0x6e,
      },
      32, "Google 'Argon2023' log" },
    { (const uint8_t[]){
          0xee, 0xcd, 0xd0, 0x64, 0xd5, 0xdb, 0x1a, 0xce, 0xc5, 0x5c, 0xb7,
          0x9d, 0xb4, 0xcd, 0x13, 0xa2, 0x32, 0x87, 0x46, 0x7c, 0xbc, 0xec,
          0xde, 0xc3, 0x51, 0x48, 0x59, 0x46, 0x71, 0x1f, 0xb5, 0x9b,
      },
      32, "Google 'Argon2024' log" },
    { (const uint8_t[]){
          0x4e, 0x75, 0xa3, 0x27, 0x5c, 0x9a, 0x10, 0xc3, 0x38, 0x5b, 0x6c,
          0xd4, 0xdf, 0x3f, 0x52, 0xeb, 0x1d, 0xf0, 0xe0, 0x8e, 0x1b, 0x8d,
          0x69, 0xc0, 0xb1, 0xfa, 0x64, 0xb1, 0x62, 0x9a, 0x39, 0xdf,
      },
      32, "Google 'Argon2025h1' log" },
    { (const uint8_t[]){
          0x12, 0xf1, 0x4e, 0x34, 0xbd, 0x53, 0x72, 0x4c, 0x84, 0x06, 0x19,
          0xc3, 0x8f, 0x3f, 0x7a, 0x13, 0xf8, 0xe7, 0xb5, 0x62, 0x87, 0x88,
          0x9c, 0x6d, 0x30, 0x05, 0x84, 0xeb, 0xe5, 0x86, 0x26, 0x3a,
      },
      32, "Google 'Argon2025h2' log" },
    { (const uint8_t[]){
          0x0e, 0x57, 0x94, 0xbc, 0xf3, 0xae, 0xa9, 0x3e, 0x33, 0x1b, 0x2c,
          0x99, 0x07, 0xb3, 0xf7, 0x90, 0xdf, 0x9b, 0xc2, 0x3d, 0x71, 0x32,
          0x25, 0xdd, 0x21, 0xa9, 0x25, 0xac, 0x61, 0xc5, 0x4e, 0x21,
      },
      32, "Google 'Argon2026h1' log" },
    { (const uint8_t[]){
          0xd7, 0x6d, 0x7d, 0x10, 0xd1, 0xa7, 0xf5, 0x77, 0xc2, 0xc7, 0xe9,
          0x5f, 0xd7, 0x00, 0xbf, 0xf9, 0x82, 0xc9, 0x33, 0x5a, 0x65, 0xe1,
          0xd0, 0xb3, 0x01, 0x73, 0x17, 0xc0, 0xc8, 0xc5, 0x69, 0x77,
      },
      32, "Google 'Argon2026h2' log" },
    { (const uint8_t[]){
          0x07, 0xb7, 0x5c, 0x1b, 0xe5, 0x7d, 0x68, 0xff, 0xf1, 0xb0, 0xc6,
          0x1d, 0x23, 0x15, 0xc7, 0xba, 0xe6, 0x57, 0x7c, 0x57, 0x94, 0xb7,
          0x6a, 0xee, 0xbc, 0x61, 0x3a, 0x1a, 0x69, 0xd3, 0xa2, 0x1c,
      },
      32, "Google 'Xenon2020' log" },
    { (const uint8_t[]){
          0x7d, 0x3e, 0xf2, 0xf8, 0x8f, 0xff, 0x88, 0x55, 0x68, 0x24, 0xc2,
          0xc0, 0xca, 0x9e, 0x52, 0x89, 0x79, 0x2b, 0xc5, 0x0e, 0x78, 0x09,
          0x7f, 0x2e, 0x6a, 0x97, 0x68, 0x99, 0x7e, 0x22, 0xf0, 0xd7,
      },
      32, "Google 'Xenon2021' log" },
    { (const uint8_t[]){
          0x46, 0xa5, 0x55, 0xeb, 0x75, 0xfa, 0x91, 0x20, 0x30, 0xb5, 0xa2,
          0x89, 0x69, 0xf4, 0xf3, 0x7d, 0x11, 0x2c, 0x41, 0x74, 0xbe, 0xfd,
          0x49, 0xb8, 0x85, 0xab, 0xf2, 0xfc, 0x70, 0xfe, 0x6d, 0x47,
      },
      32, "Google 'Xenon2022' log" },
    { (const uint8_t[]){
          0xad, 0xf7, 0xbe, 0xfa, 0x7c, 0xff, 0x10, 0xc8, 0x8b, 0x9d, 0x3d,
          0x9c, 0x1e, 0x3e, 0x18, 0x6a, 0xb4, 0x67, 0x29, 0x5d, 0xcf, 0xb1,
          0x0c, 0x24, 0xca, 0x85, 0x86, 0x34, 0xeb, 0xdc, 0x82, 0x8a,
      },
      32, "Google 'Xenon2023' log" },
    { (const uint8_t[]){
          0x76, 0xff, 0x88, 0x3f, 0x0a, 0xb6, 0xfb, 0x95, 0x51, 0xc2, 0x61,
          0xcc, 0xf5, 0x87, 0xba, 0x34, 0xb4, 0xa4, 0xcd, 0xbb, 0x29, 0xdc,
          0x68, 0x42, 0x0a, 0x9f, 0xe6, 0x67, 0x4c, 0x5a, 0x3a, 0x74,
      },
      32, "Google 'Xenon2024' log" },
    { (const uint8_t[]){
          0xcf, 0x11, 0x56, 0xee, 0xd5, 0x2e, 0x7c, 0xaf, 0xf3, 0x87, 0x5b,
          0xd9, 0x69, 0x2e, 0x9b, 0xe9, 0x1a, 0x71, 0x67, 0x4a, 0xb0, 0x17,
          0xec, 0xac, 0x01, 0xd2, 0x5b, 0x77, 0xce, 0xcc, 0x3b, 0x08,
      },
      32, "Google 'Xenon2025h1' log" },
    { (const uint8_t[]){
          0xdd, 0xdc, 0xca, 0x34, 0x95, 0xd7, 0xe1, 0x16, 0x05, 0xe7, 0x95,
          0x32, 0xfa, 0xc7, 0x9f, 0xf8, 0x3d, 0x1c, 0x50, 0xdf, 0xdb, 0x00,
          0x3a, 0x14, 0x12, 0x76, 0x0a, 0x2c, 0xac, 0xbb, 0xc8, 0x2a,
      },
      32, "Google 'Xenon2025h2' log" },
    { (const uint8_t[]){
          0x96, 0x97, 0x64, 0xbf, 0x55, 0x58, 0x97, 0xad, 0xf7, 0x43, 0x87,
          0x68, 0x37, 0x08, 0x42, 0x77, 0xe9, 0xf0, 0x3a, 0xd5, 0xf6, 0xa4,
          0xf3, 0x36, 0x6e, 0x46, 0xa4, 0x3f, 0x0f, 0xca, 0xa9, 0xc6,
      },
      32, "Google 'Xenon2026h1' log" },
    { (const uint8_t[]){
          0xd8, 0x09, 0x55, 0x3b, 0x94, 0x4f, 0x7a, 0xff, 0xc8, 0x16, 0x19,
          0x6f, 0x94, 0x4f, 0x85, 0xab, 0xb0, 0xf8, 0xfc, 0x5e, 0x87, 0x55,
          0x26, 0x0f, 0x15, 0xd1, 0x2e, 0x72, 0xbb, 0x45, 0x4b, 0x14,
      },
      32, "Google 'Xenon2026h2' log" },
    { (const uint8_t[]){
          0x68, 0xf6, 0x98, 0xf8, 0x1f, 0x64, 0x82, 0xbe, 0x3a, 0x8c, 0xee,
          0xb9, 0x28, 0x1d, 0x4c, 0xfc, 0x71, 0x51, 0x5d, 0x67, 0x93, 0xd4,
          0x44, 0xd1, 0x0a, 0x67, 0xac, 0xbb, 0x4f, 0x4f, 0xfb, 0xc4,
      },
      32, "Google 'Aviator' log" },
    { (const uint8_t[]){
          0x29, 0x3c, 0x51, 0x96, 0x54, 0xc8, 0x39, 0x65, 0xba, 0xaa, 0x50,
          0xfc, 0x58, 0x07, 0xd4, 0xb7, 0x6f, 0xbf, 0x58, 0x7a, 0x29, 0x72,
          0xdc, 0xa4, 0xc3, 0x0c, 0xf4, 0xe5, 0x45, 0x47, 0xf4, 0x78,
      },
      32, "Google 'Icarus' log" },
    { (const uint8_t[]){
          0xa4, 0xb9, 0x09, 0x90, 0xb4, 0x18, 0x58, 0x14, 0x87, 0xbb, 0x13,
          0xa2, 0xcc, 0x67, 0x70, 0x0a, 0x3c, 0x35, 0x98, 0x04, 0xf9, 0x1b,
          0xdf, 0xb8, 0xe3, 0x77, 0xcd, 0x0e, 0xc8, 0x0d, 0xdc, 0x10,
      },
      32, "Google 'Pilot' log" },
    { (const uint8_t[]){
          0xee, 0x4b, 0xbd, 0xb7, 0x75, 0xce, 0x60, 0xba, 0xe1, 0x42, 0x69,
          0x1f, 0xab, 0xe1, 0x9e, 0x66, 0xa3, 0x0f, 0x7e, 0x5f, 0xb0, 0x72,
          0xd8, 0x83, 0x00, 0xc4, 0x7b, 0x89, 0x7a, 0xa8, 0xfd, 0xcb,
      },
      32, "Google 'Rocketeer' log" },
    { (const uint8_t[]){
          0xbb, 0xd9, 0xdf, 0xbc, 0x1f, 0x8a, 0x71, 0xb5, 0x93, 0x94, 0x23,
          0x97, 0xaa, 0x92, 0x7b, 0x47, 0x38, 0x57, 0x95, 0x0a, 0xab, 0x52,
          0xe8, 0x1a, 0x90, 0x96, 0x64, 0x36, 0x8e, 0x1e, 0xd1, 0x85,
      },
      32, "Google 'Skydiver' log" },
    { (const uint8_t[]){
          0xfa, 0xd4, 0xc9, 0x7c, 0xc4, 0x9e, 0xe2, 0xf8, 0xac, 0x85, 0xc5,
          0xea, 0x5c, 0xea, 0x09, 0xd0, 0x22, 0x0d, 0xbb, 0xf4, 0xe4, 0x9c,
          0x6b, 0x50, 0x66, 0x2f, 0xf8, 0x68, 0xf8, 0x6b, 0x8c, 0x28,
      },
      32, "Google 'Argon2017' log" },
    { (const uint8_t[]){
          0xa4, 0x50, 0x12, 0x69, 0x05, 0x5a, 0x15, 0x54, 0x5e, 0x62, 0x11,
          0xab, 0x37, 0xbc, 0x10, 0x3f, 0x62, 0xae, 0x55, 0x76, 0xa4, 0x5e,
          0x4b, 0x17, 0x14, 0x45, 0x3e, 0x1b, 0x22, 0x10, 0x6a, 0x25,
      },
      32, "Google 'Argon2018' log" },
    { (const uint8_t[]){
          0x63, 0xf2, 0xdb, 0xcd, 0xe8, 0x3b, 0xcc, 0x2c, 0xcf, 0x0b, 0x72,
          0x84, 0x27, 0x57, 0x6b, 0x33, 0xa4, 0x8d, 0x61, 0x77, 0x8f, 0xbd,
          0x75, 0xa6, 0x38, 0xb1, 0xc7, 0x68, 0x54, 0x4b, 0xd8, 0x8d,
      },
      32, "Google 'Argon2019' log" },
    { (const uint8_t[]){
          0xb1, 0x0c, 0xd5, 0x59, 0xa6, 0xd6, 0x78, 0x46, 0x81, 0x1f, 0x7d,
          0xf9, 0xa5, 0x15, 0x32, 0x73, 0x9a, 0xc4, 0x8d, 0x70, 0x3b, 0xea,
          0x03, 0x23, 0xda, 0x5d, 0x38, 0x75, 0x5b, 0xc0, 0xad, 0x4e,
      },
      32, "Google 'Xenon2018' log" },
    { (const uint8_t[]){
          0x08, 0x41, 0x14, 0x98, 0x00, 0x71, 0x53, 0x2c, 0x16, 0x19, 0x04,
          0x60, 0xbc, 0xfc, 0x47, 0xfd, 0xc2, 0x65, 0x3a, 0xfa, 0x29, 0x2c,
          0x72, 0xb3, 0x7f, 0xf8, 0x63, 0xae, 0x29, 0xcc, 0xc9, 0xf0,
      },
      32, "Google 'Xenon2019' log" },
    { (const uint8_t[]){
          0xa8, 0x99, 0xd8, 0x78, 0x0c, 0x92, 0x90, 0xaa, 0xf4, 0x62, 0xf3,
          0x18, 0x80, 0xcc, 0xfb, 0xd5, 0x24, 0x51, 0xe9, 0x70, 0xd0, 0xfb,
          0xf5, 0x91, 0xef, 0x75, 0xb0, 0xd9, 0x9b, 0x64, 0x56, 0x81,
      },
      32, "Google 'Submariner' log" },
    { (const uint8_t[]){
          0x1d, 0x02, 0x4b, 0x8e, 0xb1, 0x49, 0x8b, 0x34, 0x4d, 0xfd, 0x87,
          0xea, 0x3e, 0xfc, 0x09, 0x96, 0xf7, 0x50, 0x6f, 0x23, 0x5d, 0x1d,
          0x49, 0x70, 0x61, 0xa4, 0x77, 0x3c, 0x43, 0x9c, 0x25, 0xfb,
      },
      32, "Google 'Daedalus' log" },
    { (const uint8_t[]){
          0xb0, 0xcc, 0x83, 0xe5, 0xa5, 0xf9, 0x7d, 0x6b, 0xaf, 0x7c, 0x09,
          0xcc, 0x28, 0x49, 0x04, 0x87, 0x2a, 0xc7, 0xe8, 0x8b, 0x13, 0x2c,
          0x63, 0x50, 0xb7, 0xc6, 0xfd, 0x26, 0xe1, 0x6c, 0x6c, 0x77,
      },
      32, "Google 'Testtube' log" },
    { (const uint8_t[]){
          0xc3, 0xbf, 0x03, 0xa7, 0xe1, 0xca, 0x88, 0x41, 0xc6, 0x07, 0xba,
          0xe3, 0xff, 0x42, 0x70, 0xfc, 0xa5, 0xec, 0x45, 0xb1, 0x86, 0xeb,
          0xbe, 0x4e, 0x2c, 0xf3, 0xfc, 0x77, 0x86, 0x30, 0xf5, 0xf6,
      },
      32, "Google 'Crucible' log" },
    { (const uint8_t[]){
          0x52, 0xeb, 0x4b, 0x22, 0x5e, 0xc8, 0x96, 0x97, 0x48, 0x50, 0x67,
          0x5f, 0x23, 0xe4, 0x3b, 0xc1, 0xd0, 0x21, 0xe3, 0x21, 0x4c, 0xe5,
          0x2e, 0xcd, 0x5f, 0xa8, 0x7c, 0x20, 0x3c, 0xdf, 0xca, 0x03,
      },
      32, "Google 'Solera2018' log" },
    { (const uint8_t[]){
          0x0b, 0x76, 0x0e, 0x9a, 0x8b, 0x9a, 0x68, 0x2f, 0x88, 0x98, 0x5b,
          0x15, 0xe9, 0x47, 0x50, 0x1a, 0x56, 0x44, 0x6b, 0xba, 0x88, 0x30,
          0x78, 0x5c, 0x38, 0x42, 0x99, 0x43, 0x86, 0x45, 0x0c, 0x00,
      },
      32, "Google 'Solera2019' log" },
    { (const uint8_t[]){
          0x1f, 0xc7, 0x2c, 0xe5, 0xa1, 0xb7, 0x99, 0xf4, 0x00, 0xc3, 0x59,
          0xbf, 0xf9, 0x6c, 0xa3, 0x91, 0x35, 0x48, 0xe8, 0x64, 0x42, 0x20,
          0x61, 0x09, 0x52, 0xe9, 0xba, 0x17, 0x74, 0xf7, 0xba, 0xc7,
      },
      32, "Google 'Solera2020' log" },
    { (const uint8_t[]){
          0xa3, 0xc9, 0x98, 0x45, 0xe8, 0x0a, 0xb7, 0xce, 0x00, 0x15, 0x7b,
          0x37, 0x42, 0xdf, 0x02, 0x07, 0xdd, 0x27, 0x2b, 0x2b, 0x60, 0x2e,
          0xcf, 0x98, 0xee, 0x2c, 0x12, 0xdb, 0x9c, 0x5a, 0xe7, 0xe7,
      },
      32, "Google 'Solera2021' log" },
    { (const uint8_t[]){
          0x69, 0x7a, 0xaf, 0xca, 0x1a, 0x6b, 0x53, 0x6f, 0xae, 0x21, 0x20,
          0x50, 0x46, 0xde, 0xba, 0xd7, 0xe0, 0xea, 0xea, 0x13, 0xd2, 0x43,
          0x2e, 0x6e, 0x9d, 0x8f, 0xb3, 0x79, 0xf2, 0xb9, 0xaa, 0xf3,
      },
      32, "Google 'Solera2022' log" },
    { (const uint8_t[]){
          0xf9, 0x7e, 0x97, 0xb8, 0xd3, 0x3e, 0xf7, 0xa1, 0x59, 0x02, 0xa5,
          0x3a, 0x19, 0xe1, 0x79, 0x90, 0xe5, 0xdc, 0x40, 0x6a, 0x03, 0x18,
          0x25, 0xba, 0xad, 0x93, 0xe9, 0x8f, 0x9b, 0x9c, 0x69, 0xcb,
      },
      32, "Google 'Solera2023' log" },
    { (const uint8_t[]){
          0x30, 0x24, 0xce, 0x7e, 0xeb, 0x16, 0x88, 0x62, 0x72, 0x4b, 0xea,
          0x70, 0x2e, 0xff, 0xf9, 0x92, 0xcf, 0xe4, 0x56, 0x43, 0x41, 0x91,
          0xaa, 0x59, 0x5b, 0x25, 0xf8, 0x02, 0x26, 0xc8, 0x00, 0x17,
      },
      32, "Google 'Solera2024' log" },
    { (const uint8_t[]){
          0x3f, 0xe1, 0xcb, 0x46, 0xed, 0x47, 0x35, 0x79, 0xaf, 0x01, 0x41,
          0xf9, 0x72, 0x4d, 0x9d, 0xc4, 0x43, 0x47, 0x2d, 0x75, 0x6e, 0x85,
          0xe7, 0x71, 0x9c, 0x55, 0x82, 0x48, 0x5d, 0xd4, 0xe1, 0xe4,
      },
      32, "Google 'Solera2025h1' log" },
    { (const uint8_t[]){
          0x26, 0x02, 0x39, 0x48, 0x87, 0x4c, 0xf7, 0xfc, 0xd0, 0xfb, 0x64,
          0x71, 0xa4, 0x3e, 0x84, 0x7e, 0xbb, 0x20, 0x0a, 0xe6, 0xe2, 0xfa,
          0x24, 0x23, 0x6d, 0xf6, 0xd1, 0xa6, 0x06, 0x63, 0x0f, 0xb1,
      },
      32, "Google 'Solera2025h2' log" },
    { (const uint8_t[]){
          0x5e, 0xa7, 0x73, 0xf9, 0xdf, 0x56, 0xc0, 0xe7, 0xb5, 0x36, 0x48,
          0x7d, 0xd0, 0x49, 0xe0, 0x32, 0x7a, 0x91, 0x9a, 0x0c, 0x84, 0xa1,
          0x12, 0x12, 0x84, 0x18, 0x75, 0x96, 0x81, 0x71, 0x45, 0x58,
      },
      32, "Cloudflare 'Nimbus2020' Log" },
    { (const uint8_t[]){
          0x44, 0x94, 0x65, 0x2e, 0xb0, 0xee, 0xce, 0xaf, 0xc4, 0x40, 0x07,
          0xd8, 0xa8, 0xfe, 0x28, 0xc0, 0xda, 0xe6, 0x82, 0xbe, 0xd8, 0xcb,
          0x31, 0xb5, 0x3f, 0xd3, 0x33, 0x96, 0xb5, 0xb6, 0x81, 0xa8,
      },
      32, "Cloudflare 'Nimbus2021' Log" },
    { (const uint8_t[]){
          0x41, 0xc8, 0xca, 0xb1, 0xdf, 0x22, 0x46, 0x4a, 0x10, 0xc6, 0xa1,
          0x3a, 0x09, 0x42, 0x87, 0x5e, 0x4e, 0x31, 0x8b, 0x1b, 0x03, 0xeb,
          0xeb, 0x4b, 0xc7, 0x68, 0xf0, 0x90, 0x62, 0x96, 0x06, 0xf6,
      },
      32, "Cloudflare 'Nimbus2022' Log" },
    { (const uint8_t[]){
          0x7a, 0x32, 0x8c, 0x54, 0xd8, 0xb7, 0x2d, 0xb6, 0x20, 0xea, 0x38,
          0xe0, 0x52, 0x1e, 0xe9, 0x84, 0x16, 0x70, 0x32, 0x13, 0x85, 0x4d,
          0x3b, 0xd2, 0x2b, 0xc1, 0x3a, 0x57, 0xa3, 0x52, 0xeb, 0x52,
      },
      32, "Cloudflare 'Nimbus2023' Log" },
    { (const uint8_t[]){
          0xda, 0xb6, 0xbf, 0x6b, 0x3f, 0xb5, 0xb6, 0x22, 0x9f, 0x9b, 0xc2,
          0xbb, 0x5c, 0x6b, 0xe8, 0x70, 0x91, 0x71, 0x6c, 0xbb, 0x51, 0x84,
          0x85, 0x34, 0xbd, 0xa4, 0x3d, 0x30, 0x48, 0xd7, 0xfb, 0xab,
      },
      32, "Cloudflare 'Nimbus2024' Log" },
    { (const uint8_t[]){
          0xcc, 0xfb, 0x0f, 0x6a, 0x85, 0x71, 0x09, 0x65, 0xfe, 0x95, 0x9b,
          0x53, 0xce, 0xe9, 0xb2, 0x7c, 0x22, 0xe9, 0x85, 0x5c, 0x0d, 0x97,
          0x8d, 0xb6, 0xa9, 0x7e, 0x54, 0xc0, 0xfe, 0x4c, 0x0d, 0xb0,
      },
      32, "Cloudflare 'Nimbus2025'" },
    { (const uint8_t[]){
          0xcb, 0x38, 0xf7, 0x15, 0x89, 0x7c, 0x84, 0xa1, 0x44, 0x5f, 0x5b,
          0xc1, 0xdd, 0xfb, 0xc9, 0x6e, 0xf2, 0x9a, 0x59, 0xcd, 0x47, 0x0a,
          0x69, 0x05, 0x85, 0xb0, 0xcb, 0x14, 0xc3, 0x14, 0x58, 0xe7,
      },
      32, "Cloudflare 'Nimbus2026'" },
    { (const uint8_t[]){
          0x1f, 0xbc, 0x36, 0xe0, 0x02, 0xed, 0xe9, 0x7f, 0x40, 0x19, 0x9e,
          0x86, 0xb3, 0x57, 0x3b, 0x8a, 0x42, 0x17, 0xd8, 0x01, 0x87, 0x74,
          0x6a, 0xd0, 0xda, 0x03, 0xa0, 0x60, 0x54, 0xd2, 0x0d, 0xf4,
      },
      32, "Cloudflare 'Nimbus2017' Log" },
    { (const uint8_t[]){
          0xdb, 0x74, 0xaf, 0xee, 0xcb, 0x29, 0xec, 0xb1, 0xfe, 0xca, 0x3e,
          0x71, 0x6d, 0x2c, 0xe5, 0xb9, 0xaa, 0xbb, 0x36, 0xf7, 0x84, 0x71,
          0x83, 0xc7, 0x5d, 0x9d, 0x4f, 0x37, 0xb6, 0x1f, 0xbf, 0x64,
      },
      32, "Cloudflare 'Nimbus2018' Log" },
    { (const uint8_t[]){
          0x74, 0x7e, 0xda, 0x83, 0x31, 0xad, 0x33, 0x10, 0x91, 0x21, 0x9c,
          0xce, 0x25, 0x4f, 0x42, 0x70, 0xc2, 0xbf, 0xfd, 0x5e, 0x42, 0x20,
          0x08, 0xc6, 0x37, 0x35, 0x79, 0xe6, 0x10, 0x7b, 0xcc, 0x56,
      },
      32, "Cloudflare 'Nimbus2019' Log" },
    { (const uint8_t[]){
          0x56, 0x14, 0x06, 0x9a, 0x2f, 0xd7, 0xc2, 0xec, 0xd3, 0xf5, 0xe1,
          0xbd, 0x44, 0xb2, 0x3e, 0xc7, 0x46, 0x76, 0xb9, 0xbc, 0x99, 0x11,
          0x5c, 0xc0, 0xef, 0x94, 0x98, 0x55, 0xd6, 0x89, 0xd0, 0xdd,
      },
      32, "DigiCert Log Server" },
    { (const uint8_t[]){
          0x87, 0x75, 0xbf, 0xe7, 0x59, 0x7c, 0xf8, 0x8c, 0x43, 0x99, 0x5f,
          0xbd, 0xf3, 0x6e, 0xff, 0x56, 0x8d, 0x47, 0x56, 0x36, 0xff, 0x4a,
          0xb5, 0x60, 0xc1, 0xb4, 0xea, 0xff, 0x5e, 0xa0, 0x83, 0x0f,
      },
      32, "DigiCert Log Server 2" },
    { (const uint8_t[]){
          0xf0, 0x95, 0xa4, 0x59, 0xf2, 0x00, 0xd1, 0x82, 0x40, 0x10, 0x2d,
          0x2f, 0x93, 0x88, 0x8e, 0xad, 0x4b, 0xfe, 0x1d, 0x47, 0xe3, 0x99,
          0xe1, 0xd0, 0x34, 0xa6, 0xb0, 0xa8, 0xaa, 0x8e, 0xb2, 0x73,
      },
      32, "DigiCert Yeti2020 Log" },
    { (const uint8_t[]){
          0x5c, 0xdc, 0x43, 0x92, 0xfe, 0xe6, 0xab, 0x45, 0x44, 0xb1, 0x5e,
          0x9a, 0xd4, 0x56, 0xe6, 0x10, 0x37, 0xfb, 0xd5, 0xfa, 0x47, 0xdc,
          0xa1, 0x73, 0x94, 0xb2, 0x5e, 0xe6, 0xf6, 0xc7, 0x0e, 0xca,
      },
      32, "DigiCert Yeti2021 Log" },
    { (const uint8_t[]){
          0x22, 0x45, 0x45, 0x07, 0x59, 0x55, 0x24, 0x56, 0x96, 0x3f, 0xa1,
          0x2f, 0xf1, 0xf7, 0x6d, 0x86, 0xe0, 0x23, 0x26, 0x63, 0xad, 0xc0,
          0x4b, 0x7f, 0x5d, 0xc6, 0x83, 0x5c, 0x6e, 0xe2, 0x0f, 0x02,
      },
      32, "DigiCert Yeti2022 Log" },
    { (const uint8_t[]){
          0x35, 0xcf, 0x19, 0x1b, 0xbf, 0xb1, 0x6c, 0x57, 0xbf, 0x0f, 0xad,
          0x4c, 0x6d, 0x42, 0xcb, 0xbb, 0xb6, 0x27, 0x20, 0x26, 0x51, 0xea,
          0x3f, 0xe1, 0x2a, 0xef, 0xa8, 0x03, 0xc3, 0x3b, 0xd6, 0x4c,
      },
      32, "DigiCert Yeti2023 Log" },
    { (const uint8_t[]){
          0x48, 0xb0, 0xe3, 0x6b, 0xda, 0xa6, 0x47, 0x34, 0x0f, 0xe5, 0x6a,
          0x02, 0xfa, 0x9d, 0x30, 0xeb, 0x1c, 0x52, 0x01, 0xcb, 0x56, 0xdd,
          0x2c, 0x81, 0xd9, 0xbb, 0xbf, 0xab, 0x39, 0xd8, 0x84, 0x73,
      },
      32, "DigiCert Yeti2024 Log" },
    { (const uint8_t[]){
          0x7d, 0x59, 0x1e, 0x12, 0xe1, 0x78, 0x2a, 0x7b, 0x1c, 0x61, 0x67,
          0x7c, 0x5e, 0xfd, 0xf8, 0xd0, 0x87, 0x5c, 0x14, 0xa0, 0x4e, 0x95,
          0x9e, 0xb9, 0x03, 0x2f, 0xd9, 0x0e, 0x8c, 0x2e, 0x79, 0xb8,
      },
      32, "DigiCert Yeti2025 Log" },
    { (const uint8_t[]){
          0xc6, 0x52, 0xa0, 0xec, 0x48, 0xce, 0xb3, 0xfc, 0xab, 0x17, 0x09,
          0x92, 0xc4, 0x3a, 0x87, 0x41, 0x33, 0x09, 0xe8, 0x00, 0x65, 0xa2,
          0x62, 0x52, 0x40, 0x1b, 0xa3, 0x36, 0x2a, 0x17, 0xc5, 0x65,
      },
      32, "DigiCert Nessie2020 Log" },
    { (const uint8_t[]){
          0xee, 0xc0, 0x95, 0xee, 0x8d, 0x72, 0x64, 0x0f, 0x92, 0xe3, 0xc3,
          0xb9, 0x1b, 0xc7, 0x12, 0xa3, 0x69, 0x6a, 0x09, 0x7b, 0x4b, 0x6a,
          0x1a, 0x14, 0x38, 0xe6, 0x47, 0xb2, 0xcb, 0xed, 0xc5, 0xf9,
      },
      32, "DigiCert Nessie2021 Log" },
    { (const uint8_t[]){
          0x51, 0xa3, 0xb0, 0xf5, 0xfd, 0x01, 0x79, 0x9c, 0x56, 0x6d, 0xb8,
          0x37, 0x78, 0x8f, 0x0c, 0xa4, 0x7a, 0xcc, 0x1b, 0x27, 0xcb, 0xf7,
          0x9e, 0x88, 0x42, 0x9a, 0x0d, 0xfe, 0xd4, 0x8b, 0x05, 0xe5,
      },
      32, "DigiCert Nessie2022 Log" },
    { (const uint8_t[]){
          0xb3, 0x73, 0x77, 0x07, 0xe1, 0x84, 0x50, 0xf8, 0x63, 0x86, 0xd6,
          0x05, 0xa9, 0xdc, 0x11, 0x09, 0x4a, 0x79, 0x2d, 0xb1, 0x67, 0x0c,
          0x0b, 0x87, 0xdc, 0xf0, 0x03, 0x0e, 0x79, 0x36, 0xa5, 0x9a,
      },
      32, "DigiCert Nessie2023 Log" },
    { (const uint8_t[]){
          0x73, 0xd9, 0x9e, 0x89, 0x1b, 0x4c, 0x96, 0x78, 0xa0, 0x20, 0x7d,
          0x47, 0x9d, 0xe6, 0xb2, 0xc6, 0x1c, 0xd0, 0x51, 0x5e, 0x71, 0x19,
          0x2a, 0x8c, 0x6b, 0x80, 0x10, 0x7a, 0xc1, 0x77, 0x72, 0xb5,
      },
      32, "DigiCert Nessie2024 Log" },
    { (const uint8_t[]){
          0xe6, 0xd2, 0x31, 0x63, 0x40, 0x77, 0x8c, 0xc1, 0x10, 0x41, 0x06,
          0xd7, 0x71, 0xb9, 0xce, 0xc1, 0xd2, 0x40, 0xf6, 0x96, 0x84, 0x86,
          0xfb, 0xba, 0x87, 0x32, 0x1d, 0xfd, 0x1e, 0x37, 0x8e, 0x50,
      },
      32, "DigiCert Nessie2025 Log" },
    { (const uint8_t[]){
          0xb6, 0x9d, 0xdc, 0xbc, 0x3c, 0x1a, 0xbd, 0xef, 0x6f, 0x9f, 0xd6,
          0x0c, 0x88, 0xb1, 0x06, 0x7b, 0x77, 0xf0, 0x82, 0x68, 0x8b, 0x2d,
          0x78, 0x65, 0xd0, 0x4b, 0x39, 0xab, 0xe9, 0x27, 0xa5, 0x75,
      },
      32, "DigiCert 'Wyvern2024h1' Log" },
    { (const uint8_t[]){
          0x0c, 0x2a, 0xef, 0x2c, 0x4a, 0x5b, 0x98, 0x83, 0xd4, 0xdd, 0xa3,
          0x82, 0xfe, 0x50, 0xfb, 0x51, 0x88, 0xb3, 0xe9, 0x73, 0x33, 0xa1,
          0xec, 0x53, 0xa0, 0x9d, 0xc9, 0xa7, 0x9d, 0x0d, 0x08, 0x20,
      },
      32, "DigiCert 'Wyvern2024h2' Log" },
    { (const uint8_t[]){
          0x73, 0x20, 0x22, 0x0f, 0x08, 0x16, 0x8a, 0xf9, 0xf3, 0xc4, 0xa6,
          0x8b, 0x0a, 0xb2, 0x6a, 0x9a, 0x4a, 0x00, 0xee, 0xf5, 0x77, 0x85,
          0x8a, 0x08, 0x4d, 0x05, 0x00, 0xd4, 0xa5, 0x42, 0x44, 0x59,
      },
      32, "DigiCert 'Wyvern2025h1' Log" },
    { (const uint8_t[]){
          0xed, 0x3c, 0x4b, 0xd6, 0xe8, 0x06, 0xc2, 0xa4, 0xa2, 0x00, 0x57,
          0xdb, 0xcb, 0x24, 0xe2, 0x38, 0x01, 0xdf, 0x51, 0x2f, 0xed, 0xc4,
          0x86, 0xc5, 0x70, 0x0f, 0x20, 0xdd, 0xb7, 0x3e, 0x3f, 0xe0,
      },
      32, "DigiCert 'Wyvern2025h2' Log" },
    { (const uint8_t[]){
          0x64, 0x11, 0xc4, 0x6c, 0xa4, 0x12, 0xec, 0xa7, 0x89, 0x1c, 0xa2,
          0x02, 0x2e, 0x00, 0xbc, 0xab, 0x4f, 0x28, 0x07, 0xd4, 0x1e, 0x35,
          0x27, 0xab, 0xea, 0xfe, 0xd5, 0x03, 0xc9, 0x7d, 0xcd, 0xf0,
      },
      32, "DigiCert 'Wyvern2026h1'" },
    { (const uint8_t[]){
          0xc2, 0x31, 0x7e, 0x57, 0x45, 0x19, 0xa3, 0x45, 0xee, 0x7f, 0x38,
          0xde, 0xb2, 0x90, 0x41, 0xeb, 0xc7, 0xc2, 0x21, 0x5a, 0x22, 0xbf,
          0x7f, 0xd5, 0xb5, 0xad, 0x76, 0x9a, 0xd9, 0x0e, 0x52, 0xcd,
      },
      32, "DigiCert 'Wyvern2026h2'" },
    { (const uint8_t[]){
          0xdb, 0x07, 0x6c, 0xde, 0x6a, 0x8b, 0x78, 0xec, 0x58, 0xd6, 0x05,
          0x64, 0x96, 0xeb, 0x6a, 0x26, 0xa8, 0xc5, 0x9e, 0x72, 0x12, 0x93,
          0xe8, 0xac, 0x03, 0x27, 0xdd, 0xde, 0x89, 0xdb, 0x5a, 0x2a,
      },
      32, "DigiCert 'Sphinx2024h1' Log" },
    { (const uint8_t[]){
          0xdc, 0xc9, 0x5e, 0x6f, 0xa2, 0x99, 0xb9, 0xb0, 0xfd, 0xbd, 0x6c,
          0xa6, 0xa3, 0x6e, 0x1d, 0x72, 0xc4, 0x21, 0x2f, 0xdd, 0x1e, 0x0f,
          0x47, 0x55, 0x3a, 0x36, 0xd6, 0xcf, 0x1a, 0xd1, 0x1d, 0x8d,
      },
      32, "DigiCert 'Sphinx2024h2' Log" },
    { (const uint8_t[]){
          0xde, 0x85, 0x81, 0xd7, 0x50, 0x24, 0x7c, 0x6b, 0xcd, 0xcb, 0xaf,
          0x56, 0x37, 0xc5, 0xe7, 0x81, 0xc6, 0x4c, 0xe4, 0x6e, 0xd6, 0x17,
          0x63, 0x9f, 0x8f, 0x34, 0xa7, 0x26, 0xc9, 0xe2, 0xbd, 0x37,
      },
      32, "DigiCert 'Sphinx2025h1' Log" },
    { (const uint8_t[]){
          0xa4, 0x42, 0xc5, 0x06, 0x49, 0x60, 0x61, 0x54, 0x8f, 0x0f, 0xd4,
          0xea, 0x9c, 0xfb, 0x7a, 0x2d, 0x26, 0x45, 0x4d, 0x87, 0xa9, 0x7f,
          0x2f, 0xdf, 0x45, 0x59, 0xf6, 0x27, 0x4f, 0x3a, 0x84, 0x54,
      },
      32, "DigiCert 'Sphinx2025h2' Log" },
    { (const uint8_t[]){
          0x49, 0x9c, 0x9b, 0x69, 0xde, 0x1d, 0x7c, 0xec, 0xfc, 0x36, 0xde,
          0xcd, 0x87, 0x64, 0xa6, 0xb8, 0x5b, 0xaf, 0x0a, 0x87, 0x80, 0x19,
          0xd1, 0x55, 0x52, 0xfb, 0xe9, 0xeb, 0x29, 0xdd, 0xf8, 0xc3,
      },
      32, "DigiCert 'Sphinx2026h1'" },
    { (const uint8_t[]){
          0x94, 0x4e, 0x43, 0x87, 0xfa, 0xec, 0xc1, 0xef, 0x81, 0xf3, 0x19,
          0x24, 0x26, 0xa8, 0x18, 0x65, 0x01, 0xc7, 0xd3, 0x5f, 0x38, 0x02,
          0x01, 0x3f, 0x72, 0x67, 0x7d, 0x55, 0x37, 0x2e, 0x19, 0xd8,
      },
      32, "DigiCert 'Sphinx2026h2'" },
    { (const uint8_t[]){
          0xdd, 0xeb, 0x1d, 0x2b, 0x7a, 0x0d, 0x4f, 0xa6, 0x20, 0x8b, 0x81,
          0xad, 0x81, 0x68, 0x70, 0x7e, 0x2e, 0x8e, 0x9d, 0x01, 0xd5, 0x5c,
          0x88, 0x8d, 0x3d, 0x11, 0xc4, 0xcd, 0xb6, 0xec, 0xbe, 0xcc,
      },
      32, "Symantec log" },
    { (const uint8_t[]){
          0xbc, 0x78, 0xe1, 0xdf, 0xc5, 0xf6, 0x3c, 0x68, 0x46, 0x49, 0x33,
          0x4d, 0xa1, 0x0f, 0xa1, 0x5f, 0x09, 0x79, 0x69, 0x20, 0x09, 0xc0,
          0x81, 0xb4, 0xf3, 0xf6, 0x91, 0x7f, 0x3e, 0xd9, 0xb8, 0xa5,
      },
      32, "Symantec 'Vega' log" },
    { (const uint8_t[]){
          0x15, 0x97, 0x04, 0x88, 0xd7, 0xb9, 0x97, 0xa0, 0x5b, 0xeb, 0x52,
          0x51, 0x2a, 0xde, 0xe8, 0xd2, 0xe8, 0xb4, 0xa3, 0x16, 0x52, 0x64,
          0x12, 0x1a, 0x9f, 0xab, 0xfb, 0xd5, 0xf8, 0x5a, 0xd9, 0x3f,
      },
      32, "Symantec 'Sirius' log" },
    { (const uint8_t[]){
          0x05, 0x9c, 0x01, 0xd3, 0x20, 0xe0, 0x07, 0x84, 0x13, 0x95, 0x80,
          0x49, 0x8d, 0x11, 0x7c, 0x90, 0x32, 0x66, 0xaf, 0xaf, 0x72, 0x50,
          0xb5, 0xaf, 0x3b, 0x46, 0xa4, 0x3e, 0x11, 0x84, 0x0d, 0x4a,
      },
      32, "DigiCert Yeti2022-2 Log" },
    { (const uint8_t[]){
          0xc1, 0x16, 0x4a, 0xe0, 0xa7, 0x72, 0xd2, 0xd4, 0x39, 0x2d, 0xc8,
          0x0a, 0xc1, 0x07, 0x70, 0xd4, 0xf0, 0xc4, 0x9b, 0xde, 0x99, 0x1a,
          0x48, 0x40, 0xc1, 0xfa, 0x07, 0x51, 0x64, 0xf6, 0x33, 0x60,
      },
      32, "DigiCert Yeti2018 Log" },
    { (const uint8_t[]){
          0xe2, 0x69, 0x4b, 0xae, 0x26, 0xe8, 0xe9, 0x40, 0x09, 0xe8, 0x86,
          0x1b, 0xb6, 0x3b, 0x83, 0xd4, 0x3e, 0xe7, 0xfe, 0x74, 0x88, 0xfb,
          0xa4, 0x8f, 0x28, 0x93, 0x01, 0x9d, 0xdd, 0xf1, 0xdb, 0xfe,
      },
      32, "DigiCert Yeti2019 Log" },
    { (const uint8_t[]){
          0x6f, 0xf1, 0x41, 0xb5, 0x64, 0x7e, 0x42, 0x22, 0xf7, 0xef, 0x05,
          0x2c, 0xef, 0xae, 0x7c, 0x21, 0xfd, 0x60, 0x8e, 0x27, 0xd2, 0xaf,
          0x5a, 0x6e, 0x9f, 0x4b, 0x8a, 0x37, 0xd6, 0x63, 0x3e, 0xe5,
      },
      32, "DigiCert Nessie2018 Log" },
    { (const uint8_t[]){
          0xfe, 0x44, 0x61, 0x08, 0xb1, 0xd0, 0x1a, 0xb7, 0x8a, 0x62, 0xcc,
          0xfe, 0xab, 0x6a, 0xb2, 0xb2, 0xba, 0xbf, 0xf3, 0xab, 0xda, 0xd8,
          0x0a, 0x4d, 0x8b, 0x30, 0xdf, 0x2d, 0x00, 0x08, 0x83, 0x0c,
      },
      32, "DigiCert Nessie2019 Log" },
    { (const uint8_t[]){
          0xa7, 0xce, 0x4a, 0x4e, 0x62, 0x07, 0xe0, 0xad, 0xde, 0xe5, 0xfd,
          0xaa, 0x4b, 0x1f, 0x86, 0x76, 0x87, 0x67, 0xb5, 0xd0, 0x02, 0xa5,
          0x5d, 0x47, 0x31, 0x0e, 0x7e, 0x67, 0x0a, 0x95, 0xea, 0xb2,
      },
      32, "Symantec Deneb" },
    { (const uint8_t[]){
          0xcd, 0xb5, 0x17, 0x9b, 0x7f, 0xc1, 0xc0, 0x46, 0xfe, 0xea, 0x31,
          0x13, 0x6a, 0x3f, 0x8f, 0x00, 0x2e, 0x61, 0x82, 0xfa, 0xf8, 0x89,
          0x6f, 0xec, 0xc8, 0xb2, 0xf5, 0xb5, 0xab, 0x60, 0x49, 0x00,
      },
      32, "Certly.IO log" },
    { (const uint8_t[]){
          0x74, 0x61, 0xb4, 0xa0, 0x9c, 0xfb, 0x3d, 0x41, 0xd7, 0x51, 0x59,
          0x57, 0x5b, 0x2e, 0x76, 0x49, 0xa4, 0x45, 0xa8, 0xd2, 0x77, 0x09,
          0xb0, 0xcc, 0x56, 0x4a, 0x64, 0x82, 0xb7, 0xeb, 0x41, 0xa3,
      },
      32, "Izenpe log" },
    { (const uint8_t[]){
          0x89, 0x41, 0x44, 0x9c, 0x70, 0x74, 0x2e, 0x06, 0xb9, 0xfc, 0x9c,
          0xe7, 0xb1, 0x16, 0xba, 0x00, 0x24, 0xaa, 0x36, 0xd5, 0x9a, 0xf4,
          0x4f, 0x02, 0x04, 0x40, 0x4f, 0x00, 0xf7, 0xea, 0x85, 0x66,
      },
      32, "Izenpe 'Argi' log" },
    { (const uint8_t[]){
          0x41, 0xb2, 0xdc, 0x2e, 0x89, 0xe6, 0x3c, 0xe4, 0xaf, 0x1b, 0xa7,
          0xbb, 0x29, 0xbf, 0x68, 0xc6, 0xde, 0xe6, 0xf9, 0xf1, 0xcc, 0x04,
          0x7e, 0x30, 0xdf, 0xfa, 0xe3, 0xb3, 0xba, 0x25, 0x92, 0x63,
      },
      32, "WoSign log" },
    { (const uint8_t[]){
          0x9e, 0x4f, 0xf7, 0x3d, 0xc3, 0xce, 0x22, 0x0b, 0x69, 0x21, 0x7c,
          0x89, 0x9e, 0x46, 0x80, 0x76, 0xab, 0xf8, 0xd7, 0x86, 0x36, 0xd5,
          0xcc, 0xfc, 0x85, 0xa3, 0x1a, 0x75, 0x62, 0x8b, 0xa8, 0x8b,
      },
      32, "WoSign CT log #1" },
    { (const uint8_t[]){
          0x63, 0xd0, 0x00, 0x60, 0x26, 0xdd, 0xe1, 0x0b, 0xb0, 0x60, 0x1f,
          0x45, 0x24, 0x46, 0x96, 0x5e, 0xe2, 0xb6, 0xea, 0x2c, 0xd4, 0xfb,
          0xc9, 0x5a, 0xc8, 0x66, 0xa5, 0x50, 0xaf, 0x90, 0x75, 0xb7,
      },
      32, "WoSign log 2" },
    { (const uint8_t[]){
          0xac, 0x3b, 0x9a, 0xed, 0x7f, 0xa9, 0x67, 0x47, 0x57, 0x15, 0x9e,
          0x6d, 0x7d, 0x57, 0x56, 0x72, 0xf9, 0xd9, 0x81, 0x00, 0x94, 0x1e,
          0x9b, 0xde, 0xff, 0xec, 0xa1, 0x31, 0x3b, 0x75, 0x78, 0x2d,
      },
      32, "Venafi log" },
    { (const uint8_t[]){
          0x03, 0x01, 0x9d, 0xf3, 0xfd, 0x85, 0xa6, 0x9a, 0x8e, 0xbd, 0x1f,
          0xac, 0xc6, 0xda, 0x9b, 0xa7, 0x3e, 0x46, 0x97, 0x74, 0xfe, 0x77,
          0xf5, 0x79, 0xfc, 0x5a, 0x08, 0xb8, 0x32, 0x8c, 0x1d, 0x6b,
      },
      32, "Venafi Gen2 CT log" },
    { (const uint8_t[]){
          0xa5, 0x77, 0xac, 0x9c, 0xed, 0x75, 0x48, 0xdd, 0x8f, 0x02, 0x5b,
          0x67, 0xa2, 0x41, 0x08, 0x9d, 0xf8, 0x6e, 0x0f, 0x47, 0x6e, 0xc2,
          0x03, 0xc2, 0xec, 0xbe, 0xdb, 0x18, 0x5f, 0x28, 0x26, 0x38,
      },
      32, "CNNIC CT log" },
    { (const uint8_t[]){
          0x34, 0xbb, 0x6a, 0xd6, 0xc3, 0xdf, 0x9c, 0x03, 0xee, 0xa8, 0xa4,
          0x99, 0xff, 0x78, 0x91, 0x48, 0x6c, 0x9d, 0x5e, 0x5c, 0xac, 0x92,
          0xd0, 0x1f, 0x7b, 0xfd, 0x1b, 0xce, 0x19, 0xdb, 0x48, 0xef,
      },
      32, "StartCom log" },
    { (const uint8_t[]){
          0x55, 0x81, 0xd4, 0xc2, 0x16, 0x90, 0x36, 0x01, 0x4a, 0xea, 0x0b,
          0x9b, 0x57, 0x3c, 0x53, 0xf0, 0xc0, 0xe4, 0x38, 0x78, 0x70, 0x25,
          0x08, 0x17, 0x2f, 0xa3, 0xaa, 0x1d, 0x07, 0x13, 0xd3, 0x0c,
      },
      32, "Sectigo 'Sabre' CT log" },
    { (const uint8_t[]){
          0xa2, 0xe2, 0xbf, 0xd6, 0x1e, 0xde, 0x2f, 0x2f, 0x07, 0xa0, 0xd6,
          0x4e, 0x6d, 0x37, 0xa7, 0xdc, 0x65, 0x43, 0xb0, 0xc6, 0xb5, 0x2e,
          0xa2, 0xda, 0xb7, 0x8a, 0xf8, 0x9a, 0x6d, 0xf5, 0x17, 0xd8,
      },
      32, "Sectigo 'Sabre2024h1'" },
    { (const uint8_t[]){
          0x19, 0x98, 0x10, 0x71, 0x09, 0xf0, 0xd6, 0x52, 0x2e, 0x30, 0x80,
          0xd2, 0x9e, 0x3f, 0x64, 0xbb, 0x83, 0x6e, 0x28, 0xcc, 0xf9, 0x0f,
          0x52, 0x8e, 0xee, 0xdf, 0xce, 0x4a, 0x3f, 0x16, 0xb4, 0xca,
      },
      32, "Sectigo 'Sabre2024h2'" },
    { (const uint8_t[]){
          0xe0, 0x92, 0xb3, 0xfc, 0x0c, 0x1d, 0xc8, 0xe7, 0x68, 0x36, 0x1f,
          0xde, 0x61, 0xb9, 0x96, 0x4d, 0x0a, 0x52, 0x78, 0x19, 0x8a, 0x72,
          0xd6, 0x72, 0xc4, 0xb0, 0x4d, 0xa5, 0x6d, 0x6f, 0x54, 0x04,
      },
      32, "Sectigo 'Sabre2025h1'" },
    { (const uint8_t[]){
          0x1a, 0x04, 0xff, 0x49, 0xd0, 0x54, 0x1d, 0x40, 0xaf, 0xf6, 0xa0,
          0xc3, 0xbf, 0xf1, 0xd8, 0xc4, 0x67, 0x2f, 0x4e, 0xec, 0xee, 0x23,
          0x40, 0x68, 0x98, 0x6b, 0x17, 0x40, 0x2e, 0xdc, 0x89, 0x7d,
      },
      32, "Sectigo 'Sabre2025h2'" },
    { (const uint8_t[]){
          0x6f, 0x53, 0x76, 0xac, 0x31, 0xf0, 0x31, 0x19, 0xd8, 0x99, 0x00,
          0xa4, 0x51, 0x15, 0xff, 0x77, 0x15, 0x1c, 0x11, 0xd9, 0x02, 0xc1,
          0x00, 0x29, 0x06, 0x8d, 0xb2, 0x08, 0x9a, 0x37, 0xd9, 0x13,
      },
      32, "Sectigo 'Mammoth' CT log" },
    { (const uint8_t[]){
          0x29, 0xd0, 0x3a, 0x1b, 0xb6, 0x74, 0xaa, 0x71, 0x1c, 0xd3, 0x03,
          0x5b, 0x65, 0x57, 0xc1, 0x4f, 0x8a, 0xa7, 0x8b, 0x4f, 0xe8, 0x38,
          0x94, 0x49, 0xec, 0xa4, 0x53, 0xf9, 0x44, 0xbd, 0x24, 0x68,
      },
      32, "Sectigo 'Mammoth2024h1'" },
    { (const uint8_t[]){
          0x50, 0x85, 0x01, 0x58, 0xdc, 0xb6, 0x05, 0x95, 0xc0, 0x0e, 0x92,
          0xa8, 0x11, 0x02, 0xec, 0xcd, 0xfe, 0x3f, 0x6b, 0x78, 0x58, 0x42,
          0x9f, 0x57, 0x98, 0x35, 0x38, 0xc9, 0xda, 0x52, 0x50, 0x63,
      },
      32, "Sectigo 'Mammoth2024h1b'" },
    { (const uint8_t[]){
          0xdf, 0xe1, 0x56, 0xeb, 0xaa, 0x05, 0xaf, 0xb5, 0x9c, 0x0f, 0x86,
          0x71, 0x8d, 0xa8, 0xc0, 0x32, 0x4e, 0xae, 0x56, 0xd9, 0x6e, 0xa7,
          0xf5, 0xa5, 0x6a, 0x01, 0xd1, 0xc1, 0x3b, 0xbe, 0x52, 0x5c,
      },
      32, "Sectigo 'Mammoth2024h2'" },
    { (const uint8_t[]){
          0x13, 0x4a, 0xdf, 0x1a, 0xb5, 0x98, 0x42, 0x09, 0x78, 0x0c, 0x6f,
          0xef, 0x4c, 0x7a, 0x91, 0xa4, 0x16, 0xb7, 0x23, 0x49, 0xce, 0x58,
          0x57, 0x6a, 0xdf, 0xae, 0xda, 0xa7, 0xc2, 0xab, 0xe0, 0x22,
      },
      32, "Sectigo 'Mammoth2025h1'" },
    { (const uint8_t[]){
          0xaf, 0x18, 0x1a, 0x28, 0xd6, 0x8c, 0xa3, 0xe0, 0xa9, 0x8a, 0x4c,
          0x9c, 0x67, 0xab, 0x09, 0xf8, 0xbb, 0xbc, 0x22, 0xba, 0xae, 0xbc,
          0xb1, 0x38, 0xa3, 0xa1, 0x9d, 0xd3, 0xf9, 0xb6, 0x03, 0x0d,
      },
      32, "Sectigo 'Mammoth2025h2'" },
    { (const uint8_t[]){
          0x25, 0x2f, 0x94, 0xc2, 0x2b, 0x29, 0xe9, 0x6e, 0x9f, 0x41, 0x1a,
          0x72, 0x07, 0x2b, 0x69, 0x5c, 0x5b, 0x52, 0xff, 0x97, 0xa9, 0x0d,
          0x25, 0x40, 0xbb, 0xfc, 0xdc, 0x51, 0xec, 0x4d, 0xee, 0x0b,
      },
      32, "Sectigo 'Mammoth2026h1'" },
    { (const uint8_t[]){
          0x94, 0xb1, 0xc1, 0x8a, 0xb0, 0xd0, 0x57, 0xc4, 0x7b, 0xe0, 0xac,
          0x04, 0x0e, 0x1f, 0x2c, 0xbc, 0x8d, 0xc3, 0x75, 0x72, 0x7b, 0xc9,
          0x51, 0xf2, 0x0a, 0x52, 0x61, 0x26, 0x86, 0x3b, 0xa7, 0x3c,
      },
      32, "Sectigo 'Mammoth2026h2'" },
    { (const uint8_t[]){
          0x56, 0x6c, 0xd5, 0xa3, 0x76, 0xbe, 0x83, 0xdf, 0xe3, 0x42, 0xb6,
          0x75, 0xc4, 0x9c, 0x23, 0x24, 0x98, 0xa7, 0x69, 0xba, 0xc3, 0x82,
          0xcb, 0xab, 0x49, 0xa3, 0x87, 0x7d, 0x9a, 0xb3, 0x2d, 0x01,
      },
      32, "Sectigo 'Sabre2026h1'" },
    { (const uint8_t[]){
          0x1f, 0x56, 0xd1, 0xab, 0x94, 0x70, 0x4a, 0x41, 0xdd, 0x3f, 0xea,
          0xfd, 0xf4, 0x69, 0x93, 0x55, 0x30, 0x2c, 0x14, 0x31, 0xbf, 0xe6,
          0x13, 0x46, 0x08, 0x9f, 0xff, 0xae, 0x79, 0x5d, 0xcc, 0x2f,
      },
      32, "Sectigo 'Sabre2026h2'" },
    { (const uint8_t[]){
          0xdb, 0x76, 0xfd, 0xad, 0xac, 0x65, 0xe7, 0xd0, 0x95, 0x08, 0x88,
          0x6e, 0x21, 0x59, 0xbd, 0x8b, 0x90, 0x35, 0x2f, 0x5f, 0xea, 0xd3,
          0xe3, 0xdc, 0x5e, 0x22, 0xeb, 0x35, 0x0a, 0xcc, 0x7b, 0x98,
      },
      32, "Sectigo 'Dodo' CT log" },
    { (const uint8_t[]){
          0xe7, 0x12, 0xf2, 0xb0, 0x37, 0x7e, 0x1a, 0x62, 0xfb, 0x8e, 0xc9,
          0x0c, 0x61, 0x84, 0xf1, 0xea, 0x7b, 0x37, 0xcb, 0x56, 0x1d, 0x11,
          0x26, 0x5b, 0xf3, 0xe0, 0xf3, 0x4b, 0xf2, 0x41, 0x54, 0x6e,
      },
      32, "Let's Encrypt 'Oak2020' log" },
    { (const uint8_t[]){
          0x94, 0x20, 0xbc, 0x1e, 0x8e, 0xd5, 0x8d, 0x6c, 0x88, 0x73, 0x1f,
          0x82, 0x8b, 0x22, 0x2c, 0x0d, 0xd1, 0xda, 0x4d, 0x5e, 0x6c, 0x4f,
          0x94, 0x3d, 0x61, 0xdb, 0x4e, 0x2f, 0x58, 0x4d, 0xa2, 0xc2,
      },
      32, "Let's Encrypt 'Oak2021' log" },
    { (const uint8_t[]){
          0xdf, 0xa5, 0x5e, 0xab, 0x68, 0x82, 0x4f, 0x1f, 0x6c, 0xad, 0xee,
          0xb8, 0x5f, 0x4e, 0x3e, 0x5a, 0xea, 0xcd, 0xa2, 0x12, 0xa4, 0x6a,
          0x5e, 0x8e, 0x3b, 0x12, 0xc0, 0x20, 0x44, 0x5c, 0x2a, 0x73,
      },
      32, "Let's Encrypt 'Oak2022' log" },
    { (const uint8_t[]){
          0xb7, 0x3e, 0xfb, 0x24, 0xdf, 0x9c, 0x4d, 0xba, 0x75, 0xf2, 0x39,
          0xc5, 0xba, 0x58, 0xf4, 0x6c, 0x5d, 0xfc, 0x42, 0xcf, 0x7a, 0x9f,
          0x35, 0xc4, 0x9e, 0x1d, 0x09, 0x81, 0x25, 0xed, 0xb4, 0x99,
      },
      32, "Let's Encrypt 'Oak2023' log" },
    { (const uint8_t[]){
          0x3b, 0x53, 0x77, 0x75, 0x3e, 0x2d, 0xb9, 0x80, 0x4e, 0x8b, 0x30,
          0x5b, 0x06, 0xfe, 0x40, 0x3b, 0x67, 0xd8, 0x4f, 0xc3, 0xf4, 0xc7,
          0xbd, 0x00, 0x0d, 0x2d, 0x72, 0x6f, 0xe1, 0xfa, 0xd4, 0x17,
      },
      32, "Let's Encrypt 'Oak2024H1' log" },
    { (const uint8_t[]){
          0x3f, 0x17, 0x4b, 0x4f, 0xd7, 0x22, 0x47, 0x58, 0x94, 0x1d, 0x65,
          0x1c, 0x84, 0xbe, 0x0d, 0x12, 0xed, 0x90, 0x37, 0x7f, 0x1f, 0x85,
          0x6a, 0xeb, 0xc1, 0xbf, 0x28, 0x85, 0xec, 0xf8, 0x64, 0x6e,
      },
      32, "Let's Encrypt 'Oak2024H2' log" },
    { (const uint8_t[]){
          0xa2, 0xe3, 0x0a, 0xe4, 0x45, 0xef, 0xbd, 0xad, 0x9b, 0x7e, 0x38,
          0xed, 0x47, 0x67, 0x77, 0x53, 0xd7, 0x82, 0x5b, 0x84, 0x94, 0xd7,
          0x2b, 0x5e, 0x1b, 0x2c, 0xc4, 0xb9, 0x50, 0xa4, 0x47, 0xe7,
      },
      32, "Let's Encrypt 'Oak2025h1'" },
    { (const uint8_t[]){
          0x0d, 0xe1, 0xf2, 0x30, 0x2b, 0xd3, 0x0d, 0xc1, 0x40, 0x62, 0x12,
          0x09, 0xea, 0x55, 0x2e, 0xfc, 0x47, 0x74, 0x7c, 0xb1, 0xd7, 0xe9,
          0x30, 0xef, 0x0e, 0x42, 0x1e, 0xb4, 0x7e, 0x4e, 0xaa, 0x34,
      },
      32, "Let's Encrypt 'Oak2025h2'" },
    { (const uint8_t[]){
          0x19, 0x86, 0xd4, 0xc7, 0x28, 0xaa, 0x6f, 0xfe, 0xba, 0x03, 0x6f,
          0x78, 0x2a, 0x4d, 0x01, 0x91, 0xaa, 0xce, 0x2d, 0x72, 0x31, 0x0f,
          0xae, 0xce, 0x5d, 0x70, 0x41, 0x2d, 0x25, 0x4c, 0xc7, 0xd4,
      },
      32, "Let's Encrypt 'Oak2026h1'" },
    { (const uint8_t[]){
          0xac, 0xab, 0x30, 0x70, 0x6c, 0xeb, 0xec, 0x84, 0x31, 0xf4, 0x13,
          0xd2, 0xf4, 0x91, 0x5f, 0x11, 0x1e, 0x42, 0x24, 0x43, 0xb1, 0xf2,
          0xa6, 0x8c, 0x4f, 0x3c, 0x2b, 0x3b, 0xa7, 0x1e, 0x02, 0xc3,
      },
      32, "Let's Encrypt 'Oak2026h2'" },
    { (const uint8_t[]){
          0x65, 0x9b, 0x33, 0x50, 0xf4, 0x3b, 0x12, 0xcc, 0x5e, 0xa5, 0xab,
          0x4e, 0xc7, 0x65, 0xd3, 0xfd, 0xe6, 0xc8, 0x82, 0x43, 0x77, 0x77,
          0x78, 0xe7, 0x20, 0x03, 0xf9, 0xeb, 0x2b, 0x8c, 0x31, 0x29,
      },
      32, "Let's Encrypt 'Oak2019' log" },
    { (const uint8_t[]){
          0x84, 0x9f, 0x5f, 0x7f, 0x58, 0xd2, 0xbf, 0x7b, 0x54, 0xec, 0xbd,
          0x74, 0x61, 0x1c, 0xea, 0x45, 0xc4, 0x9c, 0x98, 0xf1, 0xd6, 0x48,
          0x1b, 0xc6, 0xf6, 0x9e, 0x8c, 0x17, 0x4f, 0x24, 0xf3, 0xcf,
      },
      32, "Let's Encrypt 'Testflume2019' log" },
    { (const uint8_t[]){
          0x23, 0x2d, 0x41, 0xa4, 0xcd, 0xac, 0x87, 0xce, 0xd9, 0xf9, 0x43,
          0xf4, 0x68, 0xc2, 0x82, 0x09, 0x5a, 0xe0, 0x9d, 0x30, 0xd6, 0x2e,
          0x2f, 0xa6, 0x5d, 0xdc, 0x3b, 0x91, 0x9c, 0x2e, 0x46, 0x8f,
      },
      32, "Let's Encrypt 'Sapling 2022h2' log" },
    { (const uint8_t[]){
          0xc1, 0x83, 0x24, 0x0b, 0xf1, 0xa4, 0x50, 0xc7, 0x6f, 0xbb, 0x00,
          0x72, 0x69, 0xdc, 0xac, 0x3b, 0xe2, 0x2a, 0x48, 0x05, 0xd4, 0xdb,
          0xe0, 0x49, 0x66, 0xc3, 0xc8, 0xab, 0xc4, 0x47, 0xb0, 0x0c,
      },
      32, "Let's Encrypt 'Sapling 2023h1' log" },
    { (const uint8_t[]){
          0xc6, 0x3f, 0x22, 0x18, 0xc3, 0x7d, 0x56, 0xa6, 0xaa, 0x06, 0xb5,
          0x96, 0xda, 0x8e, 0x53, 0xd4, 0xd7, 0x15, 0x6d, 0x1e, 0x9b, 0xac,
          0x8e, 0x44, 0xd2, 0x20, 0x2d, 0xe6, 0x4d, 0x69, 0xd9, 0xdc,
      },
      32, "Let's Encrypt 'Testflume2020' log" },
    { (const uint8_t[]){
          0x03, 0xed, 0xf1, 0xda, 0x97, 0x76, 0xb6, 0xf3, 0x8c, 0x34, 0x1e,
          0x39, 0xed, 0x9d, 0x70, 0x7a, 0x75, 0x70, 0x36, 0x9c, 0xf9, 0x84,
          0x4f, 0x32, 0x7f, 0xe9, 0xe1, 0x41, 0x38, 0x36, 0x1b, 0x60,
      },
      32, "Let's Encrypt 'Testflume2021' log" },
    { (const uint8_t[]){
          0x23, 0x27, 0xef, 0xda, 0x35, 0x25, 0x10, 0xdb, 0xc0, 0x19, 0xef,
          0x49, 0x1a, 0xe3, 0xff, 0x1c, 0xc5, 0xa4, 0x79, 0xbc, 0xe3, 0x78,
          0x78, 0x36, 0x0e, 0xe3, 0x18, 0xcf, 0xfb, 0x64, 0xf8, 0xc8,
      },
      32, "Let's Encrypt 'Testflume2022' log" },
    { (const uint8_t[]){
          0x55, 0x34, 0xb7, 0xab, 0x5a, 0x6a, 0xc3, 0xa7, 0xcb, 0xeb, 0xa6,
          0x54, 0x87, 0xb2, 0xa2, 0xd7, 0x1b, 0x48, 0xf6, 0x50, 0xfa, 0x17,
          0xc5, 0x19, 0x7c, 0x97, 0xa0, 0xcb, 0x20, 0x76, 0xf3, 0xc6,
      },
      32, "Let's Encrypt 'Testflume2023' log" },
    { (const uint8_t[]){
          0x29, 0x6a, 0xfa, 0x2d, 0x56, 0x8b, 0xca, 0x0d, 0x2e, 0xa8, 0x44,
          0x95, 0x6a, 0xe9, 0x72, 0x1f, 0xc3, 0x5f, 0xa3, 0x55, 0xec, 0xda,
          0x99, 0x69, 0x3a, 0xaf, 0xd4, 0x58, 0xa7, 0x1a, 0xef, 0xdd,
      },
      32, "Let's Encrypt 'Clicky' log" },
    { (const uint8_t[]){
          0xa5, 0x95, 0x94, 0x3b, 0x53, 0x70, 0xbe, 0xe9, 0x06, 0xe0, 0x05,
          0x0d, 0x1f, 0xb5, 0xbb, 0xc6, 0xa4, 0x0e, 0x65, 0xf2, 0x65, 0xae,
          0x85, 0x2c, 0x76, 0x36, 0x3f, 0xad, 0xb2, 0x33, 0x36, 0xed,
      },
      32, "Trust Asia Log2020" },
    { (const uint8_t[]){
          0xa8, 0xdc, 0x52, 0xf6, 0x3d, 0x6b, 0x24, 0x25, 0xe5, 0x31, 0xe3,
          0x7c, 0xf4, 0xe4, 0x4a, 0x71, 0x4f, 0x14, 0x2a, 0x20, 0x80, 0x3b,
          0x0d, 0x04, 0xd2, 0xe2, 0xee, 0x06, 0x64, 0x79, 0x4a, 0x23,
      },
      32, "Trust Asia CT2021" },
    { (const uint8_t[]){
          0x67, 0x8d, 0xb6, 0x5b, 0x3e, 0x74, 0x43, 0xb6, 0xf3, 0xa3, 0x70,
          0xd5, 0xe1, 0x3a, 0xb1, 0xb4, 0x3b, 0xe0, 0xa0, 0xd3, 0x51, 0xf7,
          0xca, 0x74, 0x22, 0x50, 0xc7, 0xc6, 0xfa, 0x51, 0xa8, 0x8a,
      },
      32, "Trust Asia Log2021" },
    { (const uint8_t[]){
          0xc3, 0x65, 0xf9, 0xb3, 0x65, 0x4f, 0x32, 0x83, 0xc7, 0x9d, 0xa9,
          0x8e, 0x93, 0xd7, 0x41, 0x8f, 0x5b, 0xab, 0x7b, 0xe3, 0x25, 0x2c,
          0x98, 0xe1, 0xd2, 0xf0, 0x4b, 0xb9, 0xeb, 0x42, 0x7d, 0x23,
      },
      32, "Trust Asia Log2022" },
    { (const uint8_t[]){
          0xe8, 0x7e, 0xa7, 0x66, 0x0b, 0xc2, 0x6c, 0xf6, 0x00, 0x2e, 0xf5,
          0x72, 0x5d, 0x3f, 0xe0, 0xe3, 0x31, 0xb9, 0x39, 0x3b, 0xb9, 0x2f,
          0xbf, 0x58, 0xeb, 0x3b, 0x90, 0x49, 0xda, 0xf5, 0x43, 0x5a,
      },
      32, "Trust Asia Log2023" },
    { (const uint8_t[]){
          0x30, 0x6d, 0x29, 0x57, 0x6a, 0xd2, 0x1a, 0x9d, 0x4a, 0xe1, 0x2a,
          0xca, 0xd8, 0xaa, 0x8a, 0x78, 0x3a, 0xa6, 0x5a, 0x32, 0x11, 0x60,
          0xac, 0xff, 0x5b, 0x0e, 0xee, 0x4c, 0xa3, 0x20, 0x1d, 0x05,
      },
      32, "Trust Asia Log2024" },
    { (const uint8_t[]){
          0x87, 0x4f, 0xb5, 0x0d, 0xc0, 0x29, 0xd9, 0x93, 0x1d, 0xe5, 0x73,
          0xe9, 0xf2, 0x89, 0x9e, 0x8e, 0x45, 0x33, 0xb3, 0x92, 0xd3, 0x8b,
          0x0a, 0x46, 0x25, 0x74, 0xbf, 0x0f, 0xee, 0xb2, 0xfc, 0x1e,
      },
      32, "Trust Asia Log2024-2" },
    { (const uint8_t[]){
          0x28, 0xe2, 0x81, 0x38, 0xfd, 0x83, 0x21, 0x45, 0xe9, 0xa9, 0xd6,
          0xaa, 0x75, 0x37, 0x6d, 0x83, 0x77, 0xa8, 0x85, 0x12, 0xb3, 0xc0,
          0x7f, 0x72, 0x41, 0x48, 0x21, 0xdc, 0xbd, 0xe9, 0x8c, 0x66,
      },
      32, "TrustAsia Log2025a" },
    { (const uint8_t[]){
          0x28, 0x2c, 0x8b, 0xdd, 0x81, 0x0f, 0xf9, 0x09, 0x12, 0x0a, 0xce,
          0x16, 0xd6, 0xe0, 0xec, 0x20, 0x1b, 0xea, 0x82, 0xa3, 0xa4, 0xaf,
          0x19, 0xd9, 0xef, 0xfb, 0x59, 0xe8, 0x3f, 0xdc, 0x42, 0x68,
      },
      32, "TrustAsia Log2025b" },
    { (const uint8_t[]){
          0x74, 0xdb, 0x9d, 0x58, 0xf7, 0xd4, 0x7e, 0x9d, 0xfd, 0x78, 0x7a,
          0x16, 0x2a, 0x99, 0x1c, 0x18, 0xcf, 0x69, 0x8d, 0xa7, 0xc7, 0x29,
          0x91, 0x8c, 0x9a, 0x18, 0xb0, 0x45, 0x0d, 0xba, 0x44, 0xbc,
      },
      32, "TrustAsia 'log2026a'" },
    { (const uint8_t[]){
          0x25, 0xb7, 0xef, 0xde, 0xa1, 0x13, 0x01, 0x93, 0xed, 0x93, 0x07,
          0x97, 0x70, 0xaa, 0x32, 0x2a, 0x26, 0x62, 0x0d, 0xe3, 0x5a, 0xc8,
          0xaa, 0x7c, 0x75, 0x19, 0x7d, 0xe0, 0xb1, 0xa9, 0xe0, 0x65,
      },
      32, "TrustAsia 'log2026b'" },
    { (const uint8_t[]){
          0x45, 0x35, 0x94, 0x98, 0xd9, 0x3a, 0x89, 0xe0, 0x28, 0x03, 0x08,
          0xd3, 0x7d, 0x62, 0x6d, 0xc4, 0x23, 0x75, 0x47, 0x58, 0xdc, 0xe0,
          0x37, 0x00, 0x36, 0xfb, 0xab, 0x0e, 0xdf, 0x8a, 0x6b, 0xcf,
      },
      32, "Trust Asia Log1" },
    { (const uint8_t[]){
          0xc9, 0xcf, 0x89, 0x0a, 0x21, 0x10, 0x9c, 0x66, 0x6c, 0xc1, 0x7a,
          0x3e, 0xd0, 0x65, 0xc9, 0x30, 0xd0, 0xe0, 0x13, 0x5a, 0x9f, 0xeb,
          0xa8, 0x5a, 0xf1, 0x42, 0x10, 0xb8, 0x07, 0x24, 0x21, 0xaa,
      },
      32, "GDCA CT log #1" },
    { (const uint8_t[]){
          0x92, 0x4a, 0x30, 0xf9, 0x09, 0x33, 0x6f, 0xf4, 0x35, 0xd6, 0x99,
          0x3a, 0x10, 0xac, 0x75, 0xa2, 0xc6, 0x41, 0x72, 0x8e, 0x7f, 0xc2,
          0xd6, 0x59, 0xae, 0x61, 0x88, 0xff, 0xad, 0x40, 0xce, 0x01,
      },
      32, "GDCA CT log #2" },
    { (const uint8_t[]){
          0x71, 0x7e, 0xa7, 0x42, 0x09, 0x75, 0xbe, 0x84, 0xa2, 0x72, 0x35,
          0x53, 0xf1, 0x77, 0x7c, 0x26, 0xdd, 0x51, 0xaf, 0x4e, 0x10, 0x21,
          0x44, 0x09, 0x4d, 0x90, 0x19, 0xb4, 0x62, 0xfb, 0x66, 0x68,
      },
      32, "GDCA Log 1" },
    { (const uint8_t[]){
          0x14, 0x30, 0x8d, 0x90, 0xcc, 0xd0, 0x30, 0x13, 0x50, 0x05, 0xc0,
          0x1c, 0xa5, 0x26, 0xd8, 0x1e, 0x84, 0xe8, 0x76, 0x24, 0xe3, 0x9b,
          0x62, 0x48, 0xe0, 0x8f, 0x72, 0x4a, 0xea, 0x3b, 0xb4, 0x2a,
      },
      32, "GDCA Log 2" },
    { (const uint8_t[]){
          0xe0, 0x12, 0x76, 0x29, 0xe9, 0x04, 0x96, 0x56, 0x4e, 0x3d, 0x01,
          0x47, 0x98, 0x44, 0x98, 0xaa, 0x48, 0xf8, 0xad, 0xb1, 0x66, 0x00,
          0xeb, 0x79, 0x02, 0xa1, 0xef, 0x99, 0x09, 0x90, 0x62, 0x73,
      },
      32, "PuChuangSiDa CT log" },
    { (const uint8_t[]){
          0x53, 0x7b, 0x69, 0xa3, 0x56, 0x43, 0x35, 0xa9, 0xc0, 0x49, 0x04,
          0xe3, 0x95, 0x93, 0xb2, 0xc2, 0x98, 0xeb, 0x8d, 0x7a, 0x6e, 0x83,
          0x02, 0x36, 0x35, 0xc6, 0x27, 0x24, 0x8c, 0xd6, 0xb4, 0x40,
      },
      32, "Nordu 'flimsy' log" },
    { (const uint8_t[]){
          0xaa, 0xe7, 0x0b, 0x7f, 0x3c, 0xb8, 0xd5, 0x66, 0xc8, 0x6c, 0x2f,
          0x16, 0x97, 0x9c, 0x9f, 0x44, 0x5f, 0x69, 0xab, 0x0e, 0xb4, 0x53,
          0x55, 0x89, 0xb2, 0xf7, 0x7a, 0x03, 0x01, 0x04, 0xf3, 0xcd,
      },
      32, "Nordu 'plausible' log" },
    { (const uint8_t[]){
          0xcf, 0x55, 0xe2, 0x89, 0x23, 0x49, 0x7c, 0x34, 0x0d, 0x52, 0x06,
          0xd0, 0x53, 0x53, 0xae, 0xb2, 0x58, 0x34, 0xb5, 0x2f, 0x1f, 0x8d,
          0xc9, 0x52, 0x68, 0x09, 0xf2, 0x12, 0xef, 0xdd, 0x7c, 0xa6,
      },
      32, "SHECA CT log 1" },
    { (const uint8_t[]){
          0x32, 0xdc, 0x59, 0xc2, 0xd4, 0xc4, 0x19, 0x68, 0xd5, 0x6e, 0x14,
          0xbc, 0x61, 0xac, 0x8f, 0x0e, 0x45, 0xdb, 0x39, 0xfa, 0xf3, 0xc1,
          0x55, 0xaa, 0x42, 0x52, 0xf5, 0x00, 0x1f, 0xa0, 0xc6, 0x23,
      },
      32, "SHECA CT log 2" },
    { (const uint8_t[]){
          0x96, 0x06, 0xc0, 0x2c, 0x69, 0x00, 0x33, 0xaa, 0x1d, 0x14, 0x5f,
          0x59, 0xc6, 0xe2, 0x64, 0x8d, 0x05, 0x49, 0xf0, 0xdf, 0x96, 0xaa,
          0xb8, 0xdb, 0x91, 0x5a, 0x70, 0xd8, 0xec, 0xf3, 0x90, 0xa5,
      },
      32, "Akamai CT Log" },
    { (const uint8_t[]){
          0x39, 0x37, 0x6f, 0x54, 0x5f, 0x7b, 0x46, 0x07, 0xf5, 0x97, 0x42,
          0xd7, 0x68, 0xcd, 0x5d, 0x24, 0x37, 0xbf, 0x34, 0x73, 0xb6, 0x53,
          0x4a, 0x48, 0x34, 0xbc, 0xf7, 0x2e, 0x68, 0x1c, 0x83, 0xc9,
      },
      32, "Alpha CT Log" },
    { (const uint8_t[]){
          0xb0, 0xb7, 0x84, 0xbc, 0x81, 0xc0, 0xdd, 0xc4, 0x75, 0x44, 0xe8,
          0x83, 0xf0, 0x59, 0x85, 0xbb, 0x90, 0x77, 0xd1, 0x34, 0xd8, 0xab,
          0x88, 0xb2, 0xb2, 0xe5, 0x33, 0x98, 0x0b, 0x8e, 0x50, 0x8b,
      },
      32, "Up In The Air 'Behind the Sofa' log" },
    { (const uint8_t[]){
          0x47, 0x44, 0x47, 0x7c, 0x75, 0xde, 0x42, 0x6d, 0x5c, 0x44, 0xef,
          0xd4, 0xa9, 0x2c, 0x96, 0x77, 0x59, 0x7f, 0x65, 0x7a, 0x8f, 0xe0,
          0xca, 0xdb, 0xc6, 0xd6, 0x16, 0xed, 0xa4, 0x97, 0xc4, 0x25,
      },
      32, "Qihoo 360 2020" },
    { (const uint8_t[]){
          0xc6, 0xd7, 0xed, 0x9e, 0xdb, 0x8e, 0x74, 0xf0, 0xa7, 0x1b, 0x4d,
          0x4a, 0x98, 0x4b, 0xcb, 0xeb, 0xab, 0xbd, 0x28, 0xcc, 0x1f, 0xd7,
          0x63, 0x29, 0xe8, 0x87, 0x26, 0xcd, 0x4c, 0x25, 0x46, 0x63,
      },
      32, "Qihoo 360 2021" },
    { (const uint8_t[]){
          0x66, 0x3c, 0xb0, 0x9c, 0x1f, 0xcd, 0x9b, 0xaa, 0x62, 0x76, 0x3c,
          0xcb, 0x53, 0x4e, 0xec, 0x80, 0x58, 0x12, 0x28, 0x05, 0x07, 0xac,
          0x69, 0xa4, 0x5f, 0xcd, 0x38, 0xcf, 0x4c, 0xc7, 0x4c, 0xf1,
      },
      32, "Qihoo 360 2022" },
    { (const uint8_t[]){
          0xe2, 0x64, 0x7f, 0x6e, 0xda, 0x34, 0x05, 0x03, 0xc6, 0x4d, 0x4e,
          0x10, 0xa8, 0x69, 0x68, 0x1f, 0xde, 0x9c, 0x5a, 0x2c, 0xf3, 0xb3,
          0x2d, 0x5f, 0x20, 0x0b, 0x96, 0x36, 0x05, 0x90, 0x88, 0x23,
      },
      32, "Qihoo 360 2023" },
    { (const uint8_t[]){
          0xc5, 0xcf, 0xe5, 0x4b, 0x61, 0x51, 0xb4, 0x9b, 0x14, 0x2e, 0xd2,
          0x63, 0xbd, 0xe7, 0x32, 0x93, 0x36, 0x37, 0x99, 0x79, 0x95, 0x50,
          0xae, 0x44, 0x35, 0xcd, 0x1a, 0x69, 0x97, 0xc9, 0xc3, 0xc3,
      },
      32, "Qihoo 360 v1 2020" },
    { (const uint8_t[]){
          0x48, 0x14, 0x58, 0x7c, 0xf2, 0x8b, 0x08, 0xfe, 0x68, 0x3f, 0xd2,
          0xbc, 0xd9, 0x45, 0x99, 0x4c, 0x2e, 0xb7, 0x4c, 0x8a, 0xe8, 0xc8,
          0x7f, 0xce, 0x42, 0x9b, 0x7c, 0xd3, 0x1d, 0x51, 0xbd, 0xc4,
      },
      32, "Qihoo 360 v1 2021" },
    { (const uint8_t[]){
          0x49, 0x11, 0xb8, 0xd6, 0x14, 0xcf, 0xd3, 0xd9, 0x9f, 0x16, 0xd3,
          0x76, 0x54, 0x5e, 0xe1, 0xb8, 0xcc, 0xfc, 0x51, 0x1f, 0x50, 0x9f,
          0x08, 0x0b, 0xa0, 0xa0, 0x87, 0xd9, 0x1d, 0xfa, 0xee, 0xa9,
      },
      32, "Qihoo 360 v1 2022" },
    { (const uint8_t[]){
          0xb6, 0x74, 0x0b, 0x12, 0x00, 0x2e, 0x03, 0x3f, 0xd0, 0xe7, 0xe9,
          0x41, 0xf4, 0xba, 0x3e, 0xe1, 0xbf, 0xc1, 0x49, 0xb5, 0x24, 0xb4,
          0xcf, 0x62, 0x8d, 0x53, 0xef, 0xea, 0x1f, 0x40, 0x3a, 0x8d,
      },
      32, "Qihoo 360 v1 2023" },
    { NULL, 0, NULL }
};

/*
 * Application-Layer Protocol Negotiation (ALPN) dissector tables.
 */
static dissector_table_t ssl_alpn_dissector_table;
static dissector_table_t dtls_alpn_dissector_table;

/*
 * Special cases for prefix matching of the ALPN, if the ALPN includes
 * a version number for a draft or protocol revision.
 */
typedef struct ssl_alpn_prefix_match_protocol {
    const char      *proto_prefix;
    const char      *dissector_name;
} ssl_alpn_prefix_match_protocol_t;

static const ssl_alpn_prefix_match_protocol_t ssl_alpn_prefix_match_protocols[] = {
    /* SPDY moves so fast, just 1, 2 and 3 are registered with IANA but there
     * already exists 3.1 as of this writing... match the prefix. */
    { "spdy/",              "spdy" },
    /* draft-ietf-httpbis-http2-16 */
    { "h2-",                "http2" }, /* draft versions */
};

const value_string compress_certificate_algorithm_vals[] = {
    { 1, "zlib" },
    { 2, "brotli" },
    { 3, "zstd" },
    { 0, NULL }
};


const val64_string quic_transport_parameter_id[] = {
    { SSL_HND_QUIC_TP_ORIGINAL_DESTINATION_CONNECTION_ID, "original_destination_connection_id" },
    { SSL_HND_QUIC_TP_MAX_IDLE_TIMEOUT, "max_idle_timeout" },
    { SSL_HND_QUIC_TP_STATELESS_RESET_TOKEN, "stateless_reset_token" },
    { SSL_HND_QUIC_TP_MAX_UDP_PAYLOAD_SIZE, "max_udp_payload_size" },
    { SSL_HND_QUIC_TP_INITIAL_MAX_DATA, "initial_max_data" },
    { SSL_HND_QUIC_TP_INITIAL_MAX_STREAM_DATA_BIDI_LOCAL, "initial_max_stream_data_bidi_local" },
    { SSL_HND_QUIC_TP_INITIAL_MAX_STREAM_DATA_BIDI_REMOTE, "initial_max_stream_data_bidi_remote" },
    { SSL_HND_QUIC_TP_INITIAL_MAX_STREAM_DATA_UNI, "initial_max_stream_data_uni" },
    { SSL_HND_QUIC_TP_INITIAL_MAX_STREAMS_UNI, "initial_max_streams_uni" },
    { SSL_HND_QUIC_TP_INITIAL_MAX_STREAMS_BIDI, "initial_max_streams_bidi" },
    { SSL_HND_QUIC_TP_ACK_DELAY_EXPONENT, "ack_delay_exponent" },
    { SSL_HND_QUIC_TP_MAX_ACK_DELAY, "max_ack_delay" },
    { SSL_HND_QUIC_TP_DISABLE_ACTIVE_MIGRATION, "disable_active_migration" },
    { SSL_HND_QUIC_TP_PREFERRED_ADDRESS, "preferred_address" },
    { SSL_HND_QUIC_TP_ACTIVE_CONNECTION_ID_LIMIT, "active_connection_id_limit" },
    { SSL_HND_QUIC_TP_INITIAL_SOURCE_CONNECTION_ID, "initial_source_connection_id" },
    { SSL_HND_QUIC_TP_RETRY_SOURCE_CONNECTION_ID, "retry_source_connection_id" },
    { SSL_HND_QUIC_TP_MAX_DATAGRAM_FRAME_SIZE, "max_datagram_frame_size" },
    { SSL_HND_QUIC_TP_CIBIR_ENCODING, "cibir_encoding" },
    { SSL_HND_QUIC_TP_LOSS_BITS, "loss_bits" },
    { SSL_HND_QUIC_TP_GREASE_QUIC_BIT, "grease_quic_bit" },
    { SSL_HND_QUIC_TP_ENABLE_TIME_STAMP, "enable_time_stamp" },
    { SSL_HND_QUIC_TP_ENABLE_TIME_STAMP_V2, "enable_time_stamp_v2" },
    { SSL_HND_QUIC_TP_VERSION_INFORMATION, "version_information" },
    { SSL_HND_QUIC_TP_MIN_ACK_DELAY_OLD, "min_ack_delay" },
    { SSL_HND_QUIC_TP_GOOGLE_USER_AGENT, "google_user_agent" },
    { SSL_HND_QUIC_TP_GOOGLE_KEY_UPDATE_NOT_YET_SUPPORTED, "google_key_update_not_yet_supported" },
    { SSL_HND_QUIC_TP_GOOGLE_QUIC_VERSION, "google_quic_version" },
    { SSL_HND_QUIC_TP_GOOGLE_INITIAL_RTT, "google_initial_rtt" },
    { SSL_HND_QUIC_TP_GOOGLE_SUPPORT_HANDSHAKE_DONE, "google_support_handshake_done" },
    { SSL_HND_QUIC_TP_GOOGLE_QUIC_PARAMS, "google_quic_params" },
    { SSL_HND_QUIC_TP_GOOGLE_CONNECTION_OPTIONS, "google_connection_options" },
    { SSL_HND_QUIC_TP_FACEBOOK_PARTIAL_RELIABILITY, "facebook_partial_reliability" },
    { SSL_HND_QUIC_TP_MIN_ACK_DELAY_DRAFT_V1, "min_ack_delay (draft-01)" },
    { SSL_HND_QUIC_TP_MIN_ACK_DELAY_DRAFT05, "min_ack_delay (draft-05)" },
    { SSL_HND_QUIC_TP_MIN_ACK_DELAY, "min_ack_delay" },
    { SSL_HND_QUIC_TP_ENABLE_MULTIPATH_DRAFT04, "enable_multipath (draft-04)" },
    { SSL_HND_QUIC_TP_ENABLE_MULTIPATH_DRAFT05, "enable_multipath (draft-05)" },
    { SSL_HND_QUIC_TP_ENABLE_MULTIPATH, "enable_multipath (draft-06)" },
    { SSL_HND_QUIC_TP_INITIAL_MAX_PATHS, "initial_max_paths (draft-07/08)" },
    { SSL_HND_QUIC_TP_INITIAL_MAX_PATH_ID, "initial_max_path_id" },
    { 0, NULL }
};

/* https://tools.ietf.org/html/draft-huitema-quic-ts-03 */
const val64_string quic_enable_time_stamp_v2_vals[] = {
    { 1, "I would like to receive TIME_STAMP frames" },
    { 2, "I am able to generate TIME_STAMP frames" },
    { 3, "I am able to generate TIME_STAMP frames and I would like to receive them" },
    { 0, NULL }
};

/* https://tools.ietf.org/html/draft-multipath-04 */
const val64_string quic_enable_multipath_vals[] = {
    { 0, "don't support multipath" },
    { 1, "support multipath as defined in this document" },
    { 0, NULL }
};

/* https://www.ietf.org/archive/id/draft-ietf-tls-esni-16.txt */
const value_string tls_hello_ext_ech_clienthello_types[] = {
    { 0, "Outer Client Hello" },
    { 1, "Inner Client Hello" },
    { 0, NULL }
};

/* RFC 9180 */
const value_string kem_id_type_vals[] = {
    { 0x0000, "Reserved" },
    { 0x0010, "DHKEM(P-256, HKDF-SHA256)" },
    { 0x0011, "DHKEM(P-384, HKDF-SHA384)" },
    { 0x0012, "DHKEM(P-521, HKDF-SHA512)" },
    { 0x0020, "DHKEM(X25519, HKDF-SHA256)" },
    { 0x0021, "DHKEM(X448, HKDF-SHA512)" },
    { 0,      NULL }
};
const value_string kdf_id_type_vals[] = {
    { 0x0000, "Reserved" },
    { 0x0001, "HKDF-SHA256" },
    { 0x0002, "HKDF-SHA384" },
    { 0x0003, "HKDF-SHA512" },
    { 0,      NULL }
};
const value_string aead_id_type_vals[] = {
    { 0x0000, "Reserved" },
    { 0x0001, "AES-128-GCM" },
    { 0x0002, "AES-256-GCM" },
    { 0x0003, "ChaCha20Poly1305" },
    { 0xFFFF, "Export-only" },
    { 0,      NULL }
};

const value_string token_binding_key_parameter_vals[] = {
    { 0, "rsa2048_pkcs1.5" },
    { 1, "rsa2048_pss" },
    { 2, "ecdsap256" },
    { 0, NULL }
};

/* Lookup tables }}} */

void
quic_transport_parameter_id_base_custom(char *result, uint64_t parameter_id)
{
    const char *label;
    if (IS_GREASE_QUIC(parameter_id)) {
        label = "GREASE";
    } else {
        label = val64_to_str_const(parameter_id, quic_transport_parameter_id, "Unknown");
    }
    snprintf(result, ITEM_LABEL_LENGTH, "%s (0x%02" PRIx64 ")", label, parameter_id);
}

/* we keep this internal to packet-tls-utils, as there should be
   no need to access it any other way.

   This also allows us to hide the dependency on zlib.
*/
struct _SslDecompress {
    int compression;
#if defined (HAVE_ZLIB) || defined (HAVE_ZLIBNG)
    zlib_stream istream;
#endif
};

/* To assist in parsing client/server key exchange messages
   0 indicates unknown */
int ssl_get_keyex_alg(int cipher)
{
    /* Map Cipher suite number to Key Exchange algorithm {{{ */
    switch(cipher) {
    case 0x0017:
    case 0x0018:
    case 0x0019:
    case 0x001a:
    case 0x001b:
    case 0x0034:
    case 0x003a:
    case 0x0046:
    case 0x006c:
    case 0x006d:
    case 0x0089:
    case 0x009b:
    case 0x00a6:
    case 0x00a7:
    case 0x00bf:
    case 0x00c5:
    case 0xc084:
    case 0xc085:
        return KEX_DH_ANON;
    case 0x000b:
    case 0x000c:
    case 0x000d:
    case 0x0030:
    case 0x0036:
    case 0x003e:
    case 0x0042:
    case 0x0068:
    case 0x0085:
    case 0x0097:
    case 0x00a4:
    case 0x00a5:
    case 0x00bb:
    case 0x00c1:
    case 0xc082:
    case 0xc083:
        return KEX_DH_DSS;
    case 0x000e:
    case 0x000f:
    case 0x0010:
    case 0x0031:
    case 0x0037:
    case 0x003f:
    case 0x0043:
    case 0x0069:
    case 0x0086:
    case 0x0098:
    case 0x00a0:
    case 0x00a1:
    case 0x00bc:
    case 0x00c2:
    case 0xc07e:
    case 0xc07f:
        return KEX_DH_RSA;
    case 0x0011:
    case 0x0012:
    case 0x0013:
    case 0x0032:
    case 0x0038:
    case 0x0040:
    case 0x0044:
    case 0x0063:
    case 0x0065:
    case 0x0066:
    case 0x006a:
    case 0x0087:
    case 0x0099:
    case 0x00a2:
    case 0x00a3:
    case 0x00bd:
    case 0x00c3:
    case 0xc080:
    case 0xc081:
        return KEX_DHE_DSS;
    case 0x002d:
    case 0x008e:
    case 0x008f:
    case 0x0090:
    case 0x0091:
    case 0x00aa:
    case 0x00ab:
    case 0x00b2:
    case 0x00b3:
    case 0x00b4:
    case 0x00b5:
    case 0xc090:
    case 0xc091:
    case 0xc096:
    case 0xc097:
    case 0xc0a6:
    case 0xc0a7:
    case 0xc0aa:
    case 0xc0ab:
    case 0xccad:
    case 0xe41c:
    case 0xe41d:
        return KEX_DHE_PSK;
    case 0x0014:
    case 0x0015:
    case 0x0016:
    case 0x0033:
    case 0x0039:
    case 0x0045:
    case 0x0067:
    case 0x006b:
    case 0x0088:
    case 0x009a:
    case 0x009e:
    case 0x009f:
    case 0x00be:
    case 0x00c4:
    case 0xc07c:
    case 0xc07d:
    case 0xc09e:
    case 0xc09f:
    case 0xc0a2:
    case 0xc0a3:
    case 0xccaa:
    case 0xe41e:
    case 0xe41f:
        return KEX_DHE_RSA;
    case 0xc015:
    case 0xc016:
    case 0xc017:
    case 0xc018:
    case 0xc019:
        return KEX_ECDH_ANON;
    case 0xc001:
    case 0xc002:
    case 0xc003:
    case 0xc004:
    case 0xc005:
    case 0xc025:
    case 0xc026:
    case 0xc02d:
    case 0xc02e:
    case 0xc074:
    case 0xc075:
    case 0xc088:
    case 0xc089:
        return KEX_ECDH_ECDSA;
    case 0xc00b:
    case 0xc00c:
    case 0xc00d:
    case 0xc00e:
    case 0xc00f:
    case 0xc029:
    case 0xc02a:
    case 0xc031:
    case 0xc032:
    case 0xc078:
    case 0xc079:
    case 0xc08c:
    case 0xc08d:
        return KEX_ECDH_RSA;
    case 0xc006:
    case 0xc007:
    case 0xc008:
    case 0xc009:
    case 0xc00a:
    case 0xc023:
    case 0xc024:
    case 0xc02b:
    case 0xc02c:
    case 0xc072:
    case 0xc073:
    case 0xc086:
    case 0xc087:
    case 0xc0ac:
    case 0xc0ad:
    case 0xc0ae:
    case 0xc0af:
    case 0xcca9:
    case 0xe414:
    case 0xe415:
        return KEX_ECDHE_ECDSA;
    case 0xc033:
    case 0xc034:
    case 0xc035:
    case 0xc036:
    case 0xc037:
    case 0xc038:
    case 0xc039:
    case 0xc03a:
    case 0xc03b:
    case 0xc09a:
    case 0xc09b:
    case 0xccac:
    case 0xe418:
    case 0xe419:
    case 0xd001:
    case 0xd002:
    case 0xd003:
    case 0xd005:
        return KEX_ECDHE_PSK;
    case 0xc010:
    case 0xc011:
    case 0xc012:
    case 0xc013:
    case 0xc014:
    case 0xc027:
    case 0xc028:
    case 0xc02f:
    case 0xc030:
    case 0xc076:
    case 0xc077:
    case 0xc08a:
    case 0xc08b:
    case 0xcca8:
    case 0xe412:
    case 0xe413:
        return KEX_ECDHE_RSA;
    case 0x001e:
    case 0x001f:
    case 0x0020:
    case 0x0021:
    case 0x0022:
    case 0x0023:
    case 0x0024:
    case 0x0025:
    case 0x0026:
    case 0x0027:
    case 0x0028:
    case 0x0029:
    case 0x002a:
    case 0x002b:
        return KEX_KRB5;
    case 0x002c:
    case 0x008a:
    case 0x008b:
    case 0x008c:
    case 0x008d:
    case 0x00a8:
    case 0x00a9:
    case 0x00ae:
    case 0x00af:
    case 0x00b0:
    case 0x00b1:
    case 0xc064:
    case 0xc065:
    case 0xc08e:
    case 0xc08f:
    case 0xc094:
    case 0xc095:
    case 0xc0a4:
    case 0xc0a5:
    case 0xc0a8:
    case 0xc0a9:
    case 0xccab:
    case 0xe416:
    case 0xe417:
        return KEX_PSK;
    case 0x0001:
    case 0x0002:
    case 0x0003:
    case 0x0004:
    case 0x0005:
    case 0x0006:
    case 0x0007:
    case 0x0008:
    case 0x0009:
    case 0x000a:
    case 0x002f:
    case 0x0035:
    case 0x003b:
    case 0x003c:
    case 0x003d:
    case 0x0041:
    case 0x0060:
    case 0x0061:
    case 0x0062:
    case 0x0064:
    case 0x0084:
    case 0x0096:
    case 0x009c:
    case 0x009d:
    case 0x00ba:
    case 0x00c0:
    case 0xc07a:
    case 0xc07b:
    case 0xc09c:
    case 0xc09d:
    case 0xc0a0:
    case 0xc0a1:
    case 0xe410:
    case 0xe411:
    case 0xfefe:
    case 0xfeff:
    case 0xffe0:
    case 0xffe1:
        return KEX_RSA;
    case 0x002e:
    case 0x0092:
    case 0x0093:
    case 0x0094:
    case 0x0095:
    case 0x00ac:
    case 0x00ad:
    case 0x00b6:
    case 0x00b7:
    case 0x00b8:
    case 0x00b9:
    case 0xc092:
    case 0xc093:
    case 0xc098:
    case 0xc099:
    case 0xccae:
    case 0xe41a:
    case 0xe41b:
        return KEX_RSA_PSK;
    case 0xc01a:
    case 0xc01d:
    case 0xc020:
        return KEX_SRP_SHA;
    case 0xc01c:
    case 0xc01f:
    case 0xc022:
        return KEX_SRP_SHA_DSS;
    case 0xc01b:
    case 0xc01e:
    case 0xc021:
        return KEX_SRP_SHA_RSA;
    case 0xc0ff:
        return KEX_ECJPAKE;
    case 0xe003:
    case 0xe013:
    case 0xe053:
        return KEX_ECC_SM2;
    default:
        break;
    }

    return 0;
    /* }}} */
}

static wmem_list_t *connection_id_session_list;

void
ssl_init_cid_list(void) {
    connection_id_session_list = wmem_list_new(wmem_file_scope());
}

void
ssl_cleanup_cid_list(void) {
    wmem_destroy_list(connection_id_session_list);
}

void
ssl_add_session_by_cid(SslDecryptSession *session)
{
    wmem_list_append(connection_id_session_list, session);
}

SslDecryptSession *
ssl_get_session_by_cid(tvbuff_t *tvb, uint32_t offset)
{
    SslDecryptSession * ssl_cid = NULL;
    wmem_list_frame_t *it = wmem_list_head(connection_id_session_list);

    while (it != NULL && ssl_cid == NULL) {
        SslDecryptSession * ssl = (SslDecryptSession *)wmem_list_frame_data(it);
        DISSECTOR_ASSERT(ssl != NULL);
        SslSession *session = &ssl->session;

        if (session->client_cid_len > 0 && tvb_bytes_exist(tvb, offset, session->client_cid_len)) {
            if (tvb_memeql(tvb, offset, session->client_cid, session->client_cid_len) == 0) {
                ssl_cid = ssl;
            }
        }

        if (session->server_cid_len > 0) {
            if (tvb_memeql(tvb, offset, session->server_cid, session->server_cid_len) == 0) {
                ssl_cid = ssl;
            }
        }

        it = wmem_list_frame_next(it);
    }

    return ssl_cid;
}

/* StringInfo structure (len + data) functions {{{ */

int
ssl_data_alloc(StringInfo* str, size_t len)
{
    str->data = (unsigned char *)g_malloc(len);
    /* the allocator can return a null pointer for a size equal to 0,
     * and that must be allowed */
    if (len > 0 && !str->data)
        return -1;
    str->data_len = (unsigned) len;
    return 0;
}

void
ssl_data_set(StringInfo* str, const unsigned char* data, unsigned len)
{
    DISSECTOR_ASSERT(data);
    memcpy(str->data, data, len);
    str->data_len = len;
}

static int
ssl_data_realloc(StringInfo* str, unsigned len)
{
    str->data = (unsigned char *)g_realloc(str->data, len);
    if (!str->data)
        return -1;
    str->data_len = len;
    return 0;
}

static StringInfo *
ssl_data_clone(StringInfo *str)
{
    StringInfo *cloned_str;
    cloned_str = (StringInfo *) wmem_alloc0(wmem_file_scope(),
            sizeof(StringInfo) + str->data_len);
    cloned_str->data = (unsigned char *) (cloned_str + 1);
    ssl_data_set(cloned_str, str->data, str->data_len);
    return cloned_str;
}

static int
ssl_data_copy(StringInfo* dst, StringInfo* src)
{
    if (dst->data_len < src->data_len) {
      if (ssl_data_realloc(dst, src->data_len))
        return -1;
    }
    memcpy(dst->data, src->data, src->data_len);
    dst->data_len = src->data_len;
    return 0;
}

/* from_hex converts |hex_len| bytes of hex data from |in| and sets |*out| to
 * the result. |out->data| will be allocated using wmem_file_scope. Returns true on
 * success. */
static bool from_hex(StringInfo* out, const char* in, size_t hex_len) {
    size_t i;

    if (hex_len & 1)
        return false;

    out->data = (unsigned char *)wmem_alloc(wmem_file_scope(), hex_len / 2);
    for (i = 0; i < hex_len / 2; i++) {
        int a = ws_xton(in[i*2]);
        int b = ws_xton(in[i*2 + 1]);
        if (a == -1 || b == -1)
            return false;
        out->data[i] = a << 4 | b;
    }
    out->data_len = (unsigned)hex_len / 2;
    return true;
}
/* StringInfo structure (len + data) functions }}} */


/* libgcrypt wrappers for HMAC/message digest operations {{{ */
/* hmac abstraction layer */
#define SSL_HMAC gcry_md_hd_t

static inline int
ssl_hmac_init(SSL_HMAC* md, int algo)
{
    gcry_error_t  err;
    const char   *err_str, *err_src;

    err = gcry_md_open(md,algo, GCRY_MD_FLAG_HMAC);
    if (err != 0) {
        err_str = gcry_strerror(err);
        err_src = gcry_strsource(err);
        ssl_debug_printf("ssl_hmac_init(): gcry_md_open failed %s/%s", err_str, err_src);
        return -1;
    }
    return 0;
}

static inline int
ssl_hmac_setkey(SSL_HMAC* md, const void * key, int len)
{
    gcry_error_t  err;
    const char   *err_str, *err_src;

    err = gcry_md_setkey (*(md), key, len);
    if (err != 0) {
        err_str = gcry_strerror(err);
        err_src = gcry_strsource(err);
        ssl_debug_printf("ssl_hmac_setkey(): gcry_md_setkey failed %s/%s", err_str, err_src);
        return -1;
    }
    return 0;
}

static inline int
ssl_hmac_reset(SSL_HMAC* md)
{
    gcry_md_reset(*md);
    return 0;
}

static inline void
ssl_hmac_update(SSL_HMAC* md, const void* data, int len)
{
    gcry_md_write(*(md), data, len);
}
static inline void
ssl_hmac_final(SSL_HMAC* md, unsigned char* data, unsigned* datalen)
{
    int   algo;
    unsigned len;

    algo = gcry_md_get_algo (*(md));
    len  = gcry_md_get_algo_dlen(algo);
    DISSECTOR_ASSERT(len <= *datalen);
    memcpy(data, gcry_md_read(*(md), algo), len);
    *datalen = len;
}
static inline void
ssl_hmac_cleanup(SSL_HMAC* md)
{
    gcry_md_close(*(md));
}

/* message digest abstraction layer*/
#define SSL_MD gcry_md_hd_t

static inline int
ssl_md_init(SSL_MD* md, int algo)
{
    gcry_error_t  err;
    const char   *err_str, *err_src;
    err = gcry_md_open(md,algo, 0);
    if (err != 0) {
        err_str = gcry_strerror(err);
        err_src = gcry_strsource(err);
        ssl_debug_printf("ssl_md_init(): gcry_md_open failed %s/%s", err_str, err_src);
        return -1;
    }
    return 0;
}
static inline void
ssl_md_update(SSL_MD* md, unsigned char* data, int len)
{
    gcry_md_write(*(md), data, len);
}
static inline void
ssl_md_final(SSL_MD* md, unsigned char* data, unsigned* datalen)
{
    int algo;
    int len;
    algo = gcry_md_get_algo (*(md));
    len = gcry_md_get_algo_dlen (algo);
    memcpy(data, gcry_md_read(*(md),  algo), len);
    *datalen = len;
}
static inline void
ssl_md_cleanup(SSL_MD* md)
{
    gcry_md_close(*(md));
}

static inline void
ssl_md_reset(SSL_MD* md)
{
    gcry_md_reset(*md);
}

/* md5 /sha abstraction layer */
#define SSL_SHA_CTX gcry_md_hd_t
#define SSL_MD5_CTX gcry_md_hd_t

static inline int
ssl_sha_init(SSL_SHA_CTX* md)
{
    gcry_error_t  err;
    const char   *err_str, *err_src;
    err = gcry_md_open(md, GCRY_MD_SHA1, 0);
    if (err != 0) {
        err_str = gcry_strerror(err);
        err_src = gcry_strsource(err);
        ssl_debug_printf("ssl_sha_init(): gcry_md_open failed %s/%s", err_str, err_src);
        return -1;
    }
    return 0;
}
static inline void
ssl_sha_update(SSL_SHA_CTX* md, unsigned char* data, int len)
{
    gcry_md_write(*(md), data, len);
}
static inline void
ssl_sha_final(unsigned char* buf, SSL_SHA_CTX* md)
{
    memcpy(buf, gcry_md_read(*(md),  GCRY_MD_SHA1),
           gcry_md_get_algo_dlen(GCRY_MD_SHA1));
}

static inline void
ssl_sha_reset(SSL_SHA_CTX* md)
{
    gcry_md_reset(*md);
}

static inline void
ssl_sha_cleanup(SSL_SHA_CTX* md)
{
    gcry_md_close(*(md));
}

static inline int
ssl_md5_init(SSL_MD5_CTX* md)
{
    gcry_error_t  err;
    const char   *err_str, *err_src;
    err = gcry_md_open(md,GCRY_MD_MD5, 0);
    if (err != 0) {
        err_str = gcry_strerror(err);
        err_src = gcry_strsource(err);
        ssl_debug_printf("ssl_md5_init(): gcry_md_open failed %s/%s", err_str, err_src);
        return -1;
    }
    return 0;
}
static inline void
ssl_md5_update(SSL_MD5_CTX* md, unsigned char* data, int len)
{
    gcry_md_write(*(md), data, len);
}
static inline void
ssl_md5_final(unsigned char* buf, SSL_MD5_CTX* md)
{
    memcpy(buf, gcry_md_read(*(md),  GCRY_MD_MD5),
           gcry_md_get_algo_dlen(GCRY_MD_MD5));
}

static inline void
ssl_md5_reset(SSL_MD5_CTX* md)
{
    gcry_md_reset(*md);
}

static inline void
ssl_md5_cleanup(SSL_MD5_CTX* md)
{
    gcry_md_close(*(md));
}
/* libgcrypt wrappers for HMAC/message digest operations }}} */

/* libgcrypt wrappers for Cipher state manipulation {{{ */
int
ssl_cipher_setiv(SSL_CIPHER_CTX *cipher, unsigned char* iv, int iv_len)
{
    int ret;
#if 0
    unsigned char *ivp;
    int i;
    gcry_cipher_hd_t c;
    c=(gcry_cipher_hd_t)*cipher;
#endif
    ssl_debug_printf("--------------------------------------------------------------------");
#if 0
    for(ivp=c->iv,i=0; i < iv_len; i++ )
        {
        ssl_debug_printf("%d ",ivp[i]);
        i++;
        }
#endif
    ssl_debug_printf("--------------------------------------------------------------------");
    ret = gcry_cipher_setiv(*(cipher), iv, iv_len);
#if 0
    for(ivp=c->iv,i=0; i < iv_len; i++ )
        {
        ssl_debug_printf("%d ",ivp[i]);
        i++;
        }
#endif
    ssl_debug_printf("--------------------------------------------------------------------");
    return ret;
}
/* stream cipher abstraction layer*/
static int
ssl_cipher_init(gcry_cipher_hd_t *cipher, int algo, unsigned char* sk,
        unsigned char* iv, int mode)
{
    int gcry_modes[] = {
        GCRY_CIPHER_MODE_STREAM,
        GCRY_CIPHER_MODE_CBC,
        GCRY_CIPHER_MODE_GCM,
        GCRY_CIPHER_MODE_CCM,
        GCRY_CIPHER_MODE_CCM,
        GCRY_CIPHER_MODE_POLY1305,
        GCRY_CIPHER_MODE_ECB, /* used for DTLSv1.3 seq number encryption */
    };
    int err;
    if (algo == -1) {
        /* NULL mode */
        *(cipher) = (gcry_cipher_hd_t)-1;
        return 0;
    }
    err = gcry_cipher_open(cipher, algo, gcry_modes[mode], 0);
    if (err !=0)
        return  -1;
    err = gcry_cipher_setkey(*(cipher), sk, gcry_cipher_get_algo_keylen (algo));
    if (err != 0)
        return -1;
    /* AEAD cipher suites will set the nonce later. */
    if (mode == MODE_CBC) {
        err = gcry_cipher_setiv(*(cipher), iv, gcry_cipher_get_algo_blklen(algo));
        if (err != 0)
            return -1;
    }
    return 0;
}
static inline int
ssl_cipher_decrypt(gcry_cipher_hd_t *cipher, unsigned char * out, int outl,
                   const unsigned char * in, int inl)
{
    if ((*cipher) == (gcry_cipher_hd_t)-1)
    {
        if (in && inl)
            memcpy(out, in, outl < inl ? outl : inl);
        return 0;
    }
    return gcry_cipher_decrypt ( *(cipher), out, outl, in, inl);
}
static inline int
ssl_get_digest_by_name(const char*name)
{
    return gcry_md_map_name(name);
}
static inline int
ssl_get_cipher_by_name(const char* name)
{
    return gcry_cipher_map_name(name);
}

static inline void
ssl_cipher_cleanup(gcry_cipher_hd_t *cipher)
{
    if ((*cipher) != (gcry_cipher_hd_t)-1)
        gcry_cipher_close(*cipher);
    *cipher = NULL;
}
/* }}} */

/* Digests, Ciphers and Cipher Suites registry {{{ */
static const SslDigestAlgo digests[]={
    {"MD5",     16},
    {"SHA1",    20},
    {"SHA256",  32},
    {"SHA384",  48},
    {"SM3",     32},
    {"Not Applicable",  0},
};

#define DIGEST_MAX_SIZE 48

/* get index digest index */
static const SslDigestAlgo *
ssl_cipher_suite_dig(const SslCipherSuite *cs) {
    return &digests[cs->dig - DIG_MD5];
}

static const char *ciphers[]={
    "DES",
    "3DES",
    "ARCFOUR", /* libgcrypt does not support rc4, but this should be 100% compatible*/
    "RFC2268_128", /* libgcrypt name for RC2 with a 128-bit key */
    "IDEA",
    "AES",
    "AES256",
    "CAMELLIA128",
    "CAMELLIA256",
    "SEED",
    "CHACHA20", /* since Libgcrypt 1.7.0 */
    "SM1",
    "SM4",
    "*UNKNOWN*"
};

static const SslCipherSuite cipher_suites[]={
    {0x0001,KEX_RSA,            ENC_NULL,       DIG_MD5,    MODE_STREAM},   /* TLS_RSA_WITH_NULL_MD5 */
    {0x0002,KEX_RSA,            ENC_NULL,       DIG_SHA,    MODE_STREAM},   /* TLS_RSA_WITH_NULL_SHA */
    {0x0003,KEX_RSA,            ENC_RC4,        DIG_MD5,    MODE_STREAM},   /* TLS_RSA_EXPORT_WITH_RC4_40_MD5 */
    {0x0004,KEX_RSA,            ENC_RC4,        DIG_MD5,    MODE_STREAM},   /* TLS_RSA_WITH_RC4_128_MD5 */
    {0x0005,KEX_RSA,            ENC_RC4,        DIG_SHA,    MODE_STREAM},   /* TLS_RSA_WITH_RC4_128_SHA */
    {0x0006,KEX_RSA,            ENC_RC2,        DIG_MD5,    MODE_CBC   },   /* TLS_RSA_EXPORT_WITH_RC2_CBC_40_MD5 */
    {0x0007,KEX_RSA,            ENC_IDEA,       DIG_SHA,    MODE_CBC   },   /* TLS_RSA_WITH_IDEA_CBC_SHA */
    {0x0008,KEX_RSA,            ENC_DES,        DIG_SHA,    MODE_CBC   },   /* TLS_RSA_EXPORT_WITH_DES40_CBC_SHA */
    {0x0009,KEX_RSA,            ENC_DES,        DIG_SHA,    MODE_CBC   },   /* TLS_RSA_WITH_DES_CBC_SHA */
    {0x000A,KEX_RSA,            ENC_3DES,       DIG_SHA,    MODE_CBC   },   /* TLS_RSA_WITH_3DES_EDE_CBC_SHA */
    {0x000B,KEX_DH_DSS,         ENC_DES,        DIG_SHA,    MODE_CBC   },   /* TLS_DH_DSS_EXPORT_WITH_DES40_CBC_SHA */
    {0x000C,KEX_DH_DSS,         ENC_DES,        DIG_SHA,    MODE_CBC   },   /* TLS_DH_DSS_WITH_DES_CBC_SHA */
    {0x000D,KEX_DH_DSS,         ENC_3DES,       DIG_SHA,    MODE_CBC   },   /* TLS_DH_DSS_WITH_3DES_EDE_CBC_SHA */
    {0x000E,KEX_DH_RSA,         ENC_DES,        DIG_SHA,    MODE_CBC   },   /* TLS_DH_RSA_EXPORT_WITH_DES40_CBC_SHA */
    {0x000F,KEX_DH_RSA,         ENC_DES,        DIG_SHA,    MODE_CBC   },   /* TLS_DH_RSA_WITH_DES_CBC_SHA */
    {0x0010,KEX_DH_RSA,         ENC_3DES,       DIG_SHA,    MODE_CBC   },   /* TLS_DH_RSA_WITH_3DES_EDE_CBC_SHA */
    {0x0011,KEX_DHE_DSS,        ENC_DES,        DIG_SHA,    MODE_CBC   },   /* TLS_DHE_DSS_EXPORT_WITH_DES40_CBC_SHA */
    {0x0012,KEX_DHE_DSS,        ENC_DES,        DIG_SHA,    MODE_CBC   },   /* TLS_DHE_DSS_WITH_DES_CBC_SHA */
    {0x0013,KEX_DHE_DSS,        ENC_3DES,       DIG_SHA,    MODE_CBC   },   /* TLS_DHE_DSS_WITH_3DES_EDE_CBC_SHA */
    {0x0014,KEX_DHE_RSA,        ENC_DES,        DIG_SHA,    MODE_CBC   },   /* TLS_DHE_RSA_EXPORT_WITH_DES40_CBC_SHA */
    {0x0015,KEX_DHE_RSA,        ENC_DES,        DIG_SHA,    MODE_CBC   },   /* TLS_DHE_RSA_WITH_DES_CBC_SHA */
    {0x0016,KEX_DHE_RSA,        ENC_3DES,       DIG_SHA,    MODE_CBC   },   /* TLS_DHE_RSA_WITH_3DES_EDE_CBC_SHA */
    {0x0017,KEX_DH_ANON,        ENC_RC4,        DIG_MD5,    MODE_STREAM},   /* TLS_DH_anon_EXPORT_WITH_RC4_40_MD5 */
    {0x0018,KEX_DH_ANON,        ENC_RC4,        DIG_MD5,    MODE_STREAM},   /* TLS_DH_anon_WITH_RC4_128_MD5 */
    {0x0019,KEX_DH_ANON,        ENC_DES,        DIG_SHA,    MODE_CBC   },   /* TLS_DH_anon_EXPORT_WITH_DES40_CBC_SHA */
    {0x001A,KEX_DH_ANON,        ENC_DES,        DIG_SHA,    MODE_CBC   },   /* TLS_DH_anon_WITH_DES_CBC_SHA */
    {0x001B,KEX_DH_ANON,        ENC_3DES,       DIG_SHA,    MODE_CBC   },   /* TLS_DH_anon_WITH_3DES_EDE_CBC_SHA */
    {0x002C,KEX_PSK,            ENC_NULL,       DIG_SHA,    MODE_STREAM},   /* TLS_PSK_WITH_NULL_SHA */
    {0x002D,KEX_DHE_PSK,        ENC_NULL,       DIG_SHA,    MODE_STREAM},   /* TLS_DHE_PSK_WITH_NULL_SHA */
    {0x002E,KEX_RSA_PSK,        ENC_NULL,       DIG_SHA,    MODE_STREAM},   /* TLS_RSA_PSK_WITH_NULL_SHA */
    {0x002F,KEX_RSA,            ENC_AES,        DIG_SHA,    MODE_CBC   },   /* TLS_RSA_WITH_AES_128_CBC_SHA */
    {0x0030,KEX_DH_DSS,         ENC_AES,        DIG_SHA,    MODE_CBC   },   /* TLS_DH_DSS_WITH_AES_128_CBC_SHA */
    {0x0031,KEX_DH_RSA,         ENC_AES,        DIG_SHA,    MODE_CBC   },   /* TLS_DH_RSA_WITH_AES_128_CBC_SHA */
    {0x0032,KEX_DHE_DSS,        ENC_AES,        DIG_SHA,    MODE_CBC   },   /* TLS_DHE_DSS_WITH_AES_128_CBC_SHA */
    {0x0033,KEX_DHE_RSA,        ENC_AES,        DIG_SHA,    MODE_CBC   },   /* TLS_DHE_RSA_WITH_AES_128_CBC_SHA */
    {0x0034,KEX_DH_ANON,        ENC_AES,        DIG_SHA,    MODE_CBC   },   /* TLS_DH_anon_WITH_AES_128_CBC_SHA */
    {0x0035,KEX_RSA,            ENC_AES256,     DIG_SHA,    MODE_CBC   },   /* TLS_RSA_WITH_AES_256_CBC_SHA */
    {0x0036,KEX_DH_DSS,         ENC_AES256,     DIG_SHA,    MODE_CBC   },   /* TLS_DH_DSS_WITH_AES_256_CBC_SHA */
    {0x0037,KEX_DH_RSA,         ENC_AES256,     DIG_SHA,    MODE_CBC   },   /* TLS_DH_RSA_WITH_AES_256_CBC_SHA */
    {0x0038,KEX_DHE_DSS,        ENC_AES256,     DIG_SHA,    MODE_CBC   },   /* TLS_DHE_DSS_WITH_AES_256_CBC_SHA */
    {0x0039,KEX_DHE_RSA,        ENC_AES256,     DIG_SHA,    MODE_CBC   },   /* TLS_DHE_RSA_WITH_AES_256_CBC_SHA */
    {0x003A,KEX_DH_ANON,        ENC_AES256,     DIG_SHA,    MODE_CBC   },   /* TLS_DH_anon_WITH_AES_256_CBC_SHA */
    {0x003B,KEX_RSA,            ENC_NULL,       DIG_SHA256, MODE_STREAM},   /* TLS_RSA_WITH_NULL_SHA256 */
    {0x003C,KEX_RSA,            ENC_AES,        DIG_SHA256, MODE_CBC   },   /* TLS_RSA_WITH_AES_128_CBC_SHA256 */
    {0x003D,KEX_RSA,            ENC_AES256,     DIG_SHA256, MODE_CBC   },   /* TLS_RSA_WITH_AES_256_CBC_SHA256 */
    {0x003E,KEX_DH_DSS,         ENC_AES,        DIG_SHA256, MODE_CBC   },   /* TLS_DH_DSS_WITH_AES_128_CBC_SHA256 */
    {0x003F,KEX_DH_RSA,         ENC_AES,        DIG_SHA256, MODE_CBC   },   /* TLS_DH_RSA_WITH_AES_128_CBC_SHA256 */
    {0x0040,KEX_DHE_DSS,        ENC_AES,        DIG_SHA256, MODE_CBC   },   /* TLS_DHE_DSS_WITH_AES_128_CBC_SHA256 */
    {0x0041,KEX_RSA,            ENC_CAMELLIA128,DIG_SHA,    MODE_CBC   },   /* TLS_RSA_WITH_CAMELLIA_128_CBC_SHA */
    {0x0042,KEX_DH_DSS,         ENC_CAMELLIA128,DIG_SHA,    MODE_CBC   },   /* TLS_DH_DSS_WITH_CAMELLIA_128_CBC_SHA */
    {0x0043,KEX_DH_RSA,         ENC_CAMELLIA128,DIG_SHA,    MODE_CBC   },   /* TLS_DH_RSA_WITH_CAMELLIA_128_CBC_SHA */
    {0x0044,KEX_DHE_DSS,        ENC_CAMELLIA128,DIG_SHA,    MODE_CBC   },   /* TLS_DHE_DSS_WITH_CAMELLIA_128_CBC_SHA */
    {0x0045,KEX_DHE_RSA,        ENC_CAMELLIA128,DIG_SHA,    MODE_CBC   },   /* TLS_DHE_RSA_WITH_CAMELLIA_128_CBC_SHA */
    {0x0046,KEX_DH_ANON,        ENC_CAMELLIA128,DIG_SHA,    MODE_CBC   },   /* TLS_DH_anon_WITH_CAMELLIA_128_CBC_SHA */
    {0x0060,KEX_RSA,            ENC_RC4,        DIG_MD5,    MODE_STREAM},   /* TLS_RSA_EXPORT1024_WITH_RC4_56_MD5 */
    {0x0061,KEX_RSA,            ENC_RC2,        DIG_MD5,    MODE_STREAM},   /* TLS_RSA_EXPORT1024_WITH_RC2_CBC_56_MD5 */
    {0x0062,KEX_RSA,            ENC_DES,        DIG_SHA,    MODE_CBC   },   /* TLS_RSA_EXPORT1024_WITH_DES_CBC_SHA */
    {0x0063,KEX_DHE_DSS,        ENC_DES,        DIG_SHA,    MODE_CBC   },   /* TLS_DHE_DSS_EXPORT1024_WITH_DES_CBC_SHA */
    {0x0064,KEX_RSA,            ENC_RC4,        DIG_SHA,    MODE_STREAM},   /* TLS_RSA_EXPORT1024_WITH_RC4_56_SHA */
    {0x0065,KEX_DHE_DSS,        ENC_RC4,        DIG_SHA,    MODE_STREAM},   /* TLS_DHE_DSS_EXPORT1024_WITH_RC4_56_SHA */
    {0x0066,KEX_DHE_DSS,        ENC_RC4,        DIG_SHA,    MODE_STREAM},   /* TLS_DHE_DSS_WITH_RC4_128_SHA */
    {0x0067,KEX_DHE_RSA,        ENC_AES,        DIG_SHA256, MODE_CBC   },   /* TLS_DHE_RSA_WITH_AES_128_CBC_SHA256 */
    {0x0068,KEX_DH_DSS,         ENC_AES256,     DIG_SHA256, MODE_CBC   },   /* TLS_DH_DSS_WITH_AES_256_CBC_SHA256 */
    {0x0069,KEX_DH_RSA,         ENC_AES256,     DIG_SHA256, MODE_CBC   },   /* TLS_DH_RSA_WITH_AES_256_CBC_SHA256 */
    {0x006A,KEX_DHE_DSS,        ENC_AES256,     DIG_SHA256, MODE_CBC   },   /* TLS_DHE_DSS_WITH_AES_256_CBC_SHA256 */
    {0x006B,KEX_DHE_RSA,        ENC_AES256,     DIG_SHA256, MODE_CBC   },   /* TLS_DHE_RSA_WITH_AES_256_CBC_SHA256 */
    {0x006C,KEX_DH_ANON,        ENC_AES,        DIG_SHA256, MODE_CBC   },   /* TLS_DH_anon_WITH_AES_128_CBC_SHA256 */
    {0x006D,KEX_DH_ANON,        ENC_AES256,     DIG_SHA256, MODE_CBC   },   /* TLS_DH_anon_WITH_AES_256_CBC_SHA256 */
    {0x0084,KEX_RSA,            ENC_CAMELLIA256,DIG_SHA,    MODE_CBC   },   /* TLS_RSA_WITH_CAMELLIA_256_CBC_SHA */
    {0x0085,KEX_DH_DSS,         ENC_CAMELLIA256,DIG_SHA,    MODE_CBC   },   /* TLS_DH_DSS_WITH_CAMELLIA_256_CBC_SHA */
    {0x0086,KEX_DH_RSA,         ENC_CAMELLIA256,DIG_SHA,    MODE_CBC   },   /* TLS_DH_RSA_WITH_CAMELLIA_256_CBC_SHA */
    {0x0087,KEX_DHE_DSS,        ENC_CAMELLIA256,DIG_SHA,    MODE_CBC   },   /* TLS_DHE_DSS_WITH_CAMELLIA_256_CBC_SHA */
    {0x0088,KEX_DHE_RSA,        ENC_CAMELLIA256,DIG_SHA,    MODE_CBC   },   /* TLS_DHE_RSA_WITH_CAMELLIA_256_CBC_SHA */
    {0x0089,KEX_DH_ANON,        ENC_CAMELLIA256,DIG_SHA,    MODE_CBC   },   /* TLS_DH_anon_WITH_CAMELLIA_256_CBC_SHA */
    {0x008A,KEX_PSK,            ENC_RC4,        DIG_SHA,    MODE_STREAM},   /* TLS_PSK_WITH_RC4_128_SHA */
    {0x008B,KEX_PSK,            ENC_3DES,       DIG_SHA,    MODE_CBC   },   /* TLS_PSK_WITH_3DES_EDE_CBC_SHA */
    {0x008C,KEX_PSK,            ENC_AES,        DIG_SHA,    MODE_CBC   },   /* TLS_PSK_WITH_AES_128_CBC_SHA */
    {0x008D,KEX_PSK,            ENC_AES256,     DIG_SHA,    MODE_CBC   },   /* TLS_PSK_WITH_AES_256_CBC_SHA */
    {0x008E,KEX_DHE_PSK,        ENC_RC4,        DIG_SHA,    MODE_STREAM},   /* TLS_DHE_PSK_WITH_RC4_128_SHA */
    {0x008F,KEX_DHE_PSK,        ENC_3DES,       DIG_SHA,    MODE_CBC   },   /* TLS_DHE_PSK_WITH_3DES_EDE_CBC_SHA */
    {0x0090,KEX_DHE_PSK,        ENC_AES,        DIG_SHA,    MODE_CBC   },   /* TLS_DHE_PSK_WITH_AES_128_CBC_SHA */
    {0x0091,KEX_DHE_PSK,        ENC_AES256,     DIG_SHA,    MODE_CBC   },   /* TLS_DHE_PSK_WITH_AES_256_CBC_SHA */
    {0x0092,KEX_RSA_PSK,        ENC_RC4,        DIG_SHA,    MODE_STREAM},   /* TLS_RSA_PSK_WITH_RC4_128_SHA */
    {0x0093,KEX_RSA_PSK,        ENC_3DES,       DIG_SHA,    MODE_CBC   },   /* TLS_RSA_PSK_WITH_3DES_EDE_CBC_SHA */
    {0x0094,KEX_RSA_PSK,        ENC_AES,        DIG_SHA,    MODE_CBC   },   /* TLS_RSA_PSK_WITH_AES_128_CBC_SHA */
    {0x0095,KEX_RSA_PSK,        ENC_AES256,     DIG_SHA,    MODE_CBC   },   /* TLS_RSA_PSK_WITH_AES_256_CBC_SHA */
    {0x0096,KEX_RSA,            ENC_SEED,       DIG_SHA,    MODE_CBC   },   /* TLS_RSA_WITH_SEED_CBC_SHA */
    {0x0097,KEX_DH_DSS,         ENC_SEED,       DIG_SHA,    MODE_CBC   },   /* TLS_DH_DSS_WITH_SEED_CBC_SHA */
    {0x0098,KEX_DH_RSA,         ENC_SEED,       DIG_SHA,    MODE_CBC   },   /* TLS_DH_RSA_WITH_SEED_CBC_SHA */
    {0x0099,KEX_DHE_DSS,        ENC_SEED,       DIG_SHA,    MODE_CBC   },   /* TLS_DHE_DSS_WITH_SEED_CBC_SHA */
    {0x009A,KEX_DHE_RSA,        ENC_SEED,       DIG_SHA,    MODE_CBC   },   /* TLS_DHE_RSA_WITH_SEED_CBC_SHA */
    {0x009B,KEX_DH_ANON,        ENC_SEED,       DIG_SHA,    MODE_CBC   },   /* TLS_DH_anon_WITH_SEED_CBC_SHA */
    {0x009C,KEX_RSA,            ENC_AES,        DIG_SHA256, MODE_GCM   },   /* TLS_RSA_WITH_AES_128_GCM_SHA256 */
    {0x009D,KEX_RSA,            ENC_AES256,     DIG_SHA384, MODE_GCM   },   /* TLS_RSA_WITH_AES_256_GCM_SHA384 */
    {0x009E,KEX_DHE_RSA,        ENC_AES,        DIG_SHA256, MODE_GCM   },   /* TLS_DHE_RSA_WITH_AES_128_GCM_SHA256 */
    {0x009F,KEX_DHE_RSA,        ENC_AES256,     DIG_SHA384, MODE_GCM   },   /* TLS_DHE_RSA_WITH_AES_256_GCM_SHA384 */
    {0x00A0,KEX_DH_RSA,         ENC_AES,        DIG_SHA256, MODE_GCM   },   /* TLS_DH_RSA_WITH_AES_128_GCM_SHA256 */
    {0x00A1,KEX_DH_RSA,         ENC_AES256,     DIG_SHA384, MODE_GCM   },   /* TLS_DH_RSA_WITH_AES_256_GCM_SHA384 */
    {0x00A2,KEX_DHE_DSS,        ENC_AES,        DIG_SHA256, MODE_GCM   },   /* TLS_DHE_DSS_WITH_AES_128_GCM_SHA256 */
    {0x00A3,KEX_DHE_DSS,        ENC_AES256,     DIG_SHA384, MODE_GCM   },   /* TLS_DHE_DSS_WITH_AES_256_GCM_SHA384 */
    {0x00A4,KEX_DH_DSS,         ENC_AES,        DIG_SHA256, MODE_GCM   },   /* TLS_DH_DSS_WITH_AES_128_GCM_SHA256 */
    {0x00A5,KEX_DH_DSS,         ENC_AES256,     DIG_SHA384, MODE_GCM   },   /* TLS_DH_DSS_WITH_AES_256_GCM_SHA384 */
    {0x00A6,KEX_DH_ANON,        ENC_AES,        DIG_SHA256, MODE_GCM   },   /* TLS_DH_anon_WITH_AES_128_GCM_SHA256 */
    {0x00A7,KEX_DH_ANON,        ENC_AES256,     DIG_SHA384, MODE_GCM   },   /* TLS_DH_anon_WITH_AES_256_GCM_SHA384 */
    {0x00A8,KEX_PSK,            ENC_AES,        DIG_SHA256, MODE_GCM   },   /* TLS_PSK_WITH_AES_128_GCM_SHA256 */
    {0x00A9,KEX_PSK,            ENC_AES256,     DIG_SHA384, MODE_GCM   },   /* TLS_PSK_WITH_AES_256_GCM_SHA384 */
    {0x00AA,KEX_DHE_PSK,        ENC_AES,        DIG_SHA256, MODE_GCM   },   /* TLS_DHE_PSK_WITH_AES_128_GCM_SHA256 */
    {0x00AB,KEX_DHE_PSK,        ENC_AES256,     DIG_SHA384, MODE_GCM   },   /* TLS_DHE_PSK_WITH_AES_256_GCM_SHA384 */
    {0x00AC,KEX_RSA_PSK,        ENC_AES,        DIG_SHA256, MODE_GCM   },   /* TLS_RSA_PSK_WITH_AES_128_GCM_SHA256 */
    {0x00AD,KEX_RSA_PSK,        ENC_AES256,     DIG_SHA384, MODE_GCM   },   /* TLS_RSA_PSK_WITH_AES_256_GCM_SHA384 */
    {0x00AE,KEX_PSK,            ENC_AES,        DIG_SHA256, MODE_CBC   },   /* TLS_PSK_WITH_AES_128_CBC_SHA256 */
    {0x00AF,KEX_PSK,            ENC_AES256,     DIG_SHA384, MODE_CBC   },   /* TLS_PSK_WITH_AES_256_CBC_SHA384 */
    {0x00B0,KEX_PSK,            ENC_NULL,       DIG_SHA256, MODE_STREAM},   /* TLS_PSK_WITH_NULL_SHA256 */
    {0x00B1,KEX_PSK,            ENC_NULL,       DIG_SHA384, MODE_STREAM},   /* TLS_PSK_WITH_NULL_SHA384 */
    {0x00B2,KEX_DHE_PSK,        ENC_AES,        DIG_SHA256, MODE_CBC   },   /* TLS_DHE_PSK_WITH_AES_128_CBC_SHA256 */
    {0x00B3,KEX_DHE_PSK,        ENC_AES256,     DIG_SHA384, MODE_CBC   },   /* TLS_DHE_PSK_WITH_AES_256_CBC_SHA384 */
    {0x00B4,KEX_DHE_PSK,        ENC_NULL,       DIG_SHA256, MODE_STREAM},   /* TLS_DHE_PSK_WITH_NULL_SHA256 */
    {0x00B5,KEX_DHE_PSK,        ENC_NULL,       DIG_SHA384, MODE_STREAM},   /* TLS_DHE_PSK_WITH_NULL_SHA384 */
    {0x00B6,KEX_RSA_PSK,        ENC_AES,        DIG_SHA256, MODE_CBC   },   /* TLS_RSA_PSK_WITH_AES_128_CBC_SHA256 */
    {0x00B7,KEX_RSA_PSK,        ENC_AES256,     DIG_SHA384, MODE_CBC   },   /* TLS_RSA_PSK_WITH_AES_256_CBC_SHA384 */
    {0x00B8,KEX_RSA_PSK,        ENC_NULL,       DIG_SHA256, MODE_STREAM},   /* TLS_RSA_PSK_WITH_NULL_SHA256 */
    {0x00B9,KEX_RSA_PSK,        ENC_NULL,       DIG_SHA384, MODE_STREAM},   /* TLS_RSA_PSK_WITH_NULL_SHA384 */
    {0x00BA,KEX_RSA,            ENC_CAMELLIA128,DIG_SHA256, MODE_CBC   },   /* TLS_RSA_WITH_CAMELLIA_128_CBC_SHA256 */
    {0x00BB,KEX_DH_DSS,         ENC_CAMELLIA128,DIG_SHA256, MODE_CBC   },   /* TLS_DH_DSS_WITH_CAMELLIA_128_CBC_SHA256 */
    {0x00BC,KEX_DH_RSA,         ENC_CAMELLIA128,DIG_SHA256, MODE_CBC   },   /* TLS_DH_RSA_WITH_CAMELLIA_128_CBC_SHA256 */
    {0x00BD,KEX_DHE_DSS,        ENC_CAMELLIA128,DIG_SHA256, MODE_CBC   },   /* TLS_DHE_DSS_WITH_CAMELLIA_128_CBC_SHA256 */
    {0x00BE,KEX_DHE_RSA,        ENC_CAMELLIA128,DIG_SHA256, MODE_CBC   },   /* TLS_DHE_RSA_WITH_CAMELLIA_128_CBC_SHA256 */
    {0x00BF,KEX_DH_ANON,        ENC_CAMELLIA128,DIG_SHA256, MODE_CBC   },   /* TLS_DH_anon_WITH_CAMELLIA_128_CBC_SHA256 */
    {0x00C0,KEX_RSA,            ENC_CAMELLIA256,DIG_SHA256, MODE_CBC   },   /* TLS_RSA_WITH_CAMELLIA_256_CBC_SHA256 */
    {0x00C1,KEX_DH_DSS,         ENC_CAMELLIA256,DIG_SHA256, MODE_CBC   },   /* TLS_DH_DSS_WITH_CAMELLIA_256_CBC_SHA256 */
    {0x00C2,KEX_DH_RSA,         ENC_CAMELLIA256,DIG_SHA256, MODE_CBC   },   /* TLS_DH_RSA_WITH_CAMELLIA_256_CBC_SHA256 */
    {0x00C3,KEX_DHE_DSS,        ENC_CAMELLIA256,DIG_SHA256, MODE_CBC   },   /* TLS_DHE_DSS_WITH_CAMELLIA_256_CBC_SHA256 */
    {0x00C4,KEX_DHE_RSA,        ENC_CAMELLIA256,DIG_SHA256, MODE_CBC   },   /* TLS_DHE_RSA_WITH_CAMELLIA_256_CBC_SHA256 */
    {0x00C5,KEX_DH_ANON,        ENC_CAMELLIA256,DIG_SHA256, MODE_CBC   },   /* TLS_DH_anon_WITH_CAMELLIA_256_CBC_SHA256 */

    /* NOTE: TLS 1.3 cipher suites are incompatible with TLS 1.2. */
    {0x1301,KEX_TLS13,          ENC_AES,        DIG_SHA256, MODE_GCM   },   /* TLS_AES_128_GCM_SHA256 */
    {0x1302,KEX_TLS13,          ENC_AES256,     DIG_SHA384, MODE_GCM   },   /* TLS_AES_256_GCM_SHA384 */
    {0x1303,KEX_TLS13,          ENC_CHACHA20,   DIG_SHA256, MODE_POLY1305 }, /* TLS_CHACHA20_POLY1305_SHA256 */
    {0x1304,KEX_TLS13,          ENC_AES,        DIG_SHA256, MODE_CCM   },   /* TLS_AES_128_CCM_SHA256 */
    {0x1305,KEX_TLS13,          ENC_AES,        DIG_SHA256, MODE_CCM_8 },   /* TLS_AES_128_CCM_8_SHA256 */
    {0x00C6,KEX_TLS13,          ENC_SM4,        DIG_SM3,    MODE_GCM   },   /* TLS_SM4_GCM_SM3 */

    {0xC001,KEX_ECDH_ECDSA,     ENC_NULL,       DIG_SHA,    MODE_STREAM},   /* TLS_ECDH_ECDSA_WITH_NULL_SHA */
    {0xC002,KEX_ECDH_ECDSA,     ENC_RC4,        DIG_SHA,    MODE_STREAM},   /* TLS_ECDH_ECDSA_WITH_RC4_128_SHA */
    {0xC003,KEX_ECDH_ECDSA,     ENC_3DES,       DIG_SHA,    MODE_CBC   },   /* TLS_ECDH_ECDSA_WITH_3DES_EDE_CBC_SHA */
    {0xC004,KEX_ECDH_ECDSA,     ENC_AES,        DIG_SHA,    MODE_CBC   },   /* TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA */
    {0xC005,KEX_ECDH_ECDSA,     ENC_AES256,     DIG_SHA,    MODE_CBC   },   /* TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA */
    {0xC006,KEX_ECDHE_ECDSA,    ENC_NULL,       DIG_SHA,    MODE_STREAM},   /* TLS_ECDHE_ECDSA_WITH_NULL_SHA */
    {0xC007,KEX_ECDHE_ECDSA,    ENC_RC4,        DIG_SHA,    MODE_STREAM},   /* TLS_ECDHE_ECDSA_WITH_RC4_128_SHA */
    {0xC008,KEX_ECDHE_ECDSA,    ENC_3DES,       DIG_SHA,    MODE_CBC   },   /* TLS_ECDHE_ECDSA_WITH_3DES_EDE_CBC_SHA */
    {0xC009,KEX_ECDHE_ECDSA,    ENC_AES,        DIG_SHA,    MODE_CBC   },   /* TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA */
    {0xC00A,KEX_ECDHE_ECDSA,    ENC_AES256,     DIG_SHA,    MODE_CBC   },   /* TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA */
    {0xC00B,KEX_ECDH_RSA,       ENC_NULL,       DIG_SHA,    MODE_STREAM},   /* TLS_ECDH_RSA_WITH_NULL_SHA */
    {0xC00C,KEX_ECDH_RSA,       ENC_RC4,        DIG_SHA,    MODE_STREAM},   /* TLS_ECDH_RSA_WITH_RC4_128_SHA */
    {0xC00D,KEX_ECDH_RSA,       ENC_3DES,       DIG_SHA,    MODE_CBC   },   /* TLS_ECDH_RSA_WITH_3DES_EDE_CBC_SHA */
    {0xC00E,KEX_ECDH_RSA,       ENC_AES,        DIG_SHA,    MODE_CBC   },   /* TLS_ECDH_RSA_WITH_AES_128_CBC_SHA */
    {0xC00F,KEX_ECDH_RSA,       ENC_AES256,     DIG_SHA,    MODE_CBC   },   /* TLS_ECDH_RSA_WITH_AES_256_CBC_SHA */
    {0xC0FF,KEX_ECJPAKE,        ENC_AES,        DIG_NA,     MODE_CCM_8 },   /* TLS_ECJPAKE_WITH_AES_128_CCM_8 */
    {0xC010,KEX_ECDHE_RSA,      ENC_NULL,       DIG_SHA,    MODE_STREAM},   /* TLS_ECDHE_RSA_WITH_NULL_SHA */
    {0xC011,KEX_ECDHE_RSA,      ENC_RC4,        DIG_SHA,    MODE_STREAM},   /* TLS_ECDHE_RSA_WITH_RC4_128_SHA */
    {0xC012,KEX_ECDHE_RSA,      ENC_3DES,       DIG_SHA,    MODE_CBC   },   /* TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA */
    {0xC013,KEX_ECDHE_RSA,      ENC_AES,        DIG_SHA,    MODE_CBC   },   /* TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA */
    {0xC014,KEX_ECDHE_RSA,      ENC_AES256,     DIG_SHA,    MODE_CBC   },   /* TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA */
    {0xC015,KEX_ECDH_ANON,      ENC_NULL,       DIG_SHA,    MODE_STREAM},   /* TLS_ECDH_anon_WITH_NULL_SHA */
    {0xC016,KEX_ECDH_ANON,      ENC_RC4,        DIG_SHA,    MODE_STREAM},   /* TLS_ECDH_anon_WITH_RC4_128_SHA */
    {0xC017,KEX_ECDH_ANON,      ENC_3DES,       DIG_SHA,    MODE_CBC   },   /* TLS_ECDH_anon_WITH_3DES_EDE_CBC_SHA */
    {0xC018,KEX_ECDH_ANON,      ENC_AES,        DIG_SHA,    MODE_CBC   },   /* TLS_ECDH_anon_WITH_AES_128_CBC_SHA */
    {0xC019,KEX_ECDH_ANON,      ENC_AES256,     DIG_SHA,    MODE_CBC   },   /* TLS_ECDH_anon_WITH_AES_256_CBC_SHA */
    {0xC01A,KEX_SRP_SHA,        ENC_3DES,       DIG_SHA,    MODE_CBC   },   /* TLS_SRP_SHA_WITH_3DES_EDE_CBC_SHA */
    {0xC01B,KEX_SRP_SHA_RSA,    ENC_3DES,       DIG_SHA,    MODE_CBC   },   /* TLS_SRP_SHA_RSA_WITH_3DES_EDE_CBC_SHA */
    {0xC01C,KEX_SRP_SHA_DSS,    ENC_3DES,       DIG_SHA,    MODE_CBC   },   /* TLS_SRP_SHA_DSS_WITH_3DES_EDE_CBC_SHA */
    {0xC01D,KEX_SRP_SHA,        ENC_AES,        DIG_SHA,    MODE_CBC   },   /* TLS_SRP_SHA_WITH_AES_128_CBC_SHA */
    {0xC01E,KEX_SRP_SHA_RSA,    ENC_AES,        DIG_SHA,    MODE_CBC   },   /* TLS_SRP_SHA_RSA_WITH_AES_128_CBC_SHA */
    {0xC01F,KEX_SRP_SHA_DSS,    ENC_AES,        DIG_SHA,    MODE_CBC   },   /* TLS_SRP_SHA_DSS_WITH_AES_128_CBC_SHA */
    {0xC020,KEX_SRP_SHA,        ENC_AES256,     DIG_SHA,    MODE_CBC   },   /* TLS_SRP_SHA_WITH_AES_256_CBC_SHA */
    {0xC021,KEX_SRP_SHA_RSA,    ENC_AES256,     DIG_SHA,    MODE_CBC   },   /* TLS_SRP_SHA_RSA_WITH_AES_256_CBC_SHA */
    {0xC022,KEX_SRP_SHA_DSS,    ENC_AES256,     DIG_SHA,    MODE_CBC   },   /* TLS_SRP_SHA_DSS_WITH_AES_256_CBC_SHA */
    {0xC023,KEX_ECDHE_ECDSA,    ENC_AES,        DIG_SHA256, MODE_CBC   },   /* TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256 */
    {0xC024,KEX_ECDHE_ECDSA,    ENC_AES256,     DIG_SHA384, MODE_CBC   },   /* TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384 */
    {0xC025,KEX_ECDH_ECDSA,     ENC_AES,        DIG_SHA256, MODE_CBC   },   /* TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA256 */
    {0xC026,KEX_ECDH_ECDSA,     ENC_AES256,     DIG_SHA384, MODE_CBC   },   /* TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA384 */
    {0xC027,KEX_ECDHE_RSA,      ENC_AES,        DIG_SHA256, MODE_CBC   },   /* TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256 */
    {0xC028,KEX_ECDHE_RSA,      ENC_AES256,     DIG_SHA384, MODE_CBC   },   /* TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384 */
    {0xC029,KEX_ECDH_RSA,       ENC_AES,        DIG_SHA256, MODE_CBC   },   /* TLS_ECDH_RSA_WITH_AES_128_CBC_SHA256 */
    {0xC02A,KEX_ECDH_RSA,       ENC_AES256,     DIG_SHA384, MODE_CBC   },   /* TLS_ECDH_RSA_WITH_AES_256_CBC_SHA384 */
    {0xC02B,KEX_ECDHE_ECDSA,    ENC_AES,        DIG_SHA256, MODE_GCM   },   /* TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256 */
    {0xC02C,KEX_ECDHE_ECDSA,    ENC_AES256,     DIG_SHA384, MODE_GCM   },   /* TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384 */
    {0xC02D,KEX_ECDH_ECDSA,     ENC_AES,        DIG_SHA256, MODE_GCM   },   /* TLS_ECDH_ECDSA_WITH_AES_128_GCM_SHA256 */
    {0xC02E,KEX_ECDH_ECDSA,     ENC_AES256,     DIG_SHA384, MODE_GCM   },   /* TLS_ECDH_ECDSA_WITH_AES_256_GCM_SHA384 */
    {0xC02F,KEX_ECDHE_RSA,      ENC_AES,        DIG_SHA256, MODE_GCM   },   /* TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256 */
    {0xC030,KEX_ECDHE_RSA,      ENC_AES256,     DIG_SHA384, MODE_GCM   },   /* TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384 */
    {0xC031,KEX_ECDH_RSA,       ENC_AES,        DIG_SHA256, MODE_GCM   },   /* TLS_ECDH_RSA_WITH_AES_128_GCM_SHA256 */
    {0xC032,KEX_ECDH_RSA,       ENC_AES256,     DIG_SHA384, MODE_GCM   },   /* TLS_ECDH_RSA_WITH_AES_256_GCM_SHA384 */
    {0xC033,KEX_ECDHE_PSK,      ENC_RC4,        DIG_SHA,    MODE_STREAM},   /* TLS_ECDHE_PSK_WITH_RC4_128_SHA */
    {0xC034,KEX_ECDHE_PSK,      ENC_3DES,       DIG_SHA,    MODE_CBC   },   /* TLS_ECDHE_PSK_WITH_3DES_EDE_CBC_SHA */
    {0xC035,KEX_ECDHE_PSK,      ENC_AES,        DIG_SHA,    MODE_CBC   },   /* TLS_ECDHE_PSK_WITH_AES_128_CBC_SHA */
    {0xC036,KEX_ECDHE_PSK,      ENC_AES256,     DIG_SHA,    MODE_CBC   },   /* TLS_ECDHE_PSK_WITH_AES_256_CBC_SHA */
    {0xC037,KEX_ECDHE_PSK,      ENC_AES,        DIG_SHA256, MODE_CBC   },   /* TLS_ECDHE_PSK_WITH_AES_128_CBC_SHA256 */
    {0xC038,KEX_ECDHE_PSK,      ENC_AES256,     DIG_SHA384, MODE_CBC   },   /* TLS_ECDHE_PSK_WITH_AES_256_CBC_SHA384 */
    {0xC039,KEX_ECDHE_PSK,      ENC_NULL,       DIG_SHA,    MODE_STREAM},   /* TLS_ECDHE_PSK_WITH_NULL_SHA */
    {0xC03A,KEX_ECDHE_PSK,      ENC_NULL,       DIG_SHA256, MODE_STREAM},   /* TLS_ECDHE_PSK_WITH_NULL_SHA256 */
    {0xC03B,KEX_ECDHE_PSK,      ENC_NULL,       DIG_SHA384, MODE_STREAM},   /* TLS_ECDHE_PSK_WITH_NULL_SHA384 */
    {0xC072,KEX_ECDHE_ECDSA,    ENC_CAMELLIA128,DIG_SHA256, MODE_CBC   },   /* TLS_ECDHE_ECDSA_WITH_CAMELLIA_128_CBC_SHA256 */
    {0xC073,KEX_ECDHE_ECDSA,    ENC_CAMELLIA256,DIG_SHA384, MODE_CBC   },   /* TLS_ECDHE_ECDSA_WITH_CAMELLIA_256_CBC_SHA384 */
    {0xC074,KEX_ECDH_ECDSA,     ENC_CAMELLIA128,DIG_SHA256, MODE_CBC   },   /* TLS_ECDH_ECDSA_WITH_CAMELLIA_128_CBC_SHA256 */
    {0xC075,KEX_ECDH_ECDSA,     ENC_CAMELLIA256,DIG_SHA384, MODE_CBC   },   /* TLS_ECDH_ECDSA_WITH_CAMELLIA_256_CBC_SHA384 */
    {0xC076,KEX_ECDHE_RSA,      ENC_CAMELLIA128,DIG_SHA256, MODE_CBC   },   /* TLS_ECDHE_RSA_WITH_CAMELLIA_128_CBC_SHA256 */
    {0xC077,KEX_ECDHE_RSA,      ENC_CAMELLIA256,DIG_SHA384, MODE_CBC   },   /* TLS_ECDHE_RSA_WITH_CAMELLIA_256_CBC_SHA384 */
    {0xC078,KEX_ECDH_RSA,       ENC_CAMELLIA128,DIG_SHA256, MODE_CBC   },   /* TLS_ECDH_RSA_WITH_CAMELLIA_128_CBC_SHA256 */
    {0xC079,KEX_ECDH_RSA,       ENC_CAMELLIA256,DIG_SHA384, MODE_CBC   },   /* TLS_ECDH_RSA_WITH_CAMELLIA_256_CBC_SHA384 */
    {0xC07A,KEX_RSA,            ENC_CAMELLIA128,DIG_SHA256, MODE_GCM   },   /* TLS_RSA_WITH_CAMELLIA_128_GCM_SHA256 */
    {0xC07B,KEX_RSA,            ENC_CAMELLIA256,DIG_SHA384, MODE_GCM   },   /* TLS_RSA_WITH_CAMELLIA_256_GCM_SHA384 */
    {0xC07C,KEX_DHE_RSA,        ENC_CAMELLIA128,DIG_SHA256, MODE_GCM   },   /* TLS_DHE_RSA_WITH_CAMELLIA_128_GCM_SHA256 */
    {0xC07D,KEX_DHE_RSA,        ENC_CAMELLIA256,DIG_SHA384, MODE_GCM   },   /* TLS_DHE_RSA_WITH_CAMELLIA_256_GCM_SHA384 */
    {0xC07E,KEX_DH_RSA,         ENC_CAMELLIA128,DIG_SHA256, MODE_GCM   },   /* TLS_DH_RSA_WITH_CAMELLIA_128_GCM_SHA256 */
    {0xC07F,KEX_DH_RSA,         ENC_CAMELLIA256,DIG_SHA384, MODE_GCM   },   /* TLS_DH_RSA_WITH_CAMELLIA_256_GCM_SHA384 */
    {0xC080,KEX_DHE_DSS,        ENC_CAMELLIA128,DIG_SHA256, MODE_GCM   },   /* TLS_DHE_DSS_WITH_CAMELLIA_128_GCM_SHA256 */
    {0xC081,KEX_DHE_DSS,        ENC_CAMELLIA256,DIG_SHA384, MODE_GCM   },   /* TLS_DHE_DSS_WITH_CAMELLIA_256_GCM_SHA384 */
    {0xC082,KEX_DH_DSS,         ENC_CAMELLIA128,DIG_SHA256, MODE_GCM   },   /* TLS_DH_DSS_WITH_CAMELLIA_128_GCM_SHA256 */
    {0xC083,KEX_DH_DSS,         ENC_CAMELLIA256,DIG_SHA384, MODE_GCM   },   /* TLS_DH_DSS_WITH_CAMELLIA_256_GCM_SHA384 */
    {0xC084,KEX_DH_ANON,        ENC_CAMELLIA128,DIG_SHA256, MODE_GCM   },   /* TLS_DH_anon_WITH_CAMELLIA_128_GCM_SHA256 */
    {0xC085,KEX_DH_ANON,        ENC_CAMELLIA256,DIG_SHA384, MODE_GCM   },   /* TLS_DH_anon_WITH_CAMELLIA_256_GCM_SHA384 */
    {0xC086,KEX_ECDHE_ECDSA,    ENC_CAMELLIA128,DIG_SHA256, MODE_GCM   },   /* TLS_ECDHE_ECDSA_WITH_CAMELLIA_128_GCM_SHA256 */
    {0xC087,KEX_ECDHE_ECDSA,    ENC_CAMELLIA256,DIG_SHA384, MODE_GCM   },   /* TLS_ECDHE_ECDSA_WITH_CAMELLIA_256_GCM_SHA384 */
    {0xC088,KEX_ECDH_ECDSA,     ENC_CAMELLIA128,DIG_SHA256, MODE_GCM   },   /* TLS_ECDH_ECDSA_WITH_CAMELLIA_128_GCM_SHA256 */
    {0xC089,KEX_ECDH_ECDSA,     ENC_CAMELLIA256,DIG_SHA384, MODE_GCM   },   /* TLS_ECDH_ECDSA_WITH_CAMELLIA_256_GCM_SHA384 */
    {0xC08A,KEX_ECDHE_RSA,      ENC_CAMELLIA128,DIG_SHA256, MODE_GCM   },   /* TLS_ECDHE_RSA_WITH_CAMELLIA_128_GCM_SHA256 */
    {0xC08B,KEX_ECDHE_RSA,      ENC_CAMELLIA256,DIG_SHA384, MODE_GCM   },   /* TLS_ECDHE_RSA_WITH_CAMELLIA_256_GCM_SHA384 */
    {0xC08C,KEX_ECDH_RSA,       ENC_CAMELLIA128,DIG_SHA256, MODE_GCM   },   /* TLS_ECDH_RSA_WITH_CAMELLIA_128_GCM_SHA256 */
    {0xC08D,KEX_ECDH_RSA,       ENC_CAMELLIA256,DIG_SHA384, MODE_GCM   },   /* TLS_ECDH_RSA_WITH_CAMELLIA_256_GCM_SHA384 */
    {0xC08E,KEX_PSK,            ENC_CAMELLIA128,DIG_SHA256, MODE_GCM   },   /* TLS_PSK_WITH_CAMELLIA_128_GCM_SHA256 */
    {0xC08F,KEX_PSK,            ENC_CAMELLIA256,DIG_SHA384, MODE_GCM   },   /* TLS_PSK_WITH_CAMELLIA_256_GCM_SHA384 */
    {0xC090,KEX_DHE_PSK,        ENC_CAMELLIA128,DIG_SHA256, MODE_GCM   },   /* TLS_DHE_PSK_WITH_CAMELLIA_128_GCM_SHA256 */
    {0xC091,KEX_DHE_PSK,        ENC_CAMELLIA256,DIG_SHA384, MODE_GCM   },   /* TLS_DHE_PSK_WITH_CAMELLIA_256_GCM_SHA384 */
    {0xC092,KEX_RSA_PSK,        ENC_CAMELLIA128,DIG_SHA256, MODE_GCM   },   /* TLS_RSA_PSK_WITH_CAMELLIA_128_GCM_SHA256 */
    {0xC093,KEX_RSA_PSK,        ENC_CAMELLIA256,DIG_SHA384, MODE_GCM   },   /* TLS_RSA_PSK_WITH_CAMELLIA_256_GCM_SHA384 */
    {0xC094,KEX_PSK,            ENC_CAMELLIA128,DIG_SHA256, MODE_CBC   },   /* TLS_PSK_WITH_CAMELLIA_128_CBC_SHA256 */
    {0xC095,KEX_PSK,            ENC_CAMELLIA256,DIG_SHA384, MODE_CBC   },   /* TLS_PSK_WITH_CAMELLIA_256_CBC_SHA384 */
    {0xC096,KEX_DHE_PSK,        ENC_CAMELLIA128,DIG_SHA256, MODE_CBC   },   /* TLS_DHE_PSK_WITH_CAMELLIA_128_CBC_SHA256 */
    {0xC097,KEX_DHE_PSK,        ENC_CAMELLIA256,DIG_SHA384, MODE_CBC   },   /* TLS_DHE_PSK_WITH_CAMELLIA_256_CBC_SHA384 */
    {0xC098,KEX_RSA_PSK,        ENC_CAMELLIA128,DIG_SHA256, MODE_CBC   },   /* TLS_RSA_PSK_WITH_CAMELLIA_128_CBC_SHA256 */
    {0xC099,KEX_RSA_PSK,        ENC_CAMELLIA256,DIG_SHA384, MODE_CBC   },   /* TLS_RSA_PSK_WITH_CAMELLIA_256_CBC_SHA384 */
    {0xC09A,KEX_ECDHE_PSK,      ENC_CAMELLIA128,DIG_SHA256, MODE_CBC   },   /* TLS_ECDHE_PSK_WITH_CAMELLIA_128_CBC_SHA256 */
    {0xC09B,KEX_ECDHE_PSK,      ENC_CAMELLIA256,DIG_SHA384, MODE_CBC   },   /* TLS_ECDHE_PSK_WITH_CAMELLIA_256_CBC_SHA384 */
    {0xC09C,KEX_RSA,            ENC_AES,        DIG_NA,     MODE_CCM   },   /* TLS_RSA_WITH_AES_128_CCM */
    {0xC09D,KEX_RSA,            ENC_AES256,     DIG_NA,     MODE_CCM   },   /* TLS_RSA_WITH_AES_256_CCM */
    {0xC09E,KEX_DHE_RSA,        ENC_AES,        DIG_NA,     MODE_CCM   },   /* TLS_DHE_RSA_WITH_AES_128_CCM */
    {0xC09F,KEX_DHE_RSA,        ENC_AES256,     DIG_NA,     MODE_CCM   },   /* TLS_DHE_RSA_WITH_AES_256_CCM */
    {0xC0A0,KEX_RSA,            ENC_AES,        DIG_NA,     MODE_CCM_8 },   /* TLS_RSA_WITH_AES_128_CCM_8 */
    {0xC0A1,KEX_RSA,            ENC_AES256,     DIG_NA,     MODE_CCM_8 },   /* TLS_RSA_WITH_AES_256_CCM_8 */
    {0xC0A2,KEX_DHE_RSA,        ENC_AES,        DIG_NA,     MODE_CCM_8 },   /* TLS_DHE_RSA_WITH_AES_128_CCM_8 */
    {0xC0A3,KEX_DHE_RSA,        ENC_AES256,     DIG_NA,     MODE_CCM_8 },   /* TLS_DHE_RSA_WITH_AES_256_CCM_8 */
    {0xC0A4,KEX_PSK,            ENC_AES,        DIG_NA,     MODE_CCM   },   /* TLS_PSK_WITH_AES_128_CCM */
    {0xC0A5,KEX_PSK,            ENC_AES256,     DIG_NA,     MODE_CCM   },   /* TLS_PSK_WITH_AES_256_CCM */
    {0xC0A6,KEX_DHE_PSK,        ENC_AES,        DIG_NA,     MODE_CCM   },   /* TLS_DHE_PSK_WITH_AES_128_CCM */
    {0xC0A7,KEX_DHE_PSK,        ENC_AES256,     DIG_NA,     MODE_CCM   },   /* TLS_DHE_PSK_WITH_AES_256_CCM */
    {0xC0A8,KEX_PSK,            ENC_AES,        DIG_NA,     MODE_CCM_8 },   /* TLS_PSK_WITH_AES_128_CCM_8 */
    {0xC0A9,KEX_PSK,            ENC_AES256,     DIG_NA,     MODE_CCM_8 },   /* TLS_PSK_WITH_AES_256_CCM_8 */
    {0xC0AA,KEX_DHE_PSK,        ENC_AES,        DIG_NA,     MODE_CCM_8 },   /* TLS_PSK_DHE_WITH_AES_128_CCM_8 */
    {0xC0AB,KEX_DHE_PSK,        ENC_AES256,     DIG_NA,     MODE_CCM_8 },   /* TLS_PSK_DHE_WITH_AES_256_CCM_8 */
    {0xC0AC,KEX_ECDHE_ECDSA,    ENC_AES,        DIG_NA,     MODE_CCM   },   /* TLS_ECDHE_ECDSA_WITH_AES_128_CCM */
    {0xC0AD,KEX_ECDHE_ECDSA,    ENC_AES256,     DIG_NA,     MODE_CCM   },   /* TLS_ECDHE_ECDSA_WITH_AES_256_CCM */
    {0xC0AE,KEX_ECDHE_ECDSA,    ENC_AES,        DIG_NA,     MODE_CCM_8 },   /* TLS_ECDHE_ECDSA_WITH_AES_128_CCM_8 */
    {0xC0AF,KEX_ECDHE_ECDSA,    ENC_AES256,     DIG_NA,     MODE_CCM_8 },   /* TLS_ECDHE_ECDSA_WITH_AES_256_CCM_8 */
    {0xCCA8,KEX_ECDHE_RSA,      ENC_CHACHA20,   DIG_SHA256, MODE_POLY1305 }, /* TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256 */
    {0xCCA9,KEX_ECDHE_ECDSA,    ENC_CHACHA20,   DIG_SHA256, MODE_POLY1305 }, /* TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256 */
    {0xCCAA,KEX_DHE_RSA,        ENC_CHACHA20,   DIG_SHA256, MODE_POLY1305 }, /* TLS_DHE_RSA_WITH_CHACHA20_POLY1305_SHA256 */
    {0xCCAB,KEX_PSK,            ENC_CHACHA20,   DIG_SHA256, MODE_POLY1305 }, /* TLS_PSK_WITH_CHACHA20_POLY1305_SHA256 */
    {0xCCAC,KEX_ECDHE_PSK,      ENC_CHACHA20,   DIG_SHA256, MODE_POLY1305 }, /* TLS_ECDHE_PSK_WITH_CHACHA20_POLY1305_SHA256 */
    {0xCCAD,KEX_DHE_PSK,        ENC_CHACHA20,   DIG_SHA256, MODE_POLY1305 }, /* TLS_DHE_PSK_WITH_CHACHA20_POLY1305_SHA256 */
    {0xCCAE,KEX_RSA_PSK,        ENC_CHACHA20,   DIG_SHA256, MODE_POLY1305 }, /* TLS_RSA_PSK_WITH_CHACHA20_POLY1305_SHA256 */
    {0xD001,KEX_ECDHE_PSK,      ENC_AES,        DIG_SHA256, MODE_GCM},       /* TLS_ECDHE_PSK_WITH_AES_128_GCM_SHA256 */
    {0xD002,KEX_ECDHE_PSK,      ENC_AES256,     DIG_SHA384, MODE_GCM},       /* TLS_ECDHE_PSK_WITH_AES_256_GCM_SHA384 */
    {0xD003,KEX_ECDHE_PSK,      ENC_AES,        DIG_SHA256, MODE_CCM_8},     /* TLS_ECDHE_PSK_WITH_AES_128_CCM_8_SHA256 */
    {0xD005,KEX_ECDHE_PSK,      ENC_AES,        DIG_SHA256, MODE_CCM},       /* TLS_ECDHE_PSK_WITH_AES_128_CCM_SHA256 */
    /* GM */
    {0xe001,KEX_ECDHE_SM2,      ENC_SM1,        DIG_SM3,    MODE_CBC},        /* ECDHE_SM1_SM3 */
    {0xe003,KEX_ECC_SM2,        ENC_SM1,        DIG_SM3,    MODE_CBC},        /* ECC_SM1_SM3 */
    {0xe005,KEX_IBSDH_SM9,      ENC_SM1,        DIG_SM3,    MODE_CBC},        /* IBSDH_SM1_SM3 */
    {0xe007,KEX_IBC_SM9,        ENC_SM1,        DIG_SM3,    MODE_CBC},        /* IBC_SM1_SM3 */
    {0xe009,KEX_RSA,            ENC_SM1,        DIG_SM3,    MODE_CBC},        /* RSA_SM1_SM3 */
    {0xe00a,KEX_RSA,            ENC_SM1,        DIG_SHA,    MODE_CBC},        /* RSA_SM1_SHA1 */
    {0xe011,KEX_ECDHE_SM2,      ENC_SM4,        DIG_SM3,    MODE_CBC},        /* ECDHE_SM4_CBC_SM3 */
    {0xe013,KEX_ECC_SM2,        ENC_SM4,        DIG_SM3,    MODE_CBC},        /* ECC_SM4_CBC_SM3 */
    {0xe015,KEX_IBSDH_SM9,      ENC_SM4,        DIG_SM3,    MODE_CBC},        /* IBSDH_SM4_CBC_SM3 */
    {0xe017,KEX_IBC_SM9,        ENC_SM4,        DIG_SM3,    MODE_CBC},        /* IBC_SM4_CBC_SM3 */
    {0xe019,KEX_RSA,            ENC_SM4,        DIG_SM3,    MODE_CBC},        /* RSA_SM4_CBC_SM3 */
    {0xe01a,KEX_RSA,            ENC_SM4,        DIG_SHA,    MODE_CBC},        /* RSA_SM4_CBC_SHA1 */
    {0xe01c,KEX_RSA,            ENC_SM4,        DIG_SHA256, MODE_CBC},        /* RSA_SM4_CBC_SHA256 */
    {0xe051,KEX_ECDHE_SM2,      ENC_SM4,        DIG_SM3,    MODE_GCM},        /* ECDHE_SM4_GCM_SM3 */
    {0xe053,KEX_ECC_SM2,        ENC_SM4,        DIG_SM3,    MODE_GCM},        /* ECC_SM4_GCM_SM3 */
    {0xe055,KEX_IBSDH_SM9,      ENC_SM4,        DIG_SM3,    MODE_GCM},        /* IBSDH_SM4_GCM_SM3 */
    {0xe057,KEX_IBC_SM9,        ENC_SM4,        DIG_SM3,    MODE_GCM},        /* IBC_SM4_GCM_SM3 */
    {0xe059,KEX_RSA,            ENC_SM4,        DIG_SM3,    MODE_GCM},        /* RSA_SM4_GCM_SM3 */
    {0xe05a,KEX_RSA,            ENC_SM4,        DIG_SHA256, MODE_GCM},        /* RSA_SM4_GCM_SHA256 */
    {-1,    0,                  0,              0,          MODE_STREAM}
};

#define MAX_BLOCK_SIZE 16
#define MAX_KEY_SIZE 32

const SslCipherSuite *
ssl_find_cipher(int num)
{
    const SslCipherSuite *c;
    for(c=cipher_suites;c->number!=-1;c++){
        if(c->number==num){
            return c;
        }
    }

    return NULL;
}

int
ssl_get_cipher_algo(const SslCipherSuite *cipher_suite)
{
    return gcry_cipher_map_name(ciphers[cipher_suite->enc - ENC_START]);
}

unsigned
ssl_get_cipher_blocksize(const SslCipherSuite *cipher_suite)
{
    int cipher_algo;
    if (cipher_suite->mode != MODE_CBC) return 0;
    cipher_algo = ssl_get_cipher_by_name(ciphers[cipher_suite->enc - ENC_START]);
    return (unsigned)gcry_cipher_get_algo_blklen(cipher_algo);
}

static unsigned
ssl_get_cipher_export_keymat_size(int cipher_suite_num)
{
    switch (cipher_suite_num) {
    /* See RFC 6101 (SSL 3.0), Table 2, column Key Material. */
    case 0x0003:    /* TLS_RSA_EXPORT_WITH_RC4_40_MD5 */
    case 0x0006:    /* TLS_RSA_EXPORT_WITH_RC2_CBC_40_MD5 */
    case 0x0008:    /* TLS_RSA_EXPORT_WITH_DES40_CBC_SHA */
    case 0x000B:    /* TLS_DH_DSS_EXPORT_WITH_DES40_CBC_SHA */
    case 0x000E:    /* TLS_DH_RSA_EXPORT_WITH_DES40_CBC_SHA */
    case 0x0011:    /* TLS_DHE_DSS_EXPORT_WITH_DES40_CBC_SHA */
    case 0x0014:    /* TLS_DHE_RSA_EXPORT_WITH_DES40_CBC_SHA */
    case 0x0017:    /* TLS_DH_anon_EXPORT_WITH_RC4_40_MD5 */
    case 0x0019:    /* TLS_DH_anon_EXPORT_WITH_DES40_CBC_SHA */
        return 5;

    /* not defined in below draft, but "implemented by several vendors",
     * https://www.ietf.org/mail-archive/web/tls/current/msg00036.html */
    case 0x0060:    /* TLS_RSA_EXPORT1024_WITH_RC4_56_MD5 */
    case 0x0061:    /* TLS_RSA_EXPORT1024_WITH_RC2_CBC_56_MD5 */
        return 7;

    /* Note: the draft states that DES_CBC needs 8 bytes, but Wireshark always
     * used 7. Until a pcap proves 8, let's use the old value. Link:
     * https://tools.ietf.org/html/draft-ietf-tls-56-bit-ciphersuites-01 */
    case 0x0062:    /* TLS_RSA_EXPORT1024_WITH_DES_CBC_SHA */
    case 0x0063:    /* TLS_DHE_DSS_EXPORT1024_WITH_DES_CBC_SHA */
    case 0x0064:    /* TLS_RSA_EXPORT1024_WITH_RC4_56_SHA */
    case 0x0065:    /* TLS_DHE_DSS_EXPORT1024_WITH_RC4_56_SHA */
        return 7;

    default:
        return 0;
    }
}

/* Digests, Ciphers and Cipher Suites registry }}} */


/* HMAC and the Pseudorandom function {{{ */
static int
tls_hash(StringInfo *secret, StringInfo *seed, int md,
         StringInfo *out, unsigned out_len)
{
    /* RFC 2246 5. HMAC and the pseudorandom function
     * '+' denotes concatenation.
     * P_hash(secret, seed) = HMAC_hash(secret, A(1) + seed) +
     *                        HMAC_hash(secret, A(2) + seed) + ...
     * A(0) = seed
     * A(i) = HMAC_hash(secret, A(i - 1))
     */
    uint8_t  *ptr;
    unsigned  left, tocpy;
    uint8_t  *A;
    uint8_t   _A[DIGEST_MAX_SIZE], tmp[DIGEST_MAX_SIZE];
    unsigned  A_l, tmp_l;
    SSL_HMAC  hm;

    ptr  = out->data;
    left = out_len;

    ssl_print_string("tls_hash: hash secret", secret);
    ssl_print_string("tls_hash: hash seed", seed);
    /* A(0) = seed */
    A = seed->data;
    A_l = seed->data_len;

    if (ssl_hmac_init(&hm, md) != 0) {
        return -1;
    }
    while (left) {
        /* A(i) = HMAC_hash(secret, A(i-1)) */
        ssl_hmac_setkey(&hm, secret->data, secret->data_len);
        ssl_hmac_update(&hm, A, A_l);
        A_l = sizeof(_A); /* upper bound len for hash output */
        ssl_hmac_final(&hm, _A, &A_l);
        A = _A;

        /* HMAC_hash(secret, A(i) + seed) */
        ssl_hmac_reset(&hm);
        ssl_hmac_setkey(&hm, secret->data, secret->data_len);
        ssl_hmac_update(&hm, A, A_l);
        ssl_hmac_update(&hm, seed->data, seed->data_len);
        tmp_l = sizeof(tmp); /* upper bound len for hash output */
        ssl_hmac_final(&hm, tmp, &tmp_l);
        ssl_hmac_reset(&hm);

        /* ssl_hmac_final puts the actual digest output size in tmp_l */
        tocpy = MIN(left, tmp_l);
        memcpy(ptr, tmp, tocpy);
        ptr += tocpy;
        left -= tocpy;
    }
    ssl_hmac_cleanup(&hm);
    out->data_len = out_len;

    ssl_print_string("hash out", out);
    return 0;
}

static bool
tls_prf(StringInfo* secret, const char *usage,
        StringInfo* rnd1, StringInfo* rnd2, StringInfo* out, unsigned out_len)
{
    StringInfo  seed, sha_out, md5_out;
    uint8_t    *ptr;
    StringInfo  s1, s2;
    unsigned    i,s_l;
    size_t      usage_len, rnd2_len;
    bool        success = false;
    usage_len = strlen(usage);
    rnd2_len = rnd2 ? rnd2->data_len : 0;

    /* initialize buffer for sha, md5 random seed*/
    if (ssl_data_alloc(&sha_out, MAX(out_len, 20)) < 0) {
        ssl_debug_printf("tls_prf: can't allocate sha out\n");
        return false;
    }
    if (ssl_data_alloc(&md5_out, MAX(out_len, 16)) < 0) {
        ssl_debug_printf("tls_prf: can't allocate md5 out\n");
        goto free_sha;
    }
    if (ssl_data_alloc(&seed, usage_len+rnd1->data_len+rnd2_len) < 0) {
        ssl_debug_printf("tls_prf: can't allocate rnd %d\n",
                         (int) (usage_len+rnd1->data_len+rnd2_len));
        goto free_md5;
    }

    ptr=seed.data;
    memcpy(ptr,usage,usage_len);
    ptr+=usage_len;
    memcpy(ptr,rnd1->data,rnd1->data_len);
    if (rnd2_len > 0) {
        ptr+=rnd1->data_len;
        memcpy(ptr,rnd2->data,rnd2->data_len);
        /*ptr+=rnd2->data_len;*/
    }

    /* initialize buffer for client/server seeds*/
    s_l=secret->data_len/2 + secret->data_len%2;
    if (ssl_data_alloc(&s1, s_l) < 0) {
        ssl_debug_printf("tls_prf: can't allocate secret %d\n", s_l);
        goto free_seed;
    }
    if (ssl_data_alloc(&s2, s_l) < 0) {
        ssl_debug_printf("tls_prf: can't allocate secret(2) %d\n", s_l);
        goto free_s1;
    }

    memcpy(s1.data,secret->data,s_l);
    memcpy(s2.data,secret->data + (secret->data_len - s_l),s_l);

    ssl_debug_printf("tls_prf: tls_hash(md5 secret_len %d seed_len %d )\n", s1.data_len, seed.data_len);
    if(tls_hash(&s1, &seed, ssl_get_digest_by_name("MD5"), &md5_out, out_len) != 0)
        goto free_s2;
    ssl_debug_printf("tls_prf: tls_hash(sha)\n");
    if(tls_hash(&s2, &seed, ssl_get_digest_by_name("SHA1"), &sha_out, out_len) != 0)
        goto free_s2;

    for (i = 0; i < out_len; i++)
        out->data[i] = md5_out.data[i] ^ sha_out.data[i];
    /* success, now store the new meaningful data length */
    out->data_len = out_len;
    success = true;

    ssl_print_string("PRF out",out);
free_s2:
    g_free(s2.data);
free_s1:
    g_free(s1.data);
free_seed:
    g_free(seed.data);
free_md5:
    g_free(md5_out.data);
free_sha:
    g_free(sha_out.data);
    return success;
}

static bool
tls12_prf(int md, StringInfo* secret, const char* usage,
          StringInfo* rnd1, StringInfo* rnd2, StringInfo* out, unsigned out_len)
{
    StringInfo label_seed;
    int success;
    size_t     usage_len, rnd2_len;
    rnd2_len = rnd2 ? rnd2->data_len : 0;

    usage_len = strlen(usage);
    if (ssl_data_alloc(&label_seed, usage_len+rnd1->data_len+rnd2_len) < 0) {
        ssl_debug_printf("tls12_prf: can't allocate label_seed\n");
        return false;
    }
    memcpy(label_seed.data, usage, usage_len);
    memcpy(label_seed.data+usage_len, rnd1->data, rnd1->data_len);
    if (rnd2_len > 0)
        memcpy(label_seed.data+usage_len+rnd1->data_len, rnd2->data, rnd2->data_len);

    ssl_debug_printf("tls12_prf: tls_hash(hash_alg %s secret_len %d seed_len %d )\n", gcry_md_algo_name(md), secret->data_len, label_seed.data_len);
    success = tls_hash(secret, &label_seed, md, out, out_len);
    g_free(label_seed.data);
    if(success != -1){
        ssl_print_string("PRF out", out);
        return true;
    }
    return false;
}

static bool
ssl3_generate_export_iv(StringInfo *r1, StringInfo *r2,
                        StringInfo *out, unsigned out_len)
{
    SSL_MD5_CTX md5;
    uint8_t     tmp[16];

    if (ssl_md5_init(&md5) != 0) {
        return false;
    }
    ssl_md5_update(&md5,r1->data,r1->data_len);
    ssl_md5_update(&md5,r2->data,r2->data_len);
    ssl_md5_final(tmp,&md5);
    ssl_md5_cleanup(&md5);

    DISSECTOR_ASSERT(out_len <= sizeof(tmp));
    ssl_data_set(out, tmp, out_len);
    ssl_print_string("export iv", out);
    return true;
}

static bool
ssl3_prf(StringInfo* secret, const char* usage,
         StringInfo* rnd1, StringInfo* rnd2, StringInfo* out, unsigned out_len)
{
    SSL_MD5_CTX  md5;
    SSL_SHA_CTX  sha;
    unsigned     off;
    int          i = 0,j;
    uint8_t      buf[20];

    if (ssl_sha_init(&sha) != 0) {
        return false;
    }
    if (ssl_md5_init(&md5) != 0) {
        ssl_sha_cleanup(&sha);
        return false;
    }
    for (off = 0; off < out_len; off += 16) {
        unsigned char outbuf[16];
        i++;

        ssl_debug_printf("ssl3_prf: sha1_hash(%d)\n",i);
        /* A, BB, CCC,  ... */
        for(j=0;j<i;j++){
            buf[j]=64+i;
        }

        ssl_sha_update(&sha,buf,i);
        ssl_sha_update(&sha,secret->data,secret->data_len);

        if(!strcmp(usage,"client write key") || !strcmp(usage,"server write key")){
            if (rnd2)
                ssl_sha_update(&sha,rnd2->data,rnd2->data_len);
            ssl_sha_update(&sha,rnd1->data,rnd1->data_len);
        }
        else{
            ssl_sha_update(&sha,rnd1->data,rnd1->data_len);
            if (rnd2)
                ssl_sha_update(&sha,rnd2->data,rnd2->data_len);
        }

        ssl_sha_final(buf,&sha);
        ssl_sha_reset(&sha);

        ssl_debug_printf("ssl3_prf: md5_hash(%d) datalen %d\n",i,
            secret->data_len);
        ssl_md5_update(&md5,secret->data,secret->data_len);
        ssl_md5_update(&md5,buf,20);
        ssl_md5_final(outbuf,&md5);
        ssl_md5_reset(&md5);

        memcpy(out->data + off, outbuf, MIN(out_len - off, 16));
    }
    ssl_sha_cleanup(&sha);
    ssl_md5_cleanup(&md5);
    out->data_len = out_len;

    return true;
}

/* out_len is the wanted output length for the pseudorandom function.
 * Ensure that ssl->cipher_suite is set. */
static bool
prf(SslDecryptSession *ssl, StringInfo *secret, const char *usage,
    StringInfo *rnd1, StringInfo *rnd2, StringInfo *out, unsigned out_len)
{
    switch (ssl->session.version) {
    case SSLV3_VERSION:
        return ssl3_prf(secret, usage, rnd1, rnd2, out, out_len);

    case TLSV1_VERSION:
    case TLSV1DOT1_VERSION:
    case DTLSV1DOT0_VERSION:
    case DTLSV1DOT0_OPENSSL_VERSION:
        return tls_prf(secret, usage, rnd1, rnd2, out, out_len);

    default: /* TLSv1.2 */
        switch (ssl->cipher_suite->dig) {
        case DIG_SM3:
#if GCRYPT_VERSION_NUMBER >= 0x010900
            return tls12_prf(GCRY_MD_SM3, secret, usage, rnd1, rnd2,
                             out, out_len);
#else
            return false;
#endif
        case DIG_SHA384:
            return tls12_prf(GCRY_MD_SHA384, secret, usage, rnd1, rnd2,
                             out, out_len);
        default:
            return tls12_prf(GCRY_MD_SHA256, secret, usage, rnd1, rnd2,
                             out, out_len);
        }
    }
}

static int tls_handshake_hash(SslDecryptSession* ssl, StringInfo* out)
{
    SSL_MD5_CTX  md5;
    SSL_SHA_CTX  sha;

    if (ssl_data_alloc(out, 36) < 0)
        return -1;

    if (ssl_md5_init(&md5) != 0)
        return -1;
    ssl_md5_update(&md5,ssl->handshake_data.data,ssl->handshake_data.data_len);
    ssl_md5_final(out->data,&md5);
    ssl_md5_cleanup(&md5);

    if (ssl_sha_init(&sha) != 0)
        return -1;
    ssl_sha_update(&sha,ssl->handshake_data.data,ssl->handshake_data.data_len);
    ssl_sha_final(out->data+16,&sha);
    ssl_sha_cleanup(&sha);
    return 0;
}

static int tls12_handshake_hash(SslDecryptSession* ssl, int md, StringInfo* out)
{
    SSL_MD  mc;
    uint8_t tmp[48];
    unsigned  len;

    if (ssl_md_init(&mc, md) != 0)
        return -1;
    ssl_md_update(&mc,ssl->handshake_data.data,ssl->handshake_data.data_len);
    ssl_md_final(&mc, tmp, &len);
    ssl_md_cleanup(&mc);

    if (ssl_data_alloc(out, len) < 0)
        return -1;
    memcpy(out->data, tmp, len);
    return 0;
}

/**
 * Obtains the label prefix used in HKDF-Expand-Label.  This function can be
 * inlined and removed once support for draft 19 and before is dropped.
 */
static inline const char *
tls13_hkdf_label_prefix(SslDecryptSession *ssl_session)
{
    if (ssl_session->session.tls13_draft_version && ssl_session->session.tls13_draft_version < 20) {
        return "TLS 1.3, ";
    } else if (ssl_session->session.version == DTLSV1DOT3_VERSION) {
        return "dtls13";
    } else {
        return "tls13 ";
    }
}

/*
 * Computes HKDF-Expand-Label(Secret, Label, Hash(context_value), Length) with a
 * custom label prefix. If "context_hash" is NULL, then an empty context is
 * used. Otherwise it must have the same length as the hash algorithm output.
 */
bool
tls13_hkdf_expand_label_context(int md, const StringInfo *secret,
                        const char *label_prefix, const char *label,
                        const uint8_t *context_hash, uint8_t context_length,
                        uint16_t out_len, unsigned char **out)
{
    /* RFC 8446 Section 7.1:
     * HKDF-Expand-Label(Secret, Label, Context, Length) =
     *      HKDF-Expand(Secret, HkdfLabel, Length)
     * struct {
     *     uint16 length = Length;
     *     opaque label<7..255> = "tls13 " + Label; // "tls13 " is label prefix.
     *     opaque context<0..255> = Context;
     * } HkdfLabel;
     *
     * RFC 5869 HMAC-based Extract-and-Expand Key Derivation Function (HKDF):
     * HKDF-Expand(PRK, info, L) -> OKM
     */
    gcry_error_t err;
    const unsigned label_prefix_length = (unsigned) strlen(label_prefix);
    const unsigned label_length = (unsigned) strlen(label);

    /* Some sanity checks */
    DISSECTOR_ASSERT(label_length > 0 && label_prefix_length + label_length <= 255);

    /* info = HkdfLabel { length, label, context } */
    GByteArray *info = g_byte_array_new();
    const uint16_t length = g_htons(out_len);
    g_byte_array_append(info, (const uint8_t *)&length, sizeof(length));

    const uint8_t label_vector_length = label_prefix_length + label_length;
    g_byte_array_append(info, &label_vector_length, 1);
    g_byte_array_append(info, (const uint8_t *)label_prefix, label_prefix_length);
    g_byte_array_append(info, (const uint8_t*)label, label_length);

    g_byte_array_append(info, &context_length, 1);
    if (context_length) {
        g_byte_array_append(info, context_hash, context_length);
    }

    *out = (unsigned char *)wmem_alloc(NULL, out_len);
    err = hkdf_expand(md, secret->data, secret->data_len, info->data, info->len, *out, out_len);
    g_byte_array_free(info, true);

    if (err) {
        ssl_debug_printf("%s failed  %d: %s\n", G_STRFUNC, md, gcry_strerror(err));
        wmem_free(NULL, *out);
        *out = NULL;
        return false;
    }

    return true;
}

bool
tls13_hkdf_expand_label(int md, const StringInfo *secret,
                        const char *label_prefix, const char *label,
                        uint16_t out_len, unsigned char **out)
{
    return tls13_hkdf_expand_label_context(md, secret, label_prefix, label, NULL, 0, out_len, out);
}
/* HMAC and the Pseudorandom function }}} */

/* Record Decompression (after decryption) {{{ */
#if defined (HAVE_ZLIB) || defined (HAVE_ZLIBNG)
/* memory allocation functions for zlib initialization */
static void* ssl_zalloc(void* opaque _U_, unsigned int no, unsigned int size)
{
    return g_malloc0(no*size);
}
static void ssl_zfree(void* opaque _U_, void* addr)
{
    g_free(addr);
}
#endif

static SslDecompress*
ssl_create_decompressor(int compression)
{
    SslDecompress *decomp;
#if defined (HAVE_ZLIB) || defined (HAVE_ZLIBNG)
    int err;
#endif

    if (compression == 0) return NULL;
    ssl_debug_printf("ssl_create_decompressor: compression method %d\n", compression);
    decomp = wmem_new(wmem_file_scope(), SslDecompress);
    decomp->compression = compression;
    switch (decomp->compression) {
#if defined (HAVE_ZLIB) || defined (HAVE_ZLIBNG)
        case 1:  /* DEFLATE */
            decomp->istream.zalloc = ssl_zalloc;
            decomp->istream.zfree = ssl_zfree;
            decomp->istream.opaque = Z_NULL;
            decomp->istream.next_in = Z_NULL;
            decomp->istream.next_out = Z_NULL;
            decomp->istream.avail_in = 0;
            decomp->istream.avail_out = 0;
            err = ZLIB_PREFIX(inflateInit)(&decomp->istream);
            if (err != Z_OK) {
                ssl_debug_printf("ssl_create_decompressor: inflateInit_() failed - %d\n", err);
                return NULL;
            }
            break;
#endif
        default:
            ssl_debug_printf("ssl_create_decompressor: unsupported compression method %d\n", decomp->compression);
            return NULL;
    }
    return decomp;
}

#if defined (HAVE_ZLIB) || defined (HAVE_ZLIBNG)
static int
ssl_decompress_record(SslDecompress* decomp, const unsigned char* in, unsigned inl, StringInfo* out_str, unsigned* outl)
{
    int err;

    switch (decomp->compression) {
        case 1:  /* DEFLATE */
            err = Z_OK;
            if (out_str->data_len < 16384) {  /* maximal plain length */
                ssl_data_realloc(out_str, 16384);
            }
#ifdef z_const
            decomp->istream.next_in = in;
#else
DIAG_OFF(cast-qual)
            decomp->istream.next_in = (Bytef *)in;
DIAG_ON(cast-qual)
#endif
            decomp->istream.avail_in = inl;
            decomp->istream.next_out = out_str->data;
            decomp->istream.avail_out = out_str->data_len;
            if (inl > 0)
                err = ZLIB_PREFIX(inflate)(&decomp->istream, Z_SYNC_FLUSH);
            if (err != Z_OK) {
                ssl_debug_printf("ssl_decompress_record: inflate() failed - %d\n", err);
                return -1;
            }
            *outl = out_str->data_len - decomp->istream.avail_out;
            break;
        default:
            ssl_debug_printf("ssl_decompress_record: unsupported compression method %d\n", decomp->compression);
            return -1;
    }
    return 0;
}
#else
int
ssl_decompress_record(SslDecompress* decomp _U_, const unsigned char* in _U_, unsigned inl _U_, StringInfo* out_str _U_, unsigned* outl _U_)
{
    ssl_debug_printf("ssl_decompress_record: unsupported compression method %d\n", decomp->compression);
    return -1;
}
#endif
/* Record Decompression (after decryption) }}} */

/* Create a new structure to store decrypted chunks. {{{ */
static SslFlow*
ssl_create_flow(void)
{
  SslFlow *flow;

  flow = wmem_new(wmem_file_scope(), SslFlow);
  flow->byte_seq = 0;
  flow->flags = 0;
  flow->multisegment_pdus = wmem_tree_new(wmem_file_scope());
  return flow;
}
/* }}} */

/* Use the negotiated security parameters for decryption. {{{ */
void
ssl_change_cipher(SslDecryptSession *ssl_session, bool server)
{
    SslDecoder **new_decoder = server ? &ssl_session->server_new : &ssl_session->client_new;
    SslDecoder **dest = server ? &ssl_session->server : &ssl_session->client;
    ssl_debug_printf("ssl_change_cipher %s%s\n", server ? "SERVER" : "CLIENT",
            *new_decoder ? "" : " (No decoder found - retransmission?)");
    if (*new_decoder) {
        *dest = *new_decoder;
        *new_decoder = NULL;
    }
}
/* }}} */

/* Init cipher state given some security parameters. {{{ */
static bool
ssl_decoder_destroy_cb(wmem_allocator_t *, wmem_cb_event_t, void *);

static SslDecoder*
ssl_create_decoder(const SslCipherSuite *cipher_suite, int cipher_algo,
        int compression, uint8_t *mk, uint8_t *sk, uint8_t *sn_key, uint8_t *iv, unsigned iv_length)
{
    SslDecoder *dec;
    ssl_cipher_mode_t mode = cipher_suite->mode;

    dec = wmem_new0(wmem_file_scope(), SslDecoder);
    /* init mac buffer: mac storage is embedded into decoder struct to save a
     memory allocation and waste samo more memory*/
    dec->cipher_suite=cipher_suite;
    dec->compression = compression;
    if ((mode == MODE_STREAM && mk != NULL) || mode == MODE_CBC) {
        // AEAD ciphers use no MAC key, but stream and block ciphers do. Note
        // the special case for NULL ciphers, even if there is insufficiency
        // keying material (including MAC key), we will can still create
        // decoders since "decryption" is easy for such ciphers.
        dec->mac_key.data = dec->_mac_key_or_write_iv;
        ssl_data_set(&dec->mac_key, mk, ssl_cipher_suite_dig(cipher_suite)->len);
    } else if (mode == MODE_GCM || mode == MODE_CCM || mode == MODE_CCM_8 || mode == MODE_POLY1305) {
        // Input for the nonce, to be used with AEAD ciphers.
        DISSECTOR_ASSERT(iv_length <= sizeof(dec->_mac_key_or_write_iv));
        dec->write_iv.data = dec->_mac_key_or_write_iv;
        ssl_data_set(&dec->write_iv, iv, iv_length);
    }
    dec->seq = 0;
    dec->decomp = ssl_create_decompressor(compression);
    wmem_register_callback(wmem_file_scope(), ssl_decoder_destroy_cb, dec);

    if (ssl_cipher_init(&dec->evp,cipher_algo,sk,iv,cipher_suite->mode) < 0) {
        ssl_debug_printf("%s: can't create cipher id:%d mode:%d\n", G_STRFUNC,
            cipher_algo, cipher_suite->mode);
        return NULL;
    }

    if (cipher_suite->enc != ENC_NULL && sn_key != NULL) {
        if (cipher_suite->enc == ENC_AES || cipher_suite->enc == ENC_AES256) {
            mode = MODE_ECB;
        } else if (cipher_suite->enc == ENC_CHACHA20) {
            mode = MODE_STREAM;
        } else {
            ssl_debug_printf("not supported encryption algorithm for DTLSv1.3\n");
            return NULL;
        }

        if (ssl_cipher_init(&dec->sn_evp, cipher_algo, sn_key, NULL, mode) < 0) {
            ssl_debug_printf("%s: can't create cipher id:%d mode:%d for seq number decryption\n", G_STRFUNC,
               cipher_algo, MODE_ECB);
            ssl_cipher_cleanup(&dec->evp);
            dec->evp = NULL;
            return NULL;
        }
    } else {
        dec->sn_evp = NULL;
    }

    dec->dtls13_aad.data = NULL;
    dec->dtls13_aad.data_len = 0;
    ssl_debug_printf("decoder initialized (digest len %d)\n", ssl_cipher_suite_dig(cipher_suite)->len);
    return dec;
}

static bool
ssl_decoder_destroy_cb(wmem_allocator_t *allocator _U_, wmem_cb_event_t event _U_, void *user_data)
{
    SslDecoder *dec = (SslDecoder *) user_data;

    if (dec->evp)
        ssl_cipher_cleanup(&dec->evp);
    if (dec->sn_evp)
      ssl_cipher_cleanup(&dec->sn_evp);

#if defined (HAVE_ZLIB) || defined (HAVE_ZLIBNG)
    if (dec->decomp != NULL && dec->decomp->compression == 1 /* DEFLATE */)
        ZLIB_PREFIX(inflateEnd)(&dec->decomp->istream);
#endif

    return false;
}
/* }}} */

/* (Pre-)master secrets calculations {{{ */
#ifdef HAVE_LIBGNUTLS
static bool
ssl_decrypt_pre_master_secret(SslDecryptSession *ssl_session,
                              StringInfo *encrypted_pre_master,
                              GHashTable *key_hash);
#endif /* HAVE_LIBGNUTLS */

static bool
ssl_restore_master_key(SslDecryptSession *ssl, const char *label,
                       bool is_pre_master, GHashTable *ht, StringInfo *key);

bool
ssl_generate_pre_master_secret(SslDecryptSession *ssl_session,
                               uint32_t length, tvbuff_t *tvb, uint32_t offset,
                               const char *ssl_psk, packet_info *pinfo,
#ifdef HAVE_LIBGNUTLS
                               GHashTable *key_hash,
#endif
                               const ssl_master_key_map_t *mk_map)
{
    /* check for required session data */
    ssl_debug_printf("%s: found SSL_HND_CLIENT_KEY_EXCHG, state %X\n",
                     G_STRFUNC, ssl_session->state);
    if ((ssl_session->state & (SSL_CIPHER|SSL_CLIENT_RANDOM|SSL_SERVER_RANDOM|SSL_VERSION)) !=
        (SSL_CIPHER|SSL_CLIENT_RANDOM|SSL_SERVER_RANDOM|SSL_VERSION)) {
        ssl_debug_printf("%s: not enough data to generate key (required state %X)\n", G_STRFUNC,
                         (SSL_CIPHER|SSL_CLIENT_RANDOM|SSL_SERVER_RANDOM|SSL_VERSION));
        return false;
    }

    if (ssl_session->session.version == TLSV1DOT3_VERSION) {
        ssl_debug_printf("%s: detected TLS 1.3 which has no pre-master secrets\n", G_STRFUNC);
        return false;
    }

    /* check to see if the PMS was provided to us*/
    if (ssl_restore_master_key(ssl_session, "Unencrypted pre-master secret", true,
           mk_map->pms, &ssl_session->client_random)) {
        return true;
    }

    if (ssl_session->cipher_suite->kex == KEX_PSK)
    {
        /* calculate pre master secret*/
        StringInfo pre_master_secret;
        unsigned psk_len, pre_master_len;

        if (!ssl_psk || (ssl_psk[0] == 0)) {
            ssl_debug_printf("%s: can't find pre-shared key\n", G_STRFUNC);
            return false;
        }

        /* convert hex string into char*/
        if (!from_hex(&ssl_session->psk, ssl_psk, strlen(ssl_psk))) {
            ssl_debug_printf("%s: ssl.psk/dtls.psk contains invalid hex\n",
                             G_STRFUNC);
            return false;
        }

        psk_len = ssl_session->psk.data_len;
        if (psk_len >= (2 << 15)) {
            ssl_debug_printf("%s: ssl.psk/dtls.psk must not be larger than 2^15 - 1\n",
                             G_STRFUNC);
            return false;
        }


        pre_master_len = psk_len * 2 + 4;

        pre_master_secret.data = (unsigned char *)wmem_alloc(wmem_file_scope(), pre_master_len);
        pre_master_secret.data_len = pre_master_len;
        /* 2 bytes psk_len*/
        pre_master_secret.data[0] = psk_len >> 8;
        pre_master_secret.data[1] = psk_len & 0xFF;
        /* psk_len bytes times 0*/
        memset(&pre_master_secret.data[2], 0, psk_len);
        /* 2 bytes psk_len*/
        pre_master_secret.data[psk_len + 2] = psk_len >> 8;
        pre_master_secret.data[psk_len + 3] = psk_len & 0xFF;
        /* psk*/
        memcpy(&pre_master_secret.data[psk_len + 4], ssl_session->psk.data, psk_len);

        ssl_session->pre_master_secret.data = pre_master_secret.data;
        ssl_session->pre_master_secret.data_len = pre_master_len;
        /*ssl_debug_printf("pre master secret",&ssl->pre_master_secret);*/

        /* Remove the master secret if it was there.
           This forces keying material regeneration in
           case we're renegotiating */
        ssl_session->state &= ~(SSL_MASTER_SECRET|SSL_HAVE_SESSION_KEY);
        ssl_session->state |= SSL_PRE_MASTER_SECRET;
        return true;
    }
    else
    {
        unsigned encrlen, skip;
        encrlen = length;
        skip = 0;

        /* get encrypted data, on tls1 we have to skip two bytes
         * (it's the encrypted len and should be equal to record len - 2)
         * in case of rsa1024 that would be 128 + 2 = 130; for psk not necessary
         */
        if (ssl_session->cipher_suite->kex == KEX_RSA &&
           (ssl_session->session.version == TLSV1_VERSION ||
            ssl_session->session.version == TLSV1DOT1_VERSION ||
            ssl_session->session.version == TLSV1DOT2_VERSION ||
            ssl_session->session.version == DTLSV1DOT0_VERSION ||
            ssl_session->session.version == DTLSV1DOT2_VERSION ||
            ssl_session->session.version == TLCPV1_VERSION ))
        {
            encrlen  = tvb_get_ntohs(tvb, offset);
            skip = 2;
            if (encrlen > length - 2)
            {
                ssl_debug_printf("%s: wrong encrypted length (%d max %d)\n",
                                 G_STRFUNC, encrlen, length);
                return false;
            }
        }
        /* the valid lower bound is higher than 8, but it is sufficient for the
         * ssl keylog file below */
        if (encrlen < 8) {
            ssl_debug_printf("%s: invalid encrypted pre-master key length %d\n",
                             G_STRFUNC, encrlen);
            return false;
        }

        StringInfo encrypted_pre_master = {
            .data = (unsigned char *)tvb_memdup(pinfo->pool, tvb, offset + skip, encrlen),
            .data_len = encrlen,
        };

#ifdef HAVE_LIBGNUTLS
        /* Try to lookup an appropriate RSA private key to decrypt the Encrypted Pre-Master Secret. */
        if (ssl_session->cert_key_id) {
            if (ssl_decrypt_pre_master_secret(ssl_session, &encrypted_pre_master, key_hash))
                return true;

            ssl_debug_printf("%s: can't decrypt pre-master secret\n",
                             G_STRFUNC);
        }
#endif /* HAVE_LIBGNUTLS */

        /* try to find the pre-master secret from the encrypted one. The
         * ssl key logfile stores only the first 8 bytes, so truncate it */
        encrypted_pre_master.data_len = 8;
        if (ssl_restore_master_key(ssl_session, "Encrypted pre-master secret",
            true, mk_map->pre_master, &encrypted_pre_master))
            return true;
    }
    return false;
}

/* Used for (D)TLS 1.2 and earlier versions (not with TLS 1.3). */
int
ssl_generate_keyring_material(SslDecryptSession*ssl_session)
{
    StringInfo  key_block = { NULL, 0 };
    uint8_t     _iv_c[MAX_BLOCK_SIZE],_iv_s[MAX_BLOCK_SIZE];
    uint8_t     _key_c[MAX_KEY_SIZE],_key_s[MAX_KEY_SIZE];
    int         needed;
    int         cipher_algo = -1;   /* special value (-1) for NULL encryption */
    unsigned    encr_key_len, write_iv_len = 0;
    bool        is_export_cipher;
    uint8_t    *ptr, *c_iv = NULL, *s_iv = NULL;
    uint8_t    *c_wk = NULL, *s_wk = NULL, *c_mk = NULL, *s_mk = NULL;
    const SslCipherSuite *cipher_suite = ssl_session->cipher_suite;

    /* (D)TLS 1.3 is handled directly in tls13_change_key. */
    if (ssl_session->session.version == TLSV1DOT3_VERSION || ssl_session->session.version == DTLSV1DOT3_VERSION) {
        ssl_debug_printf("%s: detected TLS 1.3. Should not have been called!\n", G_STRFUNC);
        return -1;
    }

    /* check for enough info to proceed */
    unsigned need_all = SSL_CIPHER|SSL_CLIENT_RANDOM|SSL_SERVER_RANDOM|SSL_VERSION;
    unsigned need_any = SSL_MASTER_SECRET | SSL_PRE_MASTER_SECRET;
    if (((ssl_session->state & need_all) != need_all) || ((ssl_session->state & need_any) == 0)) {
        ssl_debug_printf("ssl_generate_keyring_material not enough data to generate key "
                         "(0x%02X required 0x%02X or 0x%02X)\n", ssl_session->state,
                         need_all|SSL_MASTER_SECRET, need_all|SSL_PRE_MASTER_SECRET);
        /* Special case: for NULL encryption, allow dissection of data even if
         * the Client Hello is missing (MAC keys are now skipped though). */
        need_all = SSL_CIPHER|SSL_VERSION;
        if ((ssl_session->state & need_all) == need_all &&
                cipher_suite->enc == ENC_NULL) {
            ssl_debug_printf("%s NULL cipher found, will create a decoder but "
                    "skip MAC validation as keys are missing.\n", G_STRFUNC);
            goto create_decoders;
        }

        return -1;
    }

    /* if master key is not available, generate is from the pre-master secret */
    if (!(ssl_session->state & SSL_MASTER_SECRET)) {
        if ((ssl_session->state & SSL_EXTENDED_MASTER_SECRET_MASK) == SSL_EXTENDED_MASTER_SECRET_MASK) {
            StringInfo handshake_hashed_data;
            int ret;

            handshake_hashed_data.data = NULL;
            handshake_hashed_data.data_len = 0;

            ssl_debug_printf("%s:PRF(pre_master_secret_extended)\n", G_STRFUNC);
            ssl_print_string("pre master secret",&ssl_session->pre_master_secret);
            DISSECTOR_ASSERT(ssl_session->handshake_data.data_len > 0);

            switch(ssl_session->session.version) {
            case TLSV1_VERSION:
            case TLSV1DOT1_VERSION:
            case DTLSV1DOT0_VERSION:
            case DTLSV1DOT0_OPENSSL_VERSION:
            case TLCPV1_VERSION:
                ret = tls_handshake_hash(ssl_session, &handshake_hashed_data);
                break;
            default:
                switch (cipher_suite->dig) {
                case DIG_SHA384:
                    ret = tls12_handshake_hash(ssl_session, GCRY_MD_SHA384, &handshake_hashed_data);
                    break;
                default:
                    ret = tls12_handshake_hash(ssl_session, GCRY_MD_SHA256, &handshake_hashed_data);
                    break;
                }
                break;
            }
            if (ret) {
                ssl_debug_printf("%s can't generate handshake hash\n", G_STRFUNC);
                return -1;
            }

            wmem_free(wmem_file_scope(), ssl_session->handshake_data.data);
            ssl_session->handshake_data.data = NULL;
            ssl_session->handshake_data.data_len = 0;

            if (!prf(ssl_session, &ssl_session->pre_master_secret, "extended master secret",
                     &handshake_hashed_data,
                     NULL, &ssl_session->master_secret,
                     SSL_MASTER_SECRET_LENGTH)) {
                ssl_debug_printf("%s can't generate master_secret\n", G_STRFUNC);
                g_free(handshake_hashed_data.data);
                return -1;
            }
            g_free(handshake_hashed_data.data);
        } else {
            ssl_debug_printf("%s:PRF(pre_master_secret)\n", G_STRFUNC);
            ssl_print_string("pre master secret",&ssl_session->pre_master_secret);
            ssl_print_string("client random",&ssl_session->client_random);
            ssl_print_string("server random",&ssl_session->server_random);
            if (!prf(ssl_session, &ssl_session->pre_master_secret, "master secret",
                     &ssl_session->client_random,
                     &ssl_session->server_random, &ssl_session->master_secret,
                     SSL_MASTER_SECRET_LENGTH)) {
                ssl_debug_printf("%s can't generate master_secret\n", G_STRFUNC);
                return -1;
            }
        }
        ssl_print_string("master secret",&ssl_session->master_secret);

        /* the pre-master secret has been 'consumed' so we must clear it now */
        ssl_session->state &= ~SSL_PRE_MASTER_SECRET;
        ssl_session->state |= SSL_MASTER_SECRET;
    }

    /* Find the Libgcrypt cipher algorithm for the given SSL cipher suite ID */
    if (cipher_suite->enc != ENC_NULL) {
        const char *cipher_name = ciphers[cipher_suite->enc-ENC_START];
        ssl_debug_printf("%s CIPHER: %s\n", G_STRFUNC, cipher_name);
        cipher_algo = ssl_get_cipher_by_name(cipher_name);
        if (cipher_algo == 0) {
            ssl_debug_printf("%s can't find cipher %s\n", G_STRFUNC, cipher_name);
            return -1;
        }
    }

    /* Export ciphers consume less material from the key block. */
    encr_key_len = ssl_get_cipher_export_keymat_size(cipher_suite->number);
    is_export_cipher = encr_key_len > 0;
    if (!is_export_cipher && cipher_suite->enc != ENC_NULL) {
        encr_key_len = (unsigned)gcry_cipher_get_algo_keylen(cipher_algo);
    }

    if (cipher_suite->mode == MODE_CBC) {
        write_iv_len = (unsigned)gcry_cipher_get_algo_blklen(cipher_algo);
    } else if (cipher_suite->mode == MODE_GCM || cipher_suite->mode == MODE_CCM || cipher_suite->mode == MODE_CCM_8) {
        /* account for a four-byte salt for client and server side (from
         * client_write_IV and server_write_IV), see GCMNonce (RFC 5288) */
        write_iv_len = 4;
    } else if (cipher_suite->mode == MODE_POLY1305) {
        /* RFC 7905: SecurityParameters.fixed_iv_length is twelve bytes */
        write_iv_len = 12;
    }

    /* Compute the key block. First figure out how much data we need */
    needed = ssl_cipher_suite_dig(cipher_suite)->len*2;     /* MAC key  */
    needed += 2 * encr_key_len;                             /* encryption key */
    needed += 2 * write_iv_len;                             /* write IV */

    key_block.data = (unsigned char *)g_malloc(needed);
    ssl_debug_printf("%s sess key generation\n", G_STRFUNC);
    if (!prf(ssl_session, &ssl_session->master_secret, "key expansion",
            &ssl_session->server_random,&ssl_session->client_random,
            &key_block, needed)) {
        ssl_debug_printf("%s can't generate key_block\n", G_STRFUNC);
        goto fail;
    }
    ssl_print_string("key expansion", &key_block);

    ptr=key_block.data;
    /* client/server write MAC key (for non-AEAD ciphers) */
    if (cipher_suite->mode == MODE_STREAM || cipher_suite->mode == MODE_CBC) {
        c_mk=ptr; ptr+=ssl_cipher_suite_dig(cipher_suite)->len;
        s_mk=ptr; ptr+=ssl_cipher_suite_dig(cipher_suite)->len;
    }
    /* client/server write encryption key */
    c_wk=ptr; ptr += encr_key_len;
    s_wk=ptr; ptr += encr_key_len;
    /* client/server write IV (used as IV (for CBC) or salt (for AEAD)) */
    if (write_iv_len > 0) {
        c_iv=ptr; ptr += write_iv_len;
        s_iv=ptr; /* ptr += write_iv_len; */
    }

    /* export ciphers work with a smaller key length */
    if (is_export_cipher) {
        if (cipher_suite->mode == MODE_CBC) {

            /* We only have room for MAX_BLOCK_SIZE bytes IVs, but that's
             all we should need. This is a sanity check */
            if (write_iv_len > MAX_BLOCK_SIZE) {
                ssl_debug_printf("%s cipher suite block must be at most %d nut is %d\n",
                        G_STRFUNC, MAX_BLOCK_SIZE, write_iv_len);
                goto fail;
            }

            if(ssl_session->session.version==SSLV3_VERSION){
                /* The length of these fields are ignored by this caller */
                StringInfo iv_c, iv_s;
                iv_c.data = _iv_c;
                iv_s.data = _iv_s;

                ssl_debug_printf("%s ssl3_generate_export_iv\n", G_STRFUNC);
                if (!ssl3_generate_export_iv(&ssl_session->client_random,
                             &ssl_session->server_random, &iv_c, write_iv_len)) {
                    goto fail;
                }
                ssl_debug_printf("%s ssl3_generate_export_iv(2)\n", G_STRFUNC);
                if (!ssl3_generate_export_iv(&ssl_session->server_random,
                             &ssl_session->client_random, &iv_s, write_iv_len)) {
                    goto fail;
                }
            }
            else{
                uint8_t _iv_block[MAX_BLOCK_SIZE * 2];
                StringInfo iv_block;
                StringInfo key_null;
                uint8_t _key_null;

                key_null.data = &_key_null;
                key_null.data_len = 0;

                iv_block.data = _iv_block;

                ssl_debug_printf("%s prf(iv_block)\n", G_STRFUNC);
                if (!prf(ssl_session, &key_null, "IV block",
                        &ssl_session->client_random,
                        &ssl_session->server_random, &iv_block,
                        write_iv_len * 2)) {
                    ssl_debug_printf("%s can't generate tls31 iv block\n", G_STRFUNC);
                    goto fail;
                }

                memcpy(_iv_c, iv_block.data, write_iv_len);
                memcpy(_iv_s, iv_block.data + write_iv_len, write_iv_len);
            }

            c_iv=_iv_c;
            s_iv=_iv_s;
        }

        if (ssl_session->session.version==SSLV3_VERSION){

            SSL_MD5_CTX md5;
            ssl_debug_printf("%s MD5(client_random)\n", G_STRFUNC);

            if (ssl_md5_init(&md5) != 0)
                goto fail;
            ssl_md5_update(&md5,c_wk,encr_key_len);
            ssl_md5_update(&md5,ssl_session->client_random.data,
                ssl_session->client_random.data_len);
            ssl_md5_update(&md5,ssl_session->server_random.data,
                ssl_session->server_random.data_len);
            ssl_md5_final(_key_c,&md5);
            ssl_md5_cleanup(&md5);
            c_wk=_key_c;

            if (ssl_md5_init(&md5) != 0)
                goto fail;
            ssl_debug_printf("%s MD5(server_random)\n", G_STRFUNC);
            ssl_md5_update(&md5,s_wk,encr_key_len);
            ssl_md5_update(&md5,ssl_session->server_random.data,
                ssl_session->server_random.data_len);
            ssl_md5_update(&md5,ssl_session->client_random.data,
                ssl_session->client_random.data_len);
            ssl_md5_final(_key_s,&md5);
            ssl_md5_cleanup(&md5);
            s_wk=_key_s;
        }
        else{
            StringInfo key_c, key_s, k;
            key_c.data = _key_c;
            key_s.data = _key_s;

            k.data = c_wk;
            k.data_len = encr_key_len;
            ssl_debug_printf("%s PRF(key_c)\n", G_STRFUNC);
            if (!prf(ssl_session, &k, "client write key",
                    &ssl_session->client_random,
                    &ssl_session->server_random, &key_c, sizeof(_key_c))) {
                ssl_debug_printf("%s can't generate tll31 server key \n", G_STRFUNC);
                goto fail;
            }
            c_wk=_key_c;

            k.data = s_wk;
            k.data_len = encr_key_len;
            ssl_debug_printf("%s PRF(key_s)\n", G_STRFUNC);
            if (!prf(ssl_session, &k, "server write key",
                    &ssl_session->client_random,
                    &ssl_session->server_random, &key_s, sizeof(_key_s))) {
                ssl_debug_printf("%s can't generate tll31 client key \n", G_STRFUNC);
                goto fail;
            }
            s_wk=_key_s;
        }
    }

    /* show key material info */
    if (c_mk != NULL) {
        ssl_print_data("Client MAC key",c_mk,ssl_cipher_suite_dig(cipher_suite)->len);
        ssl_print_data("Server MAC key",s_mk,ssl_cipher_suite_dig(cipher_suite)->len);
    }
    ssl_print_data("Client Write key", c_wk, encr_key_len);
    ssl_print_data("Server Write key", s_wk, encr_key_len);
    /* used as IV for CBC mode and the AEAD implicit nonce (salt) */
    if (write_iv_len > 0) {
        ssl_print_data("Client Write IV", c_iv, write_iv_len);
        ssl_print_data("Server Write IV", s_iv, write_iv_len);
    }

create_decoders:
    /* create both client and server ciphers*/
    ssl_debug_printf("%s ssl_create_decoder(client)\n", G_STRFUNC);
    ssl_session->client_new = ssl_create_decoder(cipher_suite, cipher_algo, ssl_session->session.compression, c_mk, c_wk, NULL, c_iv, write_iv_len);
    if (!ssl_session->client_new) {
        ssl_debug_printf("%s can't init client decoder\n", G_STRFUNC);
        goto fail;
    }
    ssl_debug_printf("%s ssl_create_decoder(server)\n", G_STRFUNC);
    ssl_session->server_new = ssl_create_decoder(cipher_suite, cipher_algo, ssl_session->session.compression, s_mk, s_wk, NULL, s_iv, write_iv_len);
    if (!ssl_session->server_new) {
        ssl_debug_printf("%s can't init server decoder\n", G_STRFUNC);
        goto fail;
    }

    /* Continue the SSL stream after renegotiation with new keys. */
    ssl_session->client_new->flow = ssl_session->client ? ssl_session->client->flow : ssl_create_flow();
    ssl_session->server_new->flow = ssl_session->server ? ssl_session->server->flow : ssl_create_flow();

    ssl_debug_printf("%s: client seq %" PRIu64 ", server seq %" PRIu64 "\n",
        G_STRFUNC, ssl_session->client_new->seq, ssl_session->server_new->seq);
    g_free(key_block.data);
    ssl_session->state |= SSL_HAVE_SESSION_KEY;
    return 0;

fail:
    g_free(key_block.data);
    return -1;
}

/* Generated the key material based on the given secret. */
bool
tls13_generate_keys(SslDecryptSession *ssl_session, const StringInfo *secret, bool is_from_server)
{
    bool        success = false;
    unsigned char     *write_key = NULL, *write_iv = NULL;
    unsigned char     *sn_key = NULL;
    SslDecoder *decoder;
    unsigned    key_length, iv_length;
    int         hash_algo;
    const SslCipherSuite *cipher_suite = ssl_session->cipher_suite;
    int         cipher_algo;

    if ((ssl_session->session.version != TLSV1DOT3_VERSION) && (ssl_session->session.version != DTLSV1DOT3_VERSION)) {
        ssl_debug_printf("%s only usable for TLS 1.3, not %#x!\n", G_STRFUNC,
                ssl_session->session.version);
        return false;
    }

    if (cipher_suite == NULL) {
        ssl_debug_printf("%s Unknown cipher\n", G_STRFUNC);
        return false;
    }

    if (cipher_suite->kex != KEX_TLS13) {
        ssl_debug_printf("%s Invalid cipher suite 0x%04x spotted!\n", G_STRFUNC, cipher_suite->number);
        return false;
    }

    /* Find the Libgcrypt cipher algorithm for the given SSL cipher suite ID */
    const char *cipher_name = ciphers[cipher_suite->enc-ENC_START];
    ssl_debug_printf("%s CIPHER: %s\n", G_STRFUNC, cipher_name);
    cipher_algo = ssl_get_cipher_by_name(cipher_name);
    if (cipher_algo == 0) {
        ssl_debug_printf("%s can't find cipher %s\n", G_STRFUNC, cipher_name);
        return false;
    }

    const char *hash_name = ssl_cipher_suite_dig(cipher_suite)->name;
    hash_algo = ssl_get_digest_by_name(hash_name);
    if (!hash_algo) {
        ssl_debug_printf("%s can't find hash function %s\n", G_STRFUNC, hash_name);
        return false;
    }

    key_length = (unsigned) gcry_cipher_get_algo_keylen(cipher_algo);
    /* AES-GCM/AES-CCM/Poly1305-ChaCha20 all have N_MIN=N_MAX = 12. */
    iv_length = 12;
    ssl_debug_printf("%s key_length %u iv_length %u\n", G_STRFUNC, key_length, iv_length);

    const char *label_prefix = tls13_hkdf_label_prefix(ssl_session);
    if (!tls13_hkdf_expand_label(hash_algo, secret, label_prefix, "key", key_length, &write_key)) {
        ssl_debug_printf("%s write_key expansion failed\n", G_STRFUNC);
        return false;
    }
    if (!tls13_hkdf_expand_label(hash_algo, secret, label_prefix, "iv", iv_length, &write_iv)) {
        ssl_debug_printf("%s write_iv expansion failed\n", G_STRFUNC);
        goto end;
    }

    if (ssl_session->session.version == DTLSV1DOT3_VERSION) {
        if (!tls13_hkdf_expand_label(hash_algo, secret, label_prefix, "sn", key_length, &sn_key)) {
            ssl_debug_printf("%s sn_key expansion failed\n", G_STRFUNC);
            goto end;
        }
    }

    ssl_print_data(is_from_server ? "Server Write Key" : "Client Write Key", write_key, key_length);
    ssl_print_data(is_from_server ? "Server Write IV" : "Client Write IV", write_iv, iv_length);
    if (ssl_session->session.version == DTLSV1DOT3_VERSION) {
        ssl_print_data(is_from_server ? "Server Write SN" : "Client Write SN", sn_key, key_length);
    }

    ssl_debug_printf("%s ssl_create_decoder(%s)\n", G_STRFUNC, is_from_server ? "server" : "client");
    decoder = ssl_create_decoder(cipher_suite, cipher_algo, 0, NULL, write_key, sn_key, write_iv, iv_length);
    if (!decoder) {
        ssl_debug_printf("%s can't init %s decoder\n", G_STRFUNC, is_from_server ? "server" : "client");
        goto end;
    }

    /* Continue the TLS session with new keys, but reuse old flow to keep things
     * like "Follow TLS" working (by linking application data records). */
    if (is_from_server) {
        decoder->flow = ssl_session->server ? ssl_session->server->flow : ssl_create_flow();
        ssl_session->server = decoder;
    } else {
        decoder->flow = ssl_session->client ? ssl_session->client->flow : ssl_create_flow();
        ssl_session->client = decoder;
    }
    ssl_debug_printf("%s %s ready using cipher suite 0x%04x (cipher %s hash %s)\n", G_STRFUNC,
                     is_from_server ? "Server" : "Client", cipher_suite->number, cipher_name, hash_name);
    success = true;

end:
    wmem_free(NULL, write_key);
    wmem_free(NULL, write_iv);
    if (sn_key)
        wmem_free(NULL, sn_key);
    return success;
}
/* (Pre-)master secrets calculations }}} */

#ifdef HAVE_LIBGNUTLS
/* Decrypt RSA pre-master secret using RSA private key. {{{ */
static bool
ssl_decrypt_pre_master_secret(SslDecryptSession *ssl_session,
    StringInfo *encrypted_pre_master, GHashTable *key_hash)
{
    int ret;

    if (!encrypted_pre_master)
        return false;

    if (KEX_IS_DH(ssl_session->cipher_suite->kex)) {
        ssl_debug_printf("%s: session uses Diffie-Hellman key exchange "
                         "(cipher suite 0x%04X %s) and cannot be decrypted "
                         "using a RSA private key file.\n",
                         G_STRFUNC, ssl_session->session.cipher,
                         val_to_str_ext_const(ssl_session->session.cipher,
                             &ssl_31_ciphersuite_ext, "unknown"));
        return false;
    } else if (ssl_session->cipher_suite->kex != KEX_RSA) {
         ssl_debug_printf("%s key exchange %d different from KEX_RSA (%d)\n",
                          G_STRFUNC, ssl_session->cipher_suite->kex, KEX_RSA);
        return false;
    }

    gnutls_privkey_t pk = (gnutls_privkey_t)g_hash_table_lookup(key_hash, ssl_session->cert_key_id);

    ssl_print_string("pre master encrypted", encrypted_pre_master);
    ssl_debug_printf("%s: RSA_private_decrypt\n", G_STRFUNC);
    const gnutls_datum_t epms = { encrypted_pre_master->data, encrypted_pre_master->data_len };
    gnutls_datum_t pms = { 0 };
    if (pk) {
        // Try to decrypt using the RSA keys table from (D)TLS preferences.
        ret = gnutls_privkey_decrypt_data(pk, 0, &epms, &pms);
    } else {
        // Try to decrypt using a hardware token.
        ret = secrets_rsa_decrypt(ssl_session->cert_key_id, epms.data, epms.size, &pms.data, &pms.size);
    }
    if (ret < 0) {
        ssl_debug_printf("%s: decryption failed: %d (%s)\n", G_STRFUNC, ret, gnutls_strerror(ret));
        return false;
    }

    if (pms.size != 48) {
        ssl_debug_printf("%s wrong pre_master_secret length (%d, expected %d)\n",
                         G_STRFUNC, pms.size, 48);
        if (pk) {
            gnutls_free(pms.data);
        } else {
            g_free(pms.data);
        }
        return false;
    }

    ssl_session->pre_master_secret.data = (uint8_t *)wmem_memdup(wmem_file_scope(), pms.data, 48);
    ssl_session->pre_master_secret.data_len = 48;
    if (pk) {
        gnutls_free(pms.data);
    } else {
        g_free(pms.data);
    }
    ssl_print_string("pre master secret", &ssl_session->pre_master_secret);

    /* Remove the master secret if it was there.
       This forces keying material regeneration in
       case we're renegotiating */
    ssl_session->state &= ~(SSL_MASTER_SECRET|SSL_HAVE_SESSION_KEY);
    ssl_session->state |= SSL_PRE_MASTER_SECRET;
    return true;
} /* }}} */
#endif /* HAVE_LIBGNUTLS */

/* Decryption integrity check {{{ */

static int
tls_check_mac(SslDecoder*decoder, int ct, int ver, uint8_t* data,
        uint32_t datalen, uint8_t* mac)
{
    SSL_HMAC hm;
    int      md;
    uint32_t len;
    uint8_t  buf[DIGEST_MAX_SIZE];
    int16_t  temp;

    md=ssl_get_digest_by_name(ssl_cipher_suite_dig(decoder->cipher_suite)->name);
    ssl_debug_printf("tls_check_mac mac type:%s md %d\n",
        ssl_cipher_suite_dig(decoder->cipher_suite)->name, md);

    if (ssl_hmac_init(&hm,md) != 0)
        return -1;
    if (ssl_hmac_setkey(&hm,decoder->mac_key.data,decoder->mac_key.data_len) != 0)
        return -1;

    /* hash sequence number */
    phton64(buf, decoder->seq);

    decoder->seq++;

    ssl_hmac_update(&hm,buf,8);

    /* hash content type */
    buf[0]=ct;
    ssl_hmac_update(&hm,buf,1);

    /* hash version,data length and data*/
    /* *((int16_t*)buf) = g_htons(ver); */
    temp = g_htons(ver);
    memcpy(buf, &temp, 2);
    ssl_hmac_update(&hm,buf,2);

    /* *((int16_t*)buf) = g_htons(datalen); */
    temp = g_htons(datalen);
    memcpy(buf, &temp, 2);
    ssl_hmac_update(&hm,buf,2);
    ssl_hmac_update(&hm,data,datalen);

    /* get digest and digest len*/
    len = sizeof(buf);
    ssl_hmac_final(&hm,buf,&len);
    ssl_hmac_cleanup(&hm);
    ssl_print_data("Mac", buf, len);
    if(memcmp(mac,buf,len))
        return -1;

    return 0;
}

static int
ssl3_check_mac(SslDecoder*decoder,int ct,uint8_t* data,
        uint32_t datalen, uint8_t* mac)
{
    SSL_MD  mc;
    int     md;
    uint32_t len;
    uint8_t buf[64],dgst[20];
    int     pad_ct;
    int16_t temp;

    pad_ct=(decoder->cipher_suite->dig==DIG_SHA)?40:48;

    /* get cipher used for digest computation */
    md=ssl_get_digest_by_name(ssl_cipher_suite_dig(decoder->cipher_suite)->name);
    if (ssl_md_init(&mc,md) !=0)
        return -1;

    /* do hash computation on data && padding */
    ssl_md_update(&mc,decoder->mac_key.data,decoder->mac_key.data_len);

    /* hash padding*/
    memset(buf,0x36,pad_ct);
    ssl_md_update(&mc,buf,pad_ct);

    /* hash sequence number */
    phton64(buf, decoder->seq);
    decoder->seq++;
    ssl_md_update(&mc,buf,8);

    /* hash content type */
    buf[0]=ct;
    ssl_md_update(&mc,buf,1);

    /* hash data length in network byte order and data*/
    /* *((int16_t* )buf) = g_htons(datalen); */
    temp = g_htons(datalen);
    memcpy(buf, &temp, 2);
    ssl_md_update(&mc,buf,2);
    ssl_md_update(&mc,data,datalen);

    /* get partial digest */
    ssl_md_final(&mc,dgst,&len);
    ssl_md_reset(&mc);

    /* hash mac key */
    ssl_md_update(&mc,decoder->mac_key.data,decoder->mac_key.data_len);

    /* hash padding and partial digest*/
    memset(buf,0x5c,pad_ct);
    ssl_md_update(&mc,buf,pad_ct);
    ssl_md_update(&mc,dgst,len);

    ssl_md_final(&mc,dgst,&len);
    ssl_md_cleanup(&mc);

    if(memcmp(mac,dgst,len))
        return -1;

    return 0;
}

static int
dtls_check_mac(SslDecryptSession *ssl, SslDecoder*decoder, int ct, uint8_t* data,
        uint32_t datalen, uint8_t* mac, const unsigned char *cid, uint8_t cidl)
{
    SSL_HMAC hm;
    int      md;
    uint32_t len;
    uint8_t  buf[DIGEST_MAX_SIZE];
    int16_t  temp;

    int ver = ssl->session.version;
    bool is_cid = ((ct == SSL_ID_TLS12_CID) && (ver == DTLSV1DOT2_VERSION));

    md=ssl_get_digest_by_name(ssl_cipher_suite_dig(decoder->cipher_suite)->name);
    ssl_debug_printf("dtls_check_mac mac type:%s md %d\n",
        ssl_cipher_suite_dig(decoder->cipher_suite)->name, md);

    if (ssl_hmac_init(&hm,md) != 0)
        return -1;
    if (ssl_hmac_setkey(&hm,decoder->mac_key.data,decoder->mac_key.data_len) != 0)
        return -1;

    ssl_debug_printf("dtls_check_mac seq: %" PRIu64 " epoch: %d\n",decoder->seq,decoder->epoch);

    if (is_cid && !ssl->session.deprecated_cid) {
        /* hash seq num placeholder */
        memset(buf,0xFF,8);
        ssl_hmac_update(&hm,buf,8);

        /* hash content type + cid length + content type */
        buf[0]=ct;
        buf[1]=cidl;
        buf[2]=ct;
        ssl_hmac_update(&hm,buf,3);

        /* hash version */
        temp = g_htons(ver);
        memcpy(buf, &temp, 2);
        ssl_hmac_update(&hm,buf,2);

        /* hash sequence number */
        phton64(buf, decoder->seq);
        buf[0]=decoder->epoch>>8;
        buf[1]=(uint8_t)decoder->epoch;
        ssl_hmac_update(&hm,buf,8);

        /* hash cid */
        ssl_hmac_update(&hm,cid,cidl);
    } else {
        /* hash sequence number */
        phton64(buf, decoder->seq);
        buf[0]=decoder->epoch>>8;
        buf[1]=(uint8_t)decoder->epoch;
        ssl_hmac_update(&hm,buf,8);

        /* hash content type */
        buf[0]=ct;
        ssl_hmac_update(&hm,buf,1);

        /* hash version */
        temp = g_htons(ver);
        memcpy(buf, &temp, 2);
        ssl_hmac_update(&hm,buf,2);

        if (is_cid && ssl->session.deprecated_cid) {
            /* hash cid */
            ssl_hmac_update(&hm,cid,cidl);

            /* hash cid length */
            buf[0] = cidl;
            ssl_hmac_update(&hm,buf,1);
        }
    }

    /* data length and data */
    temp = g_htons(datalen);
    memcpy(buf, &temp, 2);
    ssl_hmac_update(&hm,buf,2);
    ssl_hmac_update(&hm,data,datalen);

    /* get digest and digest len */
    len = sizeof(buf);
    ssl_hmac_final(&hm,buf,&len);
    ssl_hmac_cleanup(&hm);
    ssl_print_data("Mac", buf, len);
    if(memcmp(mac,buf,len))
        return -1;

    return 0;
}
/* Decryption integrity check }}} */


static bool
tls_decrypt_aead_record(SslDecryptSession *ssl, SslDecoder *decoder,
        uint8_t ct, uint16_t record_version,
        bool ignore_mac_failed,
        const unsigned char *in, uint16_t inl,
        const unsigned char *cid, uint8_t cidl,
        StringInfo *out_str, unsigned *outl)
{
    /* RFC 5246 (TLS 1.2) 6.2.3.3 defines the TLSCipherText.fragment as:
     * GenericAEADCipher: { nonce_explicit, [content] }
     * In TLS 1.3 this explicit nonce is gone.
     * With AES GCM/CCM, "[content]" is actually the concatenation of the
     * ciphertext and authentication tag.
     */
    const uint16_t  version = ssl->session.version;
    const bool      is_v12 = version == TLSV1DOT2_VERSION || version == DTLSV1DOT2_VERSION || version == TLCPV1_VERSION;
    gcry_error_t    err;
    const unsigned char   *explicit_nonce = NULL, *ciphertext;
    unsigned        ciphertext_len, auth_tag_len;
    unsigned char   nonce[12];
    const ssl_cipher_mode_t cipher_mode = decoder->cipher_suite->mode;
    const bool      is_cid = ct == SSL_ID_TLS12_CID && version == DTLSV1DOT2_VERSION;
    const uint8_t   draft_version = ssl->session.tls13_draft_version;
    const unsigned char   *auth_tag_wire;
    unsigned char   auth_tag_calc[16];
    unsigned char  *aad = NULL;
    unsigned        aad_len = 0;

    switch (cipher_mode) {
    case MODE_GCM:
    case MODE_CCM:
    case MODE_POLY1305:
        auth_tag_len = 16;
        break;
    case MODE_CCM_8:
        auth_tag_len = 8;
        break;
    default:
        ssl_debug_printf("%s unsupported cipher!\n", G_STRFUNC);
        return false;
    }

    /* Parse input into explicit nonce (TLS 1.2 only), ciphertext and tag. */
    if (is_v12 && cipher_mode != MODE_POLY1305) {
        if (inl < EXPLICIT_NONCE_LEN + auth_tag_len) {
            ssl_debug_printf("%s input %d is too small for explicit nonce %d and auth tag %d\n",
                    G_STRFUNC, inl, EXPLICIT_NONCE_LEN, auth_tag_len);
            return false;
        }
        explicit_nonce = in;
        ciphertext = explicit_nonce + EXPLICIT_NONCE_LEN;
        ciphertext_len = inl - EXPLICIT_NONCE_LEN - auth_tag_len;
    } else if (version == TLSV1DOT3_VERSION || version == DTLSV1DOT3_VERSION || cipher_mode == MODE_POLY1305) {
        if (inl < auth_tag_len) {
            ssl_debug_printf("%s input %d has no space for auth tag %d\n", G_STRFUNC, inl, auth_tag_len);
            return false;
        }
        ciphertext = in;
        ciphertext_len = inl - auth_tag_len;
    } else {
        ssl_debug_printf("%s Unexpected TLS version %#x\n", G_STRFUNC, version);
        return false;
    }
    auth_tag_wire = ciphertext + ciphertext_len;

    /*
     * Nonce construction is version-specific. Note that AEAD_CHACHA20_POLY1305
     * (RFC 7905) uses a nonce construction similar to TLS 1.3.
     */
    if (is_v12 && cipher_mode != MODE_POLY1305) {
        DISSECTOR_ASSERT(decoder->write_iv.data_len == IMPLICIT_NONCE_LEN);
        /* Implicit (4) and explicit (8) part of nonce. */
        memcpy(nonce, decoder->write_iv.data, IMPLICIT_NONCE_LEN);
        memcpy(nonce + IMPLICIT_NONCE_LEN, explicit_nonce, EXPLICIT_NONCE_LEN);

    } else if (version == TLSV1DOT3_VERSION || version == DTLSV1DOT3_VERSION ||  cipher_mode == MODE_POLY1305) {
        /*
         * Technically the nonce length must be at least 8 bytes, but for
         * AES-GCM, AES-CCM and Poly1305-ChaCha20 the nonce length is exact 12.
         */
        const unsigned nonce_len = 12;
        DISSECTOR_ASSERT(decoder->write_iv.data_len == nonce_len);
        memcpy(nonce, decoder->write_iv.data, decoder->write_iv.data_len);
        /* Sequence number is left-padded with zeroes and XORed with write_iv */
        phton64(nonce + nonce_len - 8, pntoh64(nonce + nonce_len - 8) ^ decoder->seq);
        ssl_debug_printf("%s seq %" PRIu64 "\n", G_STRFUNC, decoder->seq);
    }

    /* Set nonce and additional authentication data */
    gcry_cipher_reset(decoder->evp);
    ssl_print_data("nonce", nonce, 12);
    err = gcry_cipher_setiv(decoder->evp, nonce, 12);
    if (err) {
        ssl_debug_printf("%s failed to set nonce: %s\n", G_STRFUNC, gcry_strerror(err));
        return false;
    }

    /* (D)TLS 1.2 needs specific AAD, TLS 1.3 (before -25) uses empty AAD. */
    if (is_cid) { /* if connection ID */
        if (ssl->session.deprecated_cid) {
            aad_len = 14 + cidl;
            aad = wmem_alloc(wmem_packet_scope(), aad_len);
            phton64(aad, decoder->seq);         /* record sequence number */
            phton16(aad, decoder->epoch);       /* DTLS 1.2 includes epoch. */
            aad[8] = ct;                        /* TLSCompressed.type */
            phton16(aad + 9, record_version);   /* TLSCompressed.version */
            memcpy(aad + 11, cid, cidl);        /* cid */
            aad[11 + cidl] = cidl;              /* cid_length */
            phton16(aad + 12 + cidl, ciphertext_len);  /* TLSCompressed.length */
        } else {
            aad_len = 23 + cidl;
            aad = wmem_alloc(wmem_packet_scope(), aad_len);
            memset(aad, 0xFF, 8);               /* seq_num_placeholder */
            aad[8] = ct;                        /* TLSCompressed.type */
            aad[9] = cidl;                      /* cid_length */
            aad[10] = ct;                       /* TLSCompressed.type */
            phton16(aad + 11, record_version);  /* TLSCompressed.version */
            phton64(aad + 13, decoder->seq);    /* record sequence number */
            phton16(aad + 13, decoder->epoch);  /* DTLS 1.2 includes epoch. */
            memcpy(aad + 21, cid, cidl);        /* cid */
            phton16(aad + 21 + cidl, ciphertext_len);  /* TLSCompressed.length */
        }
    } else if (is_v12) {
        aad_len = 13;
        aad = wmem_alloc(wmem_packet_scope(), aad_len);
        phton64(aad, decoder->seq);         /* record sequence number */
        if (version == DTLSV1DOT2_VERSION) {
            phton16(aad, decoder->epoch);   /* DTLS 1.2 includes epoch. */
        }
        aad[8] = ct;                        /* TLSCompressed.type */
        phton16(aad + 9, record_version);   /* TLSCompressed.version */
        phton16(aad + 11, ciphertext_len);  /* TLSCompressed.length */
    } else if (version == DTLSV1DOT3_VERSION) {
        aad_len = decoder->dtls13_aad.data_len;
        aad = decoder->dtls13_aad.data;
    } else if (draft_version >= 25 || draft_version == 0) {
        aad_len = 5;
        aad = wmem_alloc(wmem_packet_scope(), aad_len);
        aad[0] = ct;                        /* TLSCiphertext.opaque_type (23) */
        phton16(aad + 1, record_version);   /* TLSCiphertext.legacy_record_version (0x0303) */
        phton16(aad + 3, inl);              /* TLSCiphertext.length */
    }

    if (decoder->cipher_suite->mode == MODE_CCM || decoder->cipher_suite->mode == MODE_CCM_8) {
        /* size of plaintext, additional authenticated data and auth tag. */
        uint64_t lengths[3] = { ciphertext_len, aad_len, auth_tag_len };

        gcry_cipher_ctl(decoder->evp, GCRYCTL_SET_CCM_LENGTHS, lengths, sizeof(lengths));
    }

    if (aad && aad_len > 0) {
        ssl_print_data("AAD", aad, aad_len);
        err = gcry_cipher_authenticate(decoder->evp, aad, aad_len);
        if (err) {
            ssl_debug_printf("%s failed to set AAD: %s\n", G_STRFUNC, gcry_strerror(err));
            return false;
        }
    }

    /* Decrypt now that nonce and AAD are set. */
    err = gcry_cipher_decrypt(decoder->evp, out_str->data, out_str->data_len, ciphertext, ciphertext_len);
    if (err) {
        ssl_debug_printf("%s decrypt failed: %s\n", G_STRFUNC, gcry_strerror(err));
        return false;
    }

    /* Check authentication tag for authenticity (replaces MAC) */
    err = gcry_cipher_gettag(decoder->evp, auth_tag_calc, auth_tag_len);
    if (err == 0 && !memcmp(auth_tag_calc, auth_tag_wire, auth_tag_len)) {
        ssl_print_data("auth_tag(OK)", auth_tag_calc, auth_tag_len);
    } else {
        if (err) {
            ssl_debug_printf("%s cannot obtain tag: %s\n", G_STRFUNC, gcry_strerror(err));
        } else {
            ssl_debug_printf("%s auth tag mismatch\n", G_STRFUNC);
            ssl_print_data("auth_tag(expect)", auth_tag_calc, auth_tag_len);
            ssl_print_data("auth_tag(actual)", auth_tag_wire, auth_tag_len);
        }
        if (ignore_mac_failed) {
            ssl_debug_printf("%s: auth check failed, but ignored for troubleshooting ;-)\n", G_STRFUNC);
        } else {
            return false;
        }
    }

    /*
     * Increment the (implicit) sequence number for TLS 1.2/1.3 and TLCP 1.1. This is done
     * after successful authentication to ensure that early data is skipped when
     * CLIENT_EARLY_TRAFFIC_SECRET keys are unavailable.
     */
    if (version == TLSV1DOT2_VERSION || version == TLSV1DOT3_VERSION || version == TLCPV1_VERSION) {
        decoder->seq++;
    }

    ssl_print_data("Plaintext", out_str->data, ciphertext_len);
    *outl = ciphertext_len;
    return true;
}

/* Record decryption glue based on security parameters {{{ */
/* Assume that we are called only for a non-NULL decoder which also means that
 * we have a non-NULL decoder->cipher_suite. */
int
ssl_decrypt_record(SslDecryptSession *ssl, SslDecoder *decoder, uint8_t ct, uint16_t record_version,
        bool ignore_mac_failed,
        const unsigned char *in, uint16_t inl, const unsigned char *cid, uint8_t cidl,
        StringInfo *comp_str, StringInfo *out_str, unsigned *outl)
{
    unsigned   pad, worklen, uncomplen, maclen, mac_fraglen = 0;
    uint8_t *mac = NULL, *mac_frag = NULL;

    ssl_debug_printf("ssl_decrypt_record ciphertext len %d\n", inl);
    ssl_print_data("Ciphertext",in, inl);

    if (((ssl->session.version == TLSV1DOT3_VERSION || ssl->session.version == DTLSV1DOT3_VERSION))
            != (decoder->cipher_suite->kex == KEX_TLS13)) {
        ssl_debug_printf("%s Invalid cipher suite for the protocol version!\n", G_STRFUNC);
        return -1;
    }

    /* ensure we have enough storage space for decrypted data */
    if (inl > out_str->data_len)
    {
        ssl_debug_printf("ssl_decrypt_record: allocating %d bytes for decrypt data (old len %d)\n",
                inl + 32, out_str->data_len);
        ssl_data_realloc(out_str, inl + 32);
    }

    /* AEAD ciphers (GenericAEADCipher in TLS 1.2; TLS 1.3) have no padding nor
     * a separate MAC, so use a different routine for simplicity. */
    if (decoder->cipher_suite->mode == MODE_GCM ||
        decoder->cipher_suite->mode == MODE_CCM ||
        decoder->cipher_suite->mode == MODE_CCM_8 ||
        decoder->cipher_suite->mode == MODE_POLY1305 ||
        ssl->session.version == TLSV1DOT3_VERSION ||
        ssl->session.version == DTLSV1DOT3_VERSION) {

        if (!tls_decrypt_aead_record(ssl, decoder, ct, record_version, ignore_mac_failed, in, inl, cid, cidl, out_str, &worklen)) {
            /* decryption failed */
            return -1;
        }

        goto skip_mac;
    }

    /* RFC 6101/2246: SSLCipherText/TLSCipherText has two structures for types:
     * (notation: { unencrypted, [ encrypted ] })
     * GenericStreamCipher: { [content, mac] }
     * GenericBlockCipher: { IV (TLS 1.1+), [content, mac, padding, padding_len] }
     * RFC 5426 (TLS 1.2): TLSCipherText has additionally:
     * GenericAEADCipher: { nonce_explicit, [content] }
     * RFC 4347 (DTLS): based on TLS 1.1, only GenericBlockCipher is supported.
     * RFC 6347 (DTLS 1.2): based on TLS 1.2, includes GenericAEADCipher too.
     */

    maclen = ssl_cipher_suite_dig(decoder->cipher_suite)->len;

    /* (TLS 1.1 and later, DTLS) Extract explicit IV for GenericBlockCipher */
    if (decoder->cipher_suite->mode == MODE_CBC) {
        unsigned blocksize = 0;

        switch (ssl->session.version) {
        case TLSV1DOT1_VERSION:
        case TLSV1DOT2_VERSION:
        case DTLSV1DOT0_VERSION:
        case DTLSV1DOT2_VERSION:
        case DTLSV1DOT3_VERSION:
        case DTLSV1DOT0_OPENSSL_VERSION:
        case TLCPV1_VERSION:
            blocksize = ssl_get_cipher_blocksize(decoder->cipher_suite);
            if (inl < blocksize) {
                ssl_debug_printf("ssl_decrypt_record failed: input %d has no space for IV %d\n",
                        inl, blocksize);
                return -1;
            }
            pad = gcry_cipher_setiv(decoder->evp, in, blocksize);
            if (pad != 0) {
                ssl_debug_printf("ssl_decrypt_record failed: failed to set IV: %s %s\n",
                        gcry_strsource (pad), gcry_strerror (pad));
            }

            inl -= blocksize;
            in += blocksize;
            break;
        }

        /* Encrypt-then-MAC for (D)TLS (RFC 7366) */
        if (ssl->state & SSL_ENCRYPT_THEN_MAC) {
            /*
             * MAC is calculated over (IV + ) ENCRYPTED contents:
             *
             *      MAC(MAC_write_key, ... +
             *          IV +       // for TLS 1.1 or greater
             *          TLSCiphertext.enc_content);
             */
            if (inl < maclen) {
                ssl_debug_printf("%s failed: input %d has no space for MAC %d\n",
                                 G_STRFUNC, inl, maclen);
                return -1;
            }
            inl -= maclen;
            mac = (uint8_t *)in + inl;
            mac_frag = (uint8_t *)in - blocksize;
            mac_fraglen = blocksize + inl;
        }
    }

    /* First decrypt*/
    if ((pad = ssl_cipher_decrypt(&decoder->evp, out_str->data, out_str->data_len, in, inl)) != 0) {
        ssl_debug_printf("ssl_decrypt_record failed: ssl_cipher_decrypt: %s %s\n", gcry_strsource (pad),
                    gcry_strerror (pad));
        return -1;
    }

    ssl_print_data("Plaintext", out_str->data, inl);
    worklen=inl;


    /* strip padding for GenericBlockCipher */
    if (decoder->cipher_suite->mode == MODE_CBC) {
        if (inl < 1) { /* Should this check happen earlier? */
            ssl_debug_printf("ssl_decrypt_record failed: input length %d too small\n", inl);
            return -1;
        }
        pad=out_str->data[inl-1];
        if (worklen <= pad) {
            ssl_debug_printf("ssl_decrypt_record failed: padding %d too large for work %d\n",
                pad, worklen);
            return -1;
        }
        worklen-=(pad+1);
        ssl_debug_printf("ssl_decrypt_record found padding %d final len %d\n",
            pad, worklen);
    }

    /* MAC for GenericStreamCipher and GenericBlockCipher.
     * (normal case without Encrypt-then-MAC (RFC 7366) extension. */
    if (!mac) {
        /*
         * MAC is calculated over the DECRYPTED contents:
         *
         *      MAC(MAC_write_key, ... + TLSCompressed.fragment);
         */
        if (worklen < maclen) {
            ssl_debug_printf("%s wrong record len/padding outlen %d\n work %d\n", G_STRFUNC, *outl, worklen);
            return -1;
        }
        worklen -= maclen;
        mac = out_str->data + worklen;
        mac_frag = out_str->data;
        mac_fraglen = worklen;
    }

    /* If NULL encryption active and no keys are available, do not bother
     * checking the MAC. We do not have keys for that. */
    if (decoder->cipher_suite->mode == MODE_STREAM &&
            decoder->cipher_suite->enc == ENC_NULL &&
            !(ssl->state & SSL_MASTER_SECRET)) {
        ssl_debug_printf("MAC check skipped due to missing keys\n");
        goto skip_mac;
    }

    /* Now check the MAC */
    ssl_debug_printf("checking mac (len %d, version %X, ct %d seq %" PRIu64 ")\n",
        worklen, ssl->session.version, ct, decoder->seq);
    if(ssl->session.version==SSLV3_VERSION){
        if(ssl3_check_mac(decoder,ct,mac_frag,mac_fraglen,mac) < 0) {
            if(ignore_mac_failed) {
                ssl_debug_printf("ssl_decrypt_record: mac failed, but ignored for troubleshooting ;-)\n");
            }
            else{
                ssl_debug_printf("ssl_decrypt_record: mac failed\n");
                return -1;
            }
        }
        else{
            ssl_debug_printf("ssl_decrypt_record: mac ok\n");
        }
    }
    else if(ssl->session.version==TLSV1_VERSION || ssl->session.version==TLSV1DOT1_VERSION || ssl->session.version==TLSV1DOT2_VERSION || ssl->session.version==TLCPV1_VERSION){
        if(tls_check_mac(decoder,ct,ssl->session.version,mac_frag,mac_fraglen,mac)< 0) {
            if(ignore_mac_failed) {
                ssl_debug_printf("ssl_decrypt_record: mac failed, but ignored for troubleshooting ;-)\n");
            }
            else{
                ssl_debug_printf("ssl_decrypt_record: mac failed\n");
                return -1;
            }
        }
        else{
            ssl_debug_printf("ssl_decrypt_record: mac ok\n");
        }
    }
    else if(ssl->session.version==DTLSV1DOT0_VERSION ||
        ssl->session.version==DTLSV1DOT2_VERSION ||
        ssl->session.version==DTLSV1DOT0_OPENSSL_VERSION){
        /* Try rfc-compliant mac first, and if failed, try old openssl's non-rfc-compliant mac */
        if(dtls_check_mac(ssl,decoder,ct,mac_frag,mac_fraglen,mac,cid,cidl)>= 0) {
            ssl_debug_printf("ssl_decrypt_record: mac ok\n");
        }
        else if(tls_check_mac(decoder,ct,TLSV1_VERSION,mac_frag,mac_fraglen,mac)>= 0) {
            ssl_debug_printf("ssl_decrypt_record: dtls rfc-compliant mac failed, but old openssl's non-rfc-compliant mac ok\n");
        }
        else if(ignore_mac_failed) {
            ssl_debug_printf("ssl_decrypt_record: mac failed, but ignored for troubleshooting ;-)\n");
        }
        else{
            ssl_debug_printf("ssl_decrypt_record: mac failed\n");
            return -1;
        }
    }
skip_mac:

    *outl = worklen;

    if (decoder->compression > 0) {
        ssl_debug_printf("ssl_decrypt_record: compression method %d\n", decoder->compression);
        ssl_data_copy(comp_str, out_str);
        ssl_print_data("Plaintext compressed", comp_str->data, worklen);
        if (!decoder->decomp) {
            ssl_debug_printf("decrypt_ssl3_record: no decoder available\n");
            return -1;
        }
        if (ssl_decompress_record(decoder->decomp, comp_str->data, worklen, out_str, &uncomplen) < 0) return -1;
        ssl_print_data("Plaintext uncompressed", out_str->data, uncomplen);
        *outl = uncomplen;
    }

    return 0;
}
/* Record decryption glue based on security parameters }}} */



#ifdef HAVE_LIBGNUTLS

/* RSA private key file processing {{{ */
static void
ssl_find_private_key_by_pubkey(SslDecryptSession *ssl,
                               gnutls_datum_t *subjectPublicKeyInfo)
{
    gnutls_pubkey_t pubkey = NULL;
    cert_key_id_t key_id;
    size_t key_id_len = sizeof(key_id);
    int r;

    if (!subjectPublicKeyInfo->size) {
        ssl_debug_printf("%s: could not find SubjectPublicKeyInfo\n", G_STRFUNC);
        return;
    }

    r = gnutls_pubkey_init(&pubkey);
    if (r < 0) {
        ssl_debug_printf("%s: failed to init pubkey: %s\n",
                G_STRFUNC, gnutls_strerror(r));
        return;
    }

    r = gnutls_pubkey_import(pubkey, subjectPublicKeyInfo, GNUTLS_X509_FMT_DER);
    if (r < 0) {
        ssl_debug_printf("%s: failed to import pubkey from handshake: %s\n",
                G_STRFUNC, gnutls_strerror(r));
        goto end;
    }

    if (gnutls_pubkey_get_pk_algorithm(pubkey, NULL) != GNUTLS_PK_RSA) {
        ssl_debug_printf("%s: Not a RSA public key - ignoring.\n", G_STRFUNC);
        goto end;
    }

    /* Generate a 20-byte SHA-1 hash. */
    r = gnutls_pubkey_get_key_id(pubkey, 0, key_id.key_id, &key_id_len);
    if (r < 0) {
        ssl_debug_printf("%s: failed to extract key id from pubkey: %s\n",
                G_STRFUNC, gnutls_strerror(r));
        goto end;
    }

    if (key_id_len != sizeof(key_id)) {
        ssl_debug_printf("%s: expected Key ID size %zu, got %zu\n",
                G_STRFUNC, sizeof(key_id), key_id_len);
        goto end;
    }

    ssl_print_data("Certificate.KeyID", key_id.key_id, key_id_len);
    ssl->cert_key_id = wmem_new(wmem_file_scope(), cert_key_id_t);
    *ssl->cert_key_id = key_id;

end:
    gnutls_pubkey_deinit(pubkey);
}

/* RSA private key file processing }}} */
#endif  /* HAVE_LIBGNUTLS */

/*--- Start of dissector-related code below ---*/

/* get ssl data for this session. if no ssl data is found allocate a new one*/
SslDecryptSession *
ssl_get_session(conversation_t *conversation, dissector_handle_t tls_handle)
{
    void               *conv_data;
    SslDecryptSession  *ssl_session;
    int                 proto_ssl;

    proto_ssl = dissector_handle_get_protocol_index(tls_handle);
    conv_data = conversation_get_proto_data(conversation, proto_ssl);
    if (conv_data != NULL)
        return (SslDecryptSession *)conv_data;

    /* no previous SSL conversation info, initialize it. */
    ssl_session = wmem_new0(wmem_file_scope(), SslDecryptSession);

    /* data_len is the part that is meaningful, not the allocated length */
    ssl_session->master_secret.data_len = 0;
    ssl_session->master_secret.data = ssl_session->_master_secret;
    ssl_session->session_id.data_len = 0;
    ssl_session->session_id.data = ssl_session->_session_id;
    ssl_session->client_random.data_len = 0;
    ssl_session->client_random.data = ssl_session->_client_random;
    ssl_session->server_random.data_len = 0;
    ssl_session->server_random.data = ssl_session->_server_random;
    ssl_session->session_ticket.data_len = 0;
    ssl_session->session_ticket.data = NULL; /* will be re-alloced as needed */
    ssl_session->server_data_for_iv.data_len = 0;
    ssl_session->server_data_for_iv.data = ssl_session->_server_data_for_iv;
    ssl_session->client_data_for_iv.data_len = 0;
    ssl_session->client_data_for_iv.data = ssl_session->_client_data_for_iv;
    ssl_session->app_data_segment.data = NULL;
    ssl_session->app_data_segment.data_len = 0;
    ssl_session->handshake_data.data=NULL;
    ssl_session->handshake_data.data_len=0;

    /* Initialize parameters which are not necessary specific to decryption. */
    ssl_session->session.version = SSL_VER_UNKNOWN;
    clear_address(&ssl_session->session.srv_addr);
    ssl_session->session.srv_ptype = PT_NONE;
    ssl_session->session.srv_port = 0;
    ssl_session->session.dtls13_current_epoch[0] = ssl_session->session.dtls13_current_epoch[1] = 0;
    ssl_session->session.dtls13_next_seq_num[0] = ssl_session->session.dtls13_next_seq_num[1] = 0;

    conversation_add_proto_data(conversation, proto_ssl, ssl_session);
    return ssl_session;
}

void ssl_reset_session(SslSession *session, SslDecryptSession *ssl, bool is_client)
{
    if (ssl) {
        /* Ensure that secrets are not restored using stale identifiers. Split
         * between client and server in case the packets somehow got out of order. */
        int clear_flags = SSL_HAVE_SESSION_KEY | SSL_MASTER_SECRET | SSL_PRE_MASTER_SECRET;

        if (is_client) {
            clear_flags |= SSL_CLIENT_EXTENDED_MASTER_SECRET;
            ssl->session_id.data_len = 0;
            ssl->session_ticket.data_len = 0;
            ssl->master_secret.data_len = 0;
            ssl->client_random.data_len = 0;
            ssl->has_early_data = false;
            if (ssl->handshake_data.data_len > 0) {
                // The EMS handshake hash starts with at the Client Hello,
                // ensure that any messages before it are forgotten.
                wmem_free(wmem_file_scope(), ssl->handshake_data.data);
                ssl->handshake_data.data = NULL;
                ssl->handshake_data.data_len = 0;
            }
        } else {
            clear_flags |= SSL_SERVER_EXTENDED_MASTER_SECRET | SSL_NEW_SESSION_TICKET;
            ssl->server_random.data_len = 0;
            ssl->pre_master_secret.data_len = 0;
#ifdef HAVE_LIBGNUTLS
            ssl->cert_key_id = NULL;
#endif
            ssl->psk.data_len = 0;
        }

        if (ssl->state & clear_flags) {
            ssl_debug_printf("%s detected renegotiation, clearing 0x%02x (%s side)\n",
                    G_STRFUNC, ssl->state & clear_flags, is_client ? "client" : "server");
            ssl->state &= ~clear_flags;
        }
    }

    /* These flags might be used for non-decryption purposes and may affect the
     * dissection, so reset them as well. */
    if (is_client) {
        session->client_cert_type = 0;
    } else {
        session->compression = 0;
        session->server_cert_type = 0;
        /* session->is_session_resumed is already handled in the ServerHello dissection. */
    }
    session->dtls13_next_seq_num[0] = session->dtls13_next_seq_num[1] = 0;
    session->dtls13_current_epoch[0] = session->dtls13_current_epoch[1] = 0;
}

void
tls_set_appdata_dissector(dissector_handle_t tls_handle, packet_info *pinfo,
                          dissector_handle_t app_handle)
{
    conversation_t  *conversation;
    SslSession      *session;

    /* Ignore if the TLS or other dissector is disabled. */
    if (!tls_handle || !app_handle)
        return;

    conversation = find_or_create_conversation(pinfo);
    session = &ssl_get_session(conversation, tls_handle)->session;
    session->app_handle = app_handle;
}

static uint32_t
ssl_starttls(dissector_handle_t tls_handle, packet_info *pinfo,
                 dissector_handle_t app_handle, uint32_t last_nontls_frame)
{
    conversation_t  *conversation;
    SslSession      *session;

    /* Ignore if the TLS dissector is disabled. */
    if (!tls_handle)
        return 0;
    /* The caller should always pass a valid handle to its own dissector. */
    DISSECTOR_ASSERT(app_handle);

    conversation = find_or_create_conversation(pinfo);
    session = &ssl_get_session(conversation, tls_handle)->session;

    ssl_debug_printf("%s: old frame %d, app_handle=%p (%s)\n", G_STRFUNC,
                     session->last_nontls_frame,
                     (void *)session->app_handle,
                     dissector_handle_get_dissector_name(session->app_handle));
    ssl_debug_printf("%s: current frame %d, app_handle=%p (%s)\n", G_STRFUNC,
                     pinfo->num, (void *)app_handle,
                     dissector_handle_get_dissector_name(app_handle));

    /* Do not switch again if a dissector did it before. */
    if (session->last_nontls_frame) {
        ssl_debug_printf("%s: not overriding previous app handle!\n", G_STRFUNC);
        return session->last_nontls_frame;
    }

    session->app_handle = app_handle;
    /* The TLS dissector should be called first for this conversation. */
    conversation_set_dissector(conversation, tls_handle);
    /* TLS starts after this frame. */
    session->last_nontls_frame = last_nontls_frame;
    return 0;
}

/* ssl_starttls_ack: mark future frames as encrypted. */
uint32_t
ssl_starttls_ack(dissector_handle_t tls_handle, packet_info *pinfo,
                 dissector_handle_t app_handle)
{
    return ssl_starttls(tls_handle, pinfo, app_handle, pinfo->num);
}

uint32_t
ssl_starttls_post_ack(dissector_handle_t tls_handle, packet_info *pinfo,
                 dissector_handle_t app_handle)
{
    return ssl_starttls(tls_handle, pinfo, app_handle, pinfo->num - 1);
}

dissector_handle_t
ssl_find_appdata_dissector(const char *name)
{
    /* Accept 'http' for backwards compatibility and sanity. */
    if (!strcmp(name, "http"))
        name = "http-over-tls";
    return find_dissector(name);
}

/* Functions for TLS/DTLS sessions and RSA private keys hashtables. {{{ */
static int
ssl_equal (const void *v, const void *v2)
{
    const StringInfo *val1;
    const StringInfo *val2;
    val1 = (const StringInfo *)v;
    val2 = (const StringInfo *)v2;

    if (val1->data_len == val2->data_len &&
        !memcmp(val1->data, val2->data, val2->data_len)) {
        return 1;
    }
    return 0;
}

static unsigned
ssl_hash  (const void *v)
{
    unsigned l,hash;
    const StringInfo* id;
    const unsigned* cur;
    hash = 0;
    id = (const StringInfo*) v;

    /*  id and id->data are mallocated in ssl_save_master_key().  As such 'data'
     *  should be aligned for any kind of access (for example as a unsigned as
     *  is done below).  The intermediate void* cast is to prevent "cast
     *  increases required alignment of target type" warnings on CPUs (such
     *  as SPARCs) that do not allow misaligned memory accesses.
     */
    cur = (const unsigned*)(void*) id->data;

    for (l=4; (l < id->data_len); l+=4, cur++)
        hash = hash ^ (*cur);

    return hash;
}
/* Functions for TLS/DTLS sessions and RSA private keys hashtables. }}} */

/* Handling of association between tls/dtls ports and clear text protocol. {{{ */
void
ssl_association_add(const char* dissector_table_name, dissector_handle_t main_handle, dissector_handle_t subdissector_handle, unsigned port, bool tcp)
{
    DISSECTOR_ASSERT(main_handle);
    DISSECTOR_ASSERT(subdissector_handle);
    /* Registration is required for Export PDU feature to work properly. */
    DISSECTOR_ASSERT_HINT(dissector_handle_get_dissector_name(subdissector_handle),
            "SSL appdata dissectors must register with register_dissector()!");
    ssl_debug_printf("association_add %s port %d handle %p\n", dissector_table_name, port, (void *)subdissector_handle);

    if (port) {
        dissector_add_uint(dissector_table_name, port, subdissector_handle);
        if (tcp)
            dissector_add_uint("tcp.port", port, main_handle);
        else
            dissector_add_uint("udp.port", port, main_handle);
        dissector_add_uint("sctp.port", port, main_handle);
    } else {
        dissector_add_for_decode_as(dissector_table_name, subdissector_handle);
    }
}

void
ssl_association_remove(const char* dissector_table_name, dissector_handle_t main_handle, dissector_handle_t subdissector_handle, unsigned port, bool tcp)
{
    ssl_debug_printf("ssl_association_remove removing %s %u - handle %p\n",
                     tcp?"TCP":"UDP", port, (void *)subdissector_handle);
    if (main_handle) {
        dissector_delete_uint(tcp?"tcp.port":"udp.port", port, main_handle);
        dissector_delete_uint("sctp.port", port, main_handle);
    }

    if (port) {
        dissector_delete_uint(dissector_table_name, port, subdissector_handle);
    }
}

void
ssl_set_server(SslSession *session, address *addr, port_type ptype, uint32_t port)
{
    copy_address_wmem(wmem_file_scope(), &session->srv_addr, addr);
    session->srv_ptype = ptype;
    session->srv_port = port;
}

int
ssl_packet_from_server(SslSession *session, dissector_table_t table, const packet_info *pinfo)
{
    int ret;
    if (session && session->srv_addr.type != AT_NONE) {
        ret = (session->srv_ptype == pinfo->ptype) &&
              (session->srv_port == pinfo->srcport) &&
              addresses_equal(&session->srv_addr, &pinfo->src);
    } else {
        ret = (dissector_get_uint_handle(table, pinfo->srcport) != 0);
    }

    ssl_debug_printf("packet_from_server: is from server - %s\n", (ret)?"TRUE":"FALSE");
    return ret;
}
/* Handling of association between tls/dtls ports and clear text protocol. }}} */


/* Links SSL records with the real packet data. {{{ */
SslPacketInfo *
tls_add_packet_info(int proto, packet_info *pinfo, uint8_t curr_layer_num_ssl)
{
    SslPacketInfo *pi = (SslPacketInfo *)p_get_proto_data(wmem_file_scope(), pinfo, proto, curr_layer_num_ssl);
    if (!pi) {
        pi = wmem_new0(wmem_file_scope(), SslPacketInfo);
        pi->srcport = pinfo->srcport;
        pi->destport = pinfo->destport;
        p_add_proto_data(wmem_file_scope(), pinfo, proto, curr_layer_num_ssl, pi);
    }

    return pi;
}

/**
 * Remembers the decrypted TLS record fragment (TLSInnerPlaintext in TLS 1.3) to
 * avoid the need for a decoder in the second pass. Additionally, it remembers
 * sequence numbers (for reassembly and Follow TLS Stream).
 *
 * @param proto The protocol identifier (proto_ssl or proto_dtls).
 * @param pinfo The packet where the record originates from.
 * @param data Decrypted data to store in the record.
 * @param data_len Length of decrypted record data.
 * @param record_id The identifier for this record within the current packet.
 * @param flow Information about sequence numbers, etc.
 * @param type TLS Content Type (such as handshake or application_data).
 * @param curr_layer_num_ssl The layer identifier for this TLS session.
 */
void
ssl_add_record_info(int proto, packet_info *pinfo, const unsigned char *data, int data_len, int record_id, SslFlow *flow, ContentType type, uint8_t curr_layer_num_ssl)
{
    SslRecordInfo* rec, **prec;
    SslPacketInfo *pi = tls_add_packet_info(proto, pinfo, curr_layer_num_ssl);

    rec = wmem_new(wmem_file_scope(), SslRecordInfo);
    rec->plain_data = (unsigned char *)wmem_memdup(wmem_file_scope(), data, data_len);
    rec->data_len = data_len;
    rec->id = record_id;
    rec->type = type;
    rec->next = NULL;

    if (flow && type == SSL_ID_APP_DATA) {
        rec->seq = flow->byte_seq;
        rec->flow = flow;
        flow->byte_seq += data_len;
        ssl_debug_printf("%s stored decrypted record seq=%d nxtseq=%d flow=%p\n",
                         G_STRFUNC, rec->seq, rec->seq + data_len, (void*)flow);
    }

    /* Remember decrypted records. */
    prec = &pi->records;
    while (*prec) prec = &(*prec)->next;
    *prec = rec;
}

/* search in packet data for the specified id; return a newly created tvb for the associated data */
tvbuff_t*
ssl_get_record_info(tvbuff_t *parent_tvb, int proto, packet_info *pinfo, int record_id, uint8_t curr_layer_num_ssl, SslRecordInfo **matched_record)
{
    SslRecordInfo* rec;
    SslPacketInfo* pi;
    pi = (SslPacketInfo *)p_get_proto_data(wmem_file_scope(), pinfo, proto, curr_layer_num_ssl);

    if (!pi)
        return NULL;

    for (rec = pi->records; rec; rec = rec->next)
        if (rec->id == record_id) {
            *matched_record = rec;
            /* link new real_data_tvb with a parent tvb so it is freed when frame dissection is complete */
            return tvb_new_child_real_data(parent_tvb, rec->plain_data, rec->data_len, rec->data_len);
        }

    return NULL;
}
/* Links SSL records with the real packet data. }}} */

/* initialize/reset per capture state data (ssl sessions cache). {{{ */
void
ssl_common_init(ssl_master_key_map_t *mk_map,
                StringInfo *decrypted_data, StringInfo *compressed_data)
{
    mk_map->session = g_hash_table_new(ssl_hash, ssl_equal);
    mk_map->tickets = g_hash_table_new(ssl_hash, ssl_equal);
    mk_map->crandom = g_hash_table_new(ssl_hash, ssl_equal);
    mk_map->pre_master = g_hash_table_new(ssl_hash, ssl_equal);
    mk_map->pms = g_hash_table_new(ssl_hash, ssl_equal);
    mk_map->tls13_client_early = g_hash_table_new(ssl_hash, ssl_equal);
    mk_map->tls13_client_handshake = g_hash_table_new(ssl_hash, ssl_equal);
    mk_map->tls13_server_handshake = g_hash_table_new(ssl_hash, ssl_equal);
    mk_map->tls13_client_appdata = g_hash_table_new(ssl_hash, ssl_equal);
    mk_map->tls13_server_appdata = g_hash_table_new(ssl_hash, ssl_equal);
    mk_map->tls13_early_exporter = g_hash_table_new(ssl_hash, ssl_equal);
    mk_map->tls13_exporter = g_hash_table_new(ssl_hash, ssl_equal);

    mk_map->used_crandom = g_hash_table_new(ssl_hash, ssl_equal);

    ssl_data_alloc(decrypted_data, 32);
    ssl_data_alloc(compressed_data, 32);
}

void
ssl_common_cleanup(ssl_master_key_map_t *mk_map, FILE **ssl_keylog_file,
                   StringInfo *decrypted_data, StringInfo *compressed_data)
{
    g_hash_table_destroy(mk_map->session);
    g_hash_table_destroy(mk_map->tickets);
    g_hash_table_destroy(mk_map->crandom);
    g_hash_table_destroy(mk_map->pre_master);
    g_hash_table_destroy(mk_map->pms);
    g_hash_table_destroy(mk_map->tls13_client_early);
    g_hash_table_destroy(mk_map->tls13_client_handshake);
    g_hash_table_destroy(mk_map->tls13_server_handshake);
    g_hash_table_destroy(mk_map->tls13_client_appdata);
    g_hash_table_destroy(mk_map->tls13_server_appdata);
    g_hash_table_destroy(mk_map->tls13_early_exporter);
    g_hash_table_destroy(mk_map->tls13_exporter);

    g_hash_table_destroy(mk_map->used_crandom);

    g_free(decrypted_data->data);
    g_free(compressed_data->data);

    /* close the previous keylog file now that the cache are cleared, this
     * allows the cache to be filled with the full keylog file contents. */
    if (*ssl_keylog_file) {
        fclose(*ssl_keylog_file);
        *ssl_keylog_file = NULL;
    }
}
/* }}} */

/* parse ssl related preferences (private keys and ports association strings) */
#if defined(HAVE_LIBGNUTLS)
/* Load a single RSA key file item from preferences. {{{ */
void
ssl_parse_key_list(const ssldecrypt_assoc_t *uats, GHashTable *key_hash, const char* dissector_table_name, dissector_handle_t main_handle, bool tcp)
{
    gnutls_x509_privkey_t x509_priv_key;
    gnutls_privkey_t   priv_key = NULL;
    FILE*              fp     = NULL;
    int                ret;
    size_t             key_id_len = 20;
    unsigned char     *key_id = NULL;
    char              *err = NULL;
    dissector_handle_t handle;
    /* try to load keys file first */
    fp = ws_fopen(uats->keyfile, "rb");
    if (!fp) {
        report_open_failure(uats->keyfile, errno, false);
        return;
    }

    if ((int)strlen(uats->password) == 0) {
        x509_priv_key = rsa_load_pem_key(fp, &err);
    } else {
        x509_priv_key = rsa_load_pkcs12(fp, uats->password, &err);
    }
    fclose(fp);

    if (!x509_priv_key) {
        if (err) {
            report_failure("Can't load private key from %s: %s",
                           uats->keyfile, err);
            g_free(err);
        } else
            report_failure("Can't load private key from %s: unknown error",
                           uats->keyfile);
        return;
    }
    if (err) {
        report_failure("Load of private key from %s \"succeeded\" with error %s",
                       uats->keyfile, err);
        g_free(err);
    }

    gnutls_privkey_init(&priv_key);
    ret = gnutls_privkey_import_x509(priv_key, x509_priv_key,
            GNUTLS_PRIVKEY_IMPORT_AUTO_RELEASE|GNUTLS_PRIVKEY_IMPORT_COPY);
    if (ret < 0) {
        report_failure("Can't convert private key %s: %s",
                uats->keyfile, gnutls_strerror(ret));
        goto end;
    }

    key_id = (unsigned char *) g_malloc0(key_id_len);
    ret = gnutls_x509_privkey_get_key_id(x509_priv_key, 0, key_id, &key_id_len);
    if (ret < 0) {
        report_failure("Can't calculate public key ID for %s: %s",
                uats->keyfile, gnutls_strerror(ret));
        goto end;
    }
    ssl_print_data("KeyID", key_id, key_id_len);
    if (key_id_len != 20) {
        report_failure("Expected Key ID size %u for %s, got %zu", 20,
                uats->keyfile, key_id_len);
        goto end;
    }

    g_hash_table_replace(key_hash, key_id, priv_key);
    key_id = NULL; /* used in key_hash, do not free. */
    priv_key = NULL;
    ssl_debug_printf("ssl_init private key file %s successfully loaded.\n", uats->keyfile);

    handle = ssl_find_appdata_dissector(uats->protocol);
    if (handle) {
        /* Port to subprotocol mapping */
        uint16_t port = 0;
        if (ws_strtou16(uats->port, NULL, &port)) {
            if (port > 0) {
                ssl_debug_printf("ssl_init port '%d' filename '%s' password(only for p12 file) '%s'\n",
                    port, uats->keyfile, uats->password);

                ssl_association_add(dissector_table_name, main_handle, handle, port, tcp);
            }
        } else {
            if (strcmp(uats->port, "start_tls"))
                ssl_debug_printf("invalid ssl_init_port: %s\n", uats->port);
        }
    }

end:
    gnutls_x509_privkey_deinit(x509_priv_key);
    gnutls_privkey_deinit(priv_key);
    g_free(key_id);
}
/* }}} */
#endif


/* Store/load a known (pre-)master secret from/for this SSL session. {{{ */
/** store a known (pre-)master secret into cache */
static void
ssl_save_master_key(const char *label, GHashTable *ht, StringInfo *key,
                    StringInfo *mk)
{
    StringInfo *ht_key, *master_secret;

    if (key->data_len == 0) {
        ssl_debug_printf("%s: not saving empty %s!\n", G_STRFUNC, label);
        return;
    }

    if (mk->data_len == 0) {
        ssl_debug_printf("%s not saving empty (pre-)master secret for %s!\n",
                         G_STRFUNC, label);
        return;
    }

    /* ssl_hash() depends on session_ticket->data being aligned for unsigned access
     * so be careful in changing how it is allocated. */
    ht_key = ssl_data_clone(key);
    master_secret = ssl_data_clone(mk);
    g_hash_table_insert(ht, ht_key, master_secret);

    ssl_debug_printf("%s inserted (pre-)master secret for %s\n", G_STRFUNC, label);
    ssl_print_string("stored key", ht_key);
    ssl_print_string("stored (pre-)master secret", master_secret);
}

/** restore a (pre-)master secret given some key in the cache */
static bool
ssl_restore_master_key(SslDecryptSession *ssl, const char *label,
                       bool is_pre_master, GHashTable *ht, StringInfo *key)
{
    StringInfo *ms;

    if (key->data_len == 0) {
        ssl_debug_printf("%s can't restore %smaster secret using an empty %s\n",
                         G_STRFUNC, is_pre_master ? "pre-" : "", label);
        return false;
    }

    ms = (StringInfo *)g_hash_table_lookup(ht, key);
    if (!ms) {
        ssl_debug_printf("%s can't find %smaster secret by %s\n", G_STRFUNC,
                         is_pre_master ? "pre-" : "", label);
        return false;
    }

    /* (pre)master secret found, clear knowledge of other keys and set it in the
     * current conversation */
    ssl->state &= ~(SSL_MASTER_SECRET | SSL_PRE_MASTER_SECRET |
                    SSL_HAVE_SESSION_KEY);
    if (is_pre_master) {
        /* unlike master secret, pre-master secret has a variable size (48 for
         * RSA, varying for PSK) and is therefore not statically allocated */
        ssl->pre_master_secret.data = (unsigned char *) wmem_alloc(wmem_file_scope(),
                                                            ms->data_len);
        ssl_data_set(&ssl->pre_master_secret, ms->data, ms->data_len);
        ssl->state |= SSL_PRE_MASTER_SECRET;
    } else {
        ssl_data_set(&ssl->master_secret, ms->data, ms->data_len);
        ssl->state |= SSL_MASTER_SECRET;
    }
    ssl_debug_printf("%s %smaster secret retrieved using %s\n", G_STRFUNC,
                     is_pre_master ? "pre-" : "", label);
    ssl_print_string(label, key);
    ssl_print_string("(pre-)master secret", ms);
    return true;
}
/* Store/load a known (pre-)master secret from/for this SSL session. }}} */

/* Should be called when all parameters are ready (after ChangeCipherSpec), and
 * the decoder should be attempted to be initialized. {{{*/
void
ssl_finalize_decryption(SslDecryptSession *ssl, ssl_master_key_map_t *mk_map)
{
    if (ssl->session.version == TLSV1DOT3_VERSION) {
        /* TLS 1.3 implementations only provide secrets derived from the master
         * secret which are loaded in tls13_change_key. No master secrets can be
         * loaded here, so just return. */
        return;
    }
    ssl_debug_printf("%s state = 0x%02X\n", G_STRFUNC, ssl->state);
    if (ssl->state & SSL_HAVE_SESSION_KEY) {
        ssl_debug_printf("  session key already available, nothing to do.\n");
        return;
    }
    if (!(ssl->state & SSL_CIPHER)) {
        ssl_debug_printf("  Cipher suite (Server Hello) is missing!\n");
        return;
    }

    /* for decryption, there needs to be a master secret (which can be derived
     * from pre-master secret). If missing, try to pick a master key from cache
     * (an earlier packet in the capture or key logfile). */
    if (!(ssl->state & (SSL_MASTER_SECRET | SSL_PRE_MASTER_SECRET)) &&
        !ssl_restore_master_key(ssl, "Session ID", false,
                                mk_map->session, &ssl->session_id) &&
        (!ssl->session.is_session_resumed ||
         !ssl_restore_master_key(ssl, "Session Ticket", false,
                                 mk_map->tickets, &ssl->session_ticket)) &&
        !ssl_restore_master_key(ssl, "Client Random", false,
                                mk_map->crandom, &ssl->client_random)) {
        if (ssl->cipher_suite->enc != ENC_NULL) {
            /* how unfortunate, the master secret could not be found */
            ssl_debug_printf("  Cannot find master secret\n");
            return;
        } else {
            ssl_debug_printf(" Cannot find master secret, continuing anyway "
                    "because of a NULL cipher\n");
        }
    }

    if (ssl_generate_keyring_material(ssl) < 0) {
        ssl_debug_printf("%s can't generate keyring material\n", G_STRFUNC);
        return;
    }
    /* Save Client Random/ Session ID for "SSL Export Session keys" */
    ssl_save_master_key("Client Random", mk_map->crandom,
                        &ssl->client_random, &ssl->master_secret);
    ssl_save_master_key("Session ID", mk_map->session,
                        &ssl->session_id, &ssl->master_secret);
    /* Only save the new secrets if the server sent the ticket. The client
     * ticket might have become stale. */
    if (ssl->state & SSL_NEW_SESSION_TICKET) {
        ssl_save_master_key("Session Ticket", mk_map->tickets,
                            &ssl->session_ticket, &ssl->master_secret);
    }
} /* }}} */

/* Load the traffic key secret from the keylog file. */
StringInfo *
tls13_load_secret(SslDecryptSession *ssl, ssl_master_key_map_t *mk_map,
                  bool is_from_server, TLSRecordType type)
{
    GHashTable *key_map;
    const char *label;

    if (ssl->session.version != TLSV1DOT3_VERSION && ssl->session.version != DTLSV1DOT3_VERSION) {
        ssl_debug_printf("%s TLS version %#x is not 1.3\n", G_STRFUNC, ssl->session.version);
        return NULL;
    }

    if (ssl->client_random.data_len == 0) {
        /* May happen if Hello message is missing and Finished is found. */
        ssl_debug_printf("%s missing Client Random\n", G_STRFUNC);
        return NULL;
    }

    switch (type) {
    case TLS_SECRET_0RTT_APP:
        DISSECTOR_ASSERT(!is_from_server);
        label = "CLIENT_EARLY_TRAFFIC_SECRET";
        key_map = mk_map->tls13_client_early;
        break;
    case TLS_SECRET_HANDSHAKE:
        if (is_from_server) {
            label = "SERVER_HANDSHAKE_TRAFFIC_SECRET";
            key_map = mk_map->tls13_server_handshake;
        } else {
            label = "CLIENT_HANDSHAKE_TRAFFIC_SECRET";
            key_map = mk_map->tls13_client_handshake;
        }
        break;
    case TLS_SECRET_APP:
        if (is_from_server) {
            label = "SERVER_TRAFFIC_SECRET_0";
            key_map = mk_map->tls13_server_appdata;
        } else {
            label = "CLIENT_TRAFFIC_SECRET_0";
            key_map = mk_map->tls13_client_appdata;
        }
        break;
    default:
        ws_assert_not_reached();
    }

    /* Transitioning to new keys, mark old ones as unusable. */
    ssl_debug_printf("%s transitioning to new key, old state 0x%02x\n", G_STRFUNC, ssl->state);
    ssl->state &= ~(SSL_MASTER_SECRET | SSL_PRE_MASTER_SECRET | SSL_HAVE_SESSION_KEY);

    StringInfo *secret = (StringInfo *)g_hash_table_lookup(key_map, &ssl->client_random);
    if (!secret) {
        ssl_debug_printf("%s Cannot find %s, decryption impossible\n", G_STRFUNC, label);
        /* Disable decryption, the keys are invalid. */
        if (is_from_server) {
            ssl->server = NULL;
        } else {
            ssl->client = NULL;
        }
        return NULL;
    }

    /* TLS 1.3 secret found, set new keys. */
    ssl_debug_printf("%s Retrieved TLS 1.3 traffic secret.\n", G_STRFUNC);
    ssl_print_string("Client Random", &ssl->client_random);
    ssl_print_string(label, secret);
    return secret;
}

/* Load the new key. */
void
tls13_change_key(SslDecryptSession *ssl, ssl_master_key_map_t *mk_map,
                 bool is_from_server, TLSRecordType type)
{
    if (ssl->state & SSL_QUIC_RECORD_LAYER) {
        /*
         * QUIC does not use the TLS record layer for message protection.
         * The required keys will be extracted later by QUIC.
         */
        return;
    }

    StringInfo *secret = tls13_load_secret(ssl, mk_map, is_from_server, type);
    if (!secret) {
        return;
    }

    if (tls13_generate_keys(ssl, secret, is_from_server)) {
        /*
         * Remember the application traffic secret to support Key Update. The
         * other secrets cannot be used for this purpose, so free them.
         */
        SslDecoder *decoder = is_from_server ? ssl->server : ssl->client;
        StringInfo *app_secret = &decoder->app_traffic_secret;
        if (type == TLS_SECRET_APP) {
            app_secret->data = (unsigned char *) wmem_realloc(wmem_file_scope(),
                                                       app_secret->data,
                                                       secret->data_len);
            ssl_data_set(app_secret, secret->data, secret->data_len);
        } else {
            wmem_free(wmem_file_scope(), app_secret->data);
            app_secret->data = NULL;
            app_secret->data_len = 0;
        }
    }
}

/**
 * Update to next application data traffic secret for TLS 1.3. The previous
 * secret should have been set by tls13_change_key.
 */
void
tls13_key_update(SslDecryptSession *ssl, bool is_from_server)
{
    /* RFC 8446 Section 7.2:
     * application_traffic_secret_N+1 =
     *     HKDF-Expand-Label(application_traffic_secret_N,
     *                       "traffic upd", "", Hash.length)
     *
     * Both application_traffic_secret_N are of the same length (Hash.length).
     */
    const SslCipherSuite *cipher_suite = ssl->cipher_suite;
    SslDecoder *decoder = is_from_server ? ssl->server : ssl->client;
    StringInfo *app_secret = decoder ? &decoder->app_traffic_secret : NULL;
    uint8_t tls13_draft_version = ssl->session.tls13_draft_version;

    if (!cipher_suite || !app_secret || app_secret->data_len == 0) {
        ssl_debug_printf("%s Cannot perform Key Update due to missing info\n", G_STRFUNC);
        return;
    }

    /*
     * Previous traffic secret is available, so find the hash function,
     * expand the new traffic secret and generate new keys.
     */
    const char *hash_name = ssl_cipher_suite_dig(cipher_suite)->name;
    int hash_algo = ssl_get_digest_by_name(hash_name);
    const unsigned hash_len = app_secret->data_len;
    unsigned char *new_secret;
    const char *label = "traffic upd";
    if (tls13_draft_version && tls13_draft_version < 20) {
        label = "application traffic secret";
    }
    if (!tls13_hkdf_expand_label(hash_algo, app_secret,
                                 tls13_hkdf_label_prefix(ssl),
                                 label, hash_len, &new_secret)) {
        ssl_debug_printf("%s traffic_secret_N+1 expansion failed\n", G_STRFUNC);
        return;
    }
    ssl_data_set(app_secret, new_secret, hash_len);
    if (tls13_generate_keys(ssl, app_secret, is_from_server)) {
        /*
         * Remember the application traffic secret on the new decoder to
         * support another Key Update.
         */
        decoder = is_from_server ? ssl->server : ssl->client;
        app_secret = &decoder->app_traffic_secret;
        app_secret->data = (unsigned char *) wmem_realloc(wmem_file_scope(),
                                                   app_secret->data,
                                                   hash_len);
        ssl_data_set(app_secret, new_secret, hash_len);
    }
    wmem_free(NULL, new_secret);
}

void
tls_save_crandom(SslDecryptSession *ssl, ssl_master_key_map_t *mk_map)
{
    if (ssl && (ssl->state & SSL_CLIENT_RANDOM)) {
        g_hash_table_add(mk_map->used_crandom, &ssl->client_random);
    }
}

/** SSL keylog file handling. {{{ */

static GRegex *
ssl_compile_keyfile_regex(void)
{
#define OCTET "(?:[[:xdigit:]]{2})"
    const char *pattern =
        "(?:"
        /* Matches Client Hellos having this Client Random */
        "PMS_CLIENT_RANDOM (?<client_random_pms>" OCTET "{32}) "
        /* Matches first part of encrypted RSA pre-master secret */
        "|RSA (?<encrypted_pmk>" OCTET "{8}) "
        /* Pre-Master-Secret is given, it is 48 bytes for RSA,
           but it can be of any length for DHE */
        ")(?<pms>" OCTET "+)"
        "|(?:"
        /* Matches Server Hellos having a Session ID */
        "RSA Session-ID:(?<session_id>" OCTET "+) Master-Key:"
        /* Matches Client Hellos having this Client Random */
        "|CLIENT_RANDOM (?<client_random>" OCTET "{32}) "
        /* Master-Secret is given, its length is fixed */
        ")(?<master_secret>" OCTET "{" G_STRINGIFY(SSL_MASTER_SECRET_LENGTH) "})"
        "|(?"
        /* TLS 1.3 Client Random to Derived Secrets mapping. */
        ":CLIENT_EARLY_TRAFFIC_SECRET (?<client_early>" OCTET "{32})"
        "|CLIENT_HANDSHAKE_TRAFFIC_SECRET (?<client_handshake>" OCTET "{32})"
        "|SERVER_HANDSHAKE_TRAFFIC_SECRET (?<server_handshake>" OCTET "{32})"
        "|CLIENT_TRAFFIC_SECRET_0 (?<client_appdata>" OCTET "{32})"
        "|SERVER_TRAFFIC_SECRET_0 (?<server_appdata>" OCTET "{32})"
        "|EARLY_EXPORTER_SECRET (?<early_exporter>" OCTET "{32})"
        "|EXPORTER_SECRET (?<exporter>" OCTET "{32})"
        ") (?<derived_secret>" OCTET "+)";
#undef OCTET
    static GRegex *regex = NULL;
    GError *gerr = NULL;

    if (!regex) {
        regex = g_regex_new(pattern,
                (GRegexCompileFlags)(G_REGEX_OPTIMIZE | G_REGEX_ANCHORED | G_REGEX_RAW),
                G_REGEX_MATCH_ANCHORED, &gerr);
        if (gerr) {
            ssl_debug_printf("%s failed to compile regex: %s\n", G_STRFUNC,
                             gerr->message);
            g_error_free(gerr);
            regex = NULL;
        }
    }

    return regex;
}

typedef struct ssl_master_key_match_group {
    const char *re_group_name;
    GHashTable *master_key_ht;
} ssl_master_key_match_group_t;

void
tls_keylog_process_lines(const ssl_master_key_map_t *mk_map, const uint8_t *data, unsigned datalen)
{
    ssl_master_key_match_group_t mk_groups[] = {
        { "encrypted_pmk",  mk_map->pre_master },
        { "session_id",     mk_map->session },
        { "client_random",  mk_map->crandom },
        { "client_random_pms",  mk_map->pms },
        /* TLS 1.3 map from Client Random to derived secret. */
        { "client_early",       mk_map->tls13_client_early },
        { "client_handshake",   mk_map->tls13_client_handshake },
        { "server_handshake",   mk_map->tls13_server_handshake },
        { "client_appdata",     mk_map->tls13_client_appdata },
        { "server_appdata",     mk_map->tls13_server_appdata },
        { "early_exporter",     mk_map->tls13_early_exporter },
        { "exporter",           mk_map->tls13_exporter },
    };

    /* The format of the file is a series of records with one of the following formats:
     *   - "RSA xxxx yyyy"
     *     Where xxxx are the first 8 bytes of the encrypted pre-master secret (hex-encoded)
     *     Where yyyy is the cleartext pre-master secret (hex-encoded)
     *     (this is the original format introduced with bug 4349)
     *
     *   - "RSA Session-ID:xxxx Master-Key:yyyy"
     *     Where xxxx is the SSL session ID (hex-encoded)
     *     Where yyyy is the cleartext master secret (hex-encoded)
     *     (added to support openssl s_client Master-Key output)
     *     This is somewhat is a misnomer because there's nothing RSA specific
     *     about this.
     *
     *   - "PMS_CLIENT_RANDOM xxxx yyyy"
     *     Where xxxx is the client_random from the ClientHello (hex-encoded)
     *     Where yyyy is the cleartext pre-master secret (hex-encoded)
     *     (This format allows SSL connections to be decrypted, if a user can
     *     capture the PMS but could not recover the MS for a specific session
     *     with a SSL Server.)
     *
     *   - "CLIENT_RANDOM xxxx yyyy"
     *     Where xxxx is the client_random from the ClientHello (hex-encoded)
     *     Where yyyy is the cleartext master secret (hex-encoded)
     *     (This format allows non-RSA SSL connections to be decrypted, i.e.
     *     ECDHE-RSA.)
     *
     *   - "CLIENT_EARLY_TRAFFIC_SECRET xxxx yyyy"
     *   - "CLIENT_HANDSHAKE_TRAFFIC_SECRET xxxx yyyy"
     *   - "SERVER_HANDSHAKE_TRAFFIC_SECRET xxxx yyyy"
     *   - "CLIENT_TRAFFIC_SECRET_0 xxxx yyyy"
     *   - "SERVER_TRAFFIC_SECRET_0 xxxx yyyy"
     *   - "EARLY_EXPORTER_SECRET xxxx yyyy"
     *   - "EXPORTER_SECRET xxxx yyyy"
     *     Where xxxx is the client_random from the ClientHello (hex-encoded)
     *     Where yyyy is the secret (hex-encoded) derived from the early,
     *     handshake or master secrets. (This format is introduced with TLS 1.3
     *     and supported by BoringSSL, OpenSSL, etc. See bug 12779.)
     */
    GRegex *regex = ssl_compile_keyfile_regex();
    if (!regex)
        return;

    const char *next_line = (const char *)data;
    const char *line_end = next_line + datalen;
    while (next_line && next_line < line_end) {
        const char *line = next_line;
        next_line = (const char *)memchr(line, '\n', line_end - line);
        ssize_t linelen;

        if (next_line) {
            linelen = next_line - line;
            next_line++;    /* drop LF */
        } else {
            linelen = (ssize_t)(line_end - line);
        }
        if (linelen > 0 && line[linelen - 1] == '\r') {
            linelen--;      /* drop CR */
        }

        ssl_debug_printf("  checking keylog line: %.*s\n", (int)linelen, line);
        GMatchInfo *mi;
        if (g_regex_match_full(regex, line, linelen, 0, G_REGEX_MATCH_ANCHORED, &mi, NULL)) {
            char *hex_key, *hex_pre_ms_or_ms;
            StringInfo *key = wmem_new(wmem_file_scope(), StringInfo);
            StringInfo *pre_ms_or_ms = NULL;
            GHashTable *ht = NULL;

            /* Is the PMS being supplied with the PMS_CLIENT_RANDOM
             * otherwise we will use the Master Secret
             */
            hex_pre_ms_or_ms = g_match_info_fetch_named(mi, "master_secret");
            if (hex_pre_ms_or_ms == NULL || !*hex_pre_ms_or_ms) {
                g_free(hex_pre_ms_or_ms);
                hex_pre_ms_or_ms = g_match_info_fetch_named(mi, "pms");
            }
            if (hex_pre_ms_or_ms == NULL || !*hex_pre_ms_or_ms) {
                g_free(hex_pre_ms_or_ms);
                hex_pre_ms_or_ms = g_match_info_fetch_named(mi, "derived_secret");
            }
            /* There is always a match, otherwise the regex is wrong. */
            DISSECTOR_ASSERT(hex_pre_ms_or_ms && strlen(hex_pre_ms_or_ms));

            /* convert from hex to bytes and save to hashtable */
            pre_ms_or_ms = wmem_new(wmem_file_scope(), StringInfo);
            from_hex(pre_ms_or_ms, hex_pre_ms_or_ms, strlen(hex_pre_ms_or_ms));
            g_free(hex_pre_ms_or_ms);

            /* Find a master key from any format (CLIENT_RANDOM, SID, ...) */
            for (unsigned i = 0; i < G_N_ELEMENTS(mk_groups); i++) {
                ssl_master_key_match_group_t *g = &mk_groups[i];
                hex_key = g_match_info_fetch_named(mi, g->re_group_name);
                if (hex_key && *hex_key) {
                    ssl_debug_printf("    matched %s\n", g->re_group_name);
                    ht = g->master_key_ht;
                    from_hex(key, hex_key, strlen(hex_key));
                    g_free(hex_key);
                    break;
                }
                g_free(hex_key);
            }
            DISSECTOR_ASSERT(ht); /* Cannot be reached, or regex is wrong. */

            g_hash_table_insert(ht, key, pre_ms_or_ms);

        } else if (linelen > 0 && line[0] != '#') {
            ssl_debug_printf("    unrecognized line\n");
        }
        /* always free match info even if there is no match. */
        g_match_info_free(mi);
    }
}

void
ssl_load_keyfile(const char *tls_keylog_filename, FILE **keylog_file,
                 const ssl_master_key_map_t *mk_map)
{
    /* no need to try if no key log file is configured. */
    if (!tls_keylog_filename || !*tls_keylog_filename) {
        ssl_debug_printf("%s dtls/tls.keylog_file is not configured!\n",
                         G_STRFUNC);
        return;
    }

    /* Validate regexes before even trying to use it. */
    if (!ssl_compile_keyfile_regex()) {
        return;
    }

    ssl_debug_printf("trying to use TLS keylog in %s\n", tls_keylog_filename);

    /* if the keylog file was deleted/overwritten, re-open it */
    if (*keylog_file && file_needs_reopen(ws_fileno(*keylog_file), tls_keylog_filename)) {
        ssl_debug_printf("%s file got deleted, trying to re-open\n", G_STRFUNC);
        fclose(*keylog_file);
        *keylog_file = NULL;
    }

    if (*keylog_file == NULL) {
        *keylog_file = ws_fopen(tls_keylog_filename, "r");
        if (!*keylog_file) {
            ssl_debug_printf("%s failed to open SSL keylog\n", G_STRFUNC);
            return;
        }
    }

    for (;;) {
        char buf[1110], *line;
        line = fgets(buf, sizeof(buf), *keylog_file);
        if (!line) {
            if (feof(*keylog_file)) {
                /* Ensure that newly appended keys can be read in the future. */
                clearerr(*keylog_file);
            } else if (ferror(*keylog_file)) {
                ssl_debug_printf("%s Error while reading key log file, closing it!\n", G_STRFUNC);
                fclose(*keylog_file);
                *keylog_file = NULL;
            }
            break;
        }
        tls_keylog_process_lines(mk_map, (uint8_t *)line, (int)strlen(line));
    }
}
/** SSL keylog file handling. }}} */

#ifdef SSL_DECRYPT_DEBUG /* {{{ */

static FILE* ssl_debug_file;

void
ssl_set_debug(const char* name)
{
    static int debug_file_must_be_closed;
    int         use_stderr;

    use_stderr                = name?(strcmp(name, SSL_DEBUG_USE_STDERR) == 0):0;

    if (debug_file_must_be_closed)
        fclose(ssl_debug_file);

    if (use_stderr)
        ssl_debug_file = stderr;
    else if (!name || (strcmp(name, "") ==0))
        ssl_debug_file = NULL;
    else
        ssl_debug_file = ws_fopen(name, "w");

    if (!use_stderr && ssl_debug_file)
        debug_file_must_be_closed = 1;
    else
        debug_file_must_be_closed = 0;

    ssl_debug_printf("Wireshark SSL debug log \n\n");
#ifdef HAVE_LIBGNUTLS
    ssl_debug_printf("GnuTLS version:    %s\n", gnutls_check_version(NULL));
#endif
    ssl_debug_printf("Libgcrypt version: %s\n", gcry_check_version(NULL));
    ssl_debug_printf("\n");
}

void
ssl_debug_flush(void)
{
    if (ssl_debug_file)
        fflush(ssl_debug_file);
}

void
ssl_debug_printf(const char* fmt, ...)
{
    va_list ap;

    if (!ssl_debug_file)
        return;

    va_start(ap, fmt);
    vfprintf(ssl_debug_file, fmt, ap);
    va_end(ap);
}

void
ssl_print_data(const char* name, const unsigned char* data, size_t len)
{
    size_t i, j, k;
    if (!ssl_debug_file)
        return;
    fprintf(ssl_debug_file,"%s[%d]:\n",name, (int) len);
    for (i=0; i<len; i+=16) {
        fprintf(ssl_debug_file,"| ");
        for (j=i, k=0; k<16 && j<len; ++j, ++k)
            fprintf(ssl_debug_file,"%.2x ",data[j]);
        for (; k<16; ++k)
            fprintf(ssl_debug_file,"   ");
        fputc('|', ssl_debug_file);
        for (j=i, k=0; k<16 && j<len; ++j, ++k) {
            unsigned char c = data[j];
            if (!g_ascii_isprint(c) || (c=='\t')) c = '.';
            fputc(c, ssl_debug_file);
        }
        for (; k<16; ++k)
            fputc(' ', ssl_debug_file);
        fprintf(ssl_debug_file,"|\n");
    }
}

void
ssl_print_string(const char* name, const StringInfo* data)
{
    ssl_print_data(name, data->data, data->data_len);
}
#endif /* SSL_DECRYPT_DEBUG }}} */

/* UAT preferences callbacks. {{{ */
/* checks for SSL and DTLS UAT key list fields */

bool
ssldecrypt_uat_fld_ip_chk_cb(void* r _U_, const char* p _U_, unsigned len _U_, const void* u1 _U_, const void* u2 _U_, char** err)
{
    // This should be removed in favor of Decode As. Make it optional.
    *err = NULL;
    return true;
}

bool
ssldecrypt_uat_fld_port_chk_cb(void* r _U_, const char* p, unsigned len _U_, const void* u1 _U_, const void* u2 _U_, char** err)
{
    if (!p || strlen(p) == 0u) {
        // This should be removed in favor of Decode As. Make it optional.
        *err = NULL;
        return true;
    }

    if (strcmp(p, "start_tls") != 0){
        uint16_t port;
        if (!ws_strtou16(p, NULL, &port)) {
            *err = g_strdup("Invalid port given.");
            return false;
        }
    }

    *err = NULL;
    return true;
}

bool
ssldecrypt_uat_fld_fileopen_chk_cb(void* r _U_, const char* p, unsigned len _U_, const void* u1 _U_, const void* u2 _U_, char** err)
{
    ws_statb64 st;

    if (!p || strlen(p) == 0u) {
        *err = g_strdup("No filename given.");
        return false;
    } else {
        if (ws_stat64(p, &st) != 0) {
            *err = ws_strdup_printf("File '%s' does not exist or access is denied.", p);
            return false;
        }
    }

    *err = NULL;
    return true;
}

bool
ssldecrypt_uat_fld_password_chk_cb(void *r _U_, const char *p _U_, unsigned len _U_, const void *u1 _U_, const void *u2 _U_, char **err)
{
#if defined(HAVE_LIBGNUTLS)
    ssldecrypt_assoc_t*  f  = (ssldecrypt_assoc_t *)r;
    FILE                *fp = NULL;

    if (p && (strlen(p) > 0u)) {
        fp = ws_fopen(f->keyfile, "rb");
        if (fp) {
            char *msg = NULL;
            gnutls_x509_privkey_t priv_key = rsa_load_pkcs12(fp, p, &msg);
            if (!priv_key) {
                fclose(fp);
                *err = ws_strdup_printf("Could not load PKCS#12 key file: %s", msg);
                g_free(msg);
                return false;
            }
            g_free(msg);
            gnutls_x509_privkey_deinit(priv_key);
            fclose(fp);
        } else {
            *err = ws_strdup_printf("Leave this field blank if the keyfile is not PKCS#12.");
            return false;
        }
    }

    *err = NULL;
    return true;
#else
    *err = g_strdup("Cannot load key files, support is not compiled in.");
    return false;
#endif
}
/* UAT preferences callbacks. }}} */

/** maximum size of ssl_association_info() string */
#define SSL_ASSOC_MAX_LEN 8192

typedef struct ssl_association_info_callback_data
{
    char *str;
    const char *table_protocol;
} ssl_association_info_callback_data_t;

/**
 * callback function used by ssl_association_info() to traverse the SSL associations.
 */
static void
ssl_association_info_(const char *table _U_, void *handle, void *user_data)
{
    ssl_association_info_callback_data_t* data = (ssl_association_info_callback_data_t*)user_data;
    const int l = (const int)strlen(data->str);
    snprintf(data->str+l, SSL_ASSOC_MAX_LEN-l, "'%s' %s\n", dissector_handle_get_description((dissector_handle_t)handle), data->table_protocol);
}

/**
 * @return an information string on the SSL protocol associations. The string has ephemeral lifetime/scope.
 */
char*
ssl_association_info(const char* dissector_table_name, const char* table_protocol)
{
    ssl_association_info_callback_data_t data;

    data.str = (char *)g_malloc0(SSL_ASSOC_MAX_LEN);
    data.table_protocol = table_protocol;
    dissector_table_foreach_handle(dissector_table_name, ssl_association_info_, &data);
    return data.str;
}


/** Begin of code related to dissection of wire data. */

/* Helpers for dissecting Variable-Length Vectors. {{{ */
bool
ssl_add_vector(ssl_common_dissect_t *hf, tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,
               unsigned offset, unsigned offset_end, uint32_t *ret_length,
               int hf_length, uint32_t min_value, uint32_t max_value)
{
    unsigned    veclen_size;
    uint32_t    veclen_value;
    proto_item *pi;

    DISSECTOR_ASSERT_CMPUINT(min_value, <=, max_value);
    if (offset > offset_end) {
        expert_add_info_format(pinfo, tree, &hf->ei.malformed_buffer_too_small,
                               "Vector offset is past buffer end offset (%u > %u)",
                               offset, offset_end);
        *ret_length = 0;
        return false;   /* Cannot read length. */
    }

    if (max_value > 0xffffff) {
        veclen_size = 4;
    } else if (max_value > 0xffff) {
        veclen_size = 3;
    } else if (max_value > 0xff) {
        veclen_size = 2;
    } else {
        veclen_size = 1;
    }

    if (offset_end - offset < veclen_size) {
        proto_tree_add_expert_format(tree, pinfo, &hf->ei.malformed_buffer_too_small,
                                     tvb, offset, offset_end - offset,
                                     "No more room for vector of length %u",
                                     veclen_size);
        *ret_length = 0;
        return false;   /* Cannot read length. */
    }

    pi = proto_tree_add_item_ret_uint(tree, hf_length, tvb, offset, veclen_size, ENC_BIG_ENDIAN, &veclen_value);
    offset += veclen_size;

    if (veclen_value < min_value) {
        expert_add_info_format(pinfo, pi, &hf->ei.malformed_vector_length,
                               "Vector length %u is smaller than minimum %u",
                               veclen_value, min_value);
    } else if (veclen_value > max_value) {
        expert_add_info_format(pinfo, pi, &hf->ei.malformed_vector_length,
                               "Vector length %u is larger than maximum %u",
                               veclen_value, max_value);
    }

    if (offset_end - offset < veclen_value) {
        expert_add_info_format(pinfo, pi, &hf->ei.malformed_buffer_too_small,
                               "Vector length %u is too large, truncating it to %u",
                               veclen_value, offset_end - offset);
        *ret_length = offset_end - offset;
        return false;   /* Length is truncated to avoid overflow. */
    }

    *ret_length = veclen_value;
    return true;        /* Length is OK. */
}

bool
ssl_end_vector(ssl_common_dissect_t *hf, tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,
               unsigned offset, unsigned offset_end)
{
    if (offset < offset_end) {
        unsigned trailing = offset_end - offset;
        proto_tree_add_expert_format(tree, pinfo, &hf->ei.malformed_trailing_data,
                                     tvb, offset, trailing,
                                     "%u trailing byte%s unprocessed",
                                     trailing, plurality(trailing, " was", "s were"));
        return false;   /* unprocessed data warning */
    } else if (offset > offset_end) {
        /*
         * Returned offset runs past the end. This should not happen and is
         * possibly a dissector bug.
         */
        unsigned excess = offset - offset_end;
        proto_tree_add_expert_format(tree, pinfo, &hf->ei.malformed_buffer_too_small,
                                     tvb, offset_end, excess,
                                     "Dissector processed too much data (%u byte%s)",
                                     excess, plurality(excess, "", "s"));
        return false;   /* overflow error */
    }

    return true;    /* OK, offset matches. */
}
/** }}} */


static uint32_t
ssl_dissect_digitally_signed(ssl_common_dissect_t *hf, tvbuff_t *tvb, packet_info *pinfo,
                             proto_tree *tree, uint32_t offset, uint32_t offset_end,
                             uint16_t version, int hf_sig_len, int hf_sig);

/* change_cipher_spec(20) dissection */
void
ssl_dissect_change_cipher_spec(ssl_common_dissect_t *hf, tvbuff_t *tvb,
                               packet_info *pinfo, proto_tree *tree,
                               uint32_t offset, SslSession *session,
                               bool is_from_server,
                               const SslDecryptSession *ssl)
{
    /*
     * struct {
     *     enum { change_cipher_spec(1), (255) } type;
     * } ChangeCipherSpec;
     */
    proto_item *ti;
    proto_item_set_text(tree,
            "%s Record Layer: %s Protocol: Change Cipher Spec",
            val_to_str_const(session->version, ssl_version_short_names, "SSL"),
            val_to_str_const(SSL_ID_CHG_CIPHER_SPEC, ssl_31_content_type, "unknown"));
    ti = proto_tree_add_item(tree, hf->hf.change_cipher_spec, tvb, offset, 1, ENC_NA);

    if (session->version == TLSV1DOT3_VERSION) {
        /* CCS is a dummy message in TLS 1.3, do not parse it further. */
        return;
    }

    /* Remember frame number of first CCS */
    uint32_t *ccs_frame = is_from_server ? &session->server_ccs_frame : &session->client_ccs_frame;
    if (*ccs_frame == 0)
        *ccs_frame = pinfo->num;

    /* Use heuristics to detect an abbreviated handshake, assume that missing
     * ServerHelloDone implies reusing previously negotiating keys. Then when
     * a Session ID or ticket is present, it must be a resumed session.
     * Normally this should be done at the Finished message, but that may be
     * encrypted so we do it here, at the last cleartext message. */
    if (is_from_server && ssl) {
        if (session->is_session_resumed) {
            const char *resumed = NULL;
            if (ssl->session_ticket.data_len) {
                resumed = "Session Ticket";
            } else if (ssl->session_id.data_len) {
                resumed = "Session ID";
            }
            if (resumed) {
                ssl_debug_printf("%s Session resumption using %s\n", G_STRFUNC, resumed);
            } else {
                /* Can happen if the capture somehow starts in the middle */
                ssl_debug_printf("%s No Session resumption, missing packets?\n", G_STRFUNC);
            }
        } else {
            ssl_debug_printf("%s Not using Session resumption\n", G_STRFUNC);
        }
    }
    if (is_from_server && session->is_session_resumed)
        expert_add_info(pinfo, ti, &hf->ei.resumed);
}

/** Begin of handshake(22) record dissections */

/* Dissects a SignatureScheme (TLS 1.3) or SignatureAndHashAlgorithm (TLS 1.2).
 * {{{ */
static void
tls_dissect_signature_algorithm(ssl_common_dissect_t *hf, tvbuff_t *tvb, proto_tree *tree, uint32_t offset, ja4_data_t *ja4_data)
{
    uint32_t    sighash, hashalg, sigalg;
    proto_item *ti_sigalg;
    proto_tree *sigalg_tree;

    ti_sigalg = proto_tree_add_item_ret_uint(tree, hf->hf.hs_sig_hash_alg, tvb,
                                             offset, 2, ENC_BIG_ENDIAN, &sighash);
    if (ja4_data) {
        wmem_list_append(ja4_data->sighash_list, GUINT_TO_POINTER(sighash));
    }

    sigalg_tree = proto_item_add_subtree(ti_sigalg, hf->ett.hs_sig_hash_alg);

    /* TLS 1.2: SignatureAndHashAlgorithm { hash, signature } */
    proto_tree_add_item_ret_uint(sigalg_tree, hf->hf.hs_sig_hash_hash, tvb,
                                 offset, 1, ENC_BIG_ENDIAN, &hashalg);
    proto_tree_add_item_ret_uint(sigalg_tree, hf->hf.hs_sig_hash_sig, tvb,
                                 offset + 1, 1, ENC_BIG_ENDIAN, &sigalg);

    /* No TLS 1.3 SignatureScheme? Fallback to TLS 1.2 interpretation. */
    if (!try_val_to_str(sighash, tls13_signature_algorithm)) {
        proto_item_set_text(ti_sigalg, "Signature Algorithm: %s %s (0x%04x)",
                val_to_str_const(hashalg, tls_hash_algorithm, "Unknown"),
                val_to_str_const(sigalg, tls_signature_algorithm, "Unknown"),
                sighash);
    }
} /* }}} */

/* dissect a list of hash algorithms, return the number of bytes dissected
   this is used for the signature algorithms extension and for the
   TLS1.2 certificate request. {{{ */
static int
ssl_dissect_hash_alg_list(ssl_common_dissect_t *hf, tvbuff_t *tvb, proto_tree *tree,
                          packet_info* pinfo, uint32_t offset, uint32_t offset_end, ja4_data_t *ja4_data)
{
    /* https://tools.ietf.org/html/rfc5246#section-7.4.1.4.1
     *  struct {
     *       HashAlgorithm hash;
     *       SignatureAlgorithm signature;
     *  } SignatureAndHashAlgorithm;
     *  SignatureAndHashAlgorithm supported_signature_algorithms<2..2^16-2>;
     */
    proto_tree *subtree;
    proto_item *ti;
    unsigned sh_alg_length;
    uint32_t    next_offset;

    /* SignatureAndHashAlgorithm supported_signature_algorithms<2..2^16-2> */
    if (!ssl_add_vector(hf, tvb, pinfo, tree, offset, offset_end, &sh_alg_length,
                        hf->hf.hs_sig_hash_alg_len, 2, UINT16_MAX - 1)) {
        return offset_end;
    }
    offset += 2;
    next_offset = offset + sh_alg_length;

    ti = proto_tree_add_none_format(tree, hf->hf.hs_sig_hash_algs, tvb, offset, sh_alg_length,
                                    "Signature Hash Algorithms (%u algorithm%s)",
                                    sh_alg_length / 2, plurality(sh_alg_length / 2, "", "s"));
    subtree = proto_item_add_subtree(ti, hf->ett.hs_sig_hash_algs);

    while (offset + 2 <= next_offset) {
        tls_dissect_signature_algorithm(hf, tvb, subtree, offset, ja4_data);
        offset += 2;
    }

    if (!ssl_end_vector(hf, tvb, pinfo, subtree, offset, next_offset)) {
        offset = next_offset;
    }

    return offset;
} /* }}} */

/* Dissection of DistinguishedName (for CertificateRequest and
 * certificate_authorities extension). {{{ */
static uint32_t
tls_dissect_certificate_authorities(ssl_common_dissect_t *hf, tvbuff_t *tvb, packet_info *pinfo,
                                    proto_tree *tree, uint32_t offset, uint32_t offset_end)
{
    proto_item *ti;
    proto_tree *subtree;
    uint32_t    dnames_length, next_offset;
    asn1_ctx_t  asn1_ctx;
    int         dnames_count = 100; /* the maximum number of DNs to add to the tree */

    /* Note: minimum length is 0 for TLS 1.1/1.2 and 3 for earlier/later */
    /* DistinguishedName certificate_authorities<0..2^16-1> */
    if (!ssl_add_vector(hf, tvb, pinfo, tree, offset, offset_end, &dnames_length,
                        hf->hf.hs_dnames_len, 0, UINT16_MAX)) {
        return offset_end;
    }
    offset += 2;
    next_offset = offset + dnames_length;

    if (dnames_length > 0) {
        ti = proto_tree_add_none_format(tree,
                hf->hf.hs_dnames,
                tvb, offset, dnames_length,
                "Distinguished Names (%d byte%s)",
                dnames_length,
                plurality(dnames_length, "", "s"));
        subtree = proto_item_add_subtree(ti, hf->ett.dnames);

        asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, true, pinfo);

        while (offset < next_offset) {
            /* get the length of the current certificate */
            uint32_t name_length;

            if (dnames_count-- == 0) {
                /* stop adding to tree when the list is considered too large
                 * https://gitlab.com/wireshark/wireshark/-/issues/16202
                   Note: dnames_count must be set low enough not to hit the
                   limit set by PINFO_LAYER_MAX_RECURSION_DEPTH in packet.c
                 */
                ti = proto_tree_add_item(subtree, hf->hf.hs_dnames_truncated,
                    tvb, offset, next_offset - offset, ENC_NA);
                proto_item_set_generated(ti);
                return next_offset;
            }

            /* opaque DistinguishedName<1..2^16-1> */
            if (!ssl_add_vector(hf, tvb, pinfo, subtree, offset, next_offset, &name_length,
                                hf->hf.hs_dname_len, 1, UINT16_MAX)) {
                return next_offset;
            }
            offset += 2;

            dissect_x509if_DistinguishedName(false, tvb, offset, &asn1_ctx,
                                             subtree, hf->hf.hs_dname);
            offset += name_length;
        }
    }
    return offset;
} /* }}} */


/** TLS Extensions (in Client Hello and Server Hello). {{{ */
static int
ssl_dissect_hnd_hello_ext_sig_hash_algs(ssl_common_dissect_t *hf, tvbuff_t *tvb,
                                        proto_tree *tree, packet_info* pinfo, uint32_t offset, uint32_t offset_end, ja4_data_t *ja4_data)
{
    return ssl_dissect_hash_alg_list(hf, tvb, tree, pinfo, offset, offset_end, ja4_data);
}

static int
ssl_dissect_hnd_ext_delegated_credentials(ssl_common_dissect_t *hf, tvbuff_t *tvb,
                                          proto_tree *tree, packet_info* pinfo, uint32_t offset, uint32_t offset_end, uint8_t hnd_type)
{
    if (hnd_type == SSL_HND_CLIENT_HELLO) {
        /*
         *  struct {
         *    SignatureScheme supported_signature_algorithm<2..2^16-2>;
         *  } SignatureSchemeList;
         */

        return ssl_dissect_hash_alg_list(hf, tvb, tree, pinfo, offset, offset_end, NULL);
    } else {
        asn1_ctx_t asn1_ctx;
        unsigned pubkey_length, sign_length;

        /*
         *  struct {
         *    uint32 valid_time;
         *    SignatureScheme expected_cert_verify_algorithm;
         *    opaque ASN1_subjectPublicKeyInfo<1..2^24-1>;
         *  } Credential;
         *
         *  struct {
         *    Credential cred;
         *    SignatureScheme algorithm;
         *    opaque signature<0..2^16-1>;
         *  } DelegatedCredential;
         */

        asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, true, pinfo);

        proto_tree_add_item(tree, hf->hf.hs_cred_valid_time, tvb, offset, 4, ENC_BIG_ENDIAN);
        offset += 4;

        tls_dissect_signature_algorithm(hf, tvb, tree, offset, NULL);
        offset += 2;

        if (!ssl_add_vector(hf, tvb, pinfo, tree, offset, offset_end, &pubkey_length,
                            hf->hf.hs_cred_pubkey_len, 1, G_MAXUINT24)) {
            return offset_end;
        }
        offset += 3;
        dissect_x509af_SubjectPublicKeyInfo(false, tvb, offset, &asn1_ctx, tree, hf->hf.hs_cred_pubkey);
        offset += pubkey_length;

        tls_dissect_signature_algorithm(hf, tvb, tree, offset, NULL);
        offset += 2;

        if (!ssl_add_vector(hf, tvb, pinfo, tree, offset, offset_end, &sign_length,
                            hf->hf.hs_cred_signature_len, 1, UINT16_MAX)) {
            return offset_end;
        }
        offset += 2;
        proto_tree_add_item(tree, hf->hf.hs_cred_signature,
                            tvb, offset, sign_length, ENC_ASCII|ENC_NA);
        offset += sign_length;

        return offset;
    }
}

static int
ssl_dissect_hnd_hello_ext_alps(ssl_common_dissect_t *hf, tvbuff_t *tvb,
                               packet_info *pinfo, proto_tree *tree,
                               uint32_t offset, uint32_t offset_end,
                               uint8_t hnd_type)
{

    /* https://datatracker.ietf.org/doc/html/draft-vvv-tls-alps-01#section-4 */

    switch (hnd_type) {
    case SSL_HND_CLIENT_HELLO: {
        proto_tree *alps_tree;
        proto_item *ti;
        uint32_t    next_offset, alps_length, name_length;

       /*
        *  opaque ProtocolName<1..2^8-1>;
        *  struct {
        *      ProtocolName supported_protocols<2..2^16-1>
        *  } ApplicationSettingsSupport;
        */

        if (!ssl_add_vector(hf, tvb, pinfo, tree, offset, offset_end, &alps_length,
                            hf->hf.hs_ext_alps_len, 2, UINT16_MAX)) {
            return offset_end;
        }
        offset += 2;
        next_offset = offset + alps_length;

        ti = proto_tree_add_item(tree, hf->hf.hs_ext_alps_alpn_list,
                                 tvb, offset, alps_length, ENC_NA);
        alps_tree = proto_item_add_subtree(ti, hf->ett.hs_ext_alps);

        /* Parse list (note missing check for end of vector, ssl_add_vector below
         * ensures that data is always available.) */
        while (offset < next_offset) {
            if (!ssl_add_vector(hf, tvb, pinfo, alps_tree, offset, next_offset, &name_length,
                                hf->hf.hs_ext_alps_alpn_str_len, 1, UINT8_MAX)) {
                return next_offset;
            }
            offset++;

            proto_tree_add_item(alps_tree, hf->hf.hs_ext_alps_alpn_str,
                                tvb, offset, name_length, ENC_ASCII|ENC_NA);
            offset += name_length;
        }

        return offset;
    }
    case SSL_HND_ENCRYPTED_EXTS:
	/* Opaque blob */
        proto_tree_add_item(tree, hf->hf.hs_ext_alps_settings,
                            tvb, offset, offset_end - offset, ENC_ASCII|ENC_NA);
        break;
    }

    return offset_end;
}

static int
ssl_dissect_hnd_hello_ext_alpn(ssl_common_dissect_t *hf, tvbuff_t *tvb,
                               packet_info *pinfo, proto_tree *tree,
                               uint32_t offset, uint32_t offset_end,
                               uint8_t hnd_type, SslSession *session,
                               bool is_dtls, ja4_data_t *ja4_data)
{

    /* https://tools.ietf.org/html/rfc7301#section-3.1
     *  opaque ProtocolName<1..2^8-1>;
     *  struct {
     *      ProtocolName protocol_name_list<2..2^16-1>
     *  } ProtocolNameList;
     */
    proto_tree *alpn_tree;
    proto_item *ti;
    uint32_t    next_offset, alpn_length, name_length;
    uint8_t    *proto_name = NULL, *client_proto_name = NULL;

    /* ProtocolName protocol_name_list<2..2^16-1> */
    if (!ssl_add_vector(hf, tvb, pinfo, tree, offset, offset_end, &alpn_length,
                        hf->hf.hs_ext_alpn_len, 2, UINT16_MAX)) {
        return offset_end;
    }
    offset += 2;
    next_offset = offset + alpn_length;

    ti = proto_tree_add_item(tree, hf->hf.hs_ext_alpn_list,
                             tvb, offset, alpn_length, ENC_NA);
    alpn_tree = proto_item_add_subtree(ti, hf->ett.hs_ext_alpn);

    /* Parse list (note missing check for end of vector, ssl_add_vector below
     * ensures that data is always available.) */
    while (offset < next_offset) {
        /* opaque ProtocolName<1..2^8-1> */
        if (!ssl_add_vector(hf, tvb, pinfo, alpn_tree, offset, next_offset, &name_length,
                            hf->hf.hs_ext_alpn_str_len, 1, UINT8_MAX)) {
            return next_offset;
        }
        offset++;

        proto_tree_add_item(alpn_tree, hf->hf.hs_ext_alpn_str,
                            tvb, offset, name_length, ENC_ASCII|ENC_NA);
        if (ja4_data && wmem_strbuf_get_len(ja4_data->alpn) == 0) {
            const char alpn_first_char = (char)tvb_get_uint8(tvb,offset);
            const char alpn_last_char = (char)tvb_get_uint8(tvb,offset + name_length - 1);
            if ((g_ascii_isprint(alpn_first_char)) && g_ascii_isprint(alpn_last_char)) {
                wmem_strbuf_append_printf(ja4_data->alpn, "%c%c", alpn_first_char, alpn_last_char);
            }
            else {
                wmem_strbuf_append_printf(ja4_data->alpn, "%x%x",(alpn_first_char >> 4) & 0x0F,
                    alpn_last_char & 0x0F);
            }
        }
        /* Remember first ALPN ProtocolName entry for server. */
        if (hnd_type == SSL_HND_SERVER_HELLO || hnd_type == SSL_HND_ENCRYPTED_EXTENSIONS) {
            /* '\0'-terminated string for dissector table match and prefix
             * comparison purposes. */
            proto_name = tvb_get_string_enc(pinfo->pool, tvb, offset,
                                            name_length, ENC_ASCII);
        } else if (hnd_type == SSL_HND_CLIENT_HELLO) {
            client_proto_name = tvb_get_string_enc(pinfo->pool, tvb, offset,
                                                   name_length, ENC_ASCII);
        }
        offset += name_length;
    }

    /* If ALPN is given in ServerHello, then ProtocolNameList MUST contain
     * exactly one "ProtocolName". */
    if (proto_name) {
        dissector_handle_t handle;

        session->alpn_name = wmem_strdup(wmem_file_scope(), proto_name);

        if (is_dtls) {
            handle = dissector_get_string_handle(dtls_alpn_dissector_table,
                                                 proto_name);
        } else {
            handle = dissector_get_string_handle(ssl_alpn_dissector_table,
                                                 proto_name);
            if (handle == NULL) {
                /* Try prefix matching */
                for (size_t i = 0; i < G_N_ELEMENTS(ssl_alpn_prefix_match_protocols); i++) {
                    const ssl_alpn_prefix_match_protocol_t *alpn_proto = &ssl_alpn_prefix_match_protocols[i];

                    /* string_string is inappropriate as it compares strings
                     * while "byte strings MUST NOT be truncated" (RFC 7301) */
                    if (g_str_has_prefix(proto_name, alpn_proto->proto_prefix)) {
                        handle = find_dissector(alpn_proto->dissector_name);
                        break;
                    }
                }
            }
        }
        if (handle != NULL) {
            /* ProtocolName match, so set the App data dissector handle.
             * This may override protocols given via the UAT dialog, but
             * since the ALPN hint is precise, do it anyway. */
            ssl_debug_printf("%s: changing handle %p to %p (%s)", G_STRFUNC,
                             (void *)session->app_handle,
                             (void *)handle,
                             dissector_handle_get_dissector_name(handle));
            session->app_handle = handle;
        }
    } else if (client_proto_name) {
        // No current use for looking up the handle as the only consumer of this API is currently the QUIC dissector
        // and it just needs the string since there are/were various HTTP/3 ALPNs to check for.
        session->client_alpn_name = wmem_strdup(wmem_file_scope(), client_proto_name);
    }

    return offset;
}

static int
ssl_dissect_hnd_hello_ext_npn(ssl_common_dissect_t *hf, tvbuff_t *tvb,
                              packet_info *pinfo, proto_tree *tree,
                              uint32_t offset, uint32_t offset_end)
{
    /* https://tools.ietf.org/html/draft-agl-tls-nextprotoneg-04#page-3
     *   The "extension_data" field of a "next_protocol_negotiation" extension
     *   in a "ServerHello" contains an optional list of protocols advertised
     *   by the server.  Protocols are named by opaque, non-empty byte strings
     *   and the list of protocols is serialized as a concatenation of 8-bit,
     *   length prefixed byte strings.  Implementations MUST ensure that the
     *   empty string is not included and that no byte strings are truncated.
     */
    uint32_t    npn_length;
    proto_tree *npn_tree;

    /* List is optional, do not add tree if there are no entries. */
    if (offset == offset_end) {
        return offset;
    }

    npn_tree = proto_tree_add_subtree(tree, tvb, offset, offset_end - offset, hf->ett.hs_ext_npn, NULL, "Next Protocol Negotiation");

    while (offset < offset_end) {
        /* non-empty, 8-bit length prefixed strings means range 1..255 */
        if (!ssl_add_vector(hf, tvb, pinfo, npn_tree, offset, offset_end, &npn_length,
                            hf->hf.hs_ext_npn_str_len, 1, UINT8_MAX)) {
            return offset_end;
        }
        offset++;

        proto_tree_add_item(npn_tree, hf->hf.hs_ext_npn_str,
                            tvb, offset, npn_length, ENC_ASCII|ENC_NA);
        offset += npn_length;
    }

    return offset;
}

static int
ssl_dissect_hnd_hello_ext_reneg_info(ssl_common_dissect_t *hf, tvbuff_t *tvb,
                                     packet_info *pinfo, proto_tree *tree,
                                     uint32_t offset, uint32_t offset_end)
{
    /* https://tools.ietf.org/html/rfc5746#section-3.2
     *  struct {
     *      opaque renegotiated_connection<0..255>;
     *  } RenegotiationInfo;
     *
     */
    proto_tree *reneg_info_tree;
    uint32_t    reneg_info_length;

    reneg_info_tree = proto_tree_add_subtree(tree, tvb, offset, offset_end - offset, hf->ett.hs_ext_reneg_info, NULL, "Renegotiation Info extension");

    /* opaque renegotiated_connection<0..255> */
    if (!ssl_add_vector(hf, tvb, pinfo, reneg_info_tree, offset, offset_end, &reneg_info_length,
                        hf->hf.hs_ext_reneg_info_len, 0, 255)) {
        return offset_end;
    }
    offset++;

    if (reneg_info_length > 0) {
        proto_tree_add_item(reneg_info_tree, hf->hf.hs_ext_reneg_info, tvb, offset, reneg_info_length, ENC_NA);
        offset += reneg_info_length;
    }

    return offset;
}

static int
ssl_dissect_hnd_hello_ext_key_share_entry(ssl_common_dissect_t *hf, tvbuff_t *tvb, packet_info *pinfo,
                                          proto_tree *tree, uint32_t offset, uint32_t offset_end,
                                          const char **group_name_out)
{
   /* RFC 8446 Section 4.2.8
    *   struct {
    *       NamedGroup group;
    *       opaque key_exchange<1..2^16-1>;
    *   } KeyShareEntry;
    */
    uint32_t key_exchange_length, group;
    proto_tree *ks_tree;

    ks_tree = proto_tree_add_subtree(tree, tvb, offset, 4, hf->ett.hs_ext_key_share_ks, NULL, "Key Share Entry");

    proto_tree_add_item_ret_uint(ks_tree, hf->hf.hs_ext_key_share_group, tvb, offset, 2, ENC_BIG_ENDIAN, &group);
    offset += 2;
    const char *group_name = val_to_str(group, ssl_extension_curves, "Unknown (%u)");
    proto_item_append_text(ks_tree, ": Group: %s", group_name);
    if (group_name_out) {
        *group_name_out = !IS_GREASE_TLS(group) ? group_name : NULL;
    }

    /* opaque key_exchange<1..2^16-1> */
    if (!ssl_add_vector(hf, tvb, pinfo, ks_tree, offset, offset_end, &key_exchange_length,
                        hf->hf.hs_ext_key_share_key_exchange_length, 1, UINT16_MAX)) {
        return offset_end;  /* Bad (possible truncated) length, skip to end of KeyShare extension. */
    }
    offset += 2;
    proto_item_set_len(ks_tree, 2 + 2 + key_exchange_length);
    proto_item_append_text(ks_tree, ", Key Exchange length: %u", key_exchange_length);

    proto_tree_add_item(ks_tree, hf->hf.hs_ext_key_share_key_exchange, tvb, offset, key_exchange_length, ENC_NA);
    offset += key_exchange_length;

    return offset;
}

static int
ssl_dissect_hnd_hello_ext_key_share(ssl_common_dissect_t *hf, tvbuff_t *tvb, packet_info *pinfo,
                                    proto_tree *tree, uint32_t offset, uint32_t offset_end,
                                    uint8_t hnd_type)
{
    proto_tree *key_share_tree;
    uint32_t next_offset;
    uint32_t client_shares_length;
    uint32_t group;
    const char *group_name = NULL;

    if (offset_end <= offset) {  /* Check if ext_len == 0 and "overflow" (offset + ext_len) > uint32_t) */
        return offset;
    }

    key_share_tree = proto_tree_add_subtree(tree, tvb, offset, offset_end - offset, hf->ett.hs_ext_key_share, NULL, "Key Share extension");

    switch(hnd_type){
        case SSL_HND_CLIENT_HELLO:
            /* KeyShareEntry client_shares<0..2^16-1> */
            if (!ssl_add_vector(hf, tvb, pinfo, key_share_tree, offset, offset_end, &client_shares_length,
                                hf->hf.hs_ext_key_share_client_length, 0, UINT16_MAX)) {
                return offset_end;
            }
            offset += 2;
            next_offset = offset + client_shares_length;
            const char *sep = " ";
            while (offset + 4 <= next_offset) { /* (NamedGroup (2 bytes), key_exchange (1 byte for length, 1 byte minimum data) */
                offset = ssl_dissect_hnd_hello_ext_key_share_entry(hf, tvb, pinfo, key_share_tree, offset, next_offset, &group_name);
                if (group_name) {
                    proto_item_append_text(tree, "%s%s", sep, group_name);
                    sep = ", ";
                }
            }
            if (!ssl_end_vector(hf, tvb, pinfo, key_share_tree, offset, next_offset)) {
                return next_offset;
            }
        break;
        case SSL_HND_SERVER_HELLO:
            offset = ssl_dissect_hnd_hello_ext_key_share_entry(hf, tvb, pinfo, key_share_tree, offset, offset_end, &group_name);
            if (group_name) {
                proto_item_append_text(tree, " %s", group_name);
            }
        break;
        case SSL_HND_HELLO_RETRY_REQUEST:
            proto_tree_add_item_ret_uint(key_share_tree, hf->hf.hs_ext_key_share_selected_group, tvb, offset, 2, ENC_BIG_ENDIAN, &group);
            offset += 2;
            group_name = val_to_str(group, ssl_extension_curves, "Unknown (%u)");
            proto_item_append_text(tree, " %s", group_name);
        break;
        default: /* no default */
        break;
    }

    return offset;
}

static int
ssl_dissect_hnd_hello_ext_pre_shared_key(ssl_common_dissect_t *hf, tvbuff_t *tvb, packet_info *pinfo,
                                         proto_tree *tree, uint32_t offset, uint32_t offset_end,
                                         uint8_t hnd_type)
{
    /* RFC 8446 Section 4.2.11
     *  struct {
     *      opaque identity<1..2^16-1>;
     *      uint32 obfuscated_ticket_age;
     *  } PskIdentity;
     *  opaque PskBinderEntry<32..255>;
     *  struct {
     *      select (Handshake.msg_type) {
     *          case client_hello:
     *              PskIdentity identities<7..2^16-1>;
     *              PskBinderEntry binders<33..2^16-1>;
     *          case server_hello:
     *              uint16 selected_identity;
     *      };
     *  } PreSharedKeyExtension;
     */

    proto_tree *psk_tree;

    psk_tree = proto_tree_add_subtree(tree, tvb, offset, offset_end - offset, hf->ett.hs_ext_pre_shared_key, NULL, "Pre-Shared Key extension");

    switch (hnd_type){
        case SSL_HND_CLIENT_HELLO: {
            uint32_t identities_length, identities_end, binders_length;

            /* PskIdentity identities<7..2^16-1> */
            if (!ssl_add_vector(hf, tvb, pinfo, psk_tree, offset, offset_end, &identities_length,
                                hf->hf.hs_ext_psk_identities_length, 7, UINT16_MAX)) {
                return offset_end;
            }
            offset += 2;
            identities_end = offset + identities_length;

            while (offset < identities_end) {
                uint32_t identity_length;
                proto_tree *identity_tree;

                identity_tree = proto_tree_add_subtree(psk_tree, tvb, offset, 4, hf->ett.hs_ext_psk_identity, NULL, "PSK Identity (");

                /* opaque identity<1..2^16-1> */
                if (!ssl_add_vector(hf, tvb, pinfo, identity_tree, offset, identities_end, &identity_length,
                                    hf->hf.hs_ext_psk_identity_identity_length, 1, UINT16_MAX)) {
                    return identities_end;
                }
                offset += 2;
                proto_item_append_text(identity_tree, "length: %u)", identity_length);

                proto_tree_add_item(identity_tree, hf->hf.hs_ext_psk_identity_identity, tvb, offset, identity_length, ENC_BIG_ENDIAN);
                offset += identity_length;

                proto_tree_add_item(identity_tree, hf->hf.hs_ext_psk_identity_obfuscated_ticket_age, tvb, offset, 4, ENC_BIG_ENDIAN);
                offset += 4;

                proto_item_set_len(identity_tree, 2 + identity_length + 4);
            }
            if (!ssl_end_vector(hf, tvb, pinfo, psk_tree, offset, identities_end)) {
                offset = identities_end;
            }

            /* PskBinderEntry binders<33..2^16-1> */
            if (!ssl_add_vector(hf, tvb, pinfo, psk_tree, offset, offset_end, &binders_length,
                                hf->hf.hs_ext_psk_binders_length, 33, UINT16_MAX)) {
                return offset_end;
            }
            offset += 2;

            proto_tree_add_item(psk_tree, hf->hf.hs_ext_psk_binders, tvb, offset, binders_length, ENC_NA);
            offset += binders_length;
        }
        break;
        case SSL_HND_SERVER_HELLO: {
            proto_tree_add_item(psk_tree, hf->hf.hs_ext_psk_identity_selected, tvb, offset, 2, ENC_BIG_ENDIAN);
            offset += 2;
        }
        break;
        default:
        break;
    }

    return offset;
}

static uint32_t
ssl_dissect_hnd_hello_ext_early_data(ssl_common_dissect_t *hf, tvbuff_t *tvb, packet_info *pinfo _U_,
                                     proto_tree *tree, uint32_t offset, uint32_t offset_end _U_,
                                     uint8_t hnd_type, SslDecryptSession *ssl)
{
    /* RFC 8446 Section 4.2.10
     *  struct {} Empty;
     *  struct {
     *      select (Handshake.msg_type) {
     *          case new_session_ticket:   uint32 max_early_data_size;
     *          case client_hello:         Empty;
     *          case encrypted_extensions: Empty;
     *      };
     *  } EarlyDataIndication;
     */
    switch (hnd_type) {
    case SSL_HND_CLIENT_HELLO:
        /* Remember that early_data will follow the handshake. */
        if (ssl) {
            ssl_debug_printf("%s found early_data extension\n", G_STRFUNC);
            ssl->has_early_data = true;
        }
        break;
    case SSL_HND_NEWSESSION_TICKET:
        proto_tree_add_item(tree, hf->hf.hs_ext_max_early_data_size, tvb, offset, 4, ENC_BIG_ENDIAN);
        offset += 4;
        break;
    default:
        break;
    }
    return offset;
}

static uint16_t
tls_try_get_version(bool is_dtls, uint16_t version, uint8_t *draft_version)
{
    if (draft_version) {
        *draft_version = 0;
    }
    if (!is_dtls) {
        uint8_t tls13_draft = extract_tls13_draft_version(version);
        if (tls13_draft != 0) {
            /* This is TLS 1.3 (a draft version). */
            if (draft_version) {
                *draft_version = tls13_draft;
            }
            version = TLSV1DOT3_VERSION;
        }
        if (version == 0xfb17 || version == 0xfb1a) {
            /* Unofficial TLS 1.3 draft version for Facebook fizz. */
            tls13_draft = (uint8_t)version;
            if (draft_version) {
                *draft_version = tls13_draft;
            }
            version = TLSV1DOT3_VERSION;
        }
    }

    switch (version) {
    case SSLV3_VERSION:
    case TLSV1_VERSION:
    case TLSV1DOT1_VERSION:
    case TLSV1DOT2_VERSION:
    case TLSV1DOT3_VERSION:
    case TLCPV1_VERSION:
        if (is_dtls)
            return SSL_VER_UNKNOWN;
        break;

    case DTLSV1DOT0_VERSION:
    case DTLSV1DOT0_OPENSSL_VERSION:
    case DTLSV1DOT2_VERSION:
    case DTLSV1DOT3_VERSION:
        if (!is_dtls)
            return SSL_VER_UNKNOWN;
        break;

    default: /* invalid version number */
        return SSL_VER_UNKNOWN;
    }

    return version;
}

static int
ssl_dissect_hnd_hello_ext_supported_versions(ssl_common_dissect_t *hf, tvbuff_t *tvb, packet_info *pinfo,
                                             proto_tree *tree, uint32_t offset, uint32_t offset_end,
                                             SslSession *session, bool is_dtls, ja4_data_t *ja4_data)
{

   /* RFC 8446 Section 4.2.1
    * struct {
    *     ProtocolVersion versions<2..254>; // ClientHello
    * } SupportedVersions;
    * Note that ServerHello and HelloRetryRequest are handled by the caller.
    */
    uint32_t    versions_length, next_offset;
    /* ProtocolVersion versions<2..254> */
    if (!ssl_add_vector(hf, tvb, pinfo, tree, offset, offset_end, &versions_length,
                        hf->hf.hs_ext_supported_versions_len, 2, 254)) {
        return offset_end;
    }
    offset++;
    next_offset = offset + versions_length;

    unsigned version;
    unsigned current_version, lowest_version = SSL_VER_UNKNOWN;
    uint8_t draft_version, max_draft_version = 0;
    const char *sep = " ";
    while (offset + 2 <= next_offset) {
        proto_tree_add_item_ret_uint(tree, hf->hf.hs_ext_supported_version, tvb, offset, 2, ENC_BIG_ENDIAN, &version);
        offset += 2;

        if (!IS_GREASE_TLS(version)) {
            proto_item_append_text(tree, "%s%s", sep, val_to_str(version, ssl_versions, "Unknown (0x%04x)"));
            sep = ", ";
        }

        current_version = tls_try_get_version(is_dtls, version, &draft_version);
        if (session->version == SSL_VER_UNKNOWN) {
            if (lowest_version == SSL_VER_UNKNOWN) {
                lowest_version = current_version;
            } else if (current_version != SSL_VER_UNKNOWN) {
                if (!is_dtls) {
                    lowest_version = MIN(lowest_version, current_version);
                } else {
                    lowest_version = MAX(lowest_version, current_version);
                }
            }
        }
        max_draft_version = MAX(draft_version, max_draft_version);
        if (ja4_data && !IS_GREASE_TLS(version)) {
            /* The DTLS version numbers get mapped to "00" for unknown per
             * JA4 spec, but if JA4 ever does support DTLS we'll probably
             * need to take the MIN instead of MAX here for DTLS.
             */
            ja4_data->max_version = MAX(version, ja4_data->max_version);
        }
    }
    if (session->version == SSL_VER_UNKNOWN && lowest_version != SSL_VER_UNKNOWN) {
        col_set_str(pinfo->cinfo, COL_PROTOCOL,
                    val_to_str_const(version, ssl_version_short_names, is_dtls ? "DTLS" : "TLS"));
    }
    if (!ssl_end_vector(hf, tvb, pinfo, tree, offset, next_offset)) {
        offset = next_offset;
    }

    /* XXX remove this when draft 19 support is dropped,
     * this is only required for early data decryption. */
    if (max_draft_version) {
        session->tls13_draft_version = max_draft_version;
    }

    return offset;
}

static int
ssl_dissect_hnd_hello_ext_cookie(ssl_common_dissect_t *hf, tvbuff_t *tvb,
                                 packet_info *pinfo, proto_tree *tree,
                                 uint32_t offset, uint32_t offset_end)
{
    /* RFC 8446 Section 4.2.2
     *  struct {
     *      opaque cookie<1..2^16-1>;
     *  } Cookie;
     */
    uint32_t cookie_length;
    /* opaque cookie<1..2^16-1> */
    if (!ssl_add_vector(hf, tvb, pinfo, tree, offset, offset_end, &cookie_length,
                        hf->hf.hs_ext_cookie_len, 1, UINT16_MAX)) {
        return offset_end;
    }
    offset += 2;

    proto_tree_add_item(tree, hf->hf.hs_ext_cookie, tvb, offset, cookie_length, ENC_NA);
    offset += cookie_length;

    return offset;
}

static int
ssl_dissect_hnd_hello_ext_psk_key_exchange_modes(ssl_common_dissect_t *hf, tvbuff_t *tvb, packet_info *pinfo,
                                                 proto_tree *tree, uint32_t offset, uint32_t offset_end)
{
    /* RFC 8446 Section 4.2.9
     * enum { psk_ke(0), psk_dhe_ke(1), (255) } PskKeyExchangeMode;
     *
     * struct {
     *     PskKeyExchangeMode ke_modes<1..255>;
     * } PskKeyExchangeModes;
     */
    uint32_t ke_modes_length, next_offset;

    /* PskKeyExchangeMode ke_modes<1..255> */
    if (!ssl_add_vector(hf, tvb, pinfo, tree, offset, offset_end, &ke_modes_length,
                        hf->hf.hs_ext_psk_ke_modes_length, 1, 255)) {
        return offset_end;
    }
    offset++;
    next_offset = offset + ke_modes_length;

    while (offset < next_offset) {
        proto_tree_add_item(tree, hf->hf.hs_ext_psk_ke_mode, tvb, offset, 1, ENC_NA);
        offset++;
    }

    return offset;
}

static uint32_t
ssl_dissect_hnd_hello_ext_certificate_authorities(ssl_common_dissect_t *hf, tvbuff_t *tvb, packet_info *pinfo,
                                                  proto_tree *tree, uint32_t offset, uint32_t offset_end)
{
    /* RFC 8446 Section 4.2.4
     *  opaque DistinguishedName<1..2^16-1>;
     *  struct {
     *      DistinguishedName authorities<3..2^16-1>;
     *  } CertificateAuthoritiesExtension;
     */
    return tls_dissect_certificate_authorities(hf, tvb, pinfo, tree, offset, offset_end);
}

static int
ssl_dissect_hnd_hello_ext_oid_filters(ssl_common_dissect_t *hf, tvbuff_t *tvb, packet_info *pinfo,
                                      proto_tree *tree, uint32_t offset, uint32_t offset_end)
{
    /* RFC 8446 Section 4.2.5
     *  struct {
     *      opaque certificate_extension_oid<1..2^8-1>;
     *      opaque certificate_extension_values<0..2^16-1>;
     *  } OIDFilter;
     *  struct {
     *      OIDFilter filters<0..2^16-1>;
     *  } OIDFilterExtension;
     */
    proto_tree *subtree;
    uint32_t    filters_length, oid_length, values_length, value_offset;
    asn1_ctx_t  asn1_ctx;
    const char *oid, *name;

    /* OIDFilter filters<0..2^16-1> */
    if (!ssl_add_vector(hf, tvb, pinfo, tree, offset, offset_end, &filters_length,
                        hf->hf.hs_ext_psk_ke_modes_length, 0, UINT16_MAX)) {
        return offset_end;
    }
    offset += 2;
    offset_end = offset + filters_length;

    asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, true, pinfo);

    while (offset < offset_end) {
        subtree = proto_tree_add_subtree(tree, tvb, offset, offset_end - offset,
                                         hf->ett.hs_ext_oid_filter, NULL, "OID Filter");

        /* opaque certificate_extension_oid<1..2^8-1> */
        if (!ssl_add_vector(hf, tvb, pinfo, subtree, offset, offset_end, &oid_length,
                    hf->hf.hs_ext_oid_filters_oid_length, 1, UINT8_MAX)) {
            return offset_end;
        }
        offset++;
        dissect_ber_object_identifier_str(false, &asn1_ctx, subtree, tvb, offset,
                                          hf->hf.hs_ext_oid_filters_oid, &oid);
        offset += oid_length;

        /* Append OID to tree label */
        name = oid_resolved_from_string(pinfo->pool, oid);
        proto_item_append_text(subtree, " (%s)", name ? name : oid);

        /* opaque certificate_extension_values<0..2^16-1> */
        if (!ssl_add_vector(hf, tvb, pinfo, subtree, offset, offset_end, &values_length,
                    hf->hf.hs_ext_oid_filters_values_length, 0, UINT16_MAX)) {
            return offset_end;
        }
        offset += 2;
        proto_item_set_len(subtree, 1 + oid_length + 2 + values_length);
        if (values_length > 0) {
            value_offset = offset;
            value_offset = dissect_ber_identifier(pinfo, subtree, tvb, value_offset, NULL, NULL, NULL);
            value_offset = dissect_ber_length(pinfo, subtree, tvb, value_offset, NULL, NULL);
            call_ber_oid_callback(oid, tvb, value_offset, pinfo, subtree, NULL);
        }
        offset += values_length;
    }

    return offset;
}

static int
ssl_dissect_hnd_hello_ext_server_name(ssl_common_dissect_t *hf, tvbuff_t *tvb,
                                      packet_info *pinfo, proto_tree *tree,
                                      uint32_t offset, uint32_t offset_end)
{
    /* https://tools.ietf.org/html/rfc6066#section-3
     *
     *  struct {
     *      NameType name_type;
     *      select (name_type) {
     *          case host_name: HostName;
     *      } name;
     *  } ServerName;
     *
     *  enum {
     *      host_name(0), (255)
     *  } NameType;
     *
     *  opaque HostName<1..2^16-1>;
     *
     *  struct {
     *      ServerName server_name_list<1..2^16-1>
     *  } ServerNameList;
     */
    proto_tree *server_name_tree;
    uint32_t    list_length, server_name_length, next_offset;

    /* The server SHALL include "server_name" extension with empty data. */
    if (offset == offset_end) {
        return offset;
    }

    server_name_tree = proto_tree_add_subtree(tree, tvb, offset, offset_end - offset, hf->ett.hs_ext_server_name, NULL, "Server Name Indication extension");

    /* ServerName server_name_list<1..2^16-1> */
    if (!ssl_add_vector(hf, tvb, pinfo, server_name_tree, offset, offset_end, &list_length,
                        hf->hf.hs_ext_server_name_list_len, 1, UINT16_MAX)) {
        return offset_end;
    }
    offset += 2;
    next_offset = offset + list_length;

    while (offset < next_offset) {
        uint32_t name_type;
        const uint8_t *server_name = NULL;
        proto_tree_add_item_ret_uint(server_name_tree, hf->hf.hs_ext_server_name_type,
                                     tvb, offset, 1, ENC_NA, &name_type);
        offset++;

        /* opaque HostName<1..2^16-1> */
        if (!ssl_add_vector(hf, tvb, pinfo, server_name_tree, offset, next_offset, &server_name_length,
                           hf->hf.hs_ext_server_name_len, 1, UINT16_MAX)) {
            return next_offset;
        }
        offset += 2;

        proto_tree_add_item_ret_string(server_name_tree, hf->hf.hs_ext_server_name,
                                       tvb, offset, server_name_length, ENC_ASCII|ENC_NA,
                                       pinfo->pool, &server_name);
        offset += server_name_length;
        // Each type must only occur once, so we don't check for duplicates.
        if (name_type == 0) {
            proto_item_append_text(tree, " name=%s", server_name);
            col_append_fstr(pinfo->cinfo, COL_INFO, " (SNI=%s)", server_name);

            if (gbl_resolv_flags.handshake_sni_addr_resolution) {
                // Client Hello: Client (Src) -> Server (Dst)
                switch (pinfo->dst.type) {
                    case AT_IPv4:
                        if (pinfo->dst.len == sizeof(uint32_t)) {
                            add_ipv4_name(*(uint32_t *)pinfo->dst.data, server_name, false);
                        }
                        break;
                    case AT_IPv6:
                        if (pinfo->dst.len == sizeof(ws_in6_addr)) {
                            add_ipv6_name(pinfo->dst.data, server_name, false);
                        }
                        break;
                }
            }
        }
    }
    return offset;
}

static int
ssl_dissect_hnd_hello_ext_session_ticket(ssl_common_dissect_t *hf, tvbuff_t *tvb,
                                      proto_tree *tree, uint32_t offset, uint32_t offset_end, uint8_t hnd_type, SslDecryptSession *ssl)
{
    unsigned    ext_len = offset_end - offset;
    if (hnd_type == SSL_HND_CLIENT_HELLO && ssl && ext_len != 0) {
        tvb_ensure_bytes_exist(tvb, offset, ext_len);
        /* Save the Session Ticket such that it can be used as identifier for
         * restoring a previous Master Secret (in ChangeCipherSpec) */
        ssl->session_ticket.data = (unsigned char*)wmem_realloc(wmem_file_scope(),
                                    ssl->session_ticket.data, ext_len);
        ssl->session_ticket.data_len = ext_len;
        tvb_memcpy(tvb,ssl->session_ticket.data, offset, ext_len);
    }
    proto_tree_add_item(tree, hf->hf.hs_ext_session_ticket,
                        tvb, offset, ext_len, ENC_NA);
    return offset + ext_len;
}

static int
ssl_dissect_hnd_hello_ext_cert_type(ssl_common_dissect_t *hf, tvbuff_t *tvb,
                                    proto_tree *tree, uint32_t offset, uint32_t offset_end,
                                    uint8_t hnd_type, uint16_t ext_type, SslSession *session)
{
    uint8_t     cert_list_length;
    uint8_t     cert_type;
    proto_tree *cert_list_tree;
    proto_item *ti;

    switch(hnd_type){
    case SSL_HND_CLIENT_HELLO:
        cert_list_length = tvb_get_uint8(tvb, offset);
        proto_tree_add_item(tree, hf->hf.hs_ext_cert_types_len,
                            tvb, offset, 1, ENC_BIG_ENDIAN);
        offset += 1;
        if (offset_end - offset != (uint32_t)cert_list_length)
            return offset;

        ti = proto_tree_add_item(tree, hf->hf.hs_ext_cert_types, tvb, offset,
                                 cert_list_length, cert_list_length);
        proto_item_append_text(ti, " (%d)", cert_list_length);

        /* make this a subtree */
        cert_list_tree = proto_item_add_subtree(ti, hf->ett.hs_ext_cert_types);

        /* loop over all point formats */
        while (cert_list_length > 0)
        {
            proto_tree_add_item(cert_list_tree, hf->hf.hs_ext_cert_type, tvb, offset, 1, ENC_BIG_ENDIAN);
            offset++;
            cert_list_length--;
        }
    break;
    case SSL_HND_SERVER_HELLO:
    case SSL_HND_ENCRYPTED_EXTENSIONS:
    case SSL_HND_CERTIFICATE:
        cert_type = tvb_get_uint8(tvb, offset);
        proto_tree_add_item(tree, hf->hf.hs_ext_cert_type, tvb, offset, 1, ENC_BIG_ENDIAN);
        offset += 1;
        if (ext_type == SSL_HND_HELLO_EXT_CERT_TYPE || ext_type == SSL_HND_HELLO_EXT_CLIENT_CERT_TYPE) {
            session->client_cert_type = cert_type;
        }
        if (ext_type == SSL_HND_HELLO_EXT_CERT_TYPE || ext_type == SSL_HND_HELLO_EXT_SERVER_CERT_TYPE) {
            session->server_cert_type = cert_type;
        }
    break;
    default: /* no default */
    break;
    }

    return offset;
}

static uint32_t
ssl_dissect_hnd_hello_ext_compress_certificate(ssl_common_dissect_t *hf, tvbuff_t *tvb, packet_info *pinfo,
                                                    proto_tree *tree, uint32_t offset, uint32_t offset_end,
                                                    uint8_t hnd_type, SslDecryptSession *ssl _U_)
{
    uint32_t compress_certificate_algorithms_length, next_offset;

    /* https://tools.ietf.org/html/draft-ietf-tls-certificate-compression-03#section-3.0
     * enum {
     *     zlib(1),
     *     brotli(2),
     *     (65535)
     * } CertificateCompressionAlgorithm;
     *
     * struct {
     *     CertificateCompressionAlgorithm algorithms<1..2^8-1>;
     * } CertificateCompressionAlgorithms;
     */
    switch (hnd_type) {
    case SSL_HND_CLIENT_HELLO:
    case SSL_HND_CERT_REQUEST:
        /* CertificateCompressionAlgorithm algorithms<1..2^8-1>;*/
        if (!ssl_add_vector(hf, tvb, pinfo, tree, offset, offset_end, &compress_certificate_algorithms_length,
                            hf->hf.hs_ext_compress_certificate_algorithms_length, 1, UINT8_MAX-1)) {
            return offset_end;
        }
        offset += 1;
        next_offset = offset + compress_certificate_algorithms_length;

        while (offset < next_offset) {
            proto_tree_add_item(tree, hf->hf.hs_ext_compress_certificate_algorithm,
                                tvb, offset, 2, ENC_BIG_ENDIAN);
            offset += 2;
        }
        break;
    default:
        break;
    }

    return offset;
}

static uint32_t
ssl_dissect_hnd_hello_ext_token_binding(ssl_common_dissect_t *hf, tvbuff_t *tvb, packet_info *pinfo,
                                        proto_tree *tree, uint32_t offset, uint32_t offset_end,
                                        uint8_t hnd_type, SslDecryptSession *ssl _U_)
{
   uint32_t key_parameters_length, next_offset;
   proto_item *p_ti;
   proto_tree *p_tree;

   /* RFC 8472
    *
    * struct {
    *     uint8 major;
    *     uint8 minor;
    * } TB_ProtocolVersion;
    *
    * enum {
    *     rsa2048_pkcs1.5(0), rsa2048_pss(1), ecdsap256(2), (255)
    * } TokenBindingKeyParameters;
    *
    * struct {
    *     TB_ProtocolVersion token_binding_version;
    *     TokenBindingKeyParameters key_parameters_list<1..2^8-1>
    * } TokenBindingParameters;
    */

    switch (hnd_type) {
    case SSL_HND_CLIENT_HELLO:
    case SSL_HND_SERVER_HELLO:
        proto_tree_add_item(tree, hf->hf.hs_ext_token_binding_version_major, tvb, offset, 1, ENC_BIG_ENDIAN);
        offset += 1;
        proto_tree_add_item(tree, hf->hf.hs_ext_token_binding_version_minor, tvb, offset, 1, ENC_BIG_ENDIAN);
        offset += 1;

        if (!ssl_add_vector(hf, tvb, pinfo, tree, offset, offset_end, &key_parameters_length,
                            hf->hf.hs_ext_token_binding_key_parameters_length, 1, UINT8_MAX)) {
            return offset_end;
        }
        offset += 1;
        next_offset = offset + key_parameters_length;

        p_ti = proto_tree_add_none_format(tree,
                                          hf->hf.hs_ext_token_binding_key_parameters,
                                          tvb, offset, key_parameters_length,
                                          "Key parameters identifiers (%d identifier%s)",
                                          key_parameters_length,
                                          plurality(key_parameters_length, "", "s"));
        p_tree = proto_item_add_subtree(p_ti, hf->ett.hs_ext_token_binding_key_parameters);

        while (offset < next_offset) {
            proto_tree_add_item(p_tree, hf->hf.hs_ext_token_binding_key_parameter,
                                tvb, offset, 1, ENC_BIG_ENDIAN);
            offset += 1;
        }

        if (!ssl_end_vector(hf, tvb, pinfo, p_tree, offset, next_offset)) {
            offset = next_offset;
        }

        break;
    default:
        break;
    }

    return offset;
}

static uint32_t
ssl_dissect_hnd_hello_ext_quic_transport_parameters(ssl_common_dissect_t *hf, tvbuff_t *tvb, packet_info *pinfo,
                                                    proto_tree *tree, uint32_t offset, uint32_t offset_end,
                                                    uint8_t hnd_type, SslDecryptSession *ssl _U_)
{
    bool use_varint_encoding = true;    // Whether this is draft -27 or newer.
    uint32_t next_offset;

    /* https://tools.ietf.org/html/draft-ietf-quic-transport-25#section-18
     *
     * Note: the following structures are not literally defined in the spec,
     * they instead use an ASCII diagram.
     *
     *   struct {
     *     uint16 id;
     *     opaque value<0..2^16-1>;
     *  } TransportParameter;                               // before draft -27
     *  TransportParameter TransportParameters<0..2^16-1>;  // before draft -27
     *
     *  struct {
     *    opaque ipv4Address[4];
     *    uint16 ipv4Port;
     *    opaque ipv6Address[16];
     *    uint16 ipv6Port;
     *    opaque connectionId<0..18>;
     *    opaque statelessResetToken[16];
     *  } PreferredAddress;
     */

    if (offset_end - offset >= 6 &&
            2 + (unsigned)tvb_get_ntohs(tvb, offset) == offset_end - offset &&
            6 + (unsigned)tvb_get_ntohs(tvb, offset + 4) <= offset_end - offset) {
        // Assume encoding of Transport Parameters draft -26 or older with at
        // least one transport parameter that has a valid length.
        use_varint_encoding = false;
    }

    if (use_varint_encoding) {
        next_offset = offset_end;
    } else {
        uint32_t quic_length;
        // Assume draft -26 or earlier.
        /* TransportParameter TransportParameters<0..2^16-1>; */
        if (!ssl_add_vector(hf, tvb, pinfo, tree, offset, offset_end, &quic_length,
                            hf->hf.hs_ext_quictp_len, 0, UINT16_MAX)) {
            return offset_end;
        }
        offset += 2;
        next_offset = offset + quic_length;
    }

    while (offset < next_offset) {
        uint64_t parameter_type;     /* 62-bit space */
        uint32_t parameter_length;
        proto_tree *parameter_tree;
        uint32_t parameter_end_offset;
        uint64_t value;
        uint32_t len = 0, i;

        parameter_tree = proto_tree_add_subtree(tree, tvb, offset, 2, hf->ett.hs_ext_quictp_parameter,
                                                NULL, "Parameter");
        /* TransportParameter ID and Length. */
        if (use_varint_encoding) {
            uint64_t parameter_length64;
            uint32_t type_len = 0;

            proto_tree_add_item_ret_varint(parameter_tree, hf->hf.hs_ext_quictp_parameter_type,
                                           tvb, offset, -1, ENC_VARINT_QUIC, &parameter_type, &type_len);
            offset += type_len;

            proto_tree_add_item_ret_varint(parameter_tree, hf->hf.hs_ext_quictp_parameter_len,
                                           tvb, offset, -1, ENC_VARINT_QUIC, &parameter_length64, &len);
            parameter_length = (uint32_t)parameter_length64;
            offset += len;

            proto_item_set_len(parameter_tree, type_len + len + parameter_length);
        } else {
            parameter_type = tvb_get_ntohs(tvb, offset);
            proto_tree_add_item(parameter_tree, hf->hf.hs_ext_quictp_parameter_type,
                                tvb, offset, 2, ENC_BIG_ENDIAN);
            offset += 2;

            /* opaque value<0..2^16-1> */
            if (!ssl_add_vector(hf, tvb, pinfo, parameter_tree, offset, next_offset, &parameter_length,
                                hf->hf.hs_ext_quictp_parameter_len_old, 0, UINT16_MAX)) {
                return next_offset;
            }
            offset += 2;

            proto_item_set_len(parameter_tree, 4 + parameter_length);
        }

        if (IS_GREASE_QUIC(parameter_type)) {
            proto_item_append_text(parameter_tree, ": GREASE");
        } else {
            proto_item_append_text(parameter_tree, ": %s", val64_to_str(parameter_type, quic_transport_parameter_id, "Unknown 0x%04x"));
        }

        proto_item_append_text(parameter_tree, " (len=%u)", parameter_length);
        parameter_end_offset = offset + parameter_length;

        proto_tree_add_item(parameter_tree, hf->hf.hs_ext_quictp_parameter_value,
                            tvb, offset, parameter_length, ENC_NA);

        switch (parameter_type) {
            case SSL_HND_QUIC_TP_ORIGINAL_DESTINATION_CONNECTION_ID:
                proto_tree_add_item(parameter_tree, hf->hf.hs_ext_quictp_parameter_original_destination_connection_id,
                                    tvb, offset, parameter_length, ENC_NA);
                offset += parameter_length;
            break;
            case SSL_HND_QUIC_TP_MAX_IDLE_TIMEOUT:
                proto_tree_add_item_ret_varint(parameter_tree, hf->hf.hs_ext_quictp_parameter_max_idle_timeout,
                                               tvb, offset, -1, ENC_VARINT_QUIC, &value, &len);
                proto_item_append_text(parameter_tree, " %" PRIu64 " ms", value);
                offset += len;
            break;
            case SSL_HND_QUIC_TP_STATELESS_RESET_TOKEN:
                proto_tree_add_item(parameter_tree, hf->hf.hs_ext_quictp_parameter_stateless_reset_token,
                                    tvb, offset, 16, ENC_BIG_ENDIAN);
                quic_add_stateless_reset_token(pinfo, tvb, offset, NULL);
                offset += 16;
            break;
            case SSL_HND_QUIC_TP_MAX_UDP_PAYLOAD_SIZE:
                proto_tree_add_item_ret_varint(parameter_tree, hf->hf.hs_ext_quictp_parameter_max_udp_payload_size,
                                               tvb, offset, -1, ENC_VARINT_QUIC, &value, &len);
                proto_item_append_text(parameter_tree, " %" PRIu64, value);
                /*TODO display expert info about invalid value (< 1252 or >65527) ? */
                offset += len;
            break;
            case SSL_HND_QUIC_TP_INITIAL_MAX_DATA:
                proto_tree_add_item_ret_varint(parameter_tree, hf->hf.hs_ext_quictp_parameter_initial_max_data,
                                               tvb, offset, -1, ENC_VARINT_QUIC, &value, &len);
                proto_item_append_text(parameter_tree, " %" PRIu64, value);
                offset += len;
            break;
            case SSL_HND_QUIC_TP_INITIAL_MAX_STREAM_DATA_BIDI_LOCAL:
                proto_tree_add_item_ret_varint(parameter_tree, hf->hf.hs_ext_quictp_parameter_initial_max_stream_data_bidi_local,
                                               tvb, offset, -1, ENC_VARINT_QUIC, &value, &len);
                proto_item_append_text(parameter_tree, " %" PRIu64, value);
                offset += len;
            break;
            case SSL_HND_QUIC_TP_INITIAL_MAX_STREAM_DATA_BIDI_REMOTE:
                proto_tree_add_item_ret_varint(parameter_tree, hf->hf.hs_ext_quictp_parameter_initial_max_stream_data_bidi_remote,
                                               tvb, offset, -1, ENC_VARINT_QUIC, &value, &len);
                proto_item_append_text(parameter_tree, " %" PRIu64, value);
                offset += len;
            break;
            case SSL_HND_QUIC_TP_INITIAL_MAX_STREAM_DATA_UNI:
                proto_tree_add_item_ret_varint(parameter_tree, hf->hf.hs_ext_quictp_parameter_initial_max_stream_data_uni,
                                               tvb, offset, -1, ENC_VARINT_QUIC, &value, &len);
                proto_item_append_text(parameter_tree, " %" PRIu64, value);
                offset += len;
            break;
            case SSL_HND_QUIC_TP_INITIAL_MAX_STREAMS_UNI:
                proto_tree_add_item_ret_varint(parameter_tree, hf->hf.hs_ext_quictp_parameter_initial_max_streams_uni,
                                               tvb, offset, -1, ENC_VARINT_QUIC, &value, &len);
                proto_item_append_text(parameter_tree, " %" PRIu64, value);
                offset += len;
            break;
            case SSL_HND_QUIC_TP_INITIAL_MAX_STREAMS_BIDI:
                proto_tree_add_item_ret_varint(parameter_tree, hf->hf.hs_ext_quictp_parameter_initial_max_streams_bidi,
                                               tvb, offset, -1, ENC_VARINT_QUIC, &value, &len);
                proto_item_append_text(parameter_tree, " %" PRIu64, value);
                offset += len;
            break;
            case SSL_HND_QUIC_TP_ACK_DELAY_EXPONENT:
                proto_tree_add_item_ret_varint(parameter_tree, hf->hf.hs_ext_quictp_parameter_ack_delay_exponent,
                                               tvb, offset, -1, ENC_VARINT_QUIC, NULL, &len);
                /*TODO display multiplier (x8) and expert info about invalid value (> 20) ? */
                offset += len;
            break;
            case SSL_HND_QUIC_TP_MAX_ACK_DELAY:
                proto_tree_add_item_ret_varint(parameter_tree, hf->hf.hs_ext_quictp_parameter_max_ack_delay,
                                               tvb, offset, -1, ENC_VARINT_QUIC, &value, &len);
                proto_item_append_text(parameter_tree, " %" PRIu64, value);
                offset += len;
            break;
            case SSL_HND_QUIC_TP_DISABLE_ACTIVE_MIGRATION:
                /* No Payload */
            break;
            case SSL_HND_QUIC_TP_PREFERRED_ADDRESS: {
                uint32_t connectionid_length;
                quic_cid_t cid;

                proto_tree_add_item(parameter_tree, hf->hf.hs_ext_quictp_parameter_pa_ipv4address,
                                    tvb, offset, 4, ENC_BIG_ENDIAN);
                offset += 4;
                proto_tree_add_item(parameter_tree, hf->hf.hs_ext_quictp_parameter_pa_ipv4port,
                                    tvb, offset, 2, ENC_BIG_ENDIAN);
                offset += 2;
                proto_tree_add_item(parameter_tree, hf->hf.hs_ext_quictp_parameter_pa_ipv6address,
                                    tvb, offset, 16, ENC_NA);
                offset += 16;
                proto_tree_add_item(parameter_tree, hf->hf.hs_ext_quictp_parameter_pa_ipv6port,
                                    tvb, offset, 2, ENC_BIG_ENDIAN);
                offset += 2;

                if (!ssl_add_vector(hf, tvb, pinfo, parameter_tree, offset, offset_end, &connectionid_length,
                                    hf->hf.hs_ext_quictp_parameter_pa_connectionid_length, 0, 20)) {
                    break;
                }
                offset += 1;

                proto_tree_add_item(parameter_tree, hf->hf.hs_ext_quictp_parameter_pa_connectionid,
                                    tvb, offset, connectionid_length, ENC_NA);
                if (connectionid_length >= 1 && connectionid_length <= QUIC_MAX_CID_LENGTH) {
                    cid.len = connectionid_length;
                    // RFC 9000 5.1.1 "If the preferred_address transport
                    // parameter is sent, the sequence number of the supplied
                    // connection ID is 1."
                    cid.seq_num = 1;
                    // Multipath draft-07 "Also, the Path Identifier for the
                    // connection ID specified in the "preferred address"
                    // transport parameter is 0."
                    cid.path_id = 0;
                    tvb_memcpy(tvb, cid.cid, offset, connectionid_length);
                    quic_add_connection(pinfo, &cid);
                }
                offset += connectionid_length;

                proto_tree_add_item(parameter_tree, hf->hf.hs_ext_quictp_parameter_pa_statelessresettoken,
                                    tvb, offset, 16, ENC_NA);
                if (connectionid_length >= 1 && connectionid_length <= QUIC_MAX_CID_LENGTH) {
                    quic_add_stateless_reset_token(pinfo, tvb, offset, &cid);
                }
                offset += 16;
            }
            break;
            case SSL_HND_QUIC_TP_ACTIVE_CONNECTION_ID_LIMIT:
                proto_tree_add_item_ret_varint(parameter_tree, hf->hf.hs_ext_quictp_parameter_active_connection_id_limit,
                                               tvb, offset, -1, ENC_VARINT_QUIC, &value, &len);
                proto_item_append_text(parameter_tree, " %" PRIu64, value);
                offset += len;
            break;
            case SSL_HND_QUIC_TP_INITIAL_SOURCE_CONNECTION_ID:
                proto_tree_add_item(parameter_tree, hf->hf.hs_ext_quictp_parameter_initial_source_connection_id,
                                    tvb, offset, parameter_length, ENC_NA);
                offset += parameter_length;
            break;
            case SSL_HND_QUIC_TP_RETRY_SOURCE_CONNECTION_ID:
                proto_tree_add_item(parameter_tree, hf->hf.hs_ext_quictp_parameter_retry_source_connection_id,
                                    tvb, offset, parameter_length, ENC_NA);
                offset += parameter_length;
            break;
            case SSL_HND_QUIC_TP_MAX_DATAGRAM_FRAME_SIZE:
                proto_tree_add_item_ret_varint(parameter_tree, hf->hf.hs_ext_quictp_parameter_max_datagram_frame_size,
                                               tvb, offset, -1, ENC_VARINT_QUIC, &value, &len);
                proto_item_append_text(parameter_tree, " %" PRIu64, value);
                offset += len;
            break;
            case SSL_HND_QUIC_TP_CIBIR_ENCODING:
                proto_tree_add_item_ret_varint(parameter_tree, hf->hf.hs_ext_quictp_parameter_cibir_encoding_length,
                                               tvb, offset, -1, ENC_VARINT_QUIC, &value, &len);
                proto_item_append_text(parameter_tree, " Length: %" PRIu64, value);
                offset += len;
                proto_tree_add_item_ret_varint(parameter_tree, hf->hf.hs_ext_quictp_parameter_cibir_encoding_offset,
                                               tvb, offset, -1, ENC_VARINT_QUIC, &value, &len);
                proto_item_append_text(parameter_tree, ", Offset: %" PRIu64, value);
                offset += len;
            break;
            case SSL_HND_QUIC_TP_LOSS_BITS:
                proto_tree_add_item_ret_varint(parameter_tree, hf->hf.hs_ext_quictp_parameter_loss_bits,
                                               tvb, offset, -1, ENC_VARINT_QUIC, &value, &len);
                if (len > 0) {
                    quic_add_loss_bits(pinfo, value);
                }
                offset += 1;
            break;
            case SSL_HND_QUIC_TP_MIN_ACK_DELAY_OLD:
            case SSL_HND_QUIC_TP_MIN_ACK_DELAY_DRAFT_V1:
            case SSL_HND_QUIC_TP_MIN_ACK_DELAY_DRAFT05:
            case SSL_HND_QUIC_TP_MIN_ACK_DELAY:
                proto_tree_add_item_ret_varint(parameter_tree, hf->hf.hs_ext_quictp_parameter_min_ack_delay,
                                               tvb, offset, -1, ENC_VARINT_QUIC, &value, &len);
                proto_item_append_text(parameter_tree, " %" PRIu64, value);
                offset += len;
            break;
            case SSL_HND_QUIC_TP_GOOGLE_USER_AGENT:
                proto_tree_add_item(parameter_tree, hf->hf.hs_ext_quictp_parameter_google_user_agent_id,
                                    tvb, offset, parameter_length, ENC_ASCII|ENC_NA);
                offset += parameter_length;
            break;
            case SSL_HND_QUIC_TP_GOOGLE_KEY_UPDATE_NOT_YET_SUPPORTED:
                proto_tree_add_item(parameter_tree, hf->hf.hs_ext_quictp_parameter_google_key_update_not_yet_supported,
                                    tvb, offset, parameter_length, ENC_NA);
                offset += parameter_length;
            break;
            case SSL_HND_QUIC_TP_GOOGLE_QUIC_VERSION:
                proto_tree_add_item(parameter_tree, hf->hf.hs_ext_quictp_parameter_google_quic_version,
                                    tvb, offset, 4, ENC_BIG_ENDIAN);
                offset += 4;
                if (hnd_type == SSL_HND_ENCRYPTED_EXTENSIONS) { /* From server */
                    uint32_t versions_length;

                    proto_tree_add_item_ret_uint(parameter_tree, hf->hf.hs_ext_quictp_parameter_google_supported_versions_length,
                                                 tvb, offset, 1, ENC_NA, &versions_length);
                    offset += 1;
                    for (i = 0; i < versions_length / 4; i++) {
                        quic_proto_tree_add_version(tvb, parameter_tree,
                                                    hf->hf.hs_ext_quictp_parameter_google_supported_version, offset);
                        offset += 4;
                    }
                }
            break;
            case SSL_HND_QUIC_TP_GOOGLE_INITIAL_RTT:
                proto_tree_add_item_ret_varint(parameter_tree, hf->hf.hs_ext_quictp_parameter_google_initial_rtt,
                                               tvb, offset, -1, ENC_VARINT_QUIC, &value, &len);
                proto_item_append_text(parameter_tree, " %" PRIu64 " us", value);
                offset += len;
            break;
            case SSL_HND_QUIC_TP_GOOGLE_SUPPORT_HANDSHAKE_DONE:
                proto_tree_add_item(parameter_tree, hf->hf.hs_ext_quictp_parameter_google_support_handshake_done,
                                    tvb, offset, parameter_length, ENC_NA);
                offset += parameter_length;
            break;
            case SSL_HND_QUIC_TP_GOOGLE_QUIC_PARAMS:
                /* This field was used for non-standard Google-specific parameters encoded as a
                 * Google QUIC_CRYPTO CHLO and it has been replaced (version >= T051) by individual
                 * parameters. Report it as a bytes blob... */
                proto_tree_add_item(parameter_tree, hf->hf.hs_ext_quictp_parameter_google_quic_params,
                                    tvb, offset, parameter_length, ENC_NA);
                /* ... and try decoding it: not sure what the first 4 bytes are (but they seems to be always 0) */
                proto_tree_add_item(parameter_tree, hf->hf.hs_ext_quictp_parameter_google_quic_params_unknown_field,
                                    tvb, offset, 4, ENC_NA);
                dissect_gquic_tags(tvb, pinfo, parameter_tree, offset + 4);
                offset += parameter_length;
            break;
            case SSL_HND_QUIC_TP_GOOGLE_CONNECTION_OPTIONS:
                proto_tree_add_item(parameter_tree, hf->hf.hs_ext_quictp_parameter_google_connection_options,
                                    tvb, offset, parameter_length, ENC_NA);
                offset += parameter_length;
            break;
            case SSL_HND_QUIC_TP_ENABLE_TIME_STAMP:
                /* No Payload */
            break;
            case SSL_HND_QUIC_TP_ENABLE_TIME_STAMP_V2:
                proto_tree_add_item_ret_varint(parameter_tree, hf->hf.hs_ext_quictp_parameter_enable_time_stamp_v2,
                                               tvb, offset, -1, ENC_VARINT_QUIC, &value, &len);
                offset += parameter_length;
            break;
            case SSL_HND_QUIC_TP_VERSION_INFORMATION:
                quic_proto_tree_add_version(tvb, parameter_tree,
                                            hf->hf.hs_ext_quictp_parameter_chosen_version, offset);
                offset += 4;
                for (i = 4; i < parameter_length; i += 4) {
                    quic_proto_tree_add_version(tvb, parameter_tree,
                                                hf->hf.hs_ext_quictp_parameter_other_version, offset);
                    offset += 4;
                }
            break;
            case SSL_HND_QUIC_TP_GREASE_QUIC_BIT:
                /* No Payload */
                quic_add_grease_quic_bit(pinfo);
            break;
            case SSL_HND_QUIC_TP_FACEBOOK_PARTIAL_RELIABILITY:
                proto_tree_add_item_ret_varint(parameter_tree, hf->hf.hs_ext_quictp_parameter_facebook_partial_reliability,
                                               tvb, offset, -1, ENC_VARINT_QUIC, &value, &len);
                offset += parameter_length;
            break;
            case SSL_HND_QUIC_TP_ENABLE_MULTIPATH_DRAFT04:
                proto_tree_add_item_ret_varint(parameter_tree, hf->hf.hs_ext_quictp_parameter_enable_multipath,
                                               tvb, offset, -1, ENC_VARINT_QUIC, &value, &len);
                if (value == 1) {
                    quic_add_multipath(pinfo, QUIC_MP_NO_PATH_ID);
                }
                offset += parameter_length;
            break;
            case SSL_HND_QUIC_TP_ENABLE_MULTIPATH_DRAFT05:
            case SSL_HND_QUIC_TP_ENABLE_MULTIPATH:
                /* No Payload */
                quic_add_multipath(pinfo, QUIC_MP_NO_PATH_ID);
            break;
            case SSL_HND_QUIC_TP_INITIAL_MAX_PATHS:
                proto_tree_add_item_ret_varint(parameter_tree, hf->hf.hs_ext_quictp_parameter_initial_max_paths,
                                               tvb, offset, -1, ENC_VARINT_QUIC, &value, &len);
                if (value > 1) {
                    quic_add_multipath(pinfo, QUIC_MP_PATH_ID);
                }
                /* multipath draft-07: "The value of the initial_max_paths
                 * parameter MUST be at least 2." TODO: Expert Info? */
                offset += parameter_length;
            break;
            case SSL_HND_QUIC_TP_INITIAL_MAX_PATH_ID:
                proto_tree_add_item_ret_varint(parameter_tree, hf->hf.hs_ext_quictp_parameter_initial_max_path_id,
                                               tvb, offset, -1, ENC_VARINT_QUIC, &value, &len);
                if (value > 1) {
                    quic_add_multipath(pinfo, QUIC_MP_PATH_ID);
                }
                offset += parameter_length;
            break;
            default:
                offset += parameter_length;
                /*TODO display expert info about unknown ? */
            break;
        }

        if (!ssl_end_vector(hf, tvb, pinfo, parameter_tree, offset, parameter_end_offset)) {
            /* Dissection did not end at expected location, fix it. */
            offset = parameter_end_offset;
        }
    }

    return offset;
}

static int
ssl_dissect_hnd_hello_common(ssl_common_dissect_t *hf, tvbuff_t *tvb,
                             proto_tree *tree, uint32_t offset,
                             SslSession *session, SslDecryptSession *ssl,
                             bool from_server, bool is_hrr)
{
    uint8_t      sessid_length;
    proto_tree  *rnd_tree;
    proto_tree  *ti_rnd;
    uint8_t      draft_version = session->tls13_draft_version;

    if (ssl) {
        StringInfo *rnd;
        if (from_server)
            rnd = &ssl->server_random;
        else
            rnd = &ssl->client_random;

        /* save provided random for later keyring generation */
        tvb_memcpy(tvb, rnd->data, offset, 32);
        rnd->data_len = 32;
        if (from_server)
            ssl->state |= SSL_SERVER_RANDOM;
        else
            ssl->state |= SSL_CLIENT_RANDOM;
        ssl_debug_printf("%s found %s RANDOM -> state 0x%02X\n", G_STRFUNC,
                from_server ? "SERVER" : "CLIENT", ssl->state);
    }

    ti_rnd = proto_tree_add_item(tree, hf->hf.hs_random, tvb, offset, 32, ENC_NA);

    if ((session->version != TLSV1DOT3_VERSION) && (session->version != DTLSV1DOT3_VERSION)) { /* No time on first bytes random with TLS 1.3 */

        rnd_tree = proto_item_add_subtree(ti_rnd, hf->ett.hs_random);
        /* show the time */
        proto_tree_add_item(rnd_tree, hf->hf.hs_random_time,
                tvb, offset, 4, ENC_TIME_SECS|ENC_BIG_ENDIAN);
        offset += 4;

        /* show the random bytes */
        proto_tree_add_item(rnd_tree, hf->hf.hs_random_bytes,
                tvb, offset, 28, ENC_NA);
        offset += 28;
    } else {
        if (is_hrr) {
            proto_item_append_text(ti_rnd, " (HelloRetryRequest magic)");
        }

        offset += 32;
    }

    /* No Session ID with TLS 1.3 on Server Hello before draft -22 */
    if (from_server == 0 || !(session->version == TLSV1DOT3_VERSION && draft_version > 0 && draft_version < 22)) {
        /* show the session id (length followed by actual Session ID) */
        sessid_length = tvb_get_uint8(tvb, offset);
        proto_tree_add_item(tree, hf->hf.hs_session_id_len,
                tvb, offset, 1, ENC_BIG_ENDIAN);
        offset++;

        if (ssl) {
            /* save the authoritative SID for later use in ChangeCipherSpec.
             * (D)TLS restricts the SID to 32 chars, it does not make sense to
             * save more, so ignore larger ones. */
            if (from_server && sessid_length <= 32) {
                tvb_memcpy(tvb, ssl->session_id.data, offset, sessid_length);
                ssl->session_id.data_len = sessid_length;
            }
        }
        if (sessid_length > 0) {
            proto_tree_add_item(tree, hf->hf.hs_session_id,
                    tvb, offset, sessid_length, ENC_NA);
            offset += sessid_length;
        }
    }

    return offset;
}

static int
ssl_dissect_hnd_hello_ext_status_request(ssl_common_dissect_t *hf, tvbuff_t *tvb, packet_info *pinfo,
                                         proto_tree *tree, uint32_t offset, uint32_t offset_end,
                                         bool has_length)
{
    /* TLS 1.2/1.3 status_request Client Hello Extension.
     * TLS 1.2 status_request_v2 CertificateStatusRequestItemV2 type.
     * https://tools.ietf.org/html/rfc6066#section-8 (status_request)
     * https://tools.ietf.org/html/rfc6961#section-2.2 (status_request_v2)
     *  struct {
     *      CertificateStatusType status_type;
     *      uint16 request_length;  // for status_request_v2
     *      select (status_type) {
     *          case ocsp: OCSPStatusRequest;
     *          case ocsp_multi: OCSPStatusRequest;
     *      } request;
     *  } CertificateStatusRequest; // CertificateStatusRequestItemV2
     *
     *  enum { ocsp(1), ocsp_multi(2), (255) } CertificateStatusType;
     *  struct {
     *      ResponderID responder_id_list<0..2^16-1>;
     *      Extensions  request_extensions;
     *  } OCSPStatusRequest;
     *  opaque ResponderID<1..2^16-1>;
     *  opaque Extensions<0..2^16-1>;
     */
    unsigned cert_status_type;

    cert_status_type = tvb_get_uint8(tvb, offset);
    proto_tree_add_item(tree, hf->hf.hs_ext_cert_status_type,
                        tvb, offset, 1, ENC_NA);
    offset++;

    if (has_length) {
        proto_tree_add_item(tree, hf->hf.hs_ext_cert_status_request_len,
                            tvb, offset, 2, ENC_BIG_ENDIAN);
        offset += 2;
    }

    switch (cert_status_type) {
    case SSL_HND_CERT_STATUS_TYPE_OCSP:
    case SSL_HND_CERT_STATUS_TYPE_OCSP_MULTI:
        {
            uint32_t     responder_id_list_len;
            uint32_t     request_extensions_len;

            /* ResponderID responder_id_list<0..2^16-1> */
            if (!ssl_add_vector(hf, tvb, pinfo, tree, offset, offset_end, &responder_id_list_len,
                                hf->hf.hs_ext_cert_status_responder_id_list_len, 0, UINT16_MAX)) {
                return offset_end;
            }
            offset += 2;
            if (responder_id_list_len != 0) {
                proto_tree_add_expert_format(tree, pinfo, &hf->ei.hs_ext_cert_status_undecoded,
                                             tvb, offset, responder_id_list_len,
                                       "Responder ID list is not implemented, contact Wireshark"
                                       " developers if you want this to be supported");
            }
            offset += responder_id_list_len;

            /* opaque Extensions<0..2^16-1> */
            if (!ssl_add_vector(hf, tvb, pinfo, tree, offset, offset_end, &request_extensions_len,
                                hf->hf.hs_ext_cert_status_request_extensions_len, 0, UINT16_MAX)) {
                return offset_end;
            }
            offset += 2;
            if (request_extensions_len != 0) {
                proto_tree_add_expert_format(tree, pinfo, &hf->ei.hs_ext_cert_status_undecoded,
                                             tvb, offset, request_extensions_len,
                                       "Request Extensions are not implemented, contact"
                                       " Wireshark developers if you want this to be supported");
            }
            offset += request_extensions_len;
            break;
        }
    }

    return offset;
}

static unsigned
ssl_dissect_hnd_hello_ext_status_request_v2(ssl_common_dissect_t *hf, tvbuff_t *tvb, packet_info *pinfo,
                                            proto_tree *tree, uint32_t offset, uint32_t offset_end)
{
    /* https://tools.ietf.org/html/rfc6961#section-2.2
     *  struct {
     *    CertificateStatusRequestItemV2 certificate_status_req_list<1..2^16-1>;
     *  } CertificateStatusRequestListV2;
     */
    uint32_t req_list_length, next_offset;

    /* CertificateStatusRequestItemV2 certificate_status_req_list<1..2^16-1> */
    if (!ssl_add_vector(hf, tvb, pinfo, tree, offset, offset_end, &req_list_length,
                        hf->hf.hs_ext_cert_status_request_list_len, 1, UINT16_MAX)) {
        return offset_end;
    }
    offset += 2;
    next_offset = offset + req_list_length;

    while (offset < next_offset) {
        offset = ssl_dissect_hnd_hello_ext_status_request(hf, tvb, pinfo, tree, offset, next_offset, true);
    }

    return offset;
}

static uint32_t
tls_dissect_ocsp_response(ssl_common_dissect_t *hf, tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,
                          uint32_t offset, uint32_t offset_end)
{
    uint32_t    response_length;
    proto_item *ocsp_resp;
    proto_tree *ocsp_resp_tree;
    asn1_ctx_t  asn1_ctx;

    /* opaque OCSPResponse<1..2^24-1>; */
    if (!ssl_add_vector(hf, tvb, pinfo, tree, offset, offset_end, &response_length,
                        hf->hf.hs_ocsp_response_len, 1, G_MAXUINT24)) {
        return offset_end;
    }
    offset += 3;

    ocsp_resp = proto_tree_add_item(tree, proto_ocsp, tvb, offset,
                                    response_length, ENC_BIG_ENDIAN);
    proto_item_set_text(ocsp_resp, "OCSP Response");
    ocsp_resp_tree = proto_item_add_subtree(ocsp_resp, hf->ett.ocsp_response);
    if (proto_is_protocol_enabled(find_protocol_by_id(proto_ocsp))) {
        asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, true, pinfo);
        dissect_ocsp_OCSPResponse(false, tvb, offset, &asn1_ctx, ocsp_resp_tree, -1);
    }
    offset += response_length;

    return offset;
}

uint32_t
tls_dissect_hnd_certificate_status(ssl_common_dissect_t *hf, tvbuff_t *tvb, packet_info *pinfo,
                                   proto_tree *tree, uint32_t offset, uint32_t offset_end)
{
    /* TLS 1.2 "CertificateStatus" handshake message.
     * TLS 1.3 "status_request" Certificate extension.
     *  struct {
     *    CertificateStatusType status_type;
     *    select (status_type) {
     *      case ocsp: OCSPResponse;
     *      case ocsp_multi: OCSPResponseList;  // status_request_v2
     *    } response;
     *  } CertificateStatus;
     *  opaque OCSPResponse<1..2^24-1>;
     *  struct {
     *    OCSPResponse ocsp_response_list<1..2^24-1>;
     *  } OCSPResponseList;                     // status_request_v2
     */
    uint32_t    status_type, resp_list_length, next_offset;

    proto_tree_add_item_ret_uint(tree, hf->hf.hs_ext_cert_status_type,
                                 tvb, offset, 1, ENC_BIG_ENDIAN, &status_type);
    offset += 1;

    switch (status_type) {
    case SSL_HND_CERT_STATUS_TYPE_OCSP:
        offset = tls_dissect_ocsp_response(hf, tvb, pinfo, tree, offset, offset_end);
        break;

    case SSL_HND_CERT_STATUS_TYPE_OCSP_MULTI:
        /* OCSPResponse ocsp_response_list<1..2^24-1> */
        if (!ssl_add_vector(hf, tvb, pinfo, tree, offset, offset_end, &resp_list_length,
                            hf->hf.hs_ocsp_response_list_len, 1, G_MAXUINT24)) {
            return offset_end;
        }
        offset += 3;
        next_offset = offset + resp_list_length;

        while (offset < next_offset) {
            offset = tls_dissect_ocsp_response(hf, tvb, pinfo, tree, offset, next_offset);
        }
        break;
    }

    return offset;
}

static unsigned
ssl_dissect_hnd_hello_ext_supported_groups(ssl_common_dissect_t *hf, tvbuff_t *tvb, packet_info *pinfo,
                                           proto_tree *tree, uint32_t offset, uint32_t offset_end,
                                           wmem_strbuf_t *ja3)
{
    /* RFC 8446 Section 4.2.7
     *  enum { ..., (0xFFFF) } NamedGroup;
     *  struct {
     *      NamedGroup named_group_list<2..2^16-1>
     *  } NamedGroupList;
     *
     * NOTE: "NamedCurve" (RFC 4492) is renamed to "NamedGroup" (RFC 7919) and
     * the extension itself from "elliptic_curves" to "supported_groups".
     */
    uint32_t    groups_length, next_offset;
    proto_tree *groups_tree;
    proto_item *ti;
    char       *ja3_dash = "";

    /* NamedGroup named_group_list<2..2^16-1> */
    if (!ssl_add_vector(hf, tvb, pinfo, tree, offset, offset_end, &groups_length,
                        hf->hf.hs_ext_supported_groups_len, 2, UINT16_MAX)) {
        return offset_end;
    }
    offset += 2;
    next_offset = offset + groups_length;

    ti = proto_tree_add_none_format(tree,
                                    hf->hf.hs_ext_supported_groups,
                                    tvb, offset, groups_length,
                                    "Supported Groups (%d group%s)",
                                    groups_length / 2,
                                    plurality(groups_length/2, "", "s"));

    /* make this a subtree */
    groups_tree = proto_item_add_subtree(ti, hf->ett.hs_ext_groups);

    if (ja3) {
        wmem_strbuf_append_c(ja3, ',');
    }
    /* loop over all groups */
    while (offset + 2 <= offset_end) {
        uint32_t    ext_supported_group;

        proto_tree_add_item_ret_uint(groups_tree, hf->hf.hs_ext_supported_group, tvb, offset, 2,
                                     ENC_BIG_ENDIAN, &ext_supported_group);
        offset += 2;
        if (ja3 && !IS_GREASE_TLS(ext_supported_group)) {
            wmem_strbuf_append_printf(ja3, "%s%i",ja3_dash, ext_supported_group);
            ja3_dash = "-";
        }
    }
    if (!ssl_end_vector(hf, tvb, pinfo, groups_tree, offset, next_offset)) {
        offset = next_offset;
    }

    return offset;
}

static int
ssl_dissect_hnd_hello_ext_ec_point_formats(ssl_common_dissect_t *hf, tvbuff_t *tvb,
                                           proto_tree *tree, uint32_t offset, wmem_strbuf_t *ja3)
{
    uint8_t     ecpf_length;
    proto_tree *ecpf_tree;
    proto_item *ti;

    ecpf_length = tvb_get_uint8(tvb, offset);
    proto_tree_add_item(tree, hf->hf.hs_ext_ec_point_formats_len,
        tvb, offset, 1, ENC_BIG_ENDIAN);

    offset += 1;
    ti = proto_tree_add_none_format(tree,
                                    hf->hf.hs_ext_ec_point_formats,
                                    tvb, offset, ecpf_length,
                                    "Elliptic curves point formats (%d)",
                                    ecpf_length);

    /* make this a subtree */
    ecpf_tree = proto_item_add_subtree(ti, hf->ett.hs_ext_curves_point_formats);

    if (ja3) {
        wmem_strbuf_append_c(ja3, ',');
    }

    /* loop over all point formats */
    while (ecpf_length > 0)
    {
        uint32_t    ext_ec_point_format;

        proto_tree_add_item_ret_uint(ecpf_tree, hf->hf.hs_ext_ec_point_format, tvb, offset, 1,
                                     ENC_BIG_ENDIAN, &ext_ec_point_format);
        offset++;
        ecpf_length--;
        if (ja3) {
            wmem_strbuf_append_printf(ja3, "%i", ext_ec_point_format);
            if (ecpf_length > 0) {
                wmem_strbuf_append_c(ja3, '-');
            }
        }
    }

    return offset;
}

static int
ssl_dissect_hnd_hello_ext_srp(ssl_common_dissect_t *hf, tvbuff_t *tvb,
                               packet_info *pinfo, proto_tree *tree,
                               uint32_t offset, uint32_t next_offset)
{
    /* https://tools.ietf.org/html/rfc5054#section-2.8.1
     *  opaque srp_I<1..2^8-1>;
     */
    uint32_t username_len;

    if (!ssl_add_vector(hf, tvb, pinfo, tree, offset, next_offset, &username_len,
                        hf->hf.hs_ext_srp_len, 1, UINT8_MAX)) {
        return next_offset;
    }
    offset++;

    proto_tree_add_item(tree, hf->hf.hs_ext_srp_username,
                        tvb, offset, username_len, ENC_UTF_8|ENC_NA);
    offset += username_len;

    return offset;
}

static uint32_t
tls_dissect_sct(ssl_common_dissect_t *hf, tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,
                uint32_t offset, uint32_t offset_end, uint16_t version)
{
    /* https://tools.ietf.org/html/rfc6962#section-3.2
     *  enum { v1(0), (255) } Version;
     *  struct {
     *      opaque key_id[32];
     *  } LogID;
     *  opaque CtExtensions<0..2^16-1>;
     *  struct {
     *      Version sct_version;
     *      LogID id;
     *      uint64 timestamp;
     *      CtExtensions extensions;
     *      digitally-signed struct { ... };
     *  } SignedCertificateTimestamp;
     */
    uint32_t    sct_version;
    uint64_t    sct_timestamp_ms;
    nstime_t    sct_timestamp;
    uint32_t    exts_len;
    const char *log_name;

    proto_tree_add_item_ret_uint(tree, hf->hf.sct_sct_version, tvb, offset, 1, ENC_NA, &sct_version);
    offset++;
    if (sct_version != 0) {
        // TODO expert info about unknown SCT version?
        return offset;
    }
    proto_tree_add_item(tree, hf->hf.sct_sct_logid, tvb, offset, 32, ENC_BIG_ENDIAN);
    log_name = bytesval_to_str(tvb_get_ptr(tvb, offset, 32), 32, ct_logids, "Unknown Log");
    proto_item_append_text(tree, " (%s)", log_name);
    offset += 32;
    sct_timestamp_ms = tvb_get_ntoh64(tvb, offset);
    sct_timestamp.secs  = (time_t)(sct_timestamp_ms / 1000);
    sct_timestamp.nsecs = (int)((sct_timestamp_ms % 1000) * 1000000);
    proto_tree_add_time(tree, hf->hf.sct_sct_timestamp, tvb, offset, 8, &sct_timestamp);
    offset += 8;
    /* opaque CtExtensions<0..2^16-1> */
    if (!ssl_add_vector(hf, tvb, pinfo, tree, offset, offset_end, &exts_len,
                        hf->hf.sct_sct_extensions_length, 0, UINT16_MAX)) {
        return offset_end;
    }
    offset += 2;
    if (exts_len > 0) {
        proto_tree_add_item(tree, hf->hf.sct_sct_extensions, tvb, offset, exts_len, ENC_BIG_ENDIAN);
        offset += exts_len;
    }
    offset = ssl_dissect_digitally_signed(hf, tvb, pinfo, tree, offset, offset_end, version,
                                          hf->hf.sct_sct_signature_length,
                                          hf->hf.sct_sct_signature);
    return offset;
}

uint32_t
tls_dissect_sct_list(ssl_common_dissect_t *hf, tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,
                     uint32_t offset, uint32_t offset_end, uint16_t version)
{
    /* https://tools.ietf.org/html/rfc6962#section-3.3
     *  opaque SerializedSCT<1..2^16-1>;
     *  struct {
     *      SerializedSCT sct_list <1..2^16-1>;
     *  } SignedCertificateTimestampList;
     */
    uint32_t    list_length, sct_length, next_offset;
    proto_tree *subtree;

    /* SerializedSCT sct_list <1..2^16-1> */
    if (!ssl_add_vector(hf, tvb, pinfo, tree, offset, offset_end, &list_length,
                        hf->hf.sct_scts_length, 1, UINT16_MAX)) {
        return offset_end;
    }
    offset += 2;

    while (offset < offset_end) {
        subtree = proto_tree_add_subtree(tree, tvb, offset, 2, hf->ett.sct, NULL, "Signed Certificate Timestamp");

        /* opaque SerializedSCT<1..2^16-1> */
        if (!ssl_add_vector(hf, tvb, pinfo, subtree, offset, offset_end, &sct_length,
                            hf->hf.sct_sct_length, 1, UINT16_MAX)) {
            return offset_end;
        }
        offset += 2;
        next_offset = offset + sct_length;
        proto_item_set_len(subtree, 2 + sct_length);
        offset = tls_dissect_sct(hf, tvb, pinfo, subtree, offset, next_offset, version);
        if (!ssl_end_vector(hf, tvb, pinfo, subtree, offset, next_offset)) {
            offset = next_offset;
        }
    }

    return offset;
}

static int
dissect_ech_hpke_cipher_suite(ssl_common_dissect_t *hf, tvbuff_t *tvb, packet_info *pinfo _U_,
                              proto_tree *tree, uint32_t offset)
{
    uint32_t kdf_id, aead_id;
    proto_item *cs_ti;
    proto_tree *cs_tree;

    cs_ti = proto_tree_add_item(tree, hf->hf.ech_hpke_keyconfig_cipher_suite,
                                tvb, offset, 4, ENC_NA);
    cs_tree = proto_item_add_subtree(cs_ti, hf->ett.ech_hpke_cipher_suite);

    proto_tree_add_item_ret_uint(cs_tree, hf->hf.ech_hpke_keyconfig_cipher_suite_kdf_id,
                                 tvb, offset, 2, ENC_BIG_ENDIAN, &kdf_id);
    offset += 2;
    proto_tree_add_item_ret_uint(cs_tree, hf->hf.ech_hpke_keyconfig_cipher_suite_aead_id,
                                 tvb, offset, 2, ENC_BIG_ENDIAN, &aead_id);
    offset += 2;

    proto_item_append_text(cs_ti, ": %s/%s",
                           val_to_str_const(kdf_id, kdf_id_type_vals, "Unknown"),
                           val_to_str_const(aead_id, aead_id_type_vals, "Unknown"));
    return offset;
}

static int
dissect_ech_hpke_key_config(ssl_common_dissect_t *hf, tvbuff_t *tvb, packet_info *pinfo,
                            proto_tree *tree, uint32_t offset, uint32_t offset_end,
                            uint32_t *config_id)
{
    uint32_t length, cipher_suite_length;
    proto_item *kc_ti, *css_ti;
    proto_tree *kc_tree, *css_tree;
    uint32_t original_offset = offset, next_offset;

    kc_ti = proto_tree_add_item(tree, hf->hf.ech_hpke_keyconfig,
                                tvb, offset, -1, ENC_NA);
    kc_tree = proto_item_add_subtree(kc_ti, hf->ett.ech_hpke_keyconfig);

    proto_tree_add_item_ret_uint(kc_tree, hf->hf.ech_hpke_keyconfig_config_id,
                                 tvb, offset, 1, ENC_BIG_ENDIAN, config_id);
    offset += 1;
    proto_tree_add_item(kc_tree, hf->hf.ech_hpke_keyconfig_kem_id,
                        tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;
    proto_tree_add_item_ret_uint(kc_tree, hf->hf.ech_hpke_keyconfig_public_key_length,
                                 tvb, offset, 2, ENC_BIG_ENDIAN, &length);
    offset += 2;
    proto_tree_add_item(kc_tree, hf->hf.ech_hpke_keyconfig_public_key,
                        tvb, offset, length, ENC_NA);
    offset += length;

    /* HpkeSymmetricCipherSuite cipher_suites<4..2^16-4> */
    if (!ssl_add_vector(hf, tvb, pinfo, kc_tree, offset, offset_end, &cipher_suite_length,
                        hf->hf.ech_hpke_keyconfig_cipher_suites_length, 4, UINT16_MAX - 3)) {
        return offset_end;
    }
    offset += 2;
    next_offset = offset + cipher_suite_length;

    css_ti = proto_tree_add_none_format(kc_tree,
                                        hf->hf.ech_hpke_keyconfig_cipher_suites,
                                        tvb, offset, cipher_suite_length,
                                        "Cipher Suites (%d suite%s)",
                                        cipher_suite_length / 4,
                                        plurality(cipher_suite_length / 4, "", "s"));
    css_tree = proto_item_add_subtree(css_ti, hf->ett.ech_hpke_cipher_suites);


    while (offset + 4 <= next_offset) {
        offset = dissect_ech_hpke_cipher_suite(hf, tvb, pinfo, css_tree, offset);
    }

    if (!ssl_end_vector(hf, tvb, pinfo, css_tree, offset, next_offset)) {
        offset = next_offset;
    }

    proto_item_set_len(kc_ti, offset - original_offset);

    return offset;
}

static int
dissect_ech_echconfig_contents(ssl_common_dissect_t *hf, tvbuff_t *tvb, packet_info *pinfo,
                               proto_tree *tree, uint32_t offset, uint32_t offset_end,
                               const uint8_t **public_name, uint32_t *config_id)
{
    uint32_t public_name_length, extensions_length, next_offset;

    offset = dissect_ech_hpke_key_config(hf, tvb, pinfo, tree, offset, offset_end, config_id);
    proto_tree_add_item(tree, hf->hf.ech_echconfigcontents_maximum_name_length,
                        tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;
    proto_tree_add_item_ret_uint(tree, hf->hf.ech_echconfigcontents_public_name_length,
                                 tvb, offset, 1, ENC_BIG_ENDIAN, &public_name_length);
    offset += 1;
    proto_tree_add_item_ret_string(tree, hf->hf.ech_echconfigcontents_public_name,
                                   tvb, offset, public_name_length, ENC_ASCII, pinfo->pool, public_name);
    offset += public_name_length;

    /* Extension extensions<0..2^16-1>; */
    if (!ssl_add_vector(hf, tvb, pinfo, tree, offset, offset_end, &extensions_length,
                        hf->hf.ech_echconfigcontents_extensions_length, 0, UINT16_MAX)) {
        return offset_end;
    }
    offset += 2;
    next_offset = offset + extensions_length;

    if (extensions_length > 0) {
        proto_tree_add_item(tree, hf->hf.ech_echconfigcontents_extensions,
                            tvb, offset, extensions_length, ENC_NA);
    }
    offset += extensions_length;

    if (!ssl_end_vector(hf, tvb, pinfo, tree, offset, next_offset)) {
        offset = next_offset;
    }

    return offset;
}

static int
dissect_ech_echconfig(ssl_common_dissect_t *hf, tvbuff_t *tvb, packet_info *pinfo,
                      proto_tree *tree, uint32_t offset, uint32_t offset_end)
{
    uint32_t version, length;
    proto_item *ech_ti;
    proto_tree *ech_tree;
    const uint8_t *public_name = NULL;
    uint32_t config_id = 0;

    ech_ti = proto_tree_add_item(tree, hf->hf.ech_echconfig, tvb, offset, -1, ENC_NA);
    ech_tree = proto_item_add_subtree(ech_ti, hf->ett.ech_echconfig);

    proto_tree_add_item_ret_uint(ech_tree, hf->hf.ech_echconfig_version,
                                 tvb, offset, 2, ENC_BIG_ENDIAN, &version);
    offset += 2;
    proto_tree_add_item_ret_uint(ech_tree, hf->hf.ech_echconfig_length,
                                 tvb, offset, 2, ENC_BIG_ENDIAN, &length);
    offset += 2;

    proto_item_set_len(ech_ti, 4 + length);

    switch(version) {
      case 0xfe0d:
        dissect_ech_echconfig_contents(hf, tvb, pinfo, ech_tree, offset, offset_end, &public_name, &config_id);
        proto_item_append_text(ech_ti, ": id=%d %s", config_id, public_name);
        break;

      default:
        expert_add_info_format(pinfo, ech_ti, &hf->ei.ech_echconfig_invalid_version, "Unsupported/unknown ECHConfig version 0x%x", version);
    }

    return 4 + length;
}

uint32_t
ssl_dissect_ext_ech_echconfiglist(ssl_common_dissect_t *hf, tvbuff_t *tvb, packet_info *pinfo,
                                  proto_tree *tree, uint32_t offset, uint32_t offset_end)
{
    uint32_t echconfiglist_length, next_offset;

    /* ECHConfig ECHConfigList<1..2^16-1>; */
    if (!ssl_add_vector(hf, tvb, pinfo, tree, offset, offset_end, &echconfiglist_length,
                        hf->hf.ech_echconfiglist_length, 1, UINT16_MAX)) {
        return offset_end;
    }
    offset += 2;
    next_offset = offset + echconfiglist_length;

    while (offset < next_offset) {
        offset += dissect_ech_echconfig(hf, tvb, pinfo, tree, offset, offset_end);
    }

    if (!ssl_end_vector(hf, tvb, pinfo, tree, offset, next_offset)) {
        offset = next_offset;
    }

    return offset;
}

static uint32_t
ssl_dissect_hnd_hello_ext_ech(ssl_common_dissect_t *hf, tvbuff_t *tvb _U_, packet_info *pinfo,
                              proto_tree *tree, uint32_t offset, uint32_t offset_end,
                              uint8_t hnd_type, SslDecryptSession *ssl _U_)
{
    uint32_t ch_type, length;
    proto_item *retry_ti;
    proto_tree *retry_tree;

    switch (hnd_type) {
    case SSL_HND_CLIENT_HELLO:
        /*
         *  enum { outer(0), inner(1) } ECHClientHelloType;
         *
         *  struct {
         *     ECHClientHelloType type;
         *     select (ECHClientHello.type) {
         *         case outer:
         *             HpkeSymmetricCipherSuite cipher_suite;
         *             uint8 config_id;
         *             opaque enc<0..2^16-1>;
         *             opaque payload<1..2^16-1>;
         *         case inner:
         *             Empty;
         *     };
         *  } ECHClientHello;
         */

        proto_tree_add_item_ret_uint(tree, hf->hf.ech_clienthello_type, tvb, offset, 1, ENC_BIG_ENDIAN, &ch_type);
        offset += 1;
        switch (ch_type) {
        case 0: /* outer */
            offset = dissect_ech_hpke_cipher_suite(hf, tvb, pinfo, tree, offset);

            proto_tree_add_item(tree, hf->hf.ech_config_id, tvb, offset, 1, ENC_BIG_ENDIAN);
            offset += 1;
            proto_tree_add_item_ret_uint(tree, hf->hf.ech_enc_length, tvb, offset, 2, ENC_BIG_ENDIAN, &length);
            offset += 2;
            proto_tree_add_item(tree, hf->hf.ech_enc, tvb, offset, length, ENC_NA);
            offset += length;
            proto_tree_add_item_ret_uint(tree, hf->hf.ech_payload_length, tvb, offset, 2, ENC_BIG_ENDIAN, &length);
            offset += 2;
            proto_tree_add_item(tree, hf->hf.ech_payload, tvb, offset, length, ENC_NA);
            offset += length;
            break;
        case 1: /* inner */
            /* We will never be here, unless we are going to have support
               for extracting the ephemeral secrets from endpoints */
            break; /* Nothing to do, data is encrypted */
        }
        break;

    case SSL_HND_ENCRYPTED_EXTENSIONS:
        /*
         * struct {
         *     ECHConfigList retry_configs;
         * } ECHEncryptedExtensions;
         */

        retry_ti = proto_tree_add_item(tree, hf->hf.ech_retry_configs, tvb, offset, offset_end - offset, ENC_NA);
        retry_tree = proto_item_add_subtree(retry_ti, hf->ett.ech_retry_configs);
        offset = ssl_dissect_ext_ech_echconfiglist(hf, tvb, pinfo, retry_tree, offset, offset_end);
        break;

    case SSL_HND_HELLO_RETRY_REQUEST:
        /*
         * struct {
         *     opaque confirmation[8];
         * } ECHHelloRetryRequest;
         */

        proto_tree_add_item(tree, hf->hf.ech_confirmation, tvb, offset, 8, ENC_NA);
        offset += 8;
        break;
    }

    return offset;
}

static uint32_t
ssl_dissect_hnd_hello_ext_esni(ssl_common_dissect_t *hf, tvbuff_t *tvb, packet_info *pinfo,
                               proto_tree *tree, uint32_t offset, uint32_t offset_end,
                               uint8_t hnd_type, SslDecryptSession *ssl _U_)
{
    uint32_t record_digest_length, encrypted_sni_length;

    switch (hnd_type) {
    case SSL_HND_CLIENT_HELLO:
        /*
         * struct {
         *     CipherSuite suite;
         *     KeyShareEntry key_share;
         *     opaque record_digest<0..2^16-1>;
         *     opaque encrypted_sni<0..2^16-1>;
         * } ClientEncryptedSNI;
         */
        proto_tree_add_item(tree, hf->hf.esni_suite, tvb, offset, 2, ENC_BIG_ENDIAN);
        offset += 2;
        offset = ssl_dissect_hnd_hello_ext_key_share_entry(hf, tvb, pinfo, tree, offset, offset_end, NULL);

        /* opaque record_digest<0..2^16-1> */
        if (!ssl_add_vector(hf, tvb, pinfo, tree, offset, offset_end, &record_digest_length,
                            hf->hf.esni_record_digest_length, 0, UINT16_MAX)) {
            return offset_end;
        }
        offset += 2;
        if (record_digest_length > 0) {
            proto_tree_add_item(tree, hf->hf.esni_record_digest, tvb, offset, record_digest_length, ENC_NA);
            offset += record_digest_length;
        }

        /* opaque encrypted_sni<0..2^16-1> */
        if (!ssl_add_vector(hf, tvb, pinfo, tree, offset, offset_end, &encrypted_sni_length,
                            hf->hf.esni_encrypted_sni_length, 0, UINT16_MAX)) {
            return offset_end;
        }
        offset += 2;
        if (encrypted_sni_length > 0) {
            proto_tree_add_item(tree, hf->hf.esni_encrypted_sni, tvb, offset, encrypted_sni_length, ENC_NA);
            offset += encrypted_sni_length;
        }
        break;

    case SSL_HND_ENCRYPTED_EXTENSIONS:
        proto_tree_add_item(tree, hf->hf.esni_nonce, tvb, offset, 16, ENC_NA);
        offset += 16;
        break;
    }

    return offset;
}
/** TLS Extensions (in Client Hello and Server Hello). }}} */

/* Connection ID dissection. {{{ */
static uint32_t
ssl_dissect_ext_connection_id(ssl_common_dissect_t *hf, tvbuff_t *tvb, packet_info *pinfo,
                              proto_tree *tree, uint32_t offset, SslDecryptSession *ssl,
                              uint8_t cidl, uint8_t **session_cid, uint8_t *session_cidl)
{
    /* keep track of the decrypt session only for the first pass */
    if (cidl > 0 && !PINFO_FD_VISITED(pinfo)) {
      tvb_ensure_bytes_exist(tvb, offset + 1, cidl);
      *session_cidl = cidl;
      *session_cid = (uint8_t*)wmem_alloc0(wmem_file_scope(), cidl);
      tvb_memcpy(tvb, *session_cid, offset + 1, cidl);
      if (ssl) {
          ssl_add_session_by_cid(ssl);
      }
    }

    proto_tree_add_item(tree, hf->hf.hs_ext_connection_id_length,
                        tvb, offset, 1, ENC_NA);
    offset++;

    if (cidl > 0) {
        proto_tree_add_item(tree, hf->hf.hs_ext_connection_id,
                            tvb, offset, cidl, ENC_NA);
        offset += cidl;
    }

    return offset;
}

static uint32_t
ssl_dissect_hnd_hello_ext_connection_id(ssl_common_dissect_t *hf, tvbuff_t *tvb, packet_info *pinfo,
                                        proto_tree *tree, uint32_t offset, uint8_t hnd_type,
                                        SslSession *session, SslDecryptSession *ssl)
{
    uint8_t cidl = tvb_get_uint8(tvb, offset);

    switch (hnd_type) {
    case SSL_HND_CLIENT_HELLO:
        session->client_cid_len_present = true;
        return ssl_dissect_ext_connection_id(hf, tvb, pinfo, tree, offset, ssl,
                                             cidl, &session->client_cid, &session->client_cid_len);
    case SSL_HND_SERVER_HELLO:
        session->server_cid_len_present = true;
        return ssl_dissect_ext_connection_id(hf, tvb, pinfo, tree, offset, ssl,
                                             cidl, &session->server_cid, &session->server_cid_len);
    default:
        return offset;
    }
} /* }}} */

/* Whether the Content and Handshake Types are valid; handle Protocol Version. {{{ */
bool
ssl_is_valid_content_type(uint8_t type)
{
    switch ((ContentType) type) {
    case SSL_ID_CHG_CIPHER_SPEC:
    case SSL_ID_ALERT:
    case SSL_ID_HANDSHAKE:
    case SSL_ID_APP_DATA:
    case SSL_ID_HEARTBEAT:
    case SSL_ID_TLS12_CID:
    case SSL_ID_DTLS13_ACK:
        return true;
    }
    return false;
}

bool
ssl_is_valid_handshake_type(uint8_t hs_type, bool is_dtls)
{
    switch ((HandshakeType) hs_type) {
    case SSL_HND_HELLO_VERIFY_REQUEST:
        /* hello_verify_request is DTLS-only */
        return is_dtls;

    case SSL_HND_HELLO_REQUEST:
    case SSL_HND_CLIENT_HELLO:
    case SSL_HND_SERVER_HELLO:
    case SSL_HND_NEWSESSION_TICKET:
    case SSL_HND_END_OF_EARLY_DATA:
    case SSL_HND_HELLO_RETRY_REQUEST:
    case SSL_HND_ENCRYPTED_EXTENSIONS:
    case SSL_HND_CERTIFICATE:
    case SSL_HND_SERVER_KEY_EXCHG:
    case SSL_HND_CERT_REQUEST:
    case SSL_HND_SVR_HELLO_DONE:
    case SSL_HND_CERT_VERIFY:
    case SSL_HND_CLIENT_KEY_EXCHG:
    case SSL_HND_FINISHED:
    case SSL_HND_CERT_URL:
    case SSL_HND_CERT_STATUS:
    case SSL_HND_SUPPLEMENTAL_DATA:
    case SSL_HND_KEY_UPDATE:
    case SSL_HND_COMPRESSED_CERTIFICATE:
    case SSL_HND_ENCRYPTED_EXTS:
        return true;
    }
    return false;
}

static bool
ssl_is_authoritative_version_message(uint8_t content_type, uint8_t handshake_type,
                                     bool is_dtls)
{
    /* Consider all valid Handshake messages (except for Client Hello) and
     * all other valid record types (other than Handshake) */
    return (content_type == SSL_ID_HANDSHAKE &&
            ssl_is_valid_handshake_type(handshake_type, is_dtls) &&
            handshake_type != SSL_HND_CLIENT_HELLO) ||
           (content_type != SSL_ID_HANDSHAKE &&
            ssl_is_valid_content_type(content_type));
}

/**
 * Scan a Server Hello handshake message for the negotiated version. For TLS 1.3
 * draft 22 and newer, it also checks whether it is a HelloRetryRequest.
 * Returns true if the supported_versions extension was found, false if not.
 */
bool
tls_scan_server_hello(tvbuff_t *tvb, uint32_t offset, uint32_t offset_end,
                      uint16_t *server_version, bool *is_hrr)
{
    /* SHA256("HelloRetryRequest") */
    static const uint8_t tls13_hrr_random_magic[] = {
        0xcf, 0x21, 0xad, 0x74, 0xe5, 0x9a, 0x61, 0x11, 0xbe, 0x1d, 0x8c, 0x02, 0x1e, 0x65, 0xb8, 0x91,
        0xc2, 0xa2, 0x11, 0x16, 0x7a, 0xbb, 0x8c, 0x5e, 0x07, 0x9e, 0x09, 0xe2, 0xc8, 0xa8, 0x33, 0x9c
    };
    uint8_t session_id_length;

    *server_version = tvb_get_ntohs(tvb, offset);

    /*
     * Try to look for supported_versions extension. Minimum length:
     * 2 + 32 + 1 = 35 (version, random, session id length)
     * 2 + 1 + 2 = 5 (cipher suite, compression method, extensions length)
     * 2 + 2 + 2 = 6 (ext type, ext len, version)
     *
     * We only check for the [legacy_]version field to be [D]TLS 1.2; if it's 1.3,
     * there's a separate expert info warning for that.
     */
    if ((*server_version == TLSV1DOT2_VERSION || *server_version == DTLSV1DOT2_VERSION) && offset_end - offset >= 46) {
        offset += 2;
        if (is_hrr) {
            *is_hrr = tvb_memeql(tvb, offset, tls13_hrr_random_magic, sizeof(tls13_hrr_random_magic)) == 0;
        }
        offset += 32;
        session_id_length = tvb_get_uint8(tvb, offset);
        offset++;
        if (offset_end - offset < session_id_length + 5u) {
            return false;
        }
        offset += session_id_length + 5;

        while (offset_end - offset >= 6) {
            uint16_t ext_type = tvb_get_ntohs(tvb, offset);
            uint16_t ext_len = tvb_get_ntohs(tvb, offset + 2);
            if (offset_end - offset < 4u + ext_len) {
                break;  /* not enough data for type, length and data */
            }
            if (ext_type == SSL_HND_HELLO_EXT_SUPPORTED_VERSIONS) {
                if (ext_len == 2) {
                    *server_version = tvb_get_ntohs(tvb, offset + 4);
                }
                return true;
            }
            offset += 4 + ext_len;
        }
    } else {
        if (is_hrr) {
            *is_hrr = false;
        }
    }
    return false;
}

/**
 * Scan a Client Hello handshake message to see if the supported_versions
 * extension is found, in which case the version field is legacy_version.
 */
static bool
tls_scan_client_hello(tvbuff_t *tvb, uint32_t offset, uint32_t offset_end)
{
    uint8_t session_id_length;

    uint16_t client_version = tvb_get_ntohs(tvb, offset);

    /*
     * Try to look for supported_versions extension. Minimum length:
     * 2 + 32 + 1 = 35 (version, random, session id length)
     * 2 + 2 + 1 + 2 = 5 (cipher suite, compression method, extensions length)
     * 2 + 2 + 2 = 6 (ext type, ext len, version)
     *
     * We only check for the [legacy_]version field to be [D]TLS 1.2; if it's 1.3,
     * there's a separate expert info warning for that.
     */
    if ((client_version == TLSV1DOT2_VERSION || client_version == DTLSV1DOT2_VERSION) && offset_end - offset >= 46) {
        offset += 2;
        offset += 32;
        session_id_length = tvb_get_uint8(tvb, offset);
        offset++;
        if (offset_end - offset < session_id_length + 2u) {
            return false;
        }
        offset += session_id_length;
        if (client_version == DTLSV1DOT2_VERSION) {
            uint8_t cookie_length = tvb_get_uint8(tvb, offset);
            offset++;
            if (offset_end - offset < cookie_length + 2u) {
                return false;
            }
        }
        uint16_t cipher_suites_length = tvb_get_ntohs(tvb, offset);
        offset += 2;
        if (offset_end - offset < cipher_suites_length + 1u) {
            return false;
        }
        offset += cipher_suites_length;
        uint8_t compression_methods_length = tvb_get_uint8(tvb, offset);
        offset++;
        if (offset_end - offset < compression_methods_length + 2u) {
            return false;
        }
        offset += compression_methods_length + 2;

        while (offset_end - offset >= 6) {
            uint16_t ext_type = tvb_get_ntohs(tvb, offset);
            uint16_t ext_len = tvb_get_ntohs(tvb, offset + 2);
            if (offset_end - offset < 4u + ext_len) {
                break;  /* not enough data for type, length and data */
            }
            if (ext_type == SSL_HND_HELLO_EXT_SUPPORTED_VERSIONS) {
                return true;
            }
            offset += 4 + ext_len;
        }
    }
    return false;
}
void
ssl_try_set_version(SslSession *session, SslDecryptSession *ssl,
                    uint8_t content_type, uint8_t handshake_type,
                    bool is_dtls, uint16_t version)
{
    uint8_t tls13_draft = 0;

    if (!ssl_is_authoritative_version_message(content_type, handshake_type,
                is_dtls))
        return;

    version = tls_try_get_version(is_dtls, version, &tls13_draft);
    if (version == SSL_VER_UNKNOWN) {
        return;
    }

    session->tls13_draft_version = tls13_draft;
    session->version = version;
    if (ssl) {
        ssl->state |= SSL_VERSION;
        ssl_debug_printf("%s found version 0x%04X -> state 0x%02X\n", G_STRFUNC, version, ssl->state);
    }
}

void
ssl_check_record_length(ssl_common_dissect_t *hf, packet_info *pinfo,
                        ContentType content_type,
                        unsigned record_length, proto_item *length_pi,
                        uint16_t version, tvbuff_t *decrypted_tvb)
{
    unsigned max_expansion;
    if (version == TLSV1DOT3_VERSION) {
        /* TLS 1.3: Max length is 2^14 + 256 */
        max_expansion = 256;
    } else {
        /* RFC 5246, Section 6.2.3: TLSCiphertext.fragment length MUST NOT exceed 2^14 + 2048 */
        max_expansion = 2048;
    }
    /*
     * RFC 5246 (TLS 1.2), Section 6.2.1 forbids zero-length Handshake, Alert
     * and ChangeCipherSpec.
     * RFC 6520 (Heartbeats) does not mention zero-length Heartbeat fragments,
     * so assume it is permitted.
     * RFC 6347 (DTLS 1.2) does not mention zero-length fragments either, so
     * assume TLS 1.2 requirements.
     */
    if (record_length == 0 &&
            (content_type == SSL_ID_CHG_CIPHER_SPEC ||
             content_type == SSL_ID_ALERT ||
             content_type == SSL_ID_HANDSHAKE)) {
        expert_add_info_format(pinfo, length_pi, &hf->ei.record_length_invalid,
                               "Zero-length %s fragments are not allowed",
                               val_to_str_const(content_type, ssl_31_content_type, "unknown"));
    }
    if (record_length > TLS_MAX_RECORD_LENGTH + max_expansion) {
        expert_add_info_format(pinfo, length_pi, &hf->ei.record_length_invalid,
                               "TLSCiphertext length MUST NOT exceed 2^14 + %u", max_expansion);
    }
    if (decrypted_tvb && tvb_captured_length(decrypted_tvb) > TLS_MAX_RECORD_LENGTH) {
        expert_add_info_format(pinfo, length_pi, &hf->ei.record_length_invalid,
                               "TLSPlaintext length MUST NOT exceed 2^14");
    }
}

static void
ssl_set_cipher(SslDecryptSession *ssl, uint16_t cipher)
{
    /* store selected cipher suite for decryption */
    ssl->session.cipher = cipher;

    const SslCipherSuite *cs = ssl_find_cipher(cipher);
    if (!cs) {
        ssl->cipher_suite = NULL;
        ssl->state &= ~SSL_CIPHER;
        ssl_debug_printf("%s can't find cipher suite 0x%04X\n", G_STRFUNC, cipher);
    } else if (ssl->session.version == SSLV3_VERSION && !(cs->dig == DIG_MD5 || cs->dig == DIG_SHA)) {
        /* A malicious packet capture contains a SSL 3.0 session using a TLS 1.2
         * cipher suite that uses for example MACAlgorithm SHA256. Reject that
         * to avoid a potential buffer overflow in ssl3_check_mac. */
        ssl->cipher_suite = NULL;
        ssl->state &= ~SSL_CIPHER;
        ssl_debug_printf("%s invalid SSL 3.0 cipher suite 0x%04X\n", G_STRFUNC, cipher);
    } else {
        /* Cipher found, save this for the delayed decoder init */
        ssl->cipher_suite = cs;
        ssl->state |= SSL_CIPHER;
        ssl_debug_printf("%s found CIPHER 0x%04X %s -> state 0x%02X\n", G_STRFUNC, cipher,
                         val_to_str_ext_const(cipher, &ssl_31_ciphersuite_ext, "unknown"),
                         ssl->state);
    }
}
/* }}} */


/* Client Hello and Server Hello dissections. {{{ */
static int
ssl_dissect_hnd_extension(ssl_common_dissect_t *hf, tvbuff_t *tvb, proto_tree *tree,
                          packet_info* pinfo, uint32_t offset, uint32_t offset_end, uint8_t hnd_type,
                          SslSession *session, SslDecryptSession *ssl,
                          bool is_dtls, wmem_strbuf_t *ja3, ja4_data_t *ja4_data);
void
ssl_dissect_hnd_cli_hello(ssl_common_dissect_t *hf, tvbuff_t *tvb,
                          packet_info *pinfo, proto_tree *tree, uint32_t offset,
                          uint32_t offset_end, SslSession *session,
                          SslDecryptSession *ssl, dtls_hfs_t *dtls_hfs)
{
    /* struct {
     *     ProtocolVersion client_version;
     *     Random random;
     *     SessionID session_id;
     *     opaque cookie<0..32>;                   //new field for DTLS
     *     CipherSuite cipher_suites<2..2^16-1>;
     *     CompressionMethod compression_methods<1..2^8-1>;
     *     Extension client_hello_extension_list<0..2^16-1>;
     * } ClientHello;
     */
    proto_item *ti;
    proto_tree *cs_tree;
    uint32_t    client_version;
    uint32_t    cipher_suite_length;
    uint32_t    compression_methods_length;
    uint8_t     compression_method;
    uint32_t    next_offset;
    wmem_strbuf_t *ja3 = wmem_strbuf_new(pinfo->pool, "");
    char       *ja3_hash;
    char       *ja3_dash = "";
    char       *ja4, *ja4_r, *ja4_hash, *ja4_b, *ja4_c;
    ja4_data_t  ja4_data;
    wmem_strbuf_t *ja4_a  = wmem_strbuf_new(pinfo->pool, "");
    wmem_strbuf_t *ja4_br = wmem_strbuf_new(pinfo->pool, "");
    wmem_strbuf_t *ja4_cr = wmem_strbuf_new(pinfo->pool, "");
    wmem_list_frame_t *curr_entry;

    ja4_data.max_version = 0;
    ja4_data.server_name_present = false;
    ja4_data.num_cipher_suites = 0;
    ja4_data.num_extensions = 0;
    ja4_data.alpn = wmem_strbuf_new(pinfo->pool, "");
    ja4_data.cipher_list = wmem_list_new(pinfo->pool);
    ja4_data.extension_list = wmem_list_new(pinfo->pool);
    ja4_data.sighash_list = wmem_list_new(pinfo->pool);

    /* show the client version */
    ti = proto_tree_add_item_ret_uint(tree, hf->hf.hs_client_version, tvb,
                                      offset, 2, ENC_BIG_ENDIAN,
                                      &client_version);
    if (tls_scan_client_hello(tvb, offset, offset_end)) {
        expert_add_info(pinfo, ti, &hf->ei.legacy_version);
    }
    offset += 2;
    wmem_strbuf_append_printf(ja3, "%i,", client_version);

    /*
     * Is it version 1.3?
     * If so, that's an error; TLS and DTLS 1.3 Client Hellos claim
     * to be TLS 1.2, and mention 1.3 in an extension.  See RFC 8446
     * section 4.1.2 "Client Hello" and RFC 9147 Section 5.3 "Client
     * Hello".
     */
    if (dtls_hfs != NULL) {
        if (client_version  == DTLSV1DOT3_VERSION) {
            /* Don't do that. */
            expert_add_info(pinfo, ti, &hf->ei.client_version_error);
        }
    } else {
        if (client_version == TLSV1DOT3_VERSION) {
            /* Don't do that. */
            expert_add_info(pinfo, ti, &hf->ei.client_version_error);
        }
    }

    /* dissect fields that are present in both ClientHello and ServerHello */
    offset = ssl_dissect_hnd_hello_common(hf, tvb, tree, offset, session, ssl, false, false);

    /* fields specific for DTLS (cookie_len, cookie) */
    if (dtls_hfs != NULL) {
        uint32_t cookie_length;
        /* opaque cookie<0..32> (for DTLS only) */
        if (!ssl_add_vector(hf, tvb, pinfo, tree, offset, offset_end, &cookie_length,
                            dtls_hfs->hf_dtls_handshake_cookie_len, 0, 32)) {
            return;
        }
        offset++;
        if (cookie_length > 0) {
            proto_tree_add_item(tree, dtls_hfs->hf_dtls_handshake_cookie,
                                tvb, offset, cookie_length, ENC_NA);
            offset += cookie_length;
        }
    }

    /* CipherSuite cipher_suites<2..2^16-1> */
    if (!ssl_add_vector(hf, tvb, pinfo, tree, offset, offset_end, &cipher_suite_length,
                        hf->hf.hs_cipher_suites_len, 2, UINT16_MAX)) {
        return;
    }
    offset += 2;
    next_offset = offset + cipher_suite_length;
    ti = proto_tree_add_none_format(tree,
                                    hf->hf.hs_cipher_suites,
                                    tvb, offset, cipher_suite_length,
                                    "Cipher Suites (%d suite%s)",
                                    cipher_suite_length / 2,
                                    plurality(cipher_suite_length/2, "", "s"));
    cs_tree = proto_item_add_subtree(ti, hf->ett.cipher_suites);
    while (offset + 2 <= next_offset) {
        uint32_t    cipher_suite;

        proto_tree_add_item_ret_uint(cs_tree, hf->hf.hs_cipher_suite, tvb, offset, 2,
                                     ENC_BIG_ENDIAN, &cipher_suite);
        offset += 2;
        if (!IS_GREASE_TLS(cipher_suite)) {
            wmem_strbuf_append_printf(ja3, "%s%i",ja3_dash, cipher_suite);
            ja3_dash = "-";
            ja4_data.num_cipher_suites += 1;
            wmem_list_insert_sorted(ja4_data.cipher_list, GUINT_TO_POINTER(cipher_suite), wmem_compare_uint);
        }
    }
    wmem_strbuf_append_c(ja3, ',');
    if (!ssl_end_vector(hf, tvb, pinfo, cs_tree, offset, next_offset)) {
        offset = next_offset;
    }

    /* CompressionMethod compression_methods<1..2^8-1> */
    if (!ssl_add_vector(hf, tvb, pinfo, tree, offset, offset_end, &compression_methods_length,
                        hf->hf.hs_comp_methods_len, 1, UINT8_MAX)) {
        return;
    }
    offset++;
    next_offset = offset + compression_methods_length;
    ti = proto_tree_add_none_format(tree,
                                    hf->hf.hs_comp_methods,
                                    tvb, offset, compression_methods_length,
                                    "Compression Methods (%u method%s)",
                                    compression_methods_length,
                                    plurality(compression_methods_length,
                                      "", "s"));
    cs_tree = proto_item_add_subtree(ti, hf->ett.comp_methods);
    while (offset < next_offset) {
        compression_method = tvb_get_uint8(tvb, offset);
        /* TODO: make reserved/private comp meth. fields selectable */
        if (compression_method < 64)
            proto_tree_add_uint(cs_tree, hf->hf.hs_comp_method,
                                tvb, offset, 1, compression_method);
        else if (compression_method > 63 && compression_method < 193)
            proto_tree_add_uint_format_value(cs_tree, hf->hf.hs_comp_method, tvb, offset, 1,
                                compression_method, "Reserved - to be assigned by IANA (%u)",
                                compression_method);
        else
            proto_tree_add_uint_format_value(cs_tree, hf->hf.hs_comp_method, tvb, offset, 1,
                                compression_method, "Private use range (%u)",
                                compression_method);
        offset++;
    }

    /* SSL v3.0 has no extensions, so length field can indeed be missing. */
    if (offset < offset_end) {
        ssl_dissect_hnd_extension(hf, tvb, tree, pinfo, offset,
                                  offset_end, SSL_HND_CLIENT_HELLO,
                                  session, ssl, dtls_hfs != NULL, ja3, &ja4_data);
        if (ja4_data.max_version > 0) {
            client_version = ja4_data.max_version;
        }
    } else {
        wmem_strbuf_append_printf(ja3, ",,");
    }

    if (proto_is_frame_protocol(pinfo->layers,"tcp")) {
        wmem_strbuf_append(ja4_a, "t");
    } else if (proto_is_frame_protocol(pinfo->layers,"quic")) {
        wmem_strbuf_append(ja4_a, "q");
    } else if (proto_is_frame_protocol(pinfo->layers,"dtls")) {
        wmem_strbuf_append(ja4_a, "d");
    }
    wmem_strbuf_append_printf(ja4_a, "%s", val_to_str_const(client_version, ssl_version_ja4_names, "00"));
    wmem_strbuf_append_printf(ja4_a, "%s", ja4_data.server_name_present ? "d" : "i");
    if (ja4_data.num_cipher_suites > 99) {
        wmem_strbuf_append(ja4_a, "99");
    } else {
        wmem_strbuf_append_printf(ja4_a, "%02d", ja4_data.num_cipher_suites);
    }
    if (ja4_data.num_extensions > 99) {
        wmem_strbuf_append(ja4_a, "99");
    } else {
        wmem_strbuf_append_printf(ja4_a, "%02d", ja4_data.num_extensions);
    }
    if (wmem_strbuf_get_len(ja4_data.alpn) > 0 ) {
        wmem_strbuf_append_printf(ja4_a, "%s", wmem_strbuf_get_str(ja4_data.alpn));
    } else {
        wmem_strbuf_append(ja4_a, "00");
    }

    curr_entry = wmem_list_head(ja4_data.cipher_list);
    for (unsigned i = 0; i < wmem_list_count(ja4_data.cipher_list); i++) {
        wmem_strbuf_append_printf(ja4_br, "%04x", GPOINTER_TO_UINT(wmem_list_frame_data(curr_entry)));
        if (i < wmem_list_count(ja4_data.cipher_list) - 1) {
            wmem_strbuf_append(ja4_br, ",");
        }
        curr_entry = wmem_list_frame_next(curr_entry);
    }

    curr_entry = wmem_list_head(ja4_data.extension_list);
    for (unsigned i = 0; i < wmem_list_count(ja4_data.extension_list); i++) {
        wmem_strbuf_append_printf(ja4_cr, "%04x", GPOINTER_TO_UINT(wmem_list_frame_data(curr_entry)));
        if (i < wmem_list_count(ja4_data.extension_list) - 1) {
            wmem_strbuf_append(ja4_cr, ",");
        }
        curr_entry = wmem_list_frame_next(curr_entry);
    }

    if (wmem_list_count(ja4_data.sighash_list) > 0) {
        wmem_strbuf_append(ja4_cr, "_");
        curr_entry = wmem_list_head(ja4_data.sighash_list);
        for (unsigned i = 0; i < wmem_list_count(ja4_data.sighash_list); i++) {
            wmem_strbuf_append_printf(ja4_cr, "%04x", GPOINTER_TO_UINT(wmem_list_frame_data(curr_entry)));
            if (i < wmem_list_count(ja4_data.sighash_list) - 1) {
                wmem_strbuf_append(ja4_cr, ",");
            }
            curr_entry = wmem_list_frame_next(curr_entry);
        }
    }
    ja4_hash = g_compute_checksum_for_string(G_CHECKSUM_SHA256, wmem_strbuf_get_str(ja4_br),-1);
    ja4_b = wmem_strndup(pinfo->pool, ja4_hash, 12);
    g_free(ja4_hash);
    ja4_hash = g_compute_checksum_for_string(G_CHECKSUM_SHA256, wmem_strbuf_get_str(ja4_cr),-1);
    ja4_c = wmem_strndup(pinfo->pool, ja4_hash, 12);
    g_free(ja4_hash);

    ja4 = wmem_strdup_printf(pinfo->pool, "%s_%s_%s", wmem_strbuf_get_str(ja4_a), ja4_b, ja4_c);
    ja4_r = wmem_strdup_printf(pinfo->pool, "%s_%s_%s", wmem_strbuf_get_str(ja4_a), wmem_strbuf_get_str(ja4_br), wmem_strbuf_get_str(ja4_cr));

    ti = proto_tree_add_string(tree, hf->hf.hs_ja4, tvb, offset, 0, ja4);
    proto_item_set_generated(ti);
    ti = proto_tree_add_string(tree, hf->hf.hs_ja4_r, tvb, offset, 0, ja4_r);
    proto_item_set_generated(ti);

    ja3_hash = g_compute_checksum_for_string(G_CHECKSUM_MD5, wmem_strbuf_get_str(ja3),
            wmem_strbuf_get_len(ja3));
    ti = proto_tree_add_string(tree, hf->hf.hs_ja3_full, tvb, offset, 0, wmem_strbuf_get_str(ja3));
    proto_item_set_generated(ti);
    ti = proto_tree_add_string(tree, hf->hf.hs_ja3_hash, tvb, offset, 0, ja3_hash);
    proto_item_set_generated(ti);
    g_free(ja3_hash);
}

void
ssl_dissect_hnd_srv_hello(ssl_common_dissect_t *hf, tvbuff_t *tvb,
                          packet_info* pinfo, proto_tree *tree, uint32_t offset, uint32_t offset_end,
                          SslSession *session, SslDecryptSession *ssl,
                          bool is_dtls, bool is_hrr)
{
    /* struct {
     *     ProtocolVersion server_version;
     *     Random random;
     *     SessionID session_id;                    // TLS 1.2 and before
     *     CipherSuite cipher_suite;
     *     CompressionMethod compression_method;    // TLS 1.2 and before
     *     Extension server_hello_extension_list<0..2^16-1>;
     * } ServerHello;
     */
    uint8_t draft_version = session->tls13_draft_version;
    proto_item *ti;
    uint32_t    server_version;
    uint32_t    cipher_suite;
    wmem_strbuf_t *ja3 = wmem_strbuf_new(pinfo->pool, "");
    char       *ja3_hash;

    col_set_str(pinfo->cinfo, COL_PROTOCOL,
                val_to_str_const(session->version, ssl_version_short_names, "SSL"));

    /* Initially assume that the session is resumed. If this is not the case, a
     * ServerHelloDone will be observed before the ChangeCipherSpec message
     * which will reset this flag. */
    session->is_session_resumed = true;

    /* show the server version */
    ti = proto_tree_add_item_ret_uint(tree, hf->hf.hs_server_version, tvb,
                        offset, 2, ENC_BIG_ENDIAN, &server_version);

    uint16_t supported_server_version;
    if (tls_scan_server_hello(tvb, offset, offset_end, &supported_server_version, NULL)) {
        expert_add_info(pinfo, ti, &hf->ei.legacy_version);
    }
    /*
     * Is it version 1.3?
     * If so, that's an error; TLS and DTLS 1.3 Server Hellos claim
     * to be TLS 1.2, and mention 1.3 in an extension.  See RFC 8446
     * section 4.1.3 "Server Hello" and RFC 9147 Section 5.4 "Server
     * Hello".
     */
    if (is_dtls) {
        if (server_version  == DTLSV1DOT3_VERSION) {
            /* Don't do that. */
            expert_add_info(pinfo, ti, &hf->ei.server_version_error);
        }
    } else {
        if (server_version == TLSV1DOT3_VERSION) {
            /* Don't do that. */
            expert_add_info(pinfo, ti, &hf->ei.server_version_error);
        }
    }

    offset += 2;
    wmem_strbuf_append_printf(ja3, "%i", server_version);

    /* dissect fields that are present in both ClientHello and ServerHello */
    offset = ssl_dissect_hnd_hello_common(hf, tvb, tree, offset, session, ssl, true, is_hrr);

    if (ssl) {
        /* store selected cipher suite for decryption */
        ssl_set_cipher(ssl, tvb_get_ntohs(tvb, offset));
    }

    /* now the server-selected cipher suite */
    proto_tree_add_item_ret_uint(tree, hf->hf.hs_cipher_suite,
                        tvb, offset, 2, ENC_BIG_ENDIAN, &cipher_suite);
    offset += 2;
    wmem_strbuf_append_printf(ja3, ",%i,", cipher_suite);

    /* No compression with TLS 1.3 before draft -22 */
    if (!(session->version == TLSV1DOT3_VERSION && draft_version > 0 && draft_version < 22)) {
        if (ssl) {
            /* store selected compression method for decryption */
            ssl->session.compression = tvb_get_uint8(tvb, offset);
        }
        /* and the server-selected compression method */
        proto_tree_add_item(tree, hf->hf.hs_comp_method,
                            tvb, offset, 1, ENC_BIG_ENDIAN);
        offset++;
    }

    /* SSL v3.0 has no extensions, so length field can indeed be missing. */
    if (offset < offset_end) {
        ssl_dissect_hnd_extension(hf, tvb, tree, pinfo, offset,
                                  offset_end,
                                  is_hrr ? SSL_HND_HELLO_RETRY_REQUEST : SSL_HND_SERVER_HELLO,
                                  session, ssl, is_dtls, ja3, NULL);
    }

    ja3_hash = g_compute_checksum_for_string(G_CHECKSUM_MD5, wmem_strbuf_get_str(ja3),
            wmem_strbuf_get_len(ja3));
    ti = proto_tree_add_string(tree, hf->hf.hs_ja3s_full, tvb, offset, 0, wmem_strbuf_get_str(ja3));
    proto_item_set_generated(ti);
    ti = proto_tree_add_string(tree, hf->hf.hs_ja3s_hash, tvb, offset, 0, ja3_hash);
    proto_item_set_generated(ti);
    g_free(ja3_hash);
}
/* Client Hello and Server Hello dissections. }}} */

/* New Session Ticket dissection. {{{ */
void
ssl_dissect_hnd_new_ses_ticket(ssl_common_dissect_t *hf, tvbuff_t *tvb, packet_info *pinfo,
                               proto_tree *tree, uint32_t offset, uint32_t offset_end,
                               SslSession *session, SslDecryptSession *ssl,
                               bool is_dtls, GHashTable *session_hash)
{
    /* https://tools.ietf.org/html/rfc5077#section-3.3 (TLS >= 1.0):
     *  struct {
     *      uint32 ticket_lifetime_hint;
     *      opaque ticket<0..2^16-1>;
     *  } NewSessionTicket;
     *
     * RFC 8446 Section 4.6.1 (TLS 1.3):
     *  struct {
     *      uint32 ticket_lifetime;
     *      uint32 ticket_age_add;
     *      opaque ticket_nonce<0..255>;    // new in draft -21, updated in -22
     *      opaque ticket<1..2^16-1>;
     *      Extension extensions<0..2^16-2>;
     *  } NewSessionTicket;
     */
    proto_tree *subtree;
    proto_item *subitem;
    uint32_t    ticket_len;
    bool        is_tls13 = session->version == TLSV1DOT3_VERSION || session->version == DTLSV1DOT3_VERSION;
    unsigned char      draft_version = session->tls13_draft_version;
    uint32_t    lifetime_hint;

    subtree = proto_tree_add_subtree(tree, tvb, offset, offset_end - offset,
                                     hf->ett.session_ticket, NULL,
                                     "TLS Session Ticket");

    /* ticket lifetime hint */
    subitem = proto_tree_add_item_ret_uint(subtree, hf->hf.hs_session_ticket_lifetime_hint,
                                           tvb, offset, 4, ENC_BIG_ENDIAN, &lifetime_hint);
    offset += 4;

    if (lifetime_hint >= 60) {
        char *time_str = unsigned_time_secs_to_str(pinfo->pool, lifetime_hint);
        proto_item_append_text(subitem, " (%s)", time_str);
    }

    if (is_tls13) {

        /* for TLS 1.3: ticket_age_add */
        proto_tree_add_item(subtree, hf->hf.hs_session_ticket_age_add,
                            tvb, offset, 4, ENC_BIG_ENDIAN);
        offset += 4;

        /* for TLS 1.3: ticket_nonce (coming with Draft 21)*/
        if (draft_version == 0 || draft_version >= 21) {
            uint32_t ticket_nonce_len;

            if (!ssl_add_vector(hf, tvb, pinfo, subtree, offset, offset_end, &ticket_nonce_len,
                                hf->hf.hs_session_ticket_nonce_len, 0, 255)) {
                return;
            }
            offset++;

            proto_tree_add_item(subtree, hf->hf.hs_session_ticket_nonce, tvb, offset, ticket_nonce_len, ENC_NA);
            offset += ticket_nonce_len;
        }

    }

    /* opaque ticket<0..2^16-1> (with TLS 1.3 the minimum is 1) */
    if (!ssl_add_vector(hf, tvb, pinfo, subtree, offset, offset_end, &ticket_len,
                        hf->hf.hs_session_ticket_len, is_tls13 ? 1 : 0, UINT16_MAX)) {
        return;
    }
    offset += 2;

    /* Content depends on implementation, so just show data! */
    proto_tree_add_item(subtree, hf->hf.hs_session_ticket,
                        tvb, offset, ticket_len, ENC_NA);
    /* save the session ticket to cache for ssl_finalize_decryption */
    if (ssl && !is_tls13) {
        tvb_ensure_bytes_exist(tvb, offset, ticket_len);
        ssl->session_ticket.data = (unsigned char*)wmem_realloc(wmem_file_scope(),
                                    ssl->session_ticket.data, ticket_len);
        ssl->session_ticket.data_len = ticket_len;
        tvb_memcpy(tvb, ssl->session_ticket.data, offset, ticket_len);
        /* NewSessionTicket is received after the first (client)
         * ChangeCipherSpec, and before the second (server) ChangeCipherSpec.
         * Since the second CCS has already the session key available it will
         * just return. To ensure that the session ticket is mapped to a
         * master key (from the first CCS), save the ticket here too. */
        ssl_save_master_key("Session Ticket", session_hash,
                            &ssl->session_ticket, &ssl->master_secret);
        ssl->state |= SSL_NEW_SESSION_TICKET;
    }
    offset += ticket_len;

    if (is_tls13) {
        ssl_dissect_hnd_extension(hf, tvb, subtree, pinfo, offset,
                                  offset_end, SSL_HND_NEWSESSION_TICKET,
                                  session, ssl, is_dtls, NULL, NULL);
    }
} /* }}} */

void
ssl_dissect_hnd_hello_retry_request(ssl_common_dissect_t *hf, tvbuff_t *tvb,
                                    packet_info* pinfo, proto_tree *tree, uint32_t offset, uint32_t offset_end,
                                    SslSession *session, SslDecryptSession *ssl,
                                    bool is_dtls)
{
    /* https://tools.ietf.org/html/draft-ietf-tls-tls13-19#section-4.1.4
     * struct {
     *     ProtocolVersion server_version;
     *     CipherSuite cipher_suite;        // not before draft -19
     *     Extension extensions<2..2^16-1>;
     * } HelloRetryRequest;
     * Note: no longer used since draft -22
     */
    uint32_t    version;
    uint8_t     draft_version;

    proto_tree_add_item_ret_uint(tree, hf->hf.hs_server_version, tvb,
                                 offset, 2, ENC_BIG_ENDIAN, &version);
    draft_version = extract_tls13_draft_version(version);
    offset += 2;

    if (draft_version == 0 || draft_version >= 19) {
        proto_tree_add_item(tree, hf->hf.hs_cipher_suite,
                            tvb, offset, 2, ENC_BIG_ENDIAN);
        offset += 2;
    }

    ssl_dissect_hnd_extension(hf, tvb, tree, pinfo, offset,
                              offset_end, SSL_HND_HELLO_RETRY_REQUEST,
                              session, ssl, is_dtls, NULL, NULL);
}

void
ssl_dissect_hnd_encrypted_extensions(ssl_common_dissect_t *hf, tvbuff_t *tvb,
                                     packet_info* pinfo, proto_tree *tree, uint32_t offset, uint32_t offset_end,
                                     SslSession *session, SslDecryptSession *ssl,
                                     bool is_dtls)
{
    /* RFC 8446 Section 4.3.1
     * struct {
     *     Extension extensions<0..2^16-1>;
     * } EncryptedExtensions;
     */
    ssl_dissect_hnd_extension(hf, tvb, tree, pinfo, offset,
                              offset_end, SSL_HND_ENCRYPTED_EXTENSIONS,
                              session, ssl, is_dtls, NULL, NULL);
}

/* Certificate and Certificate Request dissections. {{{ */
void
ssl_dissect_hnd_cert(ssl_common_dissect_t *hf, tvbuff_t *tvb, proto_tree *tree,
                     uint32_t offset, uint32_t offset_end, packet_info *pinfo,
                     SslSession *session, SslDecryptSession *ssl _U_,
                     bool is_from_server, bool is_dtls)
{
    /* opaque ASN.1Cert<1..2^24-1>;
     *
     * Before RFC 8446 (TLS <= 1.2):
     *  struct {
     *     select(certificate_type) {
     *
     *         // certificate type defined in RFC 7250
     *         case RawPublicKey:
     *           opaque ASN.1_subjectPublicKeyInfo<1..2^24-1>;
     *
     *         // X.509 certificate defined in RFC 5246
     *         case X.509:
     *           ASN.1Cert certificate_list<0..2^24-1>;
     *     };
     *  } Certificate;
     *
     * RFC 8446 (since draft -20):
     *  struct {
     *      select(certificate_type){
     *          case RawPublicKey:
     *            // From RFC 7250 ASN.1_subjectPublicKeyInfo
     *            opaque ASN1_subjectPublicKeyInfo<1..2^24-1>;
     *
     *          case X.509:
     *            opaque cert_data<1..2^24-1>;
     *      }
     *      Extension extensions<0..2^16-1>;
     *  } CertificateEntry;
     *  struct {
     *      opaque certificate_request_context<0..2^8-1>;
     *      CertificateEntry certificate_list<0..2^24-1>;
     *  } Certificate;
     */
    enum { CERT_X509, CERT_RPK } cert_type;
    asn1_ctx_t  asn1_ctx;
#if defined(HAVE_LIBGNUTLS)
    gnutls_datum_t subjectPublicKeyInfo = { NULL, 0 };
    unsigned    certificate_index = 0;
#endif
    uint32_t    next_offset, certificate_list_length, cert_length;
    proto_tree *subtree = tree;

    asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, true, pinfo);

    if ((is_from_server && session->server_cert_type == SSL_HND_CERT_TYPE_RAW_PUBLIC_KEY) ||
        (!is_from_server && session->client_cert_type == SSL_HND_CERT_TYPE_RAW_PUBLIC_KEY)) {
        cert_type = CERT_RPK;
    } else {
        cert_type = CERT_X509;
    }

#if defined(HAVE_LIBGNUTLS)
    /* Ask the pkcs1 dissector to return the public key details */
    if (ssl)
        asn1_ctx.private_data = &subjectPublicKeyInfo;
#endif

    /* TLS 1.3: opaque certificate_request_context<0..2^8-1> */
    if (session->version == TLSV1DOT3_VERSION || session->version == DTLSV1DOT3_VERSION) {
        uint32_t context_length;
        if (!ssl_add_vector(hf, tvb, pinfo, tree, offset, offset_end, &context_length,
                            hf->hf.hs_certificate_request_context_length, 0, UINT8_MAX)) {
            return;
        }
        offset++;
        if (context_length > 0) {
            proto_tree_add_item(tree, hf->hf.hs_certificate_request_context,
                                tvb, offset, context_length, ENC_NA);
            offset += context_length;
        }
    }

    if ((session->version != TLSV1DOT3_VERSION && session->version != DTLSV1DOT3_VERSION) && cert_type == CERT_RPK) {
        /* For RPK before TLS 1.3, the single RPK is stored directly without
         * another "certificate_list" field. */
        certificate_list_length = offset_end - offset;
        next_offset = offset_end;
    } else {
        /* CertificateEntry certificate_list<0..2^24-1> */
        if (!ssl_add_vector(hf, tvb, pinfo, tree, offset, offset_end, &certificate_list_length,
                            hf->hf.hs_certificates_len, 0, G_MAXUINT24)) {
            return;
        }
        offset += 3;            /* 24-bit length value */
        next_offset = offset + certificate_list_length;
    }

    /* RawPublicKey must have one cert, but X.509 can have multiple. */
    if (certificate_list_length > 0 && cert_type == CERT_X509) {
        proto_item *ti;

        ti = proto_tree_add_none_format(tree,
                                        hf->hf.hs_certificates,
                                        tvb, offset, certificate_list_length,
                                        "Certificates (%u bytes)",
                                        certificate_list_length);

        /* make it a subtree */
        subtree = proto_item_add_subtree(ti, hf->ett.certificates);
    }

    while (offset < next_offset) {
        switch (cert_type) {
        case CERT_RPK:
            /* TODO add expert info if there is more than one RPK entry (certificate_index > 0) */
            /* opaque ASN.1_subjectPublicKeyInfo<1..2^24-1> */
            if (!ssl_add_vector(hf, tvb, pinfo, subtree, offset, next_offset, &cert_length,
                                hf->hf.hs_certificate_len, 1, G_MAXUINT24)) {
                return;
            }
            offset += 3;

            dissect_x509af_SubjectPublicKeyInfo(false, tvb, offset, &asn1_ctx, subtree, hf->hf.hs_certificate);
            offset += cert_length;
            break;
        case CERT_X509:
            /* opaque ASN1Cert<1..2^24-1> */
            if (!ssl_add_vector(hf, tvb, pinfo, subtree, offset, next_offset, &cert_length,
                                hf->hf.hs_certificate_len, 1, G_MAXUINT24)) {
                return;
            }
            offset += 3;

            dissect_x509af_Certificate(false, tvb, offset, &asn1_ctx, subtree, hf->hf.hs_certificate);
#if defined(HAVE_LIBGNUTLS)
            if (is_from_server && ssl && certificate_index == 0) {
                ssl_find_private_key_by_pubkey(ssl, &subjectPublicKeyInfo);
                /* Only attempt to get the RSA modulus for the first cert. */
                asn1_ctx.private_data = NULL;
            }
#endif
            offset += cert_length;
            break;
        }

        /* TLS 1.3: Extension extensions<0..2^16-1> */
        if ((session->version == TLSV1DOT3_VERSION || session->version == DTLSV1DOT3_VERSION)) {
            offset = ssl_dissect_hnd_extension(hf, tvb, subtree, pinfo, offset,
                                               next_offset, SSL_HND_CERTIFICATE,
                                               session, ssl, is_dtls, NULL, NULL);
        }

#if defined(HAVE_LIBGNUTLS)
        certificate_index++;
#endif
    }
}

void
ssl_dissect_hnd_cert_req(ssl_common_dissect_t *hf, tvbuff_t *tvb, packet_info *pinfo,
                         proto_tree *tree, uint32_t offset, uint32_t offset_end,
                         SslSession *session, bool is_dtls)
{
    /* From SSL 3.0 and up (note that since TLS 1.1 certificate_authorities can be empty):
     *    enum {
     *        rsa_sign(1), dss_sign(2), rsa_fixed_dh(3), dss_fixed_dh(4),
     *        (255)
     *    } ClientCertificateType;
     *
     *    opaque DistinguishedName<1..2^16-1>;
     *
     *    struct {
     *        ClientCertificateType certificate_types<1..2^8-1>;
     *        DistinguishedName certificate_authorities<3..2^16-1>;
     *    } CertificateRequest;
     *
     *
     * As per TLSv1.2 (RFC 5246) the format has changed to:
     *
     *    enum {
     *        rsa_sign(1), dss_sign(2), rsa_fixed_dh(3), dss_fixed_dh(4),
     *        rsa_ephemeral_dh_RESERVED(5), dss_ephemeral_dh_RESERVED(6),
     *        fortezza_dms_RESERVED(20), (255)
     *    } ClientCertificateType;
     *
     *    enum {
     *        none(0), md5(1), sha1(2), sha224(3), sha256(4), sha384(5),
     *        sha512(6), (255)
     *    } HashAlgorithm;
     *
     *    enum { anonymous(0), rsa(1), dsa(2), ecdsa(3), (255) }
     *      SignatureAlgorithm;
     *
     *    struct {
     *          HashAlgorithm hash;
     *          SignatureAlgorithm signature;
     *    } SignatureAndHashAlgorithm;
     *
     *    SignatureAndHashAlgorithm
     *      supported_signature_algorithms<2..2^16-2>;
     *
     *    opaque DistinguishedName<1..2^16-1>;
     *
     *    struct {
     *        ClientCertificateType certificate_types<1..2^8-1>;
     *        SignatureAndHashAlgorithm supported_signature_algorithms<2^16-1>;
     *        DistinguishedName certificate_authorities<0..2^16-1>;
     *    } CertificateRequest;
     *
     * draft-ietf-tls-tls13-18:
     *    struct {
     *        opaque certificate_request_context<0..2^8-1>;
     *        SignatureScheme
     *          supported_signature_algorithms<2..2^16-2>;
     *        DistinguishedName certificate_authorities<0..2^16-1>;
     *        CertificateExtension certificate_extensions<0..2^16-1>;
     *    } CertificateRequest;
     *
     * RFC 8446 (since draft-ietf-tls-tls13-19):
     *
     *    struct {
     *        opaque certificate_request_context<0..2^8-1>;
     *        Extension extensions<2..2^16-1>;
     *    } CertificateRequest;
     */
    proto_item *ti;
    proto_tree *subtree;
    uint32_t    next_offset;
    asn1_ctx_t  asn1_ctx;
    bool        is_tls13 = (session->version == TLSV1DOT3_VERSION || session->version == DTLSV1DOT3_VERSION);
    unsigned char      draft_version = session->tls13_draft_version;

    if (!tree)
        return;

    asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, true, pinfo);

    if (is_tls13) {
        uint32_t context_length;
        /* opaque certificate_request_context<0..2^8-1> */
        if (!ssl_add_vector(hf, tvb, pinfo, tree, offset, offset_end, &context_length,
                            hf->hf.hs_certificate_request_context_length, 0, UINT8_MAX)) {
            return;
        }
        offset++;
        if (context_length > 0) {
            proto_tree_add_item(tree, hf->hf.hs_certificate_request_context,
                                tvb, offset, context_length, ENC_NA);
            offset += context_length;
        }
    } else {
        uint32_t cert_types_count;
        /* ClientCertificateType certificate_types<1..2^8-1> */
        if (!ssl_add_vector(hf, tvb, pinfo, tree, offset, offset_end, &cert_types_count,
                            hf->hf.hs_cert_types_count, 1, UINT8_MAX)) {
            return;
        }
        offset++;
        next_offset = offset + cert_types_count;

        ti = proto_tree_add_none_format(tree,
                hf->hf.hs_cert_types,
                tvb, offset, cert_types_count,
                "Certificate types (%u type%s)",
                cert_types_count,
                plurality(cert_types_count, "", "s"));
        subtree = proto_item_add_subtree(ti, hf->ett.cert_types);

        while (offset < next_offset) {
            proto_tree_add_item(subtree, hf->hf.hs_cert_type, tvb, offset, 1, ENC_BIG_ENDIAN);
            offset++;
        }
    }

    if (session->version == TLSV1DOT2_VERSION || session->version == DTLSV1DOT2_VERSION ||
            (is_tls13 && (draft_version > 0 && draft_version < 19))) {
        offset = ssl_dissect_hash_alg_list(hf, tvb, tree, pinfo, offset, offset_end, NULL);
    }

    if (is_tls13 && (draft_version == 0 || draft_version >= 19)) {
        /*
         * TLS 1.3 draft 19 and newer: Extensions.
         * SslDecryptSession pointer is NULL because Certificate Extensions
         * should not influence decryption state.
         */
        ssl_dissect_hnd_extension(hf, tvb, tree, pinfo, offset,
                                  offset_end, SSL_HND_CERT_REQUEST,
                                  session, NULL, is_dtls, NULL, NULL);
    } else if (is_tls13 && draft_version <= 18) {
        /*
         * TLS 1.3 draft 18 and older: certificate_authorities and
         * certificate_extensions (a vector of OID mappings).
         */
        offset = tls_dissect_certificate_authorities(hf, tvb, pinfo, tree, offset, offset_end);
        ssl_dissect_hnd_hello_ext_oid_filters(hf, tvb, pinfo, tree, offset, offset_end);
    } else {
        /* for TLS 1.2 and older, the certificate_authorities field. */
        tls_dissect_certificate_authorities(hf, tvb, pinfo, tree, offset, offset_end);
    }
}
/* Certificate and Certificate Request dissections. }}} */

void
ssl_dissect_hnd_cli_cert_verify(ssl_common_dissect_t *hf, tvbuff_t *tvb, packet_info *pinfo,
                                proto_tree *tree, uint32_t offset, uint32_t offset_end, uint16_t version)
{
    ssl_dissect_digitally_signed(hf, tvb, pinfo, tree, offset, offset_end, version,
                                 hf->hf.hs_client_cert_vrfy_sig_len,
                                 hf->hf.hs_client_cert_vrfy_sig);
}

/* Finished dissection. {{{ */
void
ssl_dissect_hnd_finished(ssl_common_dissect_t *hf, tvbuff_t *tvb,
                         proto_tree *tree, uint32_t offset, uint32_t offset_end,
                         const SslSession *session, ssl_hfs_t *ssl_hfs)
{
    /* For SSLv3:
     *     struct {
     *         opaque md5_hash[16];
     *         opaque sha_hash[20];
     *     } Finished;
     *
     * For (D)TLS:
     *     struct {
     *         opaque verify_data[12];
     *     } Finished;
     *
     * For TLS 1.3:
     *     struct {
     *         opaque verify_data[Hash.length];
     *     }
     */
    if (!tree)
        return;

    if (session->version == SSLV3_VERSION) {
        if (ssl_hfs != NULL) {
            proto_tree_add_item(tree, ssl_hfs->hs_md5_hash,
                                tvb, offset, 16, ENC_NA);
            proto_tree_add_item(tree, ssl_hfs->hs_sha_hash,
                                tvb, offset + 16, 20, ENC_NA);
        }
    } else {
        /* Length should be 12 for TLS before 1.3, assume this is the case. */
        proto_tree_add_item(tree, hf->hf.hs_finished,
                            tvb, offset, offset_end - offset, ENC_NA);
    }
} /* }}} */

/* RFC 6066 Certificate URL handshake message dissection. {{{ */
void
ssl_dissect_hnd_cert_url(ssl_common_dissect_t *hf, tvbuff_t *tvb, proto_tree *tree, uint32_t offset)
{
    uint16_t url_hash_len;

    /* enum {
     *     individual_certs(0), pkipath(1), (255)
     * } CertChainType;
     *
     * struct {
     *     CertChainType type;
     *     URLAndHash url_and_hash_list<1..2^16-1>;
     * } CertificateURL;
     *
     * struct {
     *     opaque url<1..2^16-1>;
     *     unint8 padding;
     *     opaque SHA1Hash[20];
     * } URLAndHash;
     */

    proto_tree_add_item(tree, hf->hf.hs_ext_cert_url_type,
                        tvb, offset, 1, ENC_NA);
    offset++;

    url_hash_len = tvb_get_ntohs(tvb, offset);
    proto_tree_add_item(tree, hf->hf.hs_ext_cert_url_url_hash_list_len,
                        tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;
    while (url_hash_len-- > 0) {
        proto_item  *urlhash_item;
        proto_tree  *urlhash_tree;
        uint16_t     url_len;

        urlhash_item = proto_tree_add_item(tree, hf->hf.hs_ext_cert_url_item,
                                           tvb, offset, -1, ENC_NA);
        urlhash_tree = proto_item_add_subtree(urlhash_item, hf->ett.urlhash);

        url_len = tvb_get_ntohs(tvb, offset);
        proto_tree_add_item(urlhash_tree, hf->hf.hs_ext_cert_url_url_len,
                            tvb, offset, 2, ENC_BIG_ENDIAN);
        offset += 2;

        proto_tree_add_item(urlhash_tree, hf->hf.hs_ext_cert_url_url,
                            tvb, offset, url_len, ENC_ASCII|ENC_NA);
        offset += url_len;

        proto_tree_add_item(urlhash_tree, hf->hf.hs_ext_cert_url_padding,
                            tvb, offset, 1, ENC_NA);
        offset++;
        /* Note: RFC 6066 says that padding must be 0x01 */

        proto_tree_add_item(urlhash_tree, hf->hf.hs_ext_cert_url_sha1,
                            tvb, offset, 20, ENC_NA);
        offset += 20;
    }
} /* }}} */

void
ssl_dissect_hnd_compress_certificate(ssl_common_dissect_t *hf, tvbuff_t *tvb, proto_tree *tree,
                                      uint32_t offset, uint32_t offset_end, packet_info *pinfo,
                                      SslSession *session, SslDecryptSession *ssl,
                                      bool is_from_server, bool is_dtls)
{
    uint32_t algorithm, uncompressed_length;
    uint32_t compressed_certificate_message_length;
    tvbuff_t *uncompressed_tvb = NULL;
    proto_item *ti;
    /*
     * enum {
     *     zlib(1),
     *     brotli(2),
     *     zstd(3),
     *     (65535)
     * } CertificateCompressionAlgorithm;
     *
     * struct {
     *       CertificateCompressionAlgorithm algorithm;
     *       uint24 uncompressed_length;
     *       opaque compressed_certificate_message<1..2^24-1>;
     * } CompressedCertificate;
     */

    proto_tree_add_item_ret_uint(tree, hf->hf.hs_ext_compress_certificate_algorithm,
                                 tvb, offset, 2, ENC_BIG_ENDIAN, &algorithm);
    offset += 2;

    proto_tree_add_item_ret_uint(tree, hf->hf.hs_ext_compress_certificate_uncompressed_length,
                                 tvb, offset, 3, ENC_BIG_ENDIAN, &uncompressed_length);
    offset += 3;

    /* opaque compressed_certificate_message<1..2^24-1>; */
    if (!ssl_add_vector(hf, tvb, pinfo, tree, offset, offset_end, &compressed_certificate_message_length,
                        hf->hf.hs_ext_compress_certificate_compressed_certificate_message_length, 1, G_MAXUINT24)) {
        return;
    }
    offset += 3;

    ti = proto_tree_add_item(tree, hf->hf.hs_ext_compress_certificate_compressed_certificate_message,
                             tvb, offset, compressed_certificate_message_length, ENC_NA);

    /* Certificate decompression following algorithm */
    switch (algorithm) {
    case 2: /* brotli */
        uncompressed_tvb = tvb_child_uncompress_brotli(tvb, tvb, offset, compressed_certificate_message_length);
	break;
    /* TODO: add other algorithms */
    }

    if (uncompressed_tvb) {
        proto_tree *uncompressed_tree;

        if (uncompressed_length != tvb_captured_length(uncompressed_tvb)) {
            proto_tree_add_expert_format(tree, pinfo, &hf->ei.decompression_error,
                                         tvb, offset, offset_end - offset,
                                         "Invalid uncompressed length %u (expected %u)",
                                         tvb_captured_length(uncompressed_tvb),
                                         uncompressed_length);
        } else {
            uncompressed_tree = proto_item_add_subtree(ti, hf->ett.uncompressed_certificates);
            ssl_dissect_hnd_cert(hf, uncompressed_tvb, uncompressed_tree,
                                 0, uncompressed_length, pinfo, session, ssl, is_from_server, is_dtls);
            add_new_data_source(pinfo, uncompressed_tvb, "Uncompressed certificate(s)");
        }
    }
}

/* Dissection of TLS Extensions in Client Hello, Server Hello, etc. {{{ */
static int
ssl_dissect_hnd_extension(ssl_common_dissect_t *hf, tvbuff_t *tvb, proto_tree *tree,
                          packet_info* pinfo, uint32_t offset, uint32_t offset_end, uint8_t hnd_type,
                          SslSession *session, SslDecryptSession *ssl,
                          bool is_dtls, wmem_strbuf_t *ja3, ja4_data_t *ja4_data)
{
    uint32_t    exts_len;
    uint16_t    ext_type;
    uint32_t    ext_len;
    uint32_t    next_offset;
    proto_tree *ext_tree;
    bool        is_tls13 = session->version == TLSV1DOT3_VERSION;
    wmem_strbuf_t *ja3_sg = wmem_strbuf_new(pinfo->pool, "");
    wmem_strbuf_t *ja3_ecpf = wmem_strbuf_new(pinfo->pool, "");
    char       *ja3_dash = "";
    unsigned    supported_version;

    /* Extension extensions<0..2^16-2> (for TLS 1.3 HRR/CR min-length is 2) */
    if (!ssl_add_vector(hf, tvb, pinfo, tree, offset, offset_end, &exts_len,
                        hf->hf.hs_exts_len, 0, UINT16_MAX)) {
        return offset_end;
    }
    offset += 2;
    offset_end = offset + exts_len;

    if (ja4_data) {
        ja4_data->num_extensions = 0;
    }
    while (offset_end - offset >= 4)
    {
        ext_type = tvb_get_ntohs(tvb, offset);
        ext_len  = tvb_get_ntohs(tvb, offset + 2);

        if (ja4_data && !IS_GREASE_TLS(ext_type)) {
            ja4_data->num_extensions += 1;
            if (ext_type != SSL_HND_HELLO_EXT_SERVER_NAME &&
                ext_type != SSL_HND_HELLO_EXT_ALPN) {
                wmem_list_insert_sorted(ja4_data->extension_list, GUINT_TO_POINTER(ext_type), wmem_compare_uint);
            }
        }

        ext_tree = proto_tree_add_subtree_format(tree, tvb, offset, 4 + ext_len, hf->ett.hs_ext, NULL,
                                  "Extension: %s (len=%u)", val_to_str(ext_type,
                                            tls_hello_extension_types,
                                            "Unknown type %u"), ext_len);

        proto_tree_add_uint(ext_tree, hf->hf.hs_ext_type,
                            tvb, offset, 2, ext_type);
        offset += 2;
        if (ja3 && !IS_GREASE_TLS(ext_type)) {
            wmem_strbuf_append_printf(ja3, "%s%i",ja3_dash, ext_type);
            ja3_dash = "-";
        }

        /* opaque extension_data<0..2^16-1> */
        if (!ssl_add_vector(hf, tvb, pinfo, ext_tree, offset, offset_end, &ext_len,
                            hf->hf.hs_ext_len, 0, UINT16_MAX)) {
            return offset_end;
        }
        offset += 2;
        next_offset = offset + ext_len;

        switch (ext_type) {
        case SSL_HND_HELLO_EXT_SERVER_NAME:
            if (hnd_type == SSL_HND_CLIENT_HELLO) {
                offset = ssl_dissect_hnd_hello_ext_server_name(hf, tvb, pinfo, ext_tree, offset, next_offset);
                if (ja4_data) {
                    ja4_data->server_name_present = true;
                }
            }
            break;
        case SSL_HND_HELLO_EXT_MAX_FRAGMENT_LENGTH:
            proto_tree_add_item(ext_tree, hf->hf.hs_ext_max_fragment_length, tvb, offset, 1, ENC_NA);
            offset += 1;
            break;
        case SSL_HND_HELLO_EXT_STATUS_REQUEST:
            if (hnd_type == SSL_HND_CLIENT_HELLO) {
                offset = ssl_dissect_hnd_hello_ext_status_request(hf, tvb, pinfo, ext_tree, offset, next_offset, false);
            } else if (is_tls13 && hnd_type == SSL_HND_CERTIFICATE) {
                offset = tls_dissect_hnd_certificate_status(hf, tvb, pinfo, ext_tree, offset, next_offset);
            }
            break;
        case SSL_HND_HELLO_EXT_CERT_TYPE:
            offset = ssl_dissect_hnd_hello_ext_cert_type(hf, tvb, ext_tree,
                                                         offset, next_offset,
                                                         hnd_type, ext_type,
                                                         session);
            break;
        case SSL_HND_HELLO_EXT_SUPPORTED_GROUPS:
            if (hnd_type == SSL_HND_CLIENT_HELLO) {
                offset = ssl_dissect_hnd_hello_ext_supported_groups(hf, tvb, pinfo, ext_tree, offset,
                        next_offset, ja3_sg);
            } else {
                offset = ssl_dissect_hnd_hello_ext_supported_groups(hf, tvb, pinfo, ext_tree, offset,
                        next_offset, NULL);
            }
            break;
        case SSL_HND_HELLO_EXT_EC_POINT_FORMATS:
            if (hnd_type == SSL_HND_CLIENT_HELLO) {
                offset = ssl_dissect_hnd_hello_ext_ec_point_formats(hf, tvb, ext_tree, offset, ja3_ecpf);
            } else {
                offset = ssl_dissect_hnd_hello_ext_ec_point_formats(hf, tvb, ext_tree, offset, NULL);
            }
            break;
            break;
        case SSL_HND_HELLO_EXT_SRP:
            offset = ssl_dissect_hnd_hello_ext_srp(hf, tvb, pinfo, ext_tree, offset, next_offset);
            break;
        case SSL_HND_HELLO_EXT_SIGNATURE_ALGORITHMS:
            offset = ssl_dissect_hnd_hello_ext_sig_hash_algs(hf, tvb, ext_tree, pinfo, offset, next_offset, ja4_data);
            break;
        case SSL_HND_HELLO_EXT_SIGNATURE_ALGORITHMS_CERT: /* since TLS 1.3 draft -23 */
            offset = ssl_dissect_hnd_hello_ext_sig_hash_algs(hf, tvb, ext_tree, pinfo, offset, next_offset, NULL);
            break;
        case SSL_HND_HELLO_EXT_DELEGATED_CREDENTIALS:
            offset = ssl_dissect_hnd_ext_delegated_credentials(hf, tvb, ext_tree, pinfo, offset, next_offset, hnd_type);
            break;
        case SSL_HND_HELLO_EXT_USE_SRTP:
            if (is_dtls) {
                if (hnd_type == SSL_HND_CLIENT_HELLO) {
                    offset = dtls_dissect_hnd_hello_ext_use_srtp(pinfo, tvb, ext_tree, offset, next_offset, false);
                } else if (hnd_type == SSL_HND_SERVER_HELLO) {
                    offset = dtls_dissect_hnd_hello_ext_use_srtp(pinfo, tvb, ext_tree, offset, next_offset, true);
                }
            } else {
                // XXX expert info: This extension MUST only be used with DTLS, and not with TLS.
            }
            break;
	case SSL_HND_HELLO_EXT_ENCRYPTED_CLIENT_HELLO:
            offset = ssl_dissect_hnd_hello_ext_ech(hf, tvb, pinfo, ext_tree, offset, next_offset, hnd_type, ssl);
	    break;
        case SSL_HND_HELLO_EXT_HEARTBEAT:
            proto_tree_add_item(ext_tree, hf->hf.hs_ext_heartbeat_mode,
                                tvb, offset, 1, ENC_BIG_ENDIAN);
            offset++;
            break;
        case SSL_HND_HELLO_EXT_ALPN:
            offset = ssl_dissect_hnd_hello_ext_alpn(hf, tvb, pinfo, ext_tree, offset, next_offset, hnd_type, session, is_dtls, ja4_data);
            break;
        case SSL_HND_HELLO_EXT_STATUS_REQUEST_V2:
            if (hnd_type == SSL_HND_CLIENT_HELLO)
                offset = ssl_dissect_hnd_hello_ext_status_request_v2(hf, tvb, pinfo, ext_tree, offset, next_offset);
            break;
        case SSL_HND_HELLO_EXT_SIGNED_CERTIFICATE_TIMESTAMP:
            // TLS 1.3 note: SCT only appears in EE in draft -16 and before.
            if (hnd_type == SSL_HND_SERVER_HELLO || hnd_type == SSL_HND_ENCRYPTED_EXTENSIONS || hnd_type == SSL_HND_CERTIFICATE)
                offset = tls_dissect_sct_list(hf, tvb, pinfo, ext_tree, offset, next_offset, session->version);
            break;
        case SSL_HND_HELLO_EXT_CLIENT_CERT_TYPE:
        case SSL_HND_HELLO_EXT_SERVER_CERT_TYPE:
            offset = ssl_dissect_hnd_hello_ext_cert_type(hf, tvb, ext_tree,
                                                         offset, next_offset,
                                                         hnd_type, ext_type,
                                                         session);
            break;
        case SSL_HND_HELLO_EXT_PADDING:
            proto_tree_add_item(ext_tree, hf->hf.hs_ext_padding_data, tvb, offset, ext_len, ENC_NA);
            offset += ext_len;
            break;
        case SSL_HND_HELLO_EXT_ENCRYPT_THEN_MAC:
            if (ssl && hnd_type == SSL_HND_SERVER_HELLO) {
                ssl_debug_printf("%s enabling Encrypt-then-MAC\n", G_STRFUNC);
                ssl->state |= SSL_ENCRYPT_THEN_MAC;
            }
            break;
        case SSL_HND_HELLO_EXT_EXTENDED_MASTER_SECRET:
            if (ssl) {
                switch (hnd_type) {
                case SSL_HND_CLIENT_HELLO:
                    ssl->state |= SSL_CLIENT_EXTENDED_MASTER_SECRET;
                    break;
                case SSL_HND_SERVER_HELLO:
                    ssl->state |= SSL_SERVER_EXTENDED_MASTER_SECRET;
                    break;
                default: /* no default */
                    break;
                }
            }
            break;
        case SSL_HND_HELLO_EXT_COMPRESS_CERTIFICATE:
            offset = ssl_dissect_hnd_hello_ext_compress_certificate(hf, tvb, pinfo, ext_tree, offset, next_offset, hnd_type, ssl);
            break;
        case SSL_HND_HELLO_EXT_TOKEN_BINDING:
            offset = ssl_dissect_hnd_hello_ext_token_binding(hf, tvb, pinfo, ext_tree, offset, next_offset, hnd_type, ssl);
            break;
        case SSL_HND_HELLO_EXT_RECORD_SIZE_LIMIT:
            proto_tree_add_item(ext_tree, hf->hf.hs_ext_record_size_limit,
                                tvb, offset, 2, ENC_BIG_ENDIAN);
            offset += 2;
            break;
        case SSL_HND_HELLO_EXT_QUIC_TRANSPORT_PARAMETERS:
        case SSL_HND_HELLO_EXT_QUIC_TRANSPORT_PARAMETERS_V1:
            offset = ssl_dissect_hnd_hello_ext_quic_transport_parameters(hf, tvb, pinfo, ext_tree, offset, next_offset, hnd_type, ssl);
            break;
        case SSL_HND_HELLO_EXT_SESSION_TICKET_TLS:
            offset = ssl_dissect_hnd_hello_ext_session_ticket(hf, tvb, ext_tree, offset, next_offset, hnd_type, ssl);
            break;
        case SSL_HND_HELLO_EXT_KEY_SHARE_OLD: /* used before TLS 1.3 draft -23 */
        case SSL_HND_HELLO_EXT_KEY_SHARE:
            offset = ssl_dissect_hnd_hello_ext_key_share(hf, tvb, pinfo, ext_tree, offset, next_offset, hnd_type);
            break;
        case SSL_HND_HELLO_EXT_PRE_SHARED_KEY:
            offset = ssl_dissect_hnd_hello_ext_pre_shared_key(hf, tvb, pinfo, ext_tree, offset, next_offset, hnd_type);
            break;
        case SSL_HND_HELLO_EXT_EARLY_DATA:
        case SSL_HND_HELLO_EXT_TICKET_EARLY_DATA_INFO:
            offset = ssl_dissect_hnd_hello_ext_early_data(hf, tvb, pinfo, ext_tree, offset, next_offset, hnd_type, ssl);
            break;
        case SSL_HND_HELLO_EXT_SUPPORTED_VERSIONS:
            switch (hnd_type) {
            case SSL_HND_CLIENT_HELLO:
                offset = ssl_dissect_hnd_hello_ext_supported_versions(hf, tvb, pinfo, ext_tree, offset, next_offset, session, is_dtls, ja4_data);
                break;
            case SSL_HND_SERVER_HELLO:
            case SSL_HND_HELLO_RETRY_REQUEST:
                proto_tree_add_item_ret_uint(ext_tree, hf->hf.hs_ext_supported_version, tvb, offset, 2, ENC_BIG_ENDIAN, &supported_version);
                offset += 2;
                proto_item_append_text(ext_tree, " %s", val_to_str(supported_version, ssl_versions, "Unknown (0x%04x)"));
                break;
            }
            break;
        case SSL_HND_HELLO_EXT_COOKIE:
            offset = ssl_dissect_hnd_hello_ext_cookie(hf, tvb, pinfo, ext_tree, offset, next_offset);
            break;
        case SSL_HND_HELLO_EXT_PSK_KEY_EXCHANGE_MODES:
            offset = ssl_dissect_hnd_hello_ext_psk_key_exchange_modes(hf, tvb, pinfo, ext_tree, offset, next_offset);
            break;
        case SSL_HND_HELLO_EXT_CERTIFICATE_AUTHORITIES:
            offset = ssl_dissect_hnd_hello_ext_certificate_authorities(hf, tvb, pinfo, ext_tree, offset, next_offset);
            break;
        case SSL_HND_HELLO_EXT_OID_FILTERS:
            offset = ssl_dissect_hnd_hello_ext_oid_filters(hf, tvb, pinfo, ext_tree, offset, next_offset);
            break;
        case SSL_HND_HELLO_EXT_POST_HANDSHAKE_AUTH:
            break;
        case SSL_HND_HELLO_EXT_NPN:
            offset = ssl_dissect_hnd_hello_ext_npn(hf, tvb, pinfo, ext_tree, offset, next_offset);
            break;
        case SSL_HND_HELLO_EXT_ALPS:
            offset = ssl_dissect_hnd_hello_ext_alps(hf, tvb, pinfo, ext_tree, offset, next_offset, hnd_type);
            break;
        case SSL_HND_HELLO_EXT_RENEGOTIATION_INFO:
            offset = ssl_dissect_hnd_hello_ext_reneg_info(hf, tvb, pinfo, ext_tree, offset, next_offset);
            break;
        case SSL_HND_HELLO_EXT_ENCRYPTED_SERVER_NAME:
            offset = ssl_dissect_hnd_hello_ext_esni(hf, tvb, pinfo, ext_tree, offset, next_offset, hnd_type, ssl);
            break;
        case SSL_HND_HELLO_EXT_CONNECTION_ID_DEPRECATED:
            session->deprecated_cid = true;
            /* FALLTHRU */
        case SSL_HND_HELLO_EXT_CONNECTION_ID:
            offset = ssl_dissect_hnd_hello_ext_connection_id(hf, tvb, pinfo, ext_tree, offset, hnd_type, session, ssl);
            break;
        default:
            proto_tree_add_item(ext_tree, hf->hf.hs_ext_data,
                                        tvb, offset, ext_len, ENC_NA);
            offset += ext_len;
            break;
        }

        if (!ssl_end_vector(hf, tvb, pinfo, ext_tree, offset, next_offset)) {
            /* Dissection did not end at expected location, fix it. */
            offset = next_offset;
        }
    }

    if (ja3) {
        if (hnd_type == SSL_HND_CLIENT_HELLO) {
            if(wmem_strbuf_get_len(ja3_sg) > 0) {
                wmem_strbuf_append_printf(ja3, "%s", wmem_strbuf_get_str(ja3_sg));
            } else {
                wmem_strbuf_append_c(ja3, ',');
            }
            if(wmem_strbuf_get_len(ja3_ecpf) > 0) {
                wmem_strbuf_append_printf(ja3, "%s", wmem_strbuf_get_str(ja3_ecpf));
            } else {
                wmem_strbuf_append_c(ja3, ',');
            }
        }
    }

    /* Check if Extensions vector is correctly terminated. */
    if (!ssl_end_vector(hf, tvb, pinfo, tree, offset, offset_end)) {
        offset = offset_end;
    }

    return offset;
} /* }}} */


/* ClientKeyExchange algo-specific dissectors. {{{ */

static void
dissect_ssl3_hnd_cli_keyex_ecdh(ssl_common_dissect_t *hf, tvbuff_t *tvb,
                                proto_tree *tree, uint32_t offset,
                                uint32_t length)
{
    int         point_len;
    proto_tree *ssl_ecdh_tree;

    ssl_ecdh_tree = proto_tree_add_subtree(tree, tvb, offset, length,
                                  hf->ett.keyex_params, NULL, "EC Diffie-Hellman Client Params");

    /* point */
    point_len = tvb_get_uint8(tvb, offset);
    proto_tree_add_item(ssl_ecdh_tree, hf->hf.hs_client_keyex_point_len, tvb,
                        offset, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(ssl_ecdh_tree, hf->hf.hs_client_keyex_point, tvb,
                        offset + 1, point_len, ENC_NA);
}

static void
dissect_ssl3_hnd_cli_keyex_dhe(ssl_common_dissect_t *hf, tvbuff_t *tvb,
                               proto_tree *tree, uint32_t offset, uint32_t length)
{
    int         yc_len;
    proto_tree *ssl_dh_tree;

    ssl_dh_tree = proto_tree_add_subtree(tree, tvb, offset, length,
                                hf->ett.keyex_params, NULL, "Diffie-Hellman Client Params");

    /* ClientDiffieHellmanPublic.dh_public (explicit) */
    yc_len  = tvb_get_ntohs(tvb, offset);
    proto_tree_add_item(ssl_dh_tree, hf->hf.hs_client_keyex_yc_len, tvb,
                        offset, 2, ENC_BIG_ENDIAN);
    proto_tree_add_item(ssl_dh_tree, hf->hf.hs_client_keyex_yc, tvb,
                        offset + 2, yc_len, ENC_NA);
}

static void
dissect_ssl3_hnd_cli_keyex_rsa(ssl_common_dissect_t *hf, tvbuff_t *tvb,
                               proto_tree *tree, uint32_t offset,
                               uint32_t length, const SslSession *session)
{
    int         epms_len;
    proto_tree *ssl_rsa_tree;

    ssl_rsa_tree = proto_tree_add_subtree(tree, tvb, offset, length,
                                 hf->ett.keyex_params, NULL, "RSA Encrypted PreMaster Secret");

    /* EncryptedPreMasterSecret.pre_master_secret */
    switch (session->version) {
    case SSLV2_VERSION:
    case SSLV3_VERSION:
    case DTLSV1DOT0_OPENSSL_VERSION:
        /* OpenSSL pre-0.9.8f DTLS and pre-TLS quirk: 2-octet length vector is
         * not present. The handshake contents represents the EPMS, see:
         * https://gitlab.com/wireshark/wireshark/-/issues/10222 */
        epms_len = length;
        break;

    default:
        /* TLS and DTLS include vector length before EPMS */
        epms_len = tvb_get_ntohs(tvb, offset);
        proto_tree_add_item(ssl_rsa_tree, hf->hf.hs_client_keyex_epms_len, tvb,
                            offset, 2, ENC_BIG_ENDIAN);
        offset += 2;
        break;
    }
    proto_tree_add_item(ssl_rsa_tree, hf->hf.hs_client_keyex_epms, tvb,
                        offset, epms_len, ENC_NA);
}

/* Used in PSK cipher suites */
static uint32_t
dissect_ssl3_hnd_cli_keyex_psk(ssl_common_dissect_t *hf, tvbuff_t *tvb,
                               proto_tree *tree, uint32_t offset)
{
    unsigned     identity_len;
    proto_tree *ssl_psk_tree;

    ssl_psk_tree = proto_tree_add_subtree(tree, tvb, offset, -1,
                                 hf->ett.keyex_params, NULL, "PSK Client Params");
    /* identity */
    identity_len = tvb_get_ntohs(tvb, offset);
    proto_tree_add_item(ssl_psk_tree, hf->hf.hs_client_keyex_identity_len, tvb,
                        offset, 2, ENC_BIG_ENDIAN);
    proto_tree_add_item(ssl_psk_tree, hf->hf.hs_client_keyex_identity, tvb,
                        offset + 2, identity_len, ENC_NA);

    proto_item_set_len(ssl_psk_tree, 2 + identity_len);
    return 2 + identity_len;
}

/* Used in RSA PSK cipher suites */
static void
dissect_ssl3_hnd_cli_keyex_rsa_psk(ssl_common_dissect_t *hf, tvbuff_t *tvb,
                                   proto_tree *tree, uint32_t offset,
                                   uint32_t length)
{
    int         identity_len, epms_len;
    proto_tree *ssl_psk_tree;

    ssl_psk_tree = proto_tree_add_subtree(tree, tvb, offset, length,
                                 hf->ett.keyex_params, NULL, "RSA PSK Client Params");

    /* identity */
    identity_len = tvb_get_ntohs(tvb, offset);
    proto_tree_add_item(ssl_psk_tree, hf->hf.hs_client_keyex_identity_len,
                        tvb, offset, 2, ENC_BIG_ENDIAN);
    proto_tree_add_item(ssl_psk_tree, hf->hf.hs_client_keyex_identity,
                        tvb, offset + 2, identity_len, ENC_NA);
    offset += 2 + identity_len;

    /* Yc */
    epms_len = tvb_get_ntohs(tvb, offset);
    proto_tree_add_item(ssl_psk_tree, hf->hf.hs_client_keyex_epms_len, tvb,
                        offset, 2, ENC_BIG_ENDIAN);
    proto_tree_add_item(ssl_psk_tree, hf->hf.hs_client_keyex_epms, tvb,
                        offset + 2, epms_len, ENC_NA);
}

/* Used in Diffie-Hellman PSK cipher suites */
static void
dissect_ssl3_hnd_cli_keyex_dhe_psk(ssl_common_dissect_t *hf, tvbuff_t *tvb,
                                   proto_tree *tree, uint32_t offset, uint32_t length)
{
    /*
     *  struct {
     *      select (KeyExchangeAlgorithm) {
     *          case diffie_hellman_psk:
     *              opaque psk_identity<0..2^16-1>;
     *              ClientDiffieHellmanPublic public;
     *      } exchange_keys;
     *  } ClientKeyExchange;
     */

    uint32_t psk_len = dissect_ssl3_hnd_cli_keyex_psk(hf, tvb, tree, offset);
    dissect_ssl3_hnd_cli_keyex_dhe(hf, tvb, tree, offset + psk_len, length - psk_len);
}

/* Used in EC Diffie-Hellman PSK cipher suites */
static void
dissect_ssl3_hnd_cli_keyex_ecdh_psk(ssl_common_dissect_t *hf, tvbuff_t *tvb,
                                    proto_tree *tree, uint32_t offset, uint32_t length)
{
    /*
     *  struct {
     *      select (KeyExchangeAlgorithm) {
     *          case ec_diffie_hellman_psk:
     *              opaque psk_identity<0..2^16-1>;
     *              ClientECDiffieHellmanPublic public;
     *      } exchange_keys;
     *  } ClientKeyExchange;
     */

    uint32_t psk_len = dissect_ssl3_hnd_cli_keyex_psk(hf, tvb, tree, offset);
    dissect_ssl3_hnd_cli_keyex_ecdh(hf, tvb, tree, offset + psk_len, length - psk_len);
}

/* Used in EC J-PAKE cipher suites */
static void
dissect_ssl3_hnd_cli_keyex_ecjpake(ssl_common_dissect_t *hf, tvbuff_t *tvb,
                                   proto_tree *tree, uint32_t offset,
                                   uint32_t length)
{
    /*
     *  struct {
     *      ECPoint V;
     *      opaque r<1..2^8-1>;
     *  } ECSchnorrZKP;
     *
     *  struct {
     *      ECPoint X;
     *      ECSchnorrZKP zkp;
     *  } ECJPAKEKeyKP;
     *
     *  struct {
     *      ECJPAKEKeyKP ecjpake_key_kp;
     *  } ClientECJPAKEParams;
     *
     *  select (KeyExchangeAlgorithm) {
     *      case ecjpake:
     *          ClientECJPAKEParams params;
     *  } ClientKeyExchange;
     */

    int         point_len;
    proto_tree *ssl_ecjpake_tree;

    ssl_ecjpake_tree = proto_tree_add_subtree(tree, tvb, offset, length,
                                              hf->ett.keyex_params, NULL,
                                              "EC J-PAKE Client Params");

    /* ECJPAKEKeyKP.X */
    point_len = tvb_get_uint8(tvb, offset);
    proto_tree_add_item(ssl_ecjpake_tree, hf->hf.hs_client_keyex_xc_len, tvb,
                        offset, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(ssl_ecjpake_tree, hf->hf.hs_client_keyex_xc, tvb,
                        offset + 1, point_len, ENC_NA);
    offset += 1 + point_len;

    /* ECJPAKEKeyKP.zkp.V */
    point_len = tvb_get_uint8(tvb, offset);
    proto_tree_add_item(ssl_ecjpake_tree, hf->hf.hs_client_keyex_vc_len, tvb,
                        offset, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(ssl_ecjpake_tree, hf->hf.hs_client_keyex_vc, tvb,
                        offset + 1, point_len, ENC_NA);
    offset += 1 + point_len;

    /* ECJPAKEKeyKP.zkp.r */
    point_len = tvb_get_uint8(tvb, offset);
    proto_tree_add_item(ssl_ecjpake_tree, hf->hf.hs_client_keyex_rc_len, tvb,
                        offset, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(ssl_ecjpake_tree, hf->hf.hs_client_keyex_rc, tvb,
                        offset + 1, point_len, ENC_NA);
}

static void
dissect_ssl3_hnd_cli_keyex_ecc_sm2(ssl_common_dissect_t *hf, tvbuff_t *tvb,
                                   proto_tree *tree, uint32_t offset,
                                   uint32_t length)
{
    int epms_len;
    proto_tree *ssl_ecc_sm2_tree;

    ssl_ecc_sm2_tree = proto_tree_add_subtree(tree, tvb, offset, length,
                                              hf->ett.keyex_params, NULL,
                                              "ECC-SM2 Encrypted PreMaster Secret");

    epms_len = tvb_get_ntohs(tvb, offset);
    proto_tree_add_item(ssl_ecc_sm2_tree, hf->hf.hs_client_keyex_epms_len, tvb,
                        offset, 2, ENC_BIG_ENDIAN);
    offset += 2;
    proto_tree_add_item(ssl_ecc_sm2_tree, hf->hf.hs_client_keyex_epms, tvb,
                        offset, epms_len, ENC_NA);
}
/* ClientKeyExchange algo-specific dissectors. }}} */


/* Dissects DigitallySigned (see RFC 5246 4.7 Cryptographic Attributes). {{{ */
static uint32_t
ssl_dissect_digitally_signed(ssl_common_dissect_t *hf, tvbuff_t *tvb, packet_info *pinfo,
                             proto_tree *tree, uint32_t offset, uint32_t offset_end,
                             uint16_t version, int hf_sig_len, int hf_sig)
{
    uint32_t    sig_len;

    switch (version) {
    case TLSV1DOT2_VERSION:
    case DTLSV1DOT2_VERSION:
    case TLSV1DOT3_VERSION:
    case DTLSV1DOT3_VERSION:
        tls_dissect_signature_algorithm(hf, tvb, tree, offset, NULL);
        offset += 2;
        break;

    default:
        break;
    }

    /* Sig */
    if (!ssl_add_vector(hf, tvb, pinfo, tree, offset, offset_end, &sig_len,
                        hf_sig_len, 0, UINT16_MAX)) {
        return offset_end;
    }
    offset += 2;
    proto_tree_add_item(tree, hf_sig, tvb, offset, sig_len, ENC_NA);
    offset += sig_len;
    return offset;
} /* }}} */

/* ServerKeyExchange algo-specific dissectors. {{{ */

/* dissects signed_params inside a ServerKeyExchange for some keyex algos */
static void
dissect_ssl3_hnd_srv_keyex_sig(ssl_common_dissect_t *hf, tvbuff_t *tvb, packet_info *pinfo,
                               proto_tree *tree, uint32_t offset, uint32_t offset_end,
                               uint16_t version)
{
    /*
     * TLSv1.2 (RFC 5246 sec 7.4.8)
     *  struct {
     *      digitally-signed struct {
     *          opaque handshake_messages[handshake_messages_length];
     *      }
     *  } CertificateVerify;
     *
     * TLSv1.0/TLSv1.1 (RFC 5436 sec 7.4.8 and 7.4.3) works essentially the same
     * as TLSv1.2, but the hash algorithms are not explicit in digitally-signed.
     *
     * SSLv3 (RFC 6101 sec 5.6.8) essentially works the same as TLSv1.0 but it
     * does more hashing including the master secret and padding.
     */
    ssl_dissect_digitally_signed(hf, tvb, pinfo, tree, offset, offset_end, version,
                                 hf->hf.hs_server_keyex_sig_len,
                                 hf->hf.hs_server_keyex_sig);
}

static uint32_t
dissect_tls_ecparameters(ssl_common_dissect_t *hf, tvbuff_t *tvb, proto_tree *tree, uint32_t offset, uint32_t offset_end)
{
    /*
     * RFC 4492 ECC cipher suites for TLS
     *
     *  struct {
     *      ECCurveType    curve_type;
     *      select (curve_type) {
     *          case explicit_prime:
     *              ...
     *          case explicit_char2:
     *              ...
     *          case named_curve:
     *              NamedCurve namedcurve;
     *      };
     *  } ECParameters;
     */

    int         curve_type;

    /* ECParameters.curve_type */
    curve_type = tvb_get_uint8(tvb, offset);
    proto_tree_add_item(tree, hf->hf.hs_server_keyex_curve_type, tvb,
                        offset, 1, ENC_BIG_ENDIAN);
    offset++;

    if (curve_type != 3)
        return offset_end; /* only named_curves are supported */

    /* case curve_type == named_curve; ECParameters.namedcurve */
    proto_tree_add_item(tree, hf->hf.hs_server_keyex_named_curve, tvb,
                        offset, 2, ENC_BIG_ENDIAN);
    offset += 2;

    return offset;
}

static void
dissect_ssl3_hnd_srv_keyex_ecdh(ssl_common_dissect_t *hf, tvbuff_t *tvb, packet_info *pinfo,
                                proto_tree *tree, uint32_t offset, uint32_t offset_end,
                                uint16_t version, bool anon)
{
    /*
     * RFC 4492 ECC cipher suites for TLS
     *
     *  struct {
     *      opaque point <1..2^8-1>;
     *  } ECPoint;
     *
     *  struct {
     *      ECParameters    curve_params;
     *      ECPoint         public;
     *  } ServerECDHParams;
     *
     *  select (KeyExchangeAlgorithm) {
     *      case ec_diffie_hellman:
     *          ServerECDHParams    params;
     *          Signature           signed_params;
     *  } ServerKeyExchange;
     */

    int         point_len;
    proto_tree *ssl_ecdh_tree;

    ssl_ecdh_tree = proto_tree_add_subtree(tree, tvb, offset, offset_end - offset,
                                  hf->ett.keyex_params, NULL, "EC Diffie-Hellman Server Params");

    offset = dissect_tls_ecparameters(hf, tvb, ssl_ecdh_tree, offset, offset_end);
    if (offset >= offset_end)
        return; /* only named_curves are supported */

    /* ECPoint.point */
    point_len = tvb_get_uint8(tvb, offset);
    proto_tree_add_item(ssl_ecdh_tree, hf->hf.hs_server_keyex_point_len, tvb,
                        offset, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(ssl_ecdh_tree, hf->hf.hs_server_keyex_point, tvb,
                        offset + 1, point_len, ENC_NA);
    offset += 1 + point_len;

    /* Signature (if non-anonymous KEX) */
    if (!anon) {
        dissect_ssl3_hnd_srv_keyex_sig(hf, tvb, pinfo, ssl_ecdh_tree, offset, offset_end, version);
    }
}

static void
dissect_ssl3_hnd_srv_keyex_dhe(ssl_common_dissect_t *hf, tvbuff_t *tvb, packet_info *pinfo,
                               proto_tree *tree, uint32_t offset, uint32_t offset_end,
                               uint16_t version, bool anon)
{
    int         p_len, g_len, ys_len;
    proto_tree *ssl_dh_tree;

    ssl_dh_tree = proto_tree_add_subtree(tree, tvb, offset, offset_end - offset,
                                hf->ett.keyex_params, NULL, "Diffie-Hellman Server Params");

    /* p */
    p_len = tvb_get_ntohs(tvb, offset);
    proto_tree_add_item(ssl_dh_tree, hf->hf.hs_server_keyex_p_len, tvb,
                        offset, 2, ENC_BIG_ENDIAN);
    proto_tree_add_item(ssl_dh_tree, hf->hf.hs_server_keyex_p, tvb,
                        offset + 2, p_len, ENC_NA);
    offset += 2 + p_len;

    /* g */
    g_len = tvb_get_ntohs(tvb, offset);
    proto_tree_add_item(ssl_dh_tree, hf->hf.hs_server_keyex_g_len, tvb,
                        offset, 2, ENC_BIG_ENDIAN);
    proto_tree_add_item(ssl_dh_tree, hf->hf.hs_server_keyex_g, tvb,
                        offset + 2, g_len, ENC_NA);
    offset += 2 + g_len;

    /* Ys */
    ys_len = tvb_get_ntohs(tvb, offset);
    proto_tree_add_uint(ssl_dh_tree, hf->hf.hs_server_keyex_ys_len, tvb,
                        offset, 2, ys_len);
    proto_tree_add_item(ssl_dh_tree, hf->hf.hs_server_keyex_ys, tvb,
                        offset + 2, ys_len, ENC_NA);
    offset += 2 + ys_len;

    /* Signature (if non-anonymous KEX) */
    if (!anon) {
        dissect_ssl3_hnd_srv_keyex_sig(hf, tvb, pinfo, ssl_dh_tree, offset, offset_end, version);
    }
}

/* Only used in RSA-EXPORT cipher suites */
static void
dissect_ssl3_hnd_srv_keyex_rsa(ssl_common_dissect_t *hf, tvbuff_t *tvb, packet_info *pinfo,
                               proto_tree *tree, uint32_t offset, uint32_t offset_end,
                               uint16_t version)
{
    int         modulus_len, exponent_len;
    proto_tree *ssl_rsa_tree;

    ssl_rsa_tree = proto_tree_add_subtree(tree, tvb, offset, offset_end - offset,
                                 hf->ett.keyex_params, NULL, "RSA-EXPORT Server Params");

    /* modulus */
    modulus_len = tvb_get_ntohs(tvb, offset);
    proto_tree_add_item(ssl_rsa_tree, hf->hf.hs_server_keyex_modulus_len, tvb,
                        offset, 2, ENC_BIG_ENDIAN);
    proto_tree_add_item(ssl_rsa_tree, hf->hf.hs_server_keyex_modulus, tvb,
                        offset + 2, modulus_len, ENC_NA);
    offset += 2 + modulus_len;

    /* exponent */
    exponent_len = tvb_get_ntohs(tvb, offset);
    proto_tree_add_item(ssl_rsa_tree, hf->hf.hs_server_keyex_exponent_len,
                        tvb, offset, 2, ENC_BIG_ENDIAN);
    proto_tree_add_item(ssl_rsa_tree, hf->hf.hs_server_keyex_exponent,
                        tvb, offset + 2, exponent_len, ENC_NA);
    offset += 2 + exponent_len;

    /* Signature */
    dissect_ssl3_hnd_srv_keyex_sig(hf, tvb, pinfo, ssl_rsa_tree, offset, offset_end, version);
}

/* Used in RSA PSK and PSK cipher suites */
static uint32_t
dissect_ssl3_hnd_srv_keyex_psk(ssl_common_dissect_t *hf, tvbuff_t *tvb,
                               proto_tree *tree, uint32_t offset)
{
    unsigned     hint_len;
    proto_tree *ssl_psk_tree;

    ssl_psk_tree = proto_tree_add_subtree(tree, tvb, offset, -1,
                                 hf->ett.keyex_params, NULL, "PSK Server Params");

    /* hint */
    hint_len = tvb_get_ntohs(tvb, offset);
    proto_tree_add_item(ssl_psk_tree, hf->hf.hs_server_keyex_hint_len, tvb,
                        offset, 2, ENC_BIG_ENDIAN);
    proto_tree_add_item(ssl_psk_tree, hf->hf.hs_server_keyex_hint, tvb,
                        offset + 2, hint_len, ENC_NA);

    proto_item_set_len(ssl_psk_tree, 2 + hint_len);
    return 2 + hint_len;
}

/* Used in Diffie-Hellman PSK cipher suites */
static void
dissect_ssl3_hnd_srv_keyex_dhe_psk(ssl_common_dissect_t *hf, tvbuff_t *tvb, packet_info *pinfo,
                                   proto_tree *tree, uint32_t offset, uint32_t offset_end)
{
    /*
     *  struct {
     *      select (KeyExchangeAlgorithm) {
     *          case diffie_hellman_psk:
     *              opaque psk_identity_hint<0..2^16-1>;
     *              ServerDHParams params;
     *      };
     *  } ServerKeyExchange;
     */

    uint32_t psk_len = dissect_ssl3_hnd_srv_keyex_psk(hf, tvb, tree, offset);
    dissect_ssl3_hnd_srv_keyex_dhe(hf, tvb, pinfo, tree, offset + psk_len, offset_end, 0, true);
}

/* Used in EC Diffie-Hellman PSK cipher suites */
static void
dissect_ssl3_hnd_srv_keyex_ecdh_psk(ssl_common_dissect_t *hf, tvbuff_t *tvb, packet_info *pinfo,
                                    proto_tree *tree, uint32_t offset, uint32_t offset_end)
{
    /*
     *  struct {
     *      select (KeyExchangeAlgorithm) {
     *          case ec_diffie_hellman_psk:
     *              opaque psk_identity_hint<0..2^16-1>;
     *              ServerECDHParams params;
     *      };
     *  } ServerKeyExchange;
     */

    uint32_t psk_len = dissect_ssl3_hnd_srv_keyex_psk(hf, tvb, tree, offset);
    dissect_ssl3_hnd_srv_keyex_ecdh(hf, tvb, pinfo, tree, offset + psk_len, offset_end, 0, true);
}

/* Used in EC J-PAKE cipher suites */
static void
dissect_ssl3_hnd_srv_keyex_ecjpake(ssl_common_dissect_t *hf, tvbuff_t *tvb,
                                   proto_tree *tree, uint32_t offset, uint32_t offset_end)
{
    /*
     *  struct {
     *      ECPoint V;
     *      opaque r<1..2^8-1>;
     *  } ECSchnorrZKP;
     *
     *  struct {
     *      ECPoint X;
     *      ECSchnorrZKP zkp;
     *  } ECJPAKEKeyKP;
     *
     *  struct {
     *      ECParameters curve_params;
     *      ECJPAKEKeyKP ecjpake_key_kp;
     *  } ServerECJPAKEParams;
     *
     *  select (KeyExchangeAlgorithm) {
     *      case ecjpake:
     *          ServerECJPAKEParams params;
     *  } ServerKeyExchange;
     */

    int         point_len;
    proto_tree *ssl_ecjpake_tree;

    ssl_ecjpake_tree = proto_tree_add_subtree(tree, tvb, offset, offset_end - offset,
                                              hf->ett.keyex_params, NULL,
                                              "EC J-PAKE Server Params");

    offset = dissect_tls_ecparameters(hf, tvb, ssl_ecjpake_tree, offset, offset_end);
    if (offset >= offset_end)
        return; /* only named_curves are supported */

    /* ECJPAKEKeyKP.X */
    point_len = tvb_get_uint8(tvb, offset);
    proto_tree_add_item(ssl_ecjpake_tree, hf->hf.hs_server_keyex_xs_len, tvb,
                        offset, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(ssl_ecjpake_tree, hf->hf.hs_server_keyex_xs, tvb,
                        offset + 1, point_len, ENC_NA);
    offset += 1 + point_len;

    /* ECJPAKEKeyKP.zkp.V */
    point_len = tvb_get_uint8(tvb, offset);
    proto_tree_add_item(ssl_ecjpake_tree, hf->hf.hs_server_keyex_vs_len, tvb,
                        offset, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(ssl_ecjpake_tree, hf->hf.hs_server_keyex_vs, tvb,
                        offset + 1, point_len, ENC_NA);
    offset += 1 + point_len;

    /* ECJPAKEKeyKP.zkp.r */
    point_len = tvb_get_uint8(tvb, offset);
    proto_tree_add_item(ssl_ecjpake_tree, hf->hf.hs_server_keyex_rs_len, tvb,
                        offset, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(ssl_ecjpake_tree, hf->hf.hs_server_keyex_rs, tvb,
                        offset + 1, point_len, ENC_NA);
}

/* Only used in ECC-SM2-EXPORT cipher suites */
static void
dissect_ssl3_hnd_srv_keyex_ecc_sm2(ssl_common_dissect_t *hf, tvbuff_t *tvb, packet_info *pinfo,
                                   proto_tree *tree, uint32_t offset, uint32_t offset_end,
                                   uint16_t version)
{
    proto_tree *ssl_ecc_sm2_tree;

    ssl_ecc_sm2_tree = proto_tree_add_subtree(tree, tvb, offset, offset_end - offset,
                                              hf->ett.keyex_params, NULL, "ECC-SM2-EXPORT Server Params");

    /* Signature */
    dissect_ssl3_hnd_srv_keyex_sig(hf, tvb, pinfo, ssl_ecc_sm2_tree, offset, offset_end, version);
}
/* ServerKeyExchange algo-specific dissectors. }}} */

/* Client Key Exchange and Server Key Exchange handshake dissections. {{{ */
void
ssl_dissect_hnd_cli_keyex(ssl_common_dissect_t *hf, tvbuff_t *tvb,
                          proto_tree *tree, uint32_t offset, uint32_t length,
                          const SslSession *session)
{
    switch (ssl_get_keyex_alg(session->cipher)) {
    case KEX_DH_ANON: /* RFC 5246; DHE_DSS, DHE_RSA, DH_DSS, DH_RSA, DH_ANON: ClientDiffieHellmanPublic */
    case KEX_DH_DSS:
    case KEX_DH_RSA:
    case KEX_DHE_DSS:
    case KEX_DHE_RSA:
        dissect_ssl3_hnd_cli_keyex_dhe(hf, tvb, tree, offset, length);
        break;
    case KEX_DHE_PSK: /* RFC 4279; diffie_hellman_psk: psk_identity, ClientDiffieHellmanPublic */
        dissect_ssl3_hnd_cli_keyex_dhe_psk(hf, tvb, tree, offset, length);
        break;
    case KEX_ECDH_ANON: /* RFC 4492; ec_diffie_hellman: ClientECDiffieHellmanPublic */
    case KEX_ECDH_ECDSA:
    case KEX_ECDH_RSA:
    case KEX_ECDHE_ECDSA:
    case KEX_ECDHE_RSA:
        dissect_ssl3_hnd_cli_keyex_ecdh(hf, tvb, tree, offset, length);
        break;
    case KEX_ECDHE_PSK: /* RFC 5489; ec_diffie_hellman_psk: psk_identity, ClientECDiffieHellmanPublic */
        dissect_ssl3_hnd_cli_keyex_ecdh_psk(hf, tvb, tree, offset, length);
        break;
    case KEX_KRB5: /* RFC 2712; krb5: KerberosWrapper */
        /* XXX: implement support for KRB5 */
        proto_tree_add_expert_format(tree, NULL, &hf->ei.hs_ciphersuite_undecoded,
                                     tvb, offset, length,
                               "Kerberos ciphersuites (RFC 2712) are not implemented, contact Wireshark"
                               " developers if you want them to be supported");
        break;
    case KEX_PSK: /* RFC 4279; psk: psk_identity */
        dissect_ssl3_hnd_cli_keyex_psk(hf, tvb, tree, offset);
        break;
    case KEX_RSA: /* RFC 5246; rsa: EncryptedPreMasterSecret */
        dissect_ssl3_hnd_cli_keyex_rsa(hf, tvb, tree, offset, length, session);
        break;
    case KEX_RSA_PSK: /* RFC 4279; rsa_psk: psk_identity, EncryptedPreMasterSecret */
        dissect_ssl3_hnd_cli_keyex_rsa_psk(hf, tvb, tree, offset, length);
        break;
    case KEX_SRP_SHA: /* RFC 5054; srp: ClientSRPPublic */
    case KEX_SRP_SHA_DSS:
    case KEX_SRP_SHA_RSA:
        /* XXX: implement support for SRP_SHA* */
        proto_tree_add_expert_format(tree, NULL, &hf->ei.hs_ciphersuite_undecoded,
                                     tvb, offset, length,
                               "SRP_SHA ciphersuites (RFC 5054) are not implemented, contact Wireshark"
                               " developers if you want them to be supported");
        break;
    case KEX_ECJPAKE: /* https://tools.ietf.org/html/draft-cragie-tls-ecjpake-01 used in Thread Commissioning */
        dissect_ssl3_hnd_cli_keyex_ecjpake(hf, tvb, tree, offset, length);
        break;
    case KEX_ECC_SM2: /* GB/T 38636 */
        dissect_ssl3_hnd_cli_keyex_ecc_sm2(hf, tvb, tree, offset, length);
        break;
    default:
        proto_tree_add_expert(tree, NULL, &hf->ei.hs_ciphersuite_undecoded,
                              tvb, offset, length);
        break;
    }
}

void
ssl_dissect_hnd_srv_keyex(ssl_common_dissect_t *hf, tvbuff_t *tvb, packet_info *pinfo,
                          proto_tree *tree, uint32_t offset, uint32_t offset_end,
                          const SslSession *session)
{
    switch (ssl_get_keyex_alg(session->cipher)) {
    case KEX_DH_ANON: /* RFC 5246; ServerDHParams */
        dissect_ssl3_hnd_srv_keyex_dhe(hf, tvb, pinfo, tree, offset, offset_end, session->version, true);
        break;
    case KEX_DH_DSS: /* RFC 5246; not allowed */
    case KEX_DH_RSA:
        proto_tree_add_expert(tree, NULL, &hf->ei.hs_srv_keyex_illegal,
                              tvb, offset, offset_end - offset);
        break;
    case KEX_DHE_DSS: /* RFC 5246; dhe_dss, dhe_rsa: ServerDHParams, Signature */
    case KEX_DHE_RSA:
        dissect_ssl3_hnd_srv_keyex_dhe(hf, tvb, pinfo, tree, offset, offset_end, session->version, false);
        break;
    case KEX_DHE_PSK: /* RFC 4279; diffie_hellman_psk: psk_identity_hint, ServerDHParams */
        dissect_ssl3_hnd_srv_keyex_dhe_psk(hf, tvb, pinfo, tree, offset, offset_end);
        break;
    case KEX_ECDH_ANON: /* RFC 4492; ec_diffie_hellman: ServerECDHParams (without signature for anon) */
        dissect_ssl3_hnd_srv_keyex_ecdh(hf, tvb, pinfo, tree, offset, offset_end, session->version, true);
        break;
    case KEX_ECDHE_PSK: /* RFC 5489; psk_identity_hint, ServerECDHParams */
        dissect_ssl3_hnd_srv_keyex_ecdh_psk(hf, tvb, pinfo, tree, offset, offset_end);
        break;
    case KEX_ECDH_ECDSA: /* RFC 4492; ec_diffie_hellman: ServerECDHParams, Signature */
    case KEX_ECDH_RSA:
    case KEX_ECDHE_ECDSA:
    case KEX_ECDHE_RSA:
        dissect_ssl3_hnd_srv_keyex_ecdh(hf, tvb, pinfo, tree, offset, offset_end, session->version, false);
        break;
    case KEX_KRB5: /* RFC 2712; not allowed */
        proto_tree_add_expert(tree, NULL, &hf->ei.hs_srv_keyex_illegal,
                              tvb, offset, offset_end - offset);
        break;
    case KEX_PSK: /* RFC 4279; psk, rsa: psk_identity */
    case KEX_RSA_PSK:
        dissect_ssl3_hnd_srv_keyex_psk(hf, tvb, tree, offset);
        break;
    case KEX_RSA: /* only allowed if the public key in the server certificate is longer than 512 bits */
        dissect_ssl3_hnd_srv_keyex_rsa(hf, tvb, pinfo, tree, offset, offset_end, session->version);
        break;
    case KEX_ECC_SM2: /* GB/T 38636 */
        dissect_ssl3_hnd_srv_keyex_ecc_sm2(hf, tvb, pinfo, tree, offset, offset_end, session->version);
        break;
    case KEX_SRP_SHA: /* RFC 5054; srp: ServerSRPParams, Signature */
    case KEX_SRP_SHA_DSS:
    case KEX_SRP_SHA_RSA:
        /* XXX: implement support for SRP_SHA* */
        proto_tree_add_expert_format(tree, NULL, &hf->ei.hs_ciphersuite_undecoded,
                                     tvb, offset, offset_end - offset,
                               "SRP_SHA ciphersuites (RFC 5054) are not implemented, contact Wireshark"
                               " developers if you want them to be supported");
        break;
    case KEX_ECJPAKE: /* https://tools.ietf.org/html/draft-cragie-tls-ecjpake-01 used in Thread Commissioning */
        dissect_ssl3_hnd_srv_keyex_ecjpake(hf, tvb, tree, offset, offset_end);
        break;
    default:
        proto_tree_add_expert(tree, NULL, &hf->ei.hs_ciphersuite_undecoded,
                              tvb, offset, offset_end - offset);
        break;
    }
}
/* Client Key Exchange and Server Key Exchange handshake dissections. }}} */

void
tls13_dissect_hnd_key_update(ssl_common_dissect_t *hf, tvbuff_t *tvb,
                             proto_tree *tree, uint32_t offset)
{
    /* RFC 8446 Section 4.6.3
     *  enum {
     *      update_not_requested(0), update_requested(1), (255)
     *  } KeyUpdateRequest;
     *
     *  struct {
     *      KeyUpdateRequest request_update;
     *  } KeyUpdate;
     */
    proto_tree_add_item(tree, hf->hf.hs_key_update_request_update, tvb, offset, 1, ENC_NA);
}

void
ssl_common_register_ssl_alpn_dissector_table(const char *name,
    const char *ui_name, const int proto)
{
    ssl_alpn_dissector_table = register_dissector_table(name, ui_name,
        proto, FT_STRING, STRING_CASE_SENSITIVE);
    register_dissector_table_alias(ssl_alpn_dissector_table, "ssl.handshake.extensions_alpn_str");
}

void
ssl_common_register_dtls_alpn_dissector_table(const char *name,
    const char *ui_name, const int proto)
{
    dtls_alpn_dissector_table = register_dissector_table(name, ui_name,
        proto, FT_STRING, STRING_CASE_SENSITIVE);
    register_dissector_table_alias(ssl_alpn_dissector_table, "dtls.handshake.extensions_alpn_str");
}

void
ssl_common_register_options(module_t *module, ssl_common_options_t *options, bool is_dtls)
{
        prefs_register_string_preference(module, "psk", "Pre-Shared Key",
             "Pre-Shared Key as HEX string. Should be 0 to 16 bytes.",
             &(options->psk));

        if (is_dtls) {
            prefs_register_obsolete_preference(module, "keylog_file");
            prefs_register_static_text_preference(module, "keylog_file_removed",
                    "The (Pre)-Master-Secret log filename preference can be configured in the TLS protocol preferences.",
                    "Use the TLS protocol preference to configure the keylog file for both DTLS and TLS.");
            return;
        }

        prefs_register_filename_preference(module, "keylog_file", "(Pre)-Master-Secret log filename",
             "The name of a file which contains a list of \n"
             "(pre-)master secrets in one of the following formats:\n"
             "\n"
             "RSA <EPMS> <PMS>\n"
             "RSA Session-ID:<SSLID> Master-Key:<MS>\n"
             "CLIENT_RANDOM <CRAND> <MS>\n"
             "PMS_CLIENT_RANDOM <CRAND> <PMS>\n"
             "\n"
             "Where:\n"
             "<EPMS> = First 8 bytes of the Encrypted PMS\n"
             "<PMS> = The Pre-Master-Secret (PMS) used to derive the MS\n"
             "<SSLID> = The SSL Session ID\n"
             "<MS> = The Master-Secret (MS)\n"
             "<CRAND> = The Client's random number from the ClientHello message\n"
             "\n"
             "(All fields are in hex notation)",
             &(options->keylog_filename), false);
}

void
ssl_calculate_handshake_hash(SslDecryptSession *ssl_session, tvbuff_t *tvb, uint32_t offset, uint32_t length)
{
    if (ssl_session && ssl_session->session.version != TLSV1DOT3_VERSION && !(ssl_session->state & SSL_MASTER_SECRET)) {
        uint32_t old_length = ssl_session->handshake_data.data_len;
        ssl_debug_printf("Calculating hash with offset %d %d\n", offset, length);
        if (tvb) {
            if (tvb_bytes_exist(tvb, offset, length)) {
                ssl_session->handshake_data.data = (unsigned char *)wmem_realloc(wmem_file_scope(), ssl_session->handshake_data.data, old_length + length);
                tvb_memcpy(tvb, ssl_session->handshake_data.data + old_length, offset, length);
                ssl_session->handshake_data.data_len += length;
            }
        } else {
            /* DTLS calculates the hash as if each handshake message had been
             * sent as a single fragment (RFC 6347, section 4.2.6) and passes
             * in a null tvbuff to add 3 bytes for a zero fragment offset.
             */
            DISSECTOR_ASSERT_CMPINT(length, <, 4);
            ssl_session->handshake_data.data = (unsigned char *)wmem_realloc(wmem_file_scope(), ssl_session->handshake_data.data, old_length + length);
            memset(ssl_session->handshake_data.data + old_length, 0, length);
            ssl_session->handshake_data.data_len += length;
        }
    }
}


/*
 * Editor modelines  -  https://www.wireshark.org/tools/modelines.html
 *
 * Local variables:
 * c-basic-offset: 4
 * tab-width: 8
 * indent-tabs-mode: nil
 * End:
 *
 * vi: set shiftwidth=4 tabstop=8 expandtab:
 * :indentSize=4:tabSize=8:noTabs=true:
 */
