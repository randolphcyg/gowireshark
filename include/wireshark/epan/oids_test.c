/* oids_test.c
 * ASN.1 Object Identifier handling tests
 * Copyright 2013, Edward J. Beroset <beroset@ieee.org>
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "config.h"
#undef G_DISABLE_ASSERT

#include <stdio.h>
#include <string.h>
#include <glib.h>

#include "oids.h"
#include <epan/wmem_scopes.h>

#include <include/ws_diag_control.h>

static wmem_allocator_t *test_scope;

typedef struct
{
    const char *string;
    const char *resolved;
    unsigned encoded_len;
    const uint8_t *encoded;
    unsigned subids_len;
    uint32_t subids[];
} example_s;

DIAG_OFF_PEDANTIC
example_s ex1 = {"2.1.1", "joint-iso-itu-t.1.1", 2, (const uint8_t *)"\x51\x01", 3, {2,1,1} };
example_s ex2rel = {".81.1", ".81.1", 2, (const uint8_t*)"\x51\x01", 2, {81,1} };
example_s ex3 = {"2.1.127.16383.2097151.268435455.128.16384.2097152.268435456",
    "joint-iso-itu-t.1.127.16383.2097151.268435455.128.16384.2097152.268435456",
    25, (const uint8_t*)"\x51\x7f\xff\x7f\xff\xff\x7f\xff\xff\xff\x7f\x81\x00\x81\x80\x00\x81\x80\x80\x00\x81\x80\x80\x80\x00",
    10, { 2, 1, 0x7F, 0x3FFF, 0x1FFFFF, 0x0FFFFFFF, 1+0x7F, 1+0x3FFF, 1+0x1FFFFF, 1+0x0FFFFFFF} };

example_s ex4 = {"2.1", "joint-iso-itu-t.1", 1, (const uint8_t*)"\x51", 2, {2,1} };
example_s ex5 = {"2", "joint-iso-itu-t", 0, NULL, 1, {2} };
example_s ex6rel = {".81.127.16383.2097151.268435455.128.16384.2097152.268435456",
    ".81.127.16383.2097151.268435455.128.16384.2097152.268435456",
    25, (const uint8_t*)"\x51\x7f\xff\x7f\xff\xff\x7f\xff\xff\xff\x7f\x81\x00\x81\x80\x00\x81\x80\x80\x00\x81\x80\x80\x80\x00",
    9, { 81, 0x7F, 0x3FFF, 0x1FFFFF, 0x0FFFFFFF, 1+0x7F, 1+0x3FFF, 1+0x1FFFFF, 1+0x0FFFFFFF} };
example_s ex7 = {"2.1.1", "joint-iso-itu-t.asn1.basic-encoding", 2, (const uint8_t*)"\x51\x01", 3, {2,1,1} };
DIAG_ON_PEDANTIC

/*
 * These test are organized in order of the appearance, in oids.h, of
 * the basic oids.c functions that they test.  This makes it easier to
 * get a quick understanding of both the testing and the organization
 * of oids.h.
 *
 * Tests are named /oids/2<desttype>/<srctype>[<extra>]
 * where <desttype> is the resulting type of the conversion,
 * <srctype> is the source type and <extra> is any additional
 * information to make the test name unique.
 *
 * The types, for the purpose of this naming convention, are
 * encoded, subids, string and resolved, both, struct.
 */

/* OIDS TESTING FUNCTIONS (/oids/2subids/) */

static void
oids_test_2subids_encoded(void)
{
    uint32_t *subids = NULL;
    unsigned len;
    unsigned i;

    len = oid_encoded2subid(NULL, ex1.encoded, ex1.encoded_len, &subids);
    g_assert_true(len == ex1.subids_len);
    for (i=0; i < len; i++)
        g_assert_true(subids[i] == ex1.subids[i]);
    wmem_free(NULL, subids);
}

static void
oids_test_2subids_encoded_long(void)
{
    uint32_t *subids = NULL;
    unsigned len;
    unsigned i;

    len = oid_encoded2subid(NULL, ex3.encoded, ex3.encoded_len, &subids);
    g_assert_true(len == ex3.subids_len);
    for (i=0; i < len; i++)
        g_assert_true(subids[i] == ex3.subids[i]);
    wmem_free(NULL, subids);
}

static void
oids_test_2subids_encoded_absviasub(void)
{
    uint32_t *subids = NULL;
    unsigned len;
    unsigned i;

    len = oid_encoded2subid_sub(NULL, ex1.encoded, ex1.encoded_len, &subids, true);
    g_assert_true(len == ex1.subids_len);
    for (i=0; i < len; i++)
        g_assert_true(subids[i] == ex1.subids[i]);
    wmem_free(NULL, subids);
}

static void
oids_test_2subids_encoded_relviasub(void)
{
    uint32_t *subids = NULL;
    unsigned len;
    unsigned i;

    len = oid_encoded2subid_sub(NULL, ex2rel.encoded, ex2rel.encoded_len, &subids, false);
    g_assert_true(len == ex2rel.subids_len);
    for (i=0; i < len; i++)
        g_assert_true(subids[i] == ex2rel.subids[i]);
    wmem_free(NULL, subids);
}

static void
oids_test_2subids_string(void)
{
    uint32_t *subids = NULL;
    unsigned len, i;

    len = oid_string2subid(test_scope, ex1.string, &subids);
    g_assert_true(len == ex1.subids_len);
    for (i=0; i < len; i++)
        g_assert_true(subids[i] == ex1.subids[i]);
}

static void
oids_test_2subids_string_tooshort(void)
{
    uint32_t *subids = NULL;
    unsigned len, i;

    len = oid_string2subid(test_scope, ex5.string, &subids);
    g_assert_true(len == ex5.subids_len);
    for (i=0; i < len; i++)
        g_assert_true(subids[i] == ex5.subids[i]);
}

/* OIDS TESTING FUNCTIONS (/oids/2encoded/) */

static void
oids_test_2encoded_string_simple(void)
{
    uint8_t *encoded = NULL;
    unsigned len;

    len = oid_string2encoded(NULL, ex1.string, &encoded);
    g_assert_true(len == ex1.encoded_len);
    g_assert_true(0 == memcmp(encoded, ex1.encoded, len));
    wmem_free(NULL, encoded);
}

static void
oids_test_2encoded_string_short(void)
{
    uint8_t *encoded = NULL;
    unsigned len;

    len = oid_string2encoded(NULL, ex4.string, &encoded);
    g_assert_true(len == ex4.encoded_len);
    g_assert_true(0 == memcmp(encoded, ex4.encoded, len));
    wmem_free(NULL, encoded);
}

static void
oids_test_2encoded_string_long(void)
{
    uint8_t *encoded = NULL;
    unsigned len;

    len = oid_string2encoded(NULL, ex3.string, &encoded);
    g_assert_true(len == ex3.encoded_len);
    g_assert_true(0 == memcmp(encoded, ex3.encoded, len));
    wmem_free(NULL, encoded);
}

static void
oids_test_2encoded_string_tooshort(void)
{
    uint8_t *encoded = NULL;
    unsigned len;

    len = oid_string2encoded(NULL, ex5.string, &encoded);
    g_assert_true(len == ex5.encoded_len);
    g_assert_true(0 == memcmp(encoded, ex5.encoded, len));
    wmem_free(NULL, encoded);
}

static void
oids_test_2encoded_subids_simple(void)
{
    uint8_t *encoded = NULL;
    unsigned len;

    len = oid_subid2encoded(NULL, ex1.subids_len, ex1.subids, &encoded);
    g_assert_true(len == ex1.encoded_len);
    g_assert_true(0 == memcmp(encoded, ex1.encoded, len));
    wmem_free(NULL, encoded);
}

static void
oids_test_2encoded_subids_bad(void)
{
    uint8_t *encoded = NULL;
    unsigned len;

    len = oid_subid2encoded(NULL, ex5.subids_len, ex5.subids, &encoded);
    g_assert_true(len == ex5.encoded_len);
    g_assert_true(0 == memcmp(encoded, ex5.encoded, len));
    wmem_free(NULL, encoded);
}

/* OIDS TESTING FUNCTIONS (/oids/2string/) */

static void
oids_test_2string_encoded(void)
{
    char* oid;

    oid = oid_encoded2string(NULL, ex3.encoded, ex3.encoded_len);
    g_assert_cmpstr(oid, ==, ex3.string);
    wmem_free(NULL, oid);
}

static void
oids_test_2string_encoded_rel(void)
{
    char* oid;

    oid = rel_oid_encoded2string(NULL, ex6rel.encoded, ex3.encoded_len);
    g_assert_cmpstr(oid, ==, ex6rel.string);
    wmem_free(NULL, oid);
}


static void
oids_test_2string_subids_abs(void)
{
    char* oid;

    oid = oid_subid2string(NULL, ex1.subids, ex1.subids_len);
    g_assert_cmpstr(oid, ==, ex1.string);
    wmem_free(NULL, oid);
}

static void
oids_test_2string_subids_rel(void)
{
    char* oid;

    oid = rel_oid_subid2string(NULL, ex2rel.subids, ex2rel.subids_len, false);
    g_assert_cmpstr(oid, ==, ex2rel.string);
    wmem_free(NULL, oid);
}

static void
oids_test_2string_subids_absviarel(void)
{
    char* oid;

    oid = rel_oid_subid2string(NULL, ex1.subids, ex1.subids_len, true);
    g_assert_cmpstr(oid, ==, ex1.string);
    wmem_free(NULL, oid);
}

static void
oids_test_2string_subids_relsizes(void)
{
    char* oid;

    oid = rel_oid_subid2string(NULL, ex6rel.subids, ex6rel.subids_len, false);
    g_assert_cmpstr(oid, ==, ex6rel.string);
    wmem_free(NULL, oid);
}

/* OIDS TESTING FUNCTIONS (/oids/2resolved/) */

static void
oids_test_2resolved_subids(void)
{
    char* oid;

    oid = oid_resolved(NULL, ex1.subids_len, ex1.subids);
    g_assert_cmpstr(oid, ==, ex1.resolved);
    wmem_free(NULL, oid);
}

static void
oids_test_2resolved_encoded(void)
{
    char* oid;

    oid = oid_resolved_from_encoded(NULL, ex1.encoded, ex1.encoded_len);
    g_assert_cmpstr(oid, ==, ex1.resolved);
    wmem_free(NULL, oid);
}

static void
oids_test_2resolved_encoded_rel(void)
{
    char* oid;

    oid = rel_oid_resolved_from_encoded(NULL, ex2rel.encoded, ex2rel.encoded_len);
    g_assert_cmpstr(oid, ==, ex2rel.string);
    wmem_free(NULL, oid);
}

static void
oids_test_2resolved_string(void)
{
    char* oid;

    oid = oid_resolved_from_string(NULL, ex1.string);
    g_assert_cmpstr(oid, ==, ex1.resolved);
    wmem_free(NULL, oid);
}

/* OIDS TESTING FUNCTIONS (/oids/2both/) */

static void
oids_test_2both_subids(void)
{
    char* resolved;
    char* oid;

    oid_both(NULL, ex1.subids_len, ex1.subids, &resolved, &oid);
    g_assert_cmpstr(resolved, ==, ex1.resolved);
    g_assert_cmpstr(oid, ==, ex1.string);
    wmem_free(NULL, resolved);
    wmem_free(NULL, oid);
}

static void
oids_test_2both_encoded(void)
{
    char* resolved;
    char* oid;

    oid_both_from_encoded(NULL, ex1.encoded, ex1.encoded_len, &resolved, &oid);
    g_assert_cmpstr(resolved, ==, ex1.resolved);
    g_assert_cmpstr(oid, ==, ex1.string);
    wmem_free(NULL, resolved);
    wmem_free(NULL, oid);
}

static void
oids_test_2both_string(void)
{
    char* resolved;
    char* oid;

    oid_both_from_string(NULL, ex1.string, &resolved, &oid);
    g_assert_cmpstr(resolved, ==, ex1.resolved);
    g_assert_cmpstr(oid, ==, ex1.string);
    wmem_free(NULL, resolved);
    wmem_free(NULL, oid);
}

/* OIDS TESTING FUNCTIONS (/oids/2both/) */

static void
oids_test_2struct_subids(void)
{
    unsigned matched;
    unsigned left;
    oid_info_t *st;

    st = oid_get(ex1.subids_len, ex1.subids, &matched, &left);
    g_assert_true(matched == 1);
    g_assert_true(left == ex1.subids_len - 1);
    g_assert_true(st != NULL);
    g_assert_cmpstr(st->name, ==, "joint-iso-itu-t");
}

static void
oids_test_2struct_encoded(void)
{
    unsigned matched;
    unsigned left;
    uint32_t *subids = NULL;
    oid_info_t *st;
    unsigned len, i;

    st = oid_get_from_encoded(NULL, ex1.encoded, ex1.encoded_len, &subids, &matched, &left);
    g_assert_true(matched == 1);
    g_assert_true(left == ex1.subids_len - 1);
    g_assert_true(st != NULL);
    g_assert_cmpstr(st->name, ==, "joint-iso-itu-t");
    len = matched + left;
    g_assert_true(len == ex1.subids_len);
    for (i=0; i < len; i++)
        g_assert_true(subids[i] == ex1.subids[i]);
    wmem_free(NULL, subids);
}

static void
oids_test_2struct_string(void)
{
    unsigned matched;
    unsigned left;
    uint32_t *subids;
    oid_info_t *st;
    unsigned len, i;

    st = oid_get_from_string(test_scope, ex1.string, &subids, &matched, &left);
    g_assert_true(matched == 1);
    g_assert_true(left == ex1.subids_len - 1);
    g_assert_true(st != NULL);
    g_assert_cmpstr(st->name, ==, "joint-iso-itu-t");
    len = matched + left;
    g_assert_true(len == ex1.subids_len);
    for (i=0; i < len; i++)
        g_assert_true(subids[i] == ex1.subids[i]);
}

static void
oids_test_add_subids(void)
{
    char* oid;

    oid_add(ex7.resolved, ex7.subids_len, ex7.subids);
    oid = oid_resolved(NULL, ex7.subids_len, ex7.subids);
    g_assert_cmpstr(oid, ==, ex7.resolved);
    wmem_free(NULL, oid);
}

static void
oids_test_add_encoded(void)
{
    char* oid;

    oid_add_from_encoded(ex7.resolved, ex7.encoded, ex7.encoded_len);
    oid = oid_resolved(NULL, ex7.subids_len, ex7.subids);
    g_assert_cmpstr(oid, ==, ex7.resolved);
    wmem_free(NULL, oid);
}

static void
oids_test_add_string(void)
{
    char* oid;

    oid_add_from_string(ex7.resolved, ex7.string);
    oid = oid_resolved(NULL, ex7.subids_len, ex7.subids);
    g_assert_cmpstr(oid, ==, ex7.resolved);
    wmem_free(NULL, oid);
}

int
main(int argc, char **argv)
{
    int result;

    g_test_init(&argc, &argv, NULL);

    /* /oids/2encoded */
    g_test_add_func("/oids/2encoded/subids/simple",   oids_test_2encoded_subids_simple);
    g_test_add_func("/oids/2encoded/subids/bad",   oids_test_2encoded_subids_bad);
    g_test_add_func("/oids/2encoded/string/simple",   oids_test_2encoded_string_simple);
    g_test_add_func("/oids/2encoded/string/short",   oids_test_2encoded_string_short);
    g_test_add_func("/oids/2encoded/string/long",   oids_test_2encoded_string_long);
    g_test_add_func("/oids/2encoded/string/tooshort",   oids_test_2encoded_string_tooshort);

    /* /oids/2subids */
    g_test_add_func("/oids/2subids/string",   oids_test_2subids_string);
    g_test_add_func("/oids/2subids/string/tooshort",   oids_test_2subids_string_tooshort);
    g_test_add_func("/oids/2subids/encoded",   oids_test_2subids_encoded);
    g_test_add_func("/oids/2subids/encoded/long",   oids_test_2subids_encoded_long);
    g_test_add_func("/oids/2subids/encoded/absviasub",   oids_test_2subids_encoded_absviasub);
    g_test_add_func("/oids/2subids/encoded/relviasub",   oids_test_2subids_encoded_relviasub);


    /* /oids/2string */
    g_test_add_func("/oids/2string/subids/abs",   oids_test_2string_subids_abs);
    g_test_add_func("/oids/2string/subids/rel",   oids_test_2string_subids_rel);
    g_test_add_func("/oids/2string/subids/absviarel",   oids_test_2string_subids_absviarel);
    g_test_add_func("/oids/2string/subids/relsizes",   oids_test_2string_subids_relsizes);
    g_test_add_func("/oids/2string/encoded",   oids_test_2string_encoded);
    g_test_add_func("/oids/2string/encoded/rel",   oids_test_2string_encoded_rel);

    /* /oids/2resolved */
    g_test_add_func("/oids/2resolved/subids",   oids_test_2resolved_subids);
    g_test_add_func("/oids/2resolved/encoded",   oids_test_2resolved_encoded);
    g_test_add_func("/oids/2resolved/encoded/rel",   oids_test_2resolved_encoded_rel);
    g_test_add_func("/oids/2resolved/string",   oids_test_2resolved_string);

    /* /oids/2both */
    g_test_add_func("/oids/2both/subids",   oids_test_2both_subids);
    g_test_add_func("/oids/2both/encoded",   oids_test_2both_encoded);
    g_test_add_func("/oids/2both/string",   oids_test_2both_string);

    /* /oids/2struct */
    g_test_add_func("/oids/2struct/subids",   oids_test_2struct_subids);
    g_test_add_func("/oids/2struct/encoded",   oids_test_2struct_encoded);
    g_test_add_func("/oids/2struct/string",   oids_test_2struct_string);

    /* /oids/add */
    g_test_add_func("/oids/add/subids",   oids_test_add_subids);
    g_test_add_func("/oids/add/encoded",   oids_test_add_encoded);
    g_test_add_func("/oids/add/string",   oids_test_add_string);

    wmem_init_scopes();
    test_scope = wmem_allocator_new(WMEM_ALLOCATOR_STRICT);
    oids_init();
    result = g_test_run();
    oids_cleanup();
    wmem_destroy_allocator(test_scope);
    wmem_cleanup_scopes();

    return result;
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
