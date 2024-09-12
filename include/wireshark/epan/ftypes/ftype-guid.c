/*
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 2001 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "config.h"

#include <string.h>
#include <stdlib.h>

#include <ftypes-int.h>
#include <epan/guid-utils.h>
#include <epan/to_str.h>
#include <wsutil/array.h>

static void
guid_fvalue_set_guid(fvalue_t *fv, const e_guid_t *value)
{
    fv->value.guid = *value;
}

static const e_guid_t *
value_get(fvalue_t *fv)
{
    return &(fv->value.guid);
}

static bool
get_guid(const char *s, e_guid_t *guid)
{
    size_t i, n;
    const char *p;
    char digits[3];
    static const char fmt[] = "XXXXXXXX-XXXX-XXXX-XXXX-XXXXXXXXXXXX";
    const size_t fmtchars = sizeof(fmt) - 1;

    n = strnlen(s, fmtchars);
    if (n != fmtchars)
        return false;
    for (i=0; i<n; i++) {
        if (fmt[i] == 'X') {
            if (!g_ascii_isxdigit(s[i]))
                return false;
        } else {
            if (s[i] != fmt[i])
                return false;
        }
    }

    p = s;
    guid->data1 = (uint32_t)strtoul(p, NULL, 16);
    p += 9;
    guid->data2 = (uint16_t)strtoul(p, NULL, 16);
    p += 5;
    guid->data3 = (uint16_t)strtoul(p, NULL, 16);
    p += 5;
    for (i=0; i < sizeof(guid->data4); i++) {
        if (*p == '-') p++;
        digits[0] = *(p++);
        digits[1] = *(p++);
        digits[2] = '\0';
        guid->data4[i] = (uint8_t)strtoul(digits, NULL, 16);
    }
    return true;
}

static bool
guid_from_literal(fvalue_t *fv, const char *s, bool allow_partial_value _U_, char **err_msg)
{
     e_guid_t guid;

    if (!get_guid(s, &guid)) {
        if (err_msg != NULL)
            *err_msg = ws_strdup_printf("\"%s\" is not a valid GUID.", s);
        return false;
    }

    fv->value.guid = guid;
    return true;
}

static char *
guid_to_repr(wmem_allocator_t *scope, const fvalue_t *fv, ftrepr_t rtype _U_, int field_display _U_)
{
    return guid_to_str(scope, &fv->value.guid);
}

static enum ft_result
cmp_order(const fvalue_t *a, const fvalue_t *b, int *cmp)
{
    *cmp = memcmp(&a->value.guid, &b->value.guid, sizeof(e_guid_t));
    return FT_OK;
}

static unsigned
value_hash(const fvalue_t *fv)
{
    return guid_hash(&fv->value.guid);
}

void
ftype_register_guid(void)
{

    static const ftype_t guid_type = {
        FT_GUID,              /* ftype */
        GUID_LEN,            /* wire_size */
        NULL,                /* new_value */
        NULL,                /* copy_value */
        NULL,                /* free_value */
        guid_from_literal,   /* val_from_literal */
        NULL,                /* val_from_string */
        NULL,                /* val_from_charconst */
        NULL,                /* val_from_uinteger64 */
        NULL,                /* val_from_sinteger64 */
        NULL,                /* val_from_double */
        guid_to_repr,        /* val_to_string_repr */

        NULL,                /* val_to_uinteger64 */
        NULL,                /* val_to_sinteger64 */
        NULL,                /* val_to_double */

        { .set_value_guid = guid_fvalue_set_guid }, /* union set_value */
        { .get_value_guid = value_get },             /* union get_value */

        cmp_order,
        NULL,
        NULL,                /* cmp_matches */

        value_hash,          /* hash */
        NULL,
        NULL,
        NULL,
        NULL,
        NULL,
        NULL,                /* unary_minus */
        NULL,                /* add */
        NULL,                /* subtract */
        NULL,                /* multiply */
        NULL,                /* divide */
        NULL,                /* modulo */
    };

    ftype_register(FT_GUID, &guid_type);
}

void
ftype_register_pseudofields_guid(int proto)
{
    static int hf_ft_guid;

    static hf_register_info hf_ftypes[] = {
            { &hf_ft_guid,
                { "FT_GUID", "_ws.ftypes.guid",
                    FT_GUID, BASE_NONE, NULL, 0x00,
                    NULL, HFILL }
            },
    };

    proto_register_field_array(proto, hf_ftypes, array_length(hf_ftypes));
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
