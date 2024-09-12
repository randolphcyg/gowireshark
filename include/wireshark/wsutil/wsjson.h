/** @file
 *
 * JSON parsing functions.
 *
 * Copyright 2016, Dario Lombardo
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef __WSJSON_H__
#define __WSJSON_H__

#include "include/ws_symbol_export.h"

#include <inttypes.h>
#include <stdbool.h>

#include "jsmn.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * Check if a buffer is json an returns true if it is.
 */
WS_DLL_PUBLIC bool json_validate(const uint8_t *buf, const size_t len);

WS_DLL_PUBLIC int json_parse(const char *buf, jsmntok_t *tokens, unsigned int max_tokens);

/**
 * Get the pointer to an object belonging to parent object and named as the name variable.
 * Returns NULL if not found.
 */
WS_DLL_PUBLIC jsmntok_t *json_get_object(const char *buf, jsmntok_t *parent, const char *name);

/**
 * Get the pointer to an array belonging to parent object and named as the name variable.
 * Returns NULL if not found.
 */
WS_DLL_PUBLIC jsmntok_t *json_get_array(const char *buf, jsmntok_t *parent, const char *name);

/**
 * Get the number of elements of an array.
 * Returns -1 if the JSON objecct is not an array.
 */
WS_DLL_PUBLIC int json_get_array_len(jsmntok_t *array);

/**
 * Get the pointer to idx element of an array.
 * Returns NULL if not found.
 */
WS_DLL_PUBLIC jsmntok_t *json_get_array_index(jsmntok_t *parent, int idx);

/**
 * Get the unescaped value of a string object belonging to parent object and named as the name variable.
 * Returns NULL if not found. Caution: it modifies input buffer.
 */
WS_DLL_PUBLIC char *json_get_string(char *buf, jsmntok_t *parent, const char *name);

/**
 * Get the value of a number object belonging to parent object and named as the name variable.
 * Returns false if not found. Caution: it modifies input buffer.
 * Scientific notation not supported yet.
 */
WS_DLL_PUBLIC bool json_get_double(char *buf, jsmntok_t *parent, const char *name, double *val);

/**
 * Get the value of a boolean belonging to parent object and named as the name variable.
 * Returns false if not found. (Not the same as the boolean present but false.)
 */
WS_DLL_PUBLIC bool json_get_boolean(char *buf, jsmntok_t *parent, const char *name, bool *val);

/**
 * Decode the contents of a JSON string value by overwriting the input data.
 * Returns true on success and false if invalid characters were encountered.
 */
WS_DLL_PUBLIC bool json_decode_string_inplace(char *text);

#ifdef __cplusplus
}
#endif

#endif

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
