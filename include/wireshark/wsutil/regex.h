/** @file
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef __WSUTIL_REGEX_H__
#define __WSUTIL_REGEX_H__

#include <include/wireshark.h>

#ifdef __cplusplus
extern "C" {
#endif

struct _ws_regex;
typedef struct _ws_regex ws_regex_t;

WS_DLL_PUBLIC ws_regex_t *
ws_regex_compile(const char *patt, char **errmsg);

#define WS_REGEX_CASELESS       (1U << 0)
/* By default UTF-8 is off. This option also prevents it from being
 * turned on using a pattern option. */
#define WS_REGEX_NEVER_UTF      (1U << 1)
#define WS_REGEX_ANCHORED       (1U << 2)

WS_DLL_PUBLIC ws_regex_t *
ws_regex_compile_ex(const char *patt, ssize_t size, char **errmsg, unsigned flags);

/** Matches a null-terminated subject string. */
WS_DLL_PUBLIC bool
ws_regex_matches(const ws_regex_t *re, const char *subj);

/** Matches a subject string length in 8 bit code units. */
WS_DLL_PUBLIC bool
ws_regex_matches_length(const ws_regex_t *re,
                        const char *subj, ssize_t subj_length);

/** Returns start and end position of the matched substring.
 *
 * @note Using a nonzero subj_offset produces different results than
 * passing a pointer to the later offset as subj when the pattern
 * begins with a lookbehind.
 *
 *  pos_vect[0] is first codepoint in the matched substring.
 *  pos_vect[1] is first codepoint past the matched substring.
 *  pos_vect[1] - pos_vect[0] is the matched substring length.
 *
 */
WS_DLL_PUBLIC bool
ws_regex_matches_pos(const ws_regex_t *re,
                        const char *subj, ssize_t subj_length,
                        size_t subj_offset, size_t pos_vect[2]);

WS_DLL_PUBLIC void
ws_regex_free(ws_regex_t *re);

WS_DLL_PUBLIC const char *
ws_regex_pattern(const ws_regex_t *re);

#ifdef __cplusplus
}
#endif

#endif /* __WSUTIL_REGEX_H__ */
