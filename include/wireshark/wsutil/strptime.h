/** @file
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef __STRPTIME_H__
#define __STRPTIME_H__

#include <include/ws_symbol_export.h>
#include <time.h>

/*
 * Version of "strptime()", for the benefit of OSes that don't have it.
 */
WS_DLL_LOCAL
char *strptime_gnulib(const char *s, const char *format, struct tm *tm);

#endif
