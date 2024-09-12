/** @file
 * Types utility definitions
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef __TYPE_UTIL_H__
#define __TYPE_UTIL_H__

#include <inttypes.h>
#include "include/ws_symbol_export.h"

/*
 * uint64_t to double conversions taken from gstutils.h of GStreamer project
 *
 * GStreamer
 * Copyright (C) 1999,2000 Erik Walthinsen <omega@cse.ogi.edu>
 *                    2000 Wim Taymans <wtay@chello.be>
 *                    2002 Thomas Vander Stichele <thomas@apestaart.org>
 *
 * gstutils.h: Header for various utility functions
 *
 * GNU GPL v2
 *
 */

WS_DLL_PUBLIC
uint64_t        type_util_double_to_uint64(double value);
WS_DLL_PUBLIC
double          type_util_uint64_to_double(uint64_t value);

#ifdef _WIN32
#define         double_to_uint64(value)   type_util_double_to_uint64(value)
#define         uint64_to_double(value)   type_util_uint64_to_double(value)
#else
#define         double_to_uint64(value)   ((uint64_t)(value))
#define         uint64_to_double(value)   ((double)(value))
#endif

#endif /* __TYPE_UTIL_H__ */
