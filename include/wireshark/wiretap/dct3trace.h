/** @file
 *
 * Wiretap Library
 * Copyright (c) 1998 by Gilbert Ramirez <gram@alumni.rice.edu>
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef __W_DCT3TRACE_H__
#define __W_DCT3TRACE_H__
#include <glib.h>
#include "wtap.h"
#include "include/ws_symbol_export.h"

wtap_open_return_val dct3trace_open(wtap *wth, int *err, char **err_info);

#endif
