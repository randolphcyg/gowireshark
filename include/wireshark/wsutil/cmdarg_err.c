/* cmdarg_err.c
 * Routines to report command-line argument errors.
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "config.h"

#include "cmdarg_err.h"

static void (*print_err)(const char *, va_list ap);
static void (*print_err_cont)(const char *, va_list ap);

/*
 * Set the reporting functions for error messages.
 */
void
cmdarg_err_init(void (*err)(const char *, va_list),
                void (*err_cont)(const char *, va_list))
{
    print_err = err;
    print_err_cont = err_cont;
}

/*
 * Report an error in command-line arguments.
 */
void
vcmdarg_err(const char *fmt, va_list ap)
{
    print_err(fmt, ap);
}

void
cmdarg_err(const char *fmt, ...)
{
    va_list ap;

    va_start(ap, fmt);
    print_err(fmt, ap);
    va_end(ap);
}

/*
 * Report additional information for an error in command-line arguments.
 */
void
cmdarg_err_cont(const char *fmt, ...)
{
    va_list ap;

    va_start(ap, fmt);
    print_err_cont(fmt, ap);
    va_end(ap);
}

/*
 * Error printing routines that report to the standard error.
 */
void
stderr_cmdarg_err(const char *msg_format, va_list ap)
{
    fprintf(stderr, "%s: ", g_get_prgname());
    vfprintf(stderr, msg_format, ap);
    fprintf(stderr, "\n");
}

void
stderr_cmdarg_err_cont(const char *msg_format, va_list ap)
{
    vfprintf(stderr, msg_format, ap);
    fprintf(stderr, "\n");
}
