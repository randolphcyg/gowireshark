/** @file
 *
 * Wiretap Library
 * Copyright (c) 1998 by Gilbert Ramirez <gram@alumni.rice.edu>
 *
 * Support for Busmaster log file format
 * Copyright (c) 2019 by Maksim Salau <maksim.salau@gmail.com>
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef BUSMASTER_PRIV_H__
#define BUSMASTER_PRIV_H__

#include <gmodule.h>
#include <wiretap/wtap.h>
#include <wiretap/socketcan.h>

//#define BUSMASTER_DEBUG
//#define BUSMASTER_PARSER_TRACE

typedef enum {
    LOG_ENTRY_ERROR = -1,
    LOG_ENTRY_NONE = 0,
    LOG_ENTRY_EMPTY,
    LOG_ENTRY_HEADER,
    LOG_ENTRY_FOOTER,
    LOG_ENTRY_FOOTER_AND_HEADER,
    LOG_ENTRY_MSG,
    LOG_ENTRY_EOF,
} log_entry_type_t;

typedef enum {
    PROTOCOL_UNKNOWN = 0,
    PROTOCOL_CAN,
    PROTOCOL_LIN,
    PROTOCOL_J1939,
} protocol_type_t;

typedef enum {
    DATA_MODE_UNKNOWN = 0,
    DATA_MODE_HEX,
    DATA_MODE_DEC,
} data_mode_t;

typedef enum {
    TIME_MODE_UNKNOWN = 0,
    TIME_MODE_ABSOLUTE,
    TIME_MODE_SYSTEM,
    TIME_MODE_RELATIVE,
} time_mode_t;

typedef enum {
    MSG_TYPE_STD,
    MSG_TYPE_EXT,
    MSG_TYPE_STD_RTR,
    MSG_TYPE_EXT_RTR,
    MSG_TYPE_STD_FD,
    MSG_TYPE_EXT_FD,
    MSG_TYPE_ERR,
} msg_type_t;

typedef struct {
    unsigned year;
    unsigned month;
    unsigned day;
} msg_date_t;

typedef struct {
    unsigned hours;
    unsigned minutes;
    unsigned seconds;
    unsigned micros;
} msg_time_t;

typedef struct {
    msg_date_t date;
    msg_time_t time;
} msg_date_time_t;

typedef struct {
    unsigned   length;
    uint8_t    data[CANFD_MAX_DLEN];
} msg_data_t;

typedef struct {
    msg_time_t timestamp;
    msg_type_t type;
    uint32_t   id;
    msg_data_t data;
} msg_t;

typedef struct {
    int64_t v0;
    int64_t v1;
    int64_t v2;
    int64_t v3;
} token_t;

typedef struct {
    int64_t     file_start_offset;
    int64_t     file_end_offset;
    protocol_type_t  protocol;
    data_mode_t data_mode;
    time_mode_t time_mode;
    msg_date_t  start_date;
    msg_time_t  start_time;
} busmaster_priv_t;

typedef struct {
    FILE_T   fh;
    int64_t  file_bytes_read;

    char    *parse_error;
    int      err;
    char    *err_info;

    token_t  token;

    log_entry_type_t entry_type;
    busmaster_priv_t header;
    msg_t            msg;
} busmaster_state_t;

bool
run_busmaster_parser(busmaster_state_t *state,
                     int               *err, char **err_info);

#ifdef BUSMASTER_DEBUG
#include <stdio.h>
#define busmaster_debug_printf(...) printf(__VA_ARGS__)
#else
#define busmaster_debug_printf(...) (void)0
#endif

#endif  /* BUSMASTER_PRIV_H__ */
