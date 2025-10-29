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
    msg_date_t d;
    msg_time_t t;
} msg_date_time_t;

typedef struct {
    msg_time_t timestamp;
    wtap_can_msg_type_t type;
    uint32_t   id;
    wtap_can_msg_data_t data;
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
    msg_date_time_t  start;
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

#endif  /* BUSMASTER_PRIV_H__ */
