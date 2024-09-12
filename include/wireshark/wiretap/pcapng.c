/* pcapng.c
 *
 * Wiretap Library
 * Copyright (c) 1998 by Gilbert Ramirez <gram@alumni.rice.edu>
 *
 * File format support for pcapng file format
 * Copyright (c) 2007 by Ulf Lamping <ulf.lamping@web.de>
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

/* File format specification:
 *   https://github.com/pcapng/pcapng
 * Related Wiki page:
 *   https://gitlab.com/wireshark/wireshark/-/wikis/Development/PcapNg
 */

#include "config.h"
#define WS_LOG_DOMAIN LOG_DOMAIN_WIRETAP
#include "pcapng.h"

#include "wtap_opttypes.h"

#include <stdlib.h>
#include <string.h>
#include <errno.h>

#include <wsutil/wslog.h>
#include <wsutil/strtoi.h>
#include <wsutil/glib-compat.h>
#include <wsutil/ws_assert.h>
#include <wsutil/ws_roundup.h>
#include <wsutil/unicode-utils.h>

#include "wtap-int.h"
#include "file_wrappers.h"
#include "required_file_handlers.h"
#include "pcap-common.h"
#include "pcap-encap.h"
#include "pcapng_module.h"
#include "secrets-types.h"

#define ROUND_TO_4BYTE(len) WS_ROUNDUP_4(len)

static bool
pcapng_read(wtap *wth, wtap_rec *rec, Buffer *buf, int *err,
            char **err_info, int64_t *data_offset);
static bool
pcapng_seek_read(wtap *wth, int64_t seek_off,
                 wtap_rec *rec, Buffer *buf, int *err, char **err_info);
static void
pcapng_close(wtap *wth);

static bool
pcapng_encap_is_ft_specific(int encap);

static bool
pcapng_write_if_descr_block(wtap_dumper *wdh, wtap_block_t int_data, int *err);

/*
 * Minimum block size = size of block header + size of block trailer.
 */
#define MIN_BLOCK_SIZE  ((uint32_t)(sizeof(pcapng_block_header_t) + sizeof(uint32_t)))

/*
 * Minimum SHB size = minimum block size + size of fixed length portion of SHB.
 */
#define MIN_SHB_SIZE    ((uint32_t)(MIN_BLOCK_SIZE + sizeof(pcapng_section_header_block_t)))

/* pcapng: packet block file encoding (obsolete) */
typedef struct pcapng_packet_block_s {
    uint16_t interface_id;
    uint16_t drops_count;
    uint32_t timestamp_high;
    uint32_t timestamp_low;
    uint32_t captured_len;
    uint32_t packet_len;
    /* ... Packet Data ... */
    /* ... Padding ... */
    /* ... Options ... */
} pcapng_packet_block_t;

/*
 * Minimum PB size = minimum block size + size of fixed length portion of PB.
 */
#define MIN_PB_SIZE     ((uint32_t)(MIN_BLOCK_SIZE + sizeof(pcapng_packet_block_t)))

/* pcapng: enhanced packet block file encoding */
typedef struct pcapng_enhanced_packet_block_s {
    uint32_t interface_id;
    uint32_t timestamp_high;
    uint32_t timestamp_low;
    uint32_t captured_len;
    uint32_t packet_len;
    /* ... Packet Data ... */
    /* ... Padding ... */
    /* ... Options ... */
} pcapng_enhanced_packet_block_t;

/*
 * Minimum EPB size = minimum block size + size of fixed length portion of EPB.
 */
#define MIN_EPB_SIZE    ((uint32_t)(MIN_BLOCK_SIZE + sizeof(pcapng_enhanced_packet_block_t)))

/* pcapng: simple packet block file encoding */
typedef struct pcapng_simple_packet_block_s {
    uint32_t packet_len;
    /* ... Packet Data ... */
    /* ... Padding ... */
} pcapng_simple_packet_block_t;

/*
 * Minimum SPB size = minimum block size + size of fixed length portion of SPB.
 */
#define MIN_SPB_SIZE    ((uint32_t)(MIN_BLOCK_SIZE + sizeof(pcapng_simple_packet_block_t)))

/* pcapng: name resolution block file encoding */
typedef struct pcapng_name_resolution_block_s {
    uint16_t record_type;
    uint16_t record_len;
    /* ... Record ... */
} pcapng_name_resolution_block_t;

/*
 * Minimum NRB size = minimum block size + size of smallest NRB record
 * (there must at least be an "end of records" record).
 */
#define MIN_NRB_SIZE    ((uint32_t)(MIN_BLOCK_SIZE + sizeof(pcapng_name_resolution_block_t)))

/* pcapng: custom block file encoding */
typedef struct pcapng_custom_block_s {
    uint32_t pen;
    /* Custom data and options */
} pcapng_custom_block_t;

/*
 * Minimum CB size = minimum block size + size of fixed length portion of CB.
 */

#define MIN_CB_SIZE     ((uint32_t)(MIN_BLOCK_SIZE + sizeof(pcapng_custom_block_t)))

/*
 * Minimum ISB size = minimum block size + size of fixed length portion of ISB.
 */
#define MIN_ISB_SIZE    ((uint32_t)(MIN_BLOCK_SIZE + sizeof(pcapng_interface_statistics_block_t)))

/*
 * Minimum Sysdig size = minimum block size + packed size of sysdig_event_phdr.
 * Minimum Sysdig event v2 header size = minimum block size + packed size of sysdig_event_v2_phdr (which, in addition
 * to sysdig_event_phdr, includes the nparams 32bit value).
 */
#define SYSDIG_EVENT_HEADER_SIZE ((16 + 64 + 64 + 32 + 16)/8) /* CPU ID + TS + TID + Event len + Event type */
#define MIN_SYSDIG_EVENT_SIZE    ((uint32_t)(MIN_BLOCK_SIZE + SYSDIG_EVENT_HEADER_SIZE))
#define SYSDIG_EVENT_V2_HEADER_SIZE ((16 + 64 + 64 + 32 + 16 + 32)/8) /* CPU ID + TS + TID + Event len + Event type + nparams */
#define MIN_SYSDIG_EVENT_V2_SIZE    ((uint32_t)(MIN_BLOCK_SIZE + SYSDIG_EVENT_V2_HEADER_SIZE))

/*
 * We require __REALTIME_TIMESTAMP in the Journal Export Format reader in
 * order to set each packet timestamp. Require it here as well, although
 * it's not strictly necessary.
 */
#define SDJ__REALTIME_TIMESTAMP "__REALTIME_TIMESTAMP="
#define MIN_SYSTEMD_JOURNAL_EXPORT_ENTRY_SIZE    23 // "__REALTIME_TIMESTAMP=0\n"
#define MIN_SYSTEMD_JOURNAL_EXPORT_BLOCK_SIZE    ((uint32_t)(MIN_SYSTEMD_JOURNAL_EXPORT_ENTRY_SIZE + MIN_BLOCK_SIZE))

/* pcapng: common option header file encoding for every option type */
typedef struct pcapng_option_header_s {
    uint16_t option_code;
    uint16_t option_length;
    /* ... x bytes Option Body ... */
    /* ... Padding ... */
} pcapng_option_header_t;

struct pcapng_option {
    uint16_t type;
    uint16_t value_length;
};

/* Option codes: 16-bit field */
#define OPT_EPB_FLAGS        0x0002
#define OPT_EPB_HASH         0x0003
#define OPT_EPB_DROPCOUNT    0x0004
#define OPT_EPB_PACKETID     0x0005
#define OPT_EPB_QUEUE        0x0006
#define OPT_EPB_VERDICT      0x0007

#define OPT_NRB_DNSNAME      0x0002
#define OPT_NRB_DNSV4ADDR    0x0003
#define OPT_NRB_DNSV6ADDR    0x0004

/* MSBit of option code means "local type" */
#define OPT_LOCAL_FLAG       0x8000

/* OPT_EPB_VERDICT sub-types */
#define OPT_VERDICT_TYPE_HW  0
#define OPT_VERDICT_TYPE_TC  1
#define OPT_VERDICT_TYPE_XDP 2

/* OPT_EPB_HASH sub-types */
#define OPT_HASH_2COMP    0
#define OPT_HASH_XOR	  1
#define OPT_HASH_CRC32    2
#define OPT_HASH_MD5      3
#define OPT_HASH_SHA1     4
#define OPT_HASH_TOEPLITZ 5

/*
 * In order to keep from trying to allocate large chunks of memory,
 * which could either fail or, even if it succeeds, chew up so much
 * address space or memory+backing store as not to leave room for
 * anything else, we impose upper limits on the size of blocks we're
 * willing to handle.
 *
 * We pick a limit of an EPB with a maximum-sized D-Bus packet and 128 KiB
 * worth of options; we use the maximum D-Bus packet size as that's larger
 * than the maximum packet size for other link-layer types, and the maximum
 * packet size for other link-layer types is currently small enough that
 * the resulting block size would be less than the previous 16 MiB limit.
 */
#define MAX_BLOCK_SIZE (MIN_EPB_SIZE + WTAP_MAX_PACKET_SIZE_DBUS + 131072)

/* Note: many of the defined structures for block data are defined in wtap.h */

/* Packet data - used for both Enhanced Packet Block and the obsolete Packet Block data */
typedef struct wtapng_packet_s {
    /* mandatory */
    uint32_t                        ts_high;        /* seconds since 1.1.1970 */
    uint32_t                        ts_low;         /* fraction of seconds, depends on if_tsresol */
    uint32_t                        cap_len;        /* data length in the file */
    uint32_t                        packet_len;     /* data length on the wire */
    uint32_t                        interface_id;   /* identifier of the interface. */
    uint16_t                        drops_count;    /* drops count, only valid for packet block */
    /* 0xffff if information no available */
    /* pack_hash */
    /* XXX - put the packet data / pseudo_header here as well? */
} wtapng_packet_t;

/* Simple Packet data */
typedef struct wtapng_simple_packet_s {
    /* mandatory */
    uint32_t                        cap_len;        /* data length in the file */
    uint32_t                        packet_len;     /* data length on the wire */
    /* XXX - put the packet data / pseudo_header here as well? */
} wtapng_simple_packet_t;

/* Interface data in private struct */
typedef struct interface_info_s {
    int wtap_encap;
    uint32_t snap_len;
    uint64_t time_units_per_second;
    int tsprecision;
    int64_t tsoffset;
    int fcslen;
} interface_info_t;

typedef struct {
    unsigned current_section_number; /**< Section number of the current section being read sequentially */
    GArray *sections;             /**< Sections found in the capture file. */
} pcapng_t;

/*
 * Table for plugins to handle particular block types.
 *
 * A handler has a "read" routine and a "write" routine.
 *
 * A "read" routine returns a block as a libwiretap record, filling
 * in the wtap_rec structure with the appropriate record type and
 * other information, and filling in the supplied Buffer with
 * data for which there's no place in the wtap_rec structure.
 *
 * A "write" routine takes a libwiretap record and Buffer and writes
 * out a block.
 */
typedef struct {
    block_reader reader;
    block_writer writer;
} block_handler;

static GHashTable *block_handlers;

void
register_pcapng_block_type_handler(unsigned block_type, block_reader reader,
                                   block_writer writer)
{
    block_handler *handler;

    /*
     * Is this a known block type?
     */
    switch (block_type) {

    case BLOCK_TYPE_SHB:
    case BLOCK_TYPE_IDB:
    case BLOCK_TYPE_PB:
    case BLOCK_TYPE_SPB:
    case BLOCK_TYPE_NRB:
    case BLOCK_TYPE_ISB:
    case BLOCK_TYPE_EPB:
    case BLOCK_TYPE_DSB:
    case BLOCK_TYPE_CB_COPY:
    case BLOCK_TYPE_CB_NO_COPY:
    case BLOCK_TYPE_SYSDIG_MI:
    case BLOCK_TYPE_SYSDIG_PL_V1:
    case BLOCK_TYPE_SYSDIG_FDL_V1:
    case BLOCK_TYPE_SYSDIG_EVENT:
    case BLOCK_TYPE_SYSDIG_IL_V1:
    case BLOCK_TYPE_SYSDIG_UL_V1:
    case BLOCK_TYPE_SYSDIG_PL_V2:
    case BLOCK_TYPE_SYSDIG_EVF:
    case BLOCK_TYPE_SYSDIG_PL_V3:
    case BLOCK_TYPE_SYSDIG_PL_V4:
    case BLOCK_TYPE_SYSDIG_PL_V5:
    case BLOCK_TYPE_SYSDIG_PL_V6:
    case BLOCK_TYPE_SYSDIG_PL_V7:
    case BLOCK_TYPE_SYSDIG_PL_V8:
    case BLOCK_TYPE_SYSDIG_PL_V9:
    case BLOCK_TYPE_SYSDIG_EVENT_V2:
    case BLOCK_TYPE_SYSDIG_EVF_V2:
    case BLOCK_TYPE_SYSDIG_FDL_V2:
    case BLOCK_TYPE_SYSDIG_IL_V2:
    case BLOCK_TYPE_SYSDIG_UL_V2:
    case BLOCK_TYPE_SYSTEMD_JOURNAL_EXPORT:
        /*
         * Yes; we already handle it, and don't allow a replacement to
         * be registered (if there's a bug in our code, or there's
         * something we don't handle in that block, submit a change
         * to the main Wireshark source).
         */
        ws_warning("Attempt to register plugin for block type 0x%08x not allowed",
                     block_type);
        return;

    case BLOCK_TYPE_IRIG_TS:
    case BLOCK_TYPE_ARINC_429:
        /*
         * Yes, and we don't already handle it.  Allow a plugin to
         * handle it.
         *
         * (But why not submit the plugin source to Wireshark?)
         */
        break;

    default:
        /*
         * No; is it a local block type?
         */
         if (!(block_type & 0x80000000)) {
             /*
              * No; don't allow a plugin to be registered for it, as
              * the block type needs to be registered before it's used.
              */
            ws_warning("Attempt to register plugin for reserved block type 0x%08x not allowed",
                         block_type);
            return;
         }

         /*
          * Yes; allow the registration.
          */
         break;
    }

    if (block_handlers == NULL) {
        /*
         * Create the table of block handlers.
         *
         * XXX - there's no "g_uint_hash()" or "g_uint_equal()",
         * so we use "g_direct_hash()" and "g_direct_equal()".
         */
        block_handlers = g_hash_table_new_full(g_direct_hash,
                                               g_direct_equal,
                                               NULL, g_free);
    }
    handler = g_new(block_handler, 1);
    handler->reader = reader;
    handler->writer = writer;
    g_hash_table_insert(block_handlers, GUINT_TO_POINTER(block_type),
                              handler);
}

/*
 * Tables for plugins to handle particular options for particular block
 * types.
 *
 * An option has three handler routines:
 *
 *   An option parser, used when reading an option from a file:
 *
 *     The option parser is passed an indication of whether this section
 *     of the file is byte-swapped, the length of the option, the data of
 *     the option, a pointer to an error code, and a pointer to a pointer
 *     variable for an error string.
 *
 *     It checks whether the length and option are valid, and, if they
 *     aren't, returns false, setting the error code to the appropriate
 *     error (normally WTAP_ERR_BAD_FILE) and the error string to an
 *     appropriate string indicating the problem.
 *
 *     Otherwise, if this section of the file is byte-swapped, it byte-swaps
 *     multi-byte numerical values, so that it's in the host byte order.
 *
 *   An option sizer, used when writing an option to a file:
 *
 *     The option sizer is passed the option identifier for the option
 *     and a wtap_optval_t * that points to the data for the option.
 *
 *     It calculates how many bytes the option's data requires, not
 *     including any padding bytes, and returns that value.
 *
 *   An option writer, used when writing an option to a file:
 *
 *     The option writer is passed a wtap_dumper * to which the
 *     option data should be written, the option identifier for
 *     the option, a wtap_optval_t * that points to the data for
 *     the option, and an int * into which an error code should
 *     be stored if an error occurs when writing the option.
 *
 *     It returns a bool value of true if the attempt to
 *     write the option succeeds and false if the attempt to
 *     write the option gets an error.
 */

/*
 * Block types indices in the table of tables of option handlers.
 *
 * Block types are not guaranteed to be sequential, so we map the
 * block types we support to a sequential set.  Furthermore, all
 * packet block types have the same set of options.
 */
#define BT_INDEX_SHB        0
#define BT_INDEX_IDB        1
#define BT_INDEX_PBS        2  /* all packet blocks */
#define BT_INDEX_NRB        3
#define BT_INDEX_ISB        4
#define BT_INDEX_EVT        5
#define BT_INDEX_DSB        6

#define NUM_BT_INDICES      7

typedef struct {
    option_parser parser;
    option_sizer sizer;
    option_writer writer;
} option_handler;

static GHashTable *option_handlers[NUM_BT_INDICES];

/* Return whether this block type is handled interally, or
 * if it is returned to the caller in pcapng_read().
 * This is used by pcapng_open() to decide if it can process
 * the block.
 * Note that for block types that are registered from plugins,
 * we don't know the true answer without actually reading the block,
 * or even if there is a fixed answer for all blocks of that type,
 * so we err on the side of not processing.
 */
static bool
get_block_type_internal(unsigned block_type)
{
    switch (block_type) {

    case BLOCK_TYPE_SHB:
    case BLOCK_TYPE_IDB:
    case BLOCK_TYPE_NRB:
    case BLOCK_TYPE_DSB:
    case BLOCK_TYPE_ISB: /* XXX: ISBs should probably not be internal. */
    case BLOCK_TYPE_SYSDIG_MI:
    case BLOCK_TYPE_SYSDIG_PL_V1:
    case BLOCK_TYPE_SYSDIG_FDL_V1:
    case BLOCK_TYPE_SYSDIG_IL_V1:
    case BLOCK_TYPE_SYSDIG_UL_V1:
    case BLOCK_TYPE_SYSDIG_PL_V2:
    case BLOCK_TYPE_SYSDIG_PL_V3:
    case BLOCK_TYPE_SYSDIG_PL_V4:
    case BLOCK_TYPE_SYSDIG_PL_V5:
    case BLOCK_TYPE_SYSDIG_PL_V6:
    case BLOCK_TYPE_SYSDIG_PL_V7:
    case BLOCK_TYPE_SYSDIG_PL_V8:
    case BLOCK_TYPE_SYSDIG_PL_V9:
    case BLOCK_TYPE_SYSDIG_FDL_V2:
    case BLOCK_TYPE_SYSDIG_IL_V2:
    case BLOCK_TYPE_SYSDIG_UL_V2:
        return true;

    case BLOCK_TYPE_PB:
    case BLOCK_TYPE_EPB:
    case BLOCK_TYPE_SPB:
        return false;

    case BLOCK_TYPE_CB_COPY:
    case BLOCK_TYPE_CB_NO_COPY:
    case BLOCK_TYPE_SYSDIG_EVENT:
    case BLOCK_TYPE_SYSDIG_EVENT_V2:
    case BLOCK_TYPE_SYSDIG_EVENT_V2_LARGE:
    case BLOCK_TYPE_SYSTEMD_JOURNAL_EXPORT:
        return false;

    default:
#ifdef HAVE_PLUGINS
        /*
         * Do we have a handler for this block type?
         */
        if (block_handlers != NULL &&
            (g_hash_table_lookup(block_handlers, GUINT_TO_POINTER(block_type))) != NULL) {
                /* Yes. We don't know if the handler sets this block internal
                 * or needs to return it to the pcap_read() caller without
                 * reading it. Since this is called by pcap_open(), play it
                 * safe and tell pcap_open() to stop processing blocks.
                 * (XXX: Maybe the block type handler registration interface
                 * should include some way of indicating whether blocks are
                 * handled internally, which should hopefully be the same
                 * for all blocks of a type.)
                 */
                return false;
        }
#endif
        return true;
    }
    return false;
}

static bool
get_block_type_index(unsigned block_type, unsigned *bt_index)
{
    ws_assert(bt_index);

    switch (block_type) {

        case BLOCK_TYPE_SHB:
            *bt_index = BT_INDEX_SHB;
            break;

        case BLOCK_TYPE_IDB:
            *bt_index = BT_INDEX_IDB;
            break;

        case BLOCK_TYPE_PB:
        case BLOCK_TYPE_EPB:
        case BLOCK_TYPE_SPB:
            *bt_index = BT_INDEX_PBS;
            break;

        case BLOCK_TYPE_NRB:
            *bt_index = BT_INDEX_NRB;
            break;

        case BLOCK_TYPE_ISB:
            *bt_index = BT_INDEX_ISB;
            break;

        case BLOCK_TYPE_SYSDIG_EVENT:
        case BLOCK_TYPE_SYSDIG_EVENT_V2:
        case BLOCK_TYPE_SYSDIG_EVENT_V2_LARGE:
        case BLOCK_TYPE_SYSDIG_MI:
        case BLOCK_TYPE_SYSDIG_PL_V1:
        case BLOCK_TYPE_SYSDIG_FDL_V1:
        case BLOCK_TYPE_SYSDIG_IL_V1:
        case BLOCK_TYPE_SYSDIG_UL_V1:
        case BLOCK_TYPE_SYSDIG_PL_V2:
        case BLOCK_TYPE_SYSDIG_PL_V3:
        case BLOCK_TYPE_SYSDIG_PL_V4:
        case BLOCK_TYPE_SYSDIG_PL_V5:
        case BLOCK_TYPE_SYSDIG_PL_V6:
        case BLOCK_TYPE_SYSDIG_PL_V7:
        case BLOCK_TYPE_SYSDIG_PL_V8:
        case BLOCK_TYPE_SYSDIG_PL_V9:
        case BLOCK_TYPE_SYSDIG_FDL_V2:
        case BLOCK_TYPE_SYSDIG_IL_V2:
        case BLOCK_TYPE_SYSDIG_UL_V2:
            *bt_index = BT_INDEX_EVT;
            break;

        case BLOCK_TYPE_DSB:
            *bt_index = BT_INDEX_DSB;
            break;

        default:
            /*
             * This is a block type we don't process; either we ignore it,
             * in which case the options don't get processed, or there's
             * a plugin routine to handle it, in which case that routine
             * will do the option processing itself.
             *
             * XXX - report an error?
             */
            return false;
    }

    return true;
}

void
register_pcapng_option_handler(unsigned block_type, unsigned option_code,
                               option_parser parser,
                               option_sizer sizer,
                               option_writer writer)
{
    unsigned bt_index;
    option_handler *handler;

    if (!get_block_type_index(block_type, &bt_index))
        return;

    if (option_handlers[bt_index] == NULL) {
        /*
         * Create the table of option handlers for this block type.
         *
         * XXX - there's no "g_uint_hash()" or "g_uint_equal()",
         * so we use "g_direct_hash()" and "g_direct_equal()".
         */
        option_handlers[bt_index] = g_hash_table_new_full(g_direct_hash,
                                                          g_direct_equal,
                                                          NULL, g_free);
    }
    handler = g_new(option_handler, 1);
    handler->parser = parser;
    handler->sizer = sizer;
    handler->writer = writer;
    g_hash_table_insert(option_handlers[bt_index],
                        GUINT_TO_POINTER(option_code), handler);
}

void
pcapng_process_uint8_option(wtapng_block_t *wblock,
                            uint16_t option_code, uint16_t option_length,
                            const uint8_t *option_content)
{
    if (option_length == 1) {
        /*
         * If this option can appear only once in a block, this call
         * will fail on the second and later occurrences of the option;
         * we silently ignore the failure.
         */
        wtap_block_add_uint8_option(wblock->block, option_code, option_content[0]);
    }
}

void
pcapng_process_uint32_option(wtapng_block_t *wblock,
                             const section_info_t *section_info,
                             pcapng_opt_byte_order_e byte_order,
                             uint16_t option_code, uint16_t option_length,
                             const uint8_t *option_content)
{
    uint32_t uint32;

    if (option_length == 4) {
        /*  Don't cast a uint8_t * into a uint32_t *--the
         *  uint8_t * may not point to something that's
         *  aligned correctly.
         *
         * XXX - options are aligned on 32-bit boundaries, so, while
         * it may be true that 64-bit options aren't guaranteed to be
         * aligned on 64-bit bounaries, it shouldn't be true that 32-bit
         * options aren't guaranteed to be aligned on 32-bit boundaries.
         */
        memcpy(&uint32, option_content, sizeof(uint32_t));
        switch (byte_order) {

        case OPT_SECTION_BYTE_ORDER:
            if (section_info->byte_swapped) {
                uint32 = GUINT32_SWAP_LE_BE(uint32);
            }
            break;

        case OPT_BIG_ENDIAN:
            uint32 = GUINT32_FROM_BE(uint32);
            break;

        case OPT_LITTLE_ENDIAN:
            uint32 = GUINT32_FROM_LE(uint32);
            break;

        default:
            /*
             * This should not happen - this is called by pcapng_process_options(),
             * which returns an error for an invalid byte_order argument, and
             * otherwise passes the known-to-be-valid byte_order argument to
             * us.
             *
             * Just ignore the option.
             */
            return;
        }

        /*
         * If this option can appear only once in a block, this call
         * will fail on the second and later occurrences of the option;
         * we silently ignore the failure.
         */
        wtap_block_add_uint32_option(wblock->block, option_code, uint32);
    }
}

void
pcapng_process_timestamp_option(wtapng_block_t *wblock,
                                const section_info_t *section_info,
                                pcapng_opt_byte_order_e byte_order,
                                uint16_t option_code, uint16_t option_length,
                                const uint8_t *option_content)
{
    if (option_length == 8) {
        uint32_t high, low;
        uint64_t timestamp;

        /*  Don't cast a uint8_t * into a uint32_t *--the
         *  uint8_t * may not point to something that's
         *  aligned correctly.
         */
        memcpy(&high, option_content, sizeof(uint32_t));
        memcpy(&low, option_content + sizeof(uint32_t), sizeof(uint32_t));
        switch (byte_order) {

        case OPT_SECTION_BYTE_ORDER:
            if (section_info->byte_swapped) {
                high = GUINT32_SWAP_LE_BE(high);
                low = GUINT32_SWAP_LE_BE(low);
            }
            break;

        case OPT_BIG_ENDIAN:
            high = GUINT32_FROM_BE(high);
            low = GUINT32_FROM_BE(low);
            break;

        case OPT_LITTLE_ENDIAN:
            high = GUINT32_FROM_LE(high);
            low = GUINT32_FROM_LE(low);
            break;

        default:
            /*
             * This should not happen - this is called by pcapng_process_options(),
             * which returns an error for an invalid byte_order argument, and
             * otherwise passes the known-to-be-valid byte_order argument to
             * us.
             *
             * Just ignore the option.
             */
            return;
        }
        timestamp = (uint64_t)high;
        timestamp <<= 32;
        timestamp += (uint64_t)low;
        /*
         * If this option can appear only once in a block, this call
         * will fail on the second and later occurrences of the option;
         * we silently ignore the failure.
         */
        wtap_block_add_uint64_option(wblock->block, option_code, timestamp);
    }
}

void
pcapng_process_uint64_option(wtapng_block_t *wblock,
                             const section_info_t *section_info,
                             pcapng_opt_byte_order_e byte_order,
                             uint16_t option_code, uint16_t option_length,
                             const uint8_t *option_content)
{
    uint64_t uint64;

    if (option_length == 8) {
        /*  Don't cast a uint8_t * into a uint64_t *--the
         *  uint8_t * may not point to something that's
         *  aligned correctly.
         */
        memcpy(&uint64, option_content, sizeof(uint64_t));
        switch (byte_order) {

        case OPT_SECTION_BYTE_ORDER:
            if (section_info->byte_swapped) {
                uint64 = GUINT64_SWAP_LE_BE(uint64);
            }
            break;

        case OPT_BIG_ENDIAN:
            uint64 = GUINT64_FROM_BE(uint64);
            break;

        case OPT_LITTLE_ENDIAN:
            uint64 = GUINT64_FROM_LE(uint64);
            break;

        default:
            /*
             * This should not happen - this is called by pcapng_process_options(),
             * which returns an error for an invalid byte_order argument, and
             * otherwise passes the known-to-be-valid byte_order argument to
             * us.
             *
             * Just ignore the option.
             */
            return;
        }

        /*
         * If this option can appear only once in a block, this call
         * will fail on the second and later occurrences of the option;
         * we silently ignore the failure.
         */
        wtap_block_add_uint64_option(wblock->block, option_code, uint64);
    }
}

void
pcapng_process_int64_option(wtapng_block_t *wblock,
                            const section_info_t *section_info,
                            pcapng_opt_byte_order_e byte_order,
                            uint16_t option_code, uint16_t option_length,
                            const uint8_t *option_content)
{
    int64_t int64;

    if (option_length == 8) {
        /*  Don't cast a int8_t * into a int64_t *--the
         *  uint8_t * may not point to something that's
         *  aligned correctly.
         */
        memcpy(&int64, option_content, sizeof(int64_t));
        switch (byte_order) {

        case OPT_SECTION_BYTE_ORDER:
            if (section_info->byte_swapped) {
                int64 = GUINT64_SWAP_LE_BE(int64);
            }
            break;

        case OPT_BIG_ENDIAN:
            int64 = GUINT64_FROM_BE(int64);
            break;

        case OPT_LITTLE_ENDIAN:
            int64 = GUINT64_FROM_LE(int64);
            break;

        default:
            /*
             * This should not happen - this is called by pcapng_process_options(),
             * which returns an error for an invalid byte_order argument, and
             * otherwise passes the known-to-be-valid byte_order argument to
             * us.
             *
             * Just ignore the option.
             */
            return;
        }

        /*
         * If this option can appear only once in a block, this call
         * will fail on the second and later occurrences of the option;
         * we silently ignore the failure.
         */
        wtap_block_add_int64_option(wblock->block, option_code, int64);
    }
}

void
pcapng_process_string_option(wtapng_block_t *wblock, uint16_t option_code,
                             uint16_t option_length, const uint8_t *option_content)
{
    const char *opt = (const char *)option_content;
    size_t optlen = option_length;
    char *str;

    /* Validate UTF-8 encoding. */
    str = ws_utf8_make_valid(NULL, opt, optlen);

    wtap_block_add_string_option_owned(wblock->block, option_code, str);
}

void
pcapng_process_bytes_option(wtapng_block_t *wblock, uint16_t option_code,
                            uint16_t option_length, const uint8_t *option_content)
{
    wtap_block_add_bytes_option(wblock->block, option_code, (const char *)option_content, option_length);
}

static bool
pcapng_process_nflx_custom_option(wtapng_block_t *wblock,
                                  section_info_t *section_info,
                                  const uint8_t *value, uint16_t length)
{
    struct nflx_dumpinfo dumpinfo;
    uint32_t type, version;
    int64_t dumptime, temp;

    if (length < 4) {
        ws_debug("Length = %u too small", length);
        return false;
    }
    memcpy(&type, value, sizeof(uint32_t));
    type = GUINT32_FROM_LE(type);
    value += 4;
    length -= 4;
    ws_debug("Handling type = %u, payload of length = %u", type, length);
    switch (type) {
    case NFLX_OPT_TYPE_VERSION:
        if (length == sizeof(uint32_t)) {
            memcpy(&version, value, sizeof(uint32_t));
            version = GUINT32_FROM_LE(version);
            ws_debug("BBLog version: %u", version);
            section_info->bblog_version = version;
        } else {
            ws_debug("BBLog version parameter has strange length: %u", length);
        }
        break;
    case NFLX_OPT_TYPE_TCPINFO:
        ws_debug("BBLog tcpinfo of length: %u", length);
        if (wblock->type == BLOCK_TYPE_CB_COPY) {
            ws_buffer_assure_space(wblock->frame_buffer, length);
            wblock->rec->rec_header.custom_block_header.length = length + 4;
            memcpy(ws_buffer_start_ptr(wblock->frame_buffer), value, length);
            memcpy(&temp, value, sizeof(uint64_t));
            temp = GUINT64_FROM_LE(temp);
            wblock->rec->ts.secs = section_info->bblog_offset_tv_sec + temp;
            memcpy(&temp, value + sizeof(uint64_t), sizeof(uint64_t));
            temp = GUINT64_FROM_LE(temp);
            wblock->rec->ts.nsecs = (uint32_t)(section_info->bblog_offset_tv_usec + temp) * 1000;
            if (wblock->rec->ts.nsecs >= 1000000000) {
                wblock->rec->ts.secs += 1;
                wblock->rec->ts.nsecs -= 1000000000;
            }
            wblock->rec->presence_flags = WTAP_HAS_TS;
            wblock->internal = false;
        }
        break;
    case NFLX_OPT_TYPE_DUMPINFO:
        if (length == sizeof(struct nflx_dumpinfo)) {
            memcpy(&dumpinfo, value, sizeof(struct nflx_dumpinfo));
            section_info->bblog_offset_tv_sec = GUINT64_FROM_LE(dumpinfo.tlh_offset_tv_sec);
            section_info->bblog_offset_tv_usec = GUINT64_FROM_LE(dumpinfo.tlh_offset_tv_usec);
            ws_debug("BBLog dumpinfo time offset: %" PRIu64, section_info->bblog_offset_tv_sec);
        } else {
            ws_debug("BBLog dumpinfo parameter has strange length: %u", length);
        }
        break;
    case NFLX_OPT_TYPE_DUMPTIME:
        if (length == sizeof(int64_t)) {
            memcpy(&dumptime, value, sizeof(int64_t));
            dumptime = GINT64_FROM_LE(dumptime);
            ws_debug("BBLog dumpinfo time offset: %" PRIu64, dumptime);
        } else {
            ws_debug("BBLog dumptime parameter has strange length: %u", length);
        }
        break;
    case NFLX_OPT_TYPE_STACKNAME:
        if (length >= 2) {
            ws_debug("BBLog stack name: %.*s(%u)", length - 1, value + 1, *(uint8_t *)value);
        } else {
            ws_debug("BBLog stack name has strange length: %u)", length);
        }
        break;
    default:
        ws_debug("Unknown type: %u, length: %u", type, length);
        break;
    }
    return wtap_block_add_nflx_custom_option(wblock->block, type, value, length) == WTAP_OPTTYPE_SUCCESS;
}

static bool
pcapng_process_custom_option(wtapng_block_t *wblock,
                             section_info_t *section_info,
                             uint16_t option_code, uint16_t option_length,
                             const uint8_t *option_content,
                             pcapng_opt_byte_order_e byte_order,
                             int *err, char **err_info)
{
    uint32_t pen;
    bool ret;

    if (option_length < 4) {
        *err = WTAP_ERR_BAD_FILE;
        *err_info = ws_strdup_printf("pcapng: option length (%d) too small for custom option",
                                    option_length);
        return false;
    }
    memcpy(&pen, option_content, sizeof(uint32_t));
    switch (byte_order) {

    case OPT_SECTION_BYTE_ORDER:
        if (section_info->byte_swapped) {
            pen = GUINT32_SWAP_LE_BE(pen);
        }
        break;

    case OPT_BIG_ENDIAN:
        pen = GUINT32_FROM_BE(pen);
        break;

    case OPT_LITTLE_ENDIAN:
        pen = GUINT32_FROM_LE(pen);
        break;

    default:
        /*
         * This should not happen - this is called by pcapng_process_options(),
         * which returns an error for an invalid byte_order argument, and
         * otherwise passes the known-to-be-valid byte_order argument to
         * us.
         */
        *err = WTAP_ERR_INTERNAL;
        *err_info = ws_strdup_printf("pcapng: invalid byte order %d passed to pcapng_process_custom_option()",
                                    byte_order);
        return false;
    }
    switch (pen) {
    case PEN_NFLX:
        ret = pcapng_process_nflx_custom_option(wblock, section_info, option_content + 4, option_length - 4);
        break;
    default:
        ret = wtap_block_add_custom_option(wblock->block, option_code, pen, option_content + 4, option_length - 4) == WTAP_OPTTYPE_SUCCESS;
        ws_debug("Custom option type %u (0x%04x) with unknown pen %u with custom data of length %u", option_code, option_code, pen, option_length - 4);
        break;
    }
    ws_debug("returning %d", ret);
    return ret;
}

#ifdef HAVE_PLUGINS
static bool
pcapng_process_unhandled_option(wtapng_block_t *wblock,
                                unsigned bt_index,
                                const section_info_t *section_info,
                                uint16_t option_code, uint16_t option_length,
                                const uint8_t *option_content,
                                int *err, char **err_info)
{
    option_handler *handler;

    /*
     * Do we have a handler for this packet block option code?
     */
    if (option_handlers[bt_index] != NULL &&
        (handler = (option_handler *)g_hash_table_lookup(option_handlers[bt_index],
                                                         GUINT_TO_POINTER((unsigned)option_code))) != NULL) {
        /* Yes - call the handler. */
        if (!handler->parser(wblock->block, section_info->byte_swapped,
                             option_length, option_content, err, err_info))
            /* XXX - free anything? */
            return false;
    }
    return true;
}
#else
static bool
pcapng_process_unhandled_option(wtapng_block_t *wblock _U_,
                                unsigned bt_index _U_,
                                const section_info_t *section_info _U_,
                                uint16_t option_code _U_, uint16_t option_length _U_,
                                const uint8_t *option_content _U_,
                                int *err _U_, char **err_info _U_)
{
    return true;
}
#endif

bool
pcapng_process_options(FILE_T fh, wtapng_block_t *wblock,
                       section_info_t *section_info,
                       unsigned opt_cont_buf_len,
                       bool (*process_option)(wtapng_block_t *,
                                                  const section_info_t *,
                                                  uint16_t, uint16_t,
                                                  const uint8_t *,
                                                  int *, char **),
                       pcapng_opt_byte_order_e byte_order,
                       int *err, char **err_info)
{
    uint8_t *option_content; /* Allocate as large as the options block */
    unsigned opt_bytes_remaining;
    const uint8_t *option_ptr;
    const pcapng_option_header_t *oh;
    uint16_t option_code, option_length;
    unsigned rounded_option_length;

    ws_debug("Options %u bytes", opt_cont_buf_len);
    if (opt_cont_buf_len == 0) {
        /* No options, so nothing to do */
        return true;
    }

    /* Allocate enough memory to hold all options */
    option_content = (uint8_t *)g_try_malloc(opt_cont_buf_len);
    if (option_content == NULL) {
        *err = ENOMEM;  /* we assume we're out of memory */
        return false;
    }

    /* Read all the options into the buffer */
    if (!wtap_read_bytes(fh, option_content, opt_cont_buf_len, err, err_info)) {
        ws_debug("failed to read options");
        g_free(option_content);
        return false;
    }

    /*
     * Now process them.
     * option_ptr starts out aligned on at least a 4-byte boundary, as
     * that's what g_try_malloc() gives us, and each option is padded
     * to a length that's a multiple of 4 bytes, so it remains aligned.
     */
    option_ptr = &option_content[0];
    opt_bytes_remaining = opt_cont_buf_len;
    while (opt_bytes_remaining != 0) {
        /* Get option header. */
        oh = (const pcapng_option_header_t *)(const void *)option_ptr;
        /* Sanity check: don't run past the end of the options. */
        if (sizeof (*oh) > opt_bytes_remaining) {
            *err = WTAP_ERR_BAD_FILE;
            *err_info = ws_strdup_printf("pcapng: Not enough data for option header");
            g_free(option_content);
            return false;
        }
        option_code = oh->option_code;
        option_length = oh->option_length;
        switch (byte_order) {

        case OPT_SECTION_BYTE_ORDER:
            if (section_info->byte_swapped) {
                option_code = GUINT16_SWAP_LE_BE(option_code);
                option_length = GUINT16_SWAP_LE_BE(option_length);
            }
            break;

        case OPT_BIG_ENDIAN:
            option_code = GUINT16_FROM_BE(option_code);
            option_length = GUINT16_FROM_BE(option_length);
            break;

        case OPT_LITTLE_ENDIAN:
            option_code = GUINT16_FROM_LE(option_code);
            option_length = GUINT16_FROM_LE(option_length);
            break;

        default:
            /* Don't do that. */
            *err = WTAP_ERR_INTERNAL;
            *err_info = ws_strdup_printf("pcapng: invalid byte order %d passed to pcapng_process_options()",
                                        byte_order);
            return false;
        }
        option_ptr += sizeof (*oh); /* 4 bytes, so it remains aligned */
        opt_bytes_remaining -= sizeof (*oh);

        /* Round up option length to a multiple of 4. */
        rounded_option_length = ROUND_TO_4BYTE(option_length);

        /* Sanity check: don't run past the end of the options. */
        if (rounded_option_length > opt_bytes_remaining) {
            *err = WTAP_ERR_BAD_FILE;
            *err_info = ws_strdup_printf("pcapng: Not enough data to handle option of length %u",
                                        option_length);
            g_free(option_content);
            return false;
        }

        switch (option_code) {
            case(OPT_EOFOPT): /* opt_endofopt */
                if (opt_bytes_remaining != 0) {
                    ws_debug("%u bytes after opt_endofopt", opt_bytes_remaining);
                }
                /* padding should be ok here, just get out of this */
                opt_bytes_remaining = rounded_option_length;
                break;
            case(OPT_COMMENT):
                pcapng_process_string_option(wblock, option_code, option_length,
                                             option_ptr);
                break;
            case(OPT_CUSTOM_STR_COPY):
            case(OPT_CUSTOM_BIN_COPY):
            case(OPT_CUSTOM_STR_NO_COPY):
            case(OPT_CUSTOM_BIN_NO_COPY):
                if (!pcapng_process_custom_option(wblock, section_info,
                                                  option_code, option_length,
                                                  option_ptr,
                                                  byte_order,
                                                  err, err_info)) {
                    g_free(option_content);
                    return false;
                }
                break;

            default:
                if (process_option == NULL ||
                    !(*process_option)(wblock, (const section_info_t *)section_info, option_code,
                                       option_length, option_ptr,
                                       err, err_info)) {
                    g_free(option_content);
                    return false;
                }
        }
        option_ptr += rounded_option_length; /* multiple of 4 bytes, so it remains aligned */
        opt_bytes_remaining -= rounded_option_length;
    }
    g_free(option_content);
    return true;
}

typedef enum {
    PCAPNG_BLOCK_OK,
    PCAPNG_BLOCK_NOT_SHB,
    PCAPNG_BLOCK_ERROR
} block_return_val;

static bool
pcapng_process_section_header_block_option(wtapng_block_t *wblock,
                                           const section_info_t *section_info,
                                           uint16_t option_code,
                                           uint16_t option_length,
                                           const uint8_t *option_content,
                                           int *err, char **err_info)
{
    /*
     * Handle option content.
     *
     * ***DO NOT*** add any items to this table that are not
     * standardized option codes in either section 3.5 "Options"
     * of the current pcapng spec, at
     *
     *    https://pcapng.github.io/pcapng/draft-ietf-opsawg-pcapng.html#name-options
     *
     * or in the list of options in section 4.1 "Section Header Block"
     * of the current pcapng spec, at
     *
     *    https://pcapng.github.io/pcapng/draft-ietf-opsawg-pcapng.html#name-section-header-block
     *
     * All option codes in this switch statement here must be listed
     * in one of those places as standardized option types.
     */
    switch (option_code) {
        case(OPT_SHB_HARDWARE):
            pcapng_process_string_option(wblock, option_code, option_length,
                                         option_content);
            break;
        case(OPT_SHB_OS):
            pcapng_process_string_option(wblock, option_code, option_length,
                                         option_content);
            break;
        case(OPT_SHB_USERAPPL):
            pcapng_process_string_option(wblock, option_code, option_length,
                                         option_content);
            break;
        default:
            if (!pcapng_process_unhandled_option(wblock, BT_INDEX_SHB,
                                                 section_info, option_code,
                                                 option_length, option_content,
                                                 err, err_info))
                return false;
            break;
    }
    return true;
}

static block_return_val
pcapng_read_section_header_block(FILE_T fh, pcapng_block_header_t *bh,
                                 section_info_t *section_info,
                                 wtapng_block_t *wblock,
                                 int *err, char **err_info)
{
    bool byte_swapped;
    uint16_t version_major;
    uint16_t version_minor;
    unsigned opt_cont_buf_len;
    pcapng_section_header_block_t shb;
    wtapng_section_mandatory_t* section_data;

    /* read fixed-length part of the block */
    if (!wtap_read_bytes(fh, &shb, sizeof shb, err, err_info)) {
        /*
         * Even if this is just a short read, report it as an error.
         * It *is* a read error except when we're doing an open, in
         * which case it's a "this isn't a pcapng file" indication.
         * The open code will call us directly, and treat a short
         * read error as such an indication.
         */
        return PCAPNG_BLOCK_ERROR;
    }

    /* is the magic number one we expect? */
    switch (shb.magic) {
        case(0x1A2B3C4D):
            /* this seems pcapng with correct byte order */
            byte_swapped                = false;
            version_major               = shb.version_major;
            version_minor               = shb.version_minor;

            ws_debug("SHB (our byte order) V%u.%u, len %u",
                     version_major, version_minor, bh->block_total_length);
            break;
        case(0x4D3C2B1A):
            /* this seems pcapng with swapped byte order */
            byte_swapped                = true;
            version_major               = GUINT16_SWAP_LE_BE(shb.version_major);
            version_minor               = GUINT16_SWAP_LE_BE(shb.version_minor);

            /* tweak the block length to meet current swapping that we know now */
            bh->block_total_length  = GUINT32_SWAP_LE_BE(bh->block_total_length);

            ws_debug("SHB (byte-swapped) V%u.%u, len %u",
                     version_major, version_minor, bh->block_total_length);
            break;
        default:
            /* Not a "pcapng" magic number we know about. */
            *err = WTAP_ERR_BAD_FILE;
            *err_info = ws_strdup_printf("pcapng: unknown byte-order magic number 0x%08x", shb.magic);

            /*
             * See above comment about PCAPNG_BLOCK_NOT_SHB.
             */
            return PCAPNG_BLOCK_NOT_SHB;
    }

    /*
     * Add padding bytes to the block total length.
     *
     * See the comment in pcapng_read_block() for a long discussion
     * of this.
     */
    bh->block_total_length = ROUND_TO_4BYTE(bh->block_total_length);

    /*
     * Is this block long enough to be an SHB?
     */
    if (bh->block_total_length < MIN_SHB_SIZE) {
        /*
         * No.
         */
        *err = WTAP_ERR_BAD_FILE;
        *err_info = ws_strdup_printf("pcapng: total block length %u of an SHB is less than the minimum SHB size %u",
                                    bh->block_total_length, MIN_SHB_SIZE);
        return PCAPNG_BLOCK_ERROR;
    }

    /* OK, at this point we assume it's a pcapng file.

       Don't try to allocate memory for a huge number of options, as
       that might fail and, even if it succeeds, it might not leave
       any address space or memory+backing store for anything else.

       We do that by imposing a maximum block size of MAX_BLOCK_SIZE.
       We check for this *after* checking the SHB for its byte
       order magic number, so that non-pcapng files are less
       likely to be treated as bad pcapng files. */
    if (bh->block_total_length > MAX_BLOCK_SIZE) {
        *err = WTAP_ERR_BAD_FILE;
        *err_info = ws_strdup_printf("pcapng: total block length %u is too large (> %u)",
                                    bh->block_total_length, MAX_BLOCK_SIZE);
        return PCAPNG_BLOCK_ERROR;
    }

    /* Currently only SHB versions 1.0 and 1.2 are supported;
       version 1.2 is treated as being the same as version 1.0.
       See the current version of the pcapng specification.

       Version 1.2 is written by some programs that write additional
       block types (which can be read by any code that handles them,
       regarless of whether the minor version if 0 or 2, so that's
       not a reason to change the minor version number).

       XXX - the pcapng specification says that readers should
       just ignore sections with an unsupported version number;
       presumably they can also report an error if they skip
       all the way to the end of the file without finding
       any versions that they support. */
    if (!(version_major == 1 &&
          (version_minor == 0 || version_minor == 2))) {
        *err = WTAP_ERR_UNSUPPORTED;
        *err_info = ws_strdup_printf("pcapng: unknown SHB version %u.%u",
                                    version_major, version_minor);
        return PCAPNG_BLOCK_ERROR;
    }

    memset(section_info, 0, sizeof(section_info_t));
    section_info->byte_swapped  = byte_swapped;
    section_info->version_major = version_major;
    section_info->version_minor = version_minor;

    /*
     * Set wblock->block to a newly-allocated section header block.
     */
    wblock->block = wtap_block_create(WTAP_BLOCK_SECTION);

    /*
     * Set the mandatory values for the block.
     */
    section_data = (wtapng_section_mandatory_t*)wtap_block_get_mandatory_data(wblock->block);
    /* 64bit section_length (currently unused) */
    if (section_info->byte_swapped) {
        section_data->section_length = GUINT64_SWAP_LE_BE(shb.section_length);
    } else {
        section_data->section_length = shb.section_length;
    }

    /* Options */
    opt_cont_buf_len = bh->block_total_length - MIN_SHB_SIZE;
    if (!pcapng_process_options(fh, wblock, section_info, opt_cont_buf_len,
                                pcapng_process_section_header_block_option,
                                OPT_SECTION_BYTE_ORDER, err, err_info))
        return PCAPNG_BLOCK_ERROR;

    /*
     * We don't return these to the caller in pcapng_read().
     */
    wblock->internal = true;

    return PCAPNG_BLOCK_OK;
}

static bool
pcapng_process_if_descr_block_option(wtapng_block_t *wblock,
                                     const section_info_t *section_info,
                                     uint16_t option_code,
                                     uint16_t option_length,
                                     const uint8_t *option_content,
                                     int *err, char **err_info)
{
    if_filter_opt_t if_filter;

    /*
     * Handle option content.
     *
     * ***DO NOT*** add any items to this table that are not
     * standardized option codes in either section 3.5 "Options"
     * of the current pcapng spec, at
     *
     *    https://pcapng.github.io/pcapng/draft-ietf-opsawg-pcapng.html#name-options
     *
     * or in the list of options in section 4.1 "Section Header Block"
     * of the current pcapng spec, at
     *
     *    https://pcapng.github.io/pcapng/draft-ietf-opsawg-pcapng.html#name-section-header-block
     *
     * All option codes in this switch statement here must be listed
     * in one of those places as standardized option types.
     */
    switch (option_code) {
        case(OPT_IDB_NAME): /* if_name */
            pcapng_process_string_option(wblock, option_code, option_length,
                                         option_content);
            break;
        case(OPT_IDB_DESCRIPTION): /* if_description */
            pcapng_process_string_option(wblock, option_code, option_length,
                                         option_content);
            break;
        case(OPT_IDB_SPEED): /* if_speed */
            pcapng_process_uint64_option(wblock, section_info,
                                         OPT_SECTION_BYTE_ORDER,
                                         option_code, option_length,
                                         option_content);
            break;
        case(OPT_IDB_TSRESOL): /* if_tsresol */
            pcapng_process_uint8_option(wblock, option_code, option_length,
                                        option_content);
            break;
            /*
             * if_tzone      10  Time zone for GMT support (TODO: specify better). TODO: give a good example
             */
        case(OPT_IDB_FILTER): /* if_filter */
            if (option_length < 1) {
                *err = WTAP_ERR_BAD_FILE;
                *err_info = ws_strdup_printf("pcapng: packet block verdict option length %u is < 1",
                                            option_length);
                /* XXX - free anything? */
                return false;
            }
            /* The first byte of the Option Data keeps a code of the filter used (e.g. if this is a libpcap string,
             * or BPF bytecode.
             */
            if (option_content[0] == 0) {
                if_filter.type = if_filter_pcap;
                if_filter.data.filter_str = g_strndup((char *)option_content+1, option_length-1);
                ws_debug("filter_str %s option_length %u",
                         if_filter.data.filter_str, option_length);
                /* Fails with multiple options; we silently ignore the failure */
                wtap_block_add_if_filter_option(wblock->block, option_code, &if_filter);
                g_free(if_filter.data.filter_str);
            } else if (option_content[0] == 1) {
                /*
                 * XXX - byte-swap the code and k fields
                 * of each instruction as needed!
                 *
                 * XXX - what if option_length-1 is not a
                 * multiple of the size of a BPF instruction?
                 */
                unsigned num_insns;
                const uint8_t *insn_in;

                if_filter.type = if_filter_bpf;
                num_insns = (option_length-1)/8;
                insn_in = option_content+1;
                if_filter.data.bpf_prog.bpf_prog_len = num_insns;
                if_filter.data.bpf_prog.bpf_prog = g_new(wtap_bpf_insn_t, num_insns);
                for (unsigned i = 0; i < num_insns; i++) {
                    wtap_bpf_insn_t *insn = &if_filter.data.bpf_prog.bpf_prog[i];

                    memcpy(&insn->code, insn_in, 2);
                    if (section_info->byte_swapped)
                        insn->code = GUINT16_SWAP_LE_BE(insn->code);
                    insn_in += 2;
                    memcpy(&insn->jt, insn_in, 1);
                    insn_in += 1;
                    memcpy(&insn->jf, insn_in, 1);
                    insn_in += 1;
                    memcpy(&insn->k, insn_in, 4);
                    if (section_info->byte_swapped)
                        insn->k = GUINT32_SWAP_LE_BE(insn->k);
                    insn_in += 4;
                }
                /* Fails with multiple options; we silently ignore the failure */
                wtap_block_add_if_filter_option(wblock->block, option_code, &if_filter);
                g_free(if_filter.data.bpf_prog.bpf_prog);
            }
            break;
        case(OPT_IDB_OS): /* if_os */
            /*
             * if_os         12  A UTF-8 string containing the name of the operating system of the machine in which this interface is installed.
             * This can be different from the same information that can be contained by the Section Header Block (Section 3.1 (Section Header Block (mandatory)))
             * because the capture can have been done on a remote machine. "Windows XP SP2" / "openSUSE 10.2" / ...
             */
            pcapng_process_string_option(wblock, option_code, option_length,
                                         option_content);
            break;
        case(OPT_IDB_FCSLEN): /* if_fcslen */
            pcapng_process_uint8_option(wblock, option_code, option_length,
                                        option_content);
            break;
        case(OPT_IDB_HARDWARE): /* if_hardware */
            pcapng_process_string_option(wblock, option_code, option_length,
                                         option_content);
            break;
        /* TODO: process these! */
        case(OPT_IDB_IP4ADDR):
            /*
             * Interface network address and netmask. This option can be
             * repeated multiple times within the same Interface
             * Description Block when multiple IPv4 addresses are assigned
             * to the interface. 192 168 1 1 255 255 255 0
             */
            break;
        case(OPT_IDB_IP6ADDR):
            /*
             * Interface network address and prefix length (stored in the
             * last byte). This option can be repeated multiple times
             * within the same Interface Description Block when multiple
             * IPv6 addresses are assigned to the interface.
             * 2001:0db8:85a3:08d3:1319:8a2e:0370:7344/64 is written (in
             * hex) as "20 01 0d b8 85 a3 08 d3 13 19 8a 2e 03 70 73 44
             * 40"
             */
            break;
        case(OPT_IDB_MACADDR):
            /*
             * Interface Hardware MAC address (48 bits). 00 01 02 03 04 05
             */
            break;
        case(OPT_IDB_EUIADDR):
            /*
             * Interface Hardware EUI address (64 bits), if available.
             * TODO: give a good example
             */
             break;
        case(OPT_IDB_TZONE):
            /*
             * Time zone for GMT support.  This option has never been
             * specified in greater detail and, unless it were to identify
             * something such as an IANA time zone database timezone,
             * would be insufficient for converting between UTC and local
             * time.  Therefore, it SHOULD NOT be used; instead, the
             * if_iana_tzname option SHOULD be used if time zone
             * information is to be specified.
             *
             * Given that, we don't do anything with it.
             */
             break;
        case(OPT_IDB_TSOFFSET):
            /*
             * A 64-bit integer value that specifies an offset (in
             * seconds) that must be added to the timestamp of each packet
             * to obtain the absolute timestamp of a packet. If this optio
             * is not present, an offset of 0 is assumed (i.e., timestamps
             * in blocks are absolute timestamps.)
             */
            pcapng_process_int64_option(wblock, section_info,
                                        OPT_SECTION_BYTE_ORDER,
                                        option_code, option_length,
                                        option_content);
             break;
        default:
            if (!pcapng_process_unhandled_option(wblock, BT_INDEX_IDB,
                                                 section_info, option_code,
                                                 option_length, option_content,
                                                 err, err_info))
                return false;
            break;
    }
    return true;
}

/* "Interface Description Block" */
static bool
pcapng_read_if_descr_block(wtap *wth, FILE_T fh, pcapng_block_header_t *bh,
                           section_info_t *section_info,
                           wtapng_block_t *wblock, int *err, char **err_info)
{
    /* Default time stamp resolution is 10^6 */
    uint64_t time_units_per_second = 1000000;
    int     tsprecision = 6;
    unsigned   opt_cont_buf_len;
    pcapng_interface_description_block_t idb;
    wtapng_if_descr_mandatory_t* if_descr_mand;
    unsigned   link_type;
    uint8_t if_tsresol;

    /*
     * Is this block long enough to be an IDB?
     */
    if (bh->block_total_length < MIN_IDB_SIZE) {
        /*
         * No.
         */
        *err = WTAP_ERR_BAD_FILE;
        *err_info = ws_strdup_printf("pcapng: total block length %u of an IDB is less than the minimum IDB size %u",
                                    bh->block_total_length, MIN_IDB_SIZE);
        return false;
    }

    /* read block content */
    if (!wtap_read_bytes(fh, &idb, sizeof idb, err, err_info)) {
        ws_debug("failed to read IDB");
        return false;
    }

    /*
     * Set wblock->block to a newly-allocated interface ID and information
     * block.
     */
    wblock->block = wtap_block_create(WTAP_BLOCK_IF_ID_AND_INFO);

    /*
     * Set the mandatory values for the block.
     */
    if_descr_mand = (wtapng_if_descr_mandatory_t*)wtap_block_get_mandatory_data(wblock->block);
    if (section_info->byte_swapped) {
        link_type = GUINT16_SWAP_LE_BE(idb.linktype);
        if_descr_mand->snap_len  = GUINT32_SWAP_LE_BE(idb.snaplen);
    } else {
        link_type = idb.linktype;
        if_descr_mand->snap_len  = idb.snaplen;
    }

    if_descr_mand->wtap_encap = wtap_pcap_encap_to_wtap_encap(link_type);

    ws_debug("IDB link_type %u (%s), snap %u",
             link_type,
             wtap_encap_description(if_descr_mand->wtap_encap),
             if_descr_mand->snap_len);

    if (if_descr_mand->snap_len > wtap_max_snaplen_for_encap(if_descr_mand->wtap_encap)) {
        /*
         * We do not use this value, maybe we should check the
         * snap_len of the packets against it. For now, only warn.
         */
        ws_debug("snapshot length %u unrealistic.",
                 if_descr_mand->snap_len);
        /*if_descr_mand->snap_len = WTAP_MAX_PACKET_SIZE_STANDARD;*/
    }

    /* Options */
    opt_cont_buf_len = bh->block_total_length - MIN_IDB_SIZE;
    if (!pcapng_process_options(fh, wblock, section_info, opt_cont_buf_len,
                                pcapng_process_if_descr_block_option,
                                OPT_SECTION_BYTE_ORDER, err, err_info))
        return false;

    /*
     * Did we get a time stamp precision option?
     */
    if (wtap_block_get_uint8_option_value(wblock->block, OPT_IDB_TSRESOL,
                                          &if_tsresol) == WTAP_OPTTYPE_SUCCESS) {
        /*
         * Yes.  Set time_units_per_second appropriately.
         */
        uint8_t exponent;

        exponent = (uint8_t)(if_tsresol & 0x7f);
        if (if_tsresol & 0x80) {
            /*
             * 2^63 fits in a 64-bit unsigned number; 2^64 does not.
             *
             * ((2^64-1)/(2^63) is about 1.99, so, in practice, that
             * fine a time stamp resolution works only if you start
             * capturing at the Unix/POSIX epoch and capture for about
             * 1.9 seconds, so the maximum useful power-of-2 exponent
             * in a pcapng file is less than 63.)
             */
            if (exponent > 63) {
                /*
                 * Time units per second won't fit in a 64-bit integer,
                 * so Wireshark's current code can't read the file.
                 */
                *err = WTAP_ERR_UNSUPPORTED;
                *err_info = ws_strdup_printf("pcapng: IDB power-of-2 time stamp resolution %u > 63",
                                             exponent);
                return false;
            }

            /* 2^exponent */
            time_units_per_second = UINT64_C(1) << exponent;

            /*
             * Set the display precision to a value large enough to
             * show the fractional time units we get, so that we
             * don't display more digits than are justified.
             *
             * (That's also used as the base-10 if_tsresol value we use
             * if we write this file as a pcapng file.  Yes, that means
             * that we won't write out the exact value we read in.
             *
             * Dealing with base-2 time stamps is a bit of a mess,
             * thanks to humans counting with their fingers rather
             * than their hands, and it applies to more files than
             * pcapng files, e.g. ERF files.)
             */
            if (time_units_per_second >= 1000000000)
                tsprecision = WTAP_TSPREC_NSEC;
            else if (time_units_per_second >= 100000000)
                tsprecision = WTAP_TSPREC_10_NSEC;
            else if (time_units_per_second >= 10000000)
                tsprecision = WTAP_TSPREC_100_NSEC;
            else if (time_units_per_second >= 1000000)
                tsprecision = WTAP_TSPREC_USEC;
            else if (time_units_per_second >= 100000)
                tsprecision = WTAP_TSPREC_10_USEC;
            else if (time_units_per_second >= 10000)
                tsprecision = WTAP_TSPREC_100_USEC;
            else if (time_units_per_second >= 1000)
                tsprecision = WTAP_TSPREC_MSEC;
            else if (time_units_per_second >= 100)
                tsprecision = WTAP_TSPREC_10_MSEC;
            else if (time_units_per_second >= 10)
                tsprecision = WTAP_TSPREC_100_MSEC;
            else
                tsprecision = WTAP_TSPREC_SEC;
        } else {
            /*
             * 10^19 fits in a 64-bit unsigned number; 10^20 does not.
             *
             * ((2^64-1)/(10^19) is about 1.84, so, in practice, that
             * fine a time stamp resolution works only if you start
             * capturing at the Unix/POSIX epoch and capture for about
             * 1.8 seconds, so the maximum useful power-of-10 exponent
             * in a pcapng file is less than 19.)
             */
            uint64_t result;

            if (exponent > 19) {
                /*
                 * Time units per second won't fit in a 64-bit integer,
                 * so Wireshark's current code can't read the file.
                 */
                *err = WTAP_ERR_UNSUPPORTED;
                *err_info = ws_strdup_printf("pcapng: IDB power-of-10 time stamp resolution %u > 19",
                                             exponent);
                return false;
            }

            /* 10^exponent */
            result = 1;
            for (unsigned i = 0; i < exponent; i++) {
                result *= 10U;
            }
            time_units_per_second = result;

            /*
             * Set the display precision to min(exponent, WS_TSPREC_MAX),
             * so that we don't display more digits than are justified.
             * (That's also used as the base-10 if_tsresol value we use
             * if we write this file as a pcapng file.)
             */
            if (exponent <= WS_TSPREC_MAX) {
                tsprecision = exponent;
            } else {
                tsprecision = WS_TSPREC_MAX;
            }
        }
        if (time_units_per_second > (((uint64_t)1) << 32)) {
            ws_debug("time conversion might be inaccurate");
        }
    }

    /*
     * Set the time units per second for this interface.
     */
    if_descr_mand->time_units_per_second = time_units_per_second;

    /*
     * Set the number of digits of precision to display (and the
     * number to use for this interface if saving to a pcapng
     * file).
     */
    if_descr_mand->tsprecision = tsprecision;

    /*
     * If the per-file encapsulation isn't known, set it to this
     * interface's encapsulation.
     *
     * If it *is* known, and it isn't this interface's encapsulation,
     * set it to WTAP_ENCAP_PER_PACKET, as this file doesn't
     * have a single encapsulation for all interfaces in the file,
     * so it probably doesn't have a single encapsulation for all
     * packets in the file.
     */
    if (wth->file_encap == WTAP_ENCAP_NONE) {
        wth->file_encap = if_descr_mand->wtap_encap;
    } else {
        if (wth->file_encap != if_descr_mand->wtap_encap) {
            wth->file_encap = WTAP_ENCAP_PER_PACKET;
        }
    }

    /*
     * The same applies to the per-file time stamp resolution.
     */
    if (wth->file_tsprec == WTAP_TSPREC_UNKNOWN) {
        wth->file_tsprec = if_descr_mand->tsprecision;
    } else {
        if (wth->file_tsprec != if_descr_mand->tsprecision) {
            wth->file_tsprec = WTAP_TSPREC_PER_PACKET;
        }
    }

    /*
     * We don't return these to the caller in pcapng_read().
     */
    wblock->internal = true;

    return true;
}

static bool
pcapng_read_decryption_secrets_block(FILE_T fh, pcapng_block_header_t *bh,
                                     const section_info_t *section_info,
                                     wtapng_block_t *wblock,
                                     int *err, char **err_info)
{
    unsigned to_read;
    pcapng_decryption_secrets_block_t dsb;
    wtapng_dsb_mandatory_t *dsb_mand;

    /* read block content */
    if (!wtap_read_bytes(fh, &dsb, sizeof(dsb), err, err_info)) {
        ws_debug("failed to read DSB");
        return false;
    }

    /*
     * Set wblock->block to a newly-allocated decryption secrets block.
     */
    wblock->block = wtap_block_create(WTAP_BLOCK_DECRYPTION_SECRETS);

    /*
     * Set the mandatory values for the block.
     */
    dsb_mand = (wtapng_dsb_mandatory_t *)wtap_block_get_mandatory_data(wblock->block);
    if (section_info->byte_swapped) {
      dsb_mand->secrets_type = GUINT32_SWAP_LE_BE(dsb.secrets_type);
      dsb_mand->secrets_len = GUINT32_SWAP_LE_BE(dsb.secrets_len);
    } else {
      dsb_mand->secrets_type = dsb.secrets_type;
      dsb_mand->secrets_len = dsb.secrets_len;
    }
    /* Sanity check: assume the secrets are not larger than 1 GiB */
    if (dsb_mand->secrets_len > 1024 * 1024 * 1024) {
      *err = WTAP_ERR_BAD_FILE;
      *err_info = ws_strdup_printf("pcapng: secrets block is too large: %u", dsb_mand->secrets_len);
      return false;
    }
    dsb_mand->secrets_data = (uint8_t *)g_malloc0(dsb_mand->secrets_len);
    if (!wtap_read_bytes(fh, dsb_mand->secrets_data, dsb_mand->secrets_len, err, err_info)) {
        ws_debug("failed to read DSB");
        return false;
    }

    /* Skip past padding and discard options (not supported yet). */
    to_read = bh->block_total_length - MIN_DSB_SIZE - dsb_mand->secrets_len;
    if (!wtap_read_bytes(fh, NULL, to_read, err, err_info)) {
        ws_debug("failed to read DSB options");
        return false;
    }

    /*
     * We don't return these to the caller in pcapng_read().
     */
    wblock->internal = true;

    return true;
}

static bool
pcapng_read_meta_event_block(FILE_T fh, pcapng_block_header_t *bh,
                                     wtapng_block_t *wblock,
                                     int *err, char **err_info)
{
    unsigned to_read;
    wtapng_meta_event_mandatory_t *mev_mand;

    /*
     * Set wblock->block to a newly-allocated Sysdig meta event block.
     */
    wblock->block = wtap_block_create(WTAP_BLOCK_META_EVENT);

    /*
     * Set the mandatory values for the block.
     */
    mev_mand = (wtapng_meta_event_mandatory_t *)wtap_block_get_mandatory_data(wblock->block);
    mev_mand->mev_block_type = bh->block_type;
    mev_mand->mev_data_len = bh->block_total_length -
        (int)sizeof(pcapng_block_header_t) -
        (int)sizeof(bh->block_total_length);

    /* Sanity check: assume event data can't be larger than 1 GiB */
    if (mev_mand->mev_data_len > 1024 * 1024 * 1024) {
      *err = WTAP_ERR_BAD_FILE;
      *err_info = ws_strdup_printf("pcapng: Sysdig mev block is too large: %u", mev_mand->mev_data_len);
      return false;
    }
    mev_mand->mev_data = (uint8_t *)g_malloc(mev_mand->mev_data_len);
    if (!wtap_read_bytes(fh, mev_mand->mev_data, mev_mand->mev_data_len, err, err_info)) {
        ws_debug("failed to read Sysdig mev");
        return false;
    }

    /* Skip past padding and discard options (not supported yet). */
    to_read = bh->block_total_length - MIN_BLOCK_SIZE - mev_mand->mev_data_len;
    if (!wtap_read_bytes(fh, NULL, to_read, err, err_info)) {
        ws_debug("failed to read Sysdig mev options");
        return false;
    }

    /*
     * We don't return these to the caller in pcapng_read().
     */
    wblock->internal = true;

    return true;
}

static bool
pcapng_process_packet_block_option(wtapng_block_t *wblock,
                                   const section_info_t *section_info,
                                   uint16_t option_code,
                                   uint16_t option_length,
                                   const uint8_t *option_content,
                                   int *err, char **err_info)
{
    uint64_t tmp64;
    packet_verdict_opt_t packet_verdict;
    packet_hash_opt_t packet_hash;

    /*
     * Handle option content.
     *
     * ***DO NOT*** add any items to this table that are not
     * standardized option codes in either section 3.5 "Options"
     * of the current pcapng spec, at
     *
     *    https://pcapng.github.io/pcapng/draft-ietf-opsawg-pcapng.html#name-options
     *
     * or in the list of options in section 4.3 "Enhanced Packet Block"
     * of the current pcapng spec, at
     *
     *    https://pcapng.github.io/pcapng/draft-ietf-opsawg-pcapng.html#name-enhanced-packet-block
     *
     * All option codes in this switch statement here must be listed
     * in one of those places as standardized option types.
     */
    switch (option_code) {
        case(OPT_EPB_FLAGS):
            if (option_length != 4) {
                *err = WTAP_ERR_BAD_FILE;
                *err_info = ws_strdup_printf("pcapng: packet block flags option length %u is not 4",
                                            option_length);
                /* XXX - free anything? */
                return false;
            }
            pcapng_process_uint32_option(wblock, section_info,
                                         OPT_SECTION_BYTE_ORDER,
                                         option_code, option_length,
                                         option_content);
            break;
        case(OPT_EPB_HASH):
            if (option_length < 1) {
                *err = WTAP_ERR_BAD_FILE;
                *err_info = ws_strdup_printf("pcapng: packet block hash option length %u is < 1",
                                            option_length);
                /* XXX - free anything? */
                return false;
            }
            packet_hash.type = option_content[0];
            packet_hash.hash_bytes =
                g_byte_array_new_take((uint8_t *)g_memdup2(&option_content[1],
                                                          option_length - 1),
                                      option_length - 1);
            wtap_block_add_packet_hash_option(wblock->block, option_code, &packet_hash);
            wtap_packet_hash_free(&packet_hash);
            ws_debug("hash type %u, data len %u",
                     option_content[0], option_length - 1);
            break;
        case(OPT_EPB_DROPCOUNT):
            if (option_length != 8) {
                *err = WTAP_ERR_BAD_FILE;
                *err_info = ws_strdup_printf("pcapng: packet block drop count option length %u is not 8",
                                            option_length);
                /* XXX - free anything? */
                return false;
            }
            pcapng_process_uint64_option(wblock, section_info,
                                         OPT_SECTION_BYTE_ORDER,
                                         option_code, option_length,
                                         option_content);
            break;
        case(OPT_EPB_PACKETID):
            if (option_length != 8) {
                *err = WTAP_ERR_BAD_FILE;
                *err_info = ws_strdup_printf("pcapng: packet block packet id option length %u is not 8",
                                            option_length);
                /* XXX - free anything? */
                return false;
            }
            pcapng_process_uint64_option(wblock, section_info,
                                         OPT_SECTION_BYTE_ORDER,
                                         option_code, option_length,
                                         option_content);
            break;
        case(OPT_EPB_QUEUE):
            if (option_length != 4) {
                *err = WTAP_ERR_BAD_FILE;
                *err_info = ws_strdup_printf("pcapng: packet block queue option length %u is not 4",
                                            option_length);
                /* XXX - free anything? */
                return false;
            }
            pcapng_process_uint32_option(wblock, section_info,
                                         OPT_SECTION_BYTE_ORDER,
                                         option_code, option_length,
                                         option_content);
            break;
        case(OPT_EPB_VERDICT):
            if (option_length < 1) {
                *err = WTAP_ERR_BAD_FILE;
                *err_info = ws_strdup_printf("pcapng: packet block verdict option length %u is < 1",
                                            option_length);
                /* XXX - free anything? */
                return false;
            }
            switch (option_content[0]) {

                case(OPT_VERDICT_TYPE_HW):
                    packet_verdict.type = packet_verdict_hardware;
                    packet_verdict.data.verdict_bytes =
                        g_byte_array_new_take((uint8_t *)g_memdup2(&option_content[1],
                                                                  option_length - 1),
                                              option_length - 1);
                    break;

                case(OPT_VERDICT_TYPE_TC):
                    if (option_length != 9) {
                        *err = WTAP_ERR_BAD_FILE;
                        *err_info = ws_strdup_printf("pcapng: packet block TC verdict option length %u is != 9",
                                                    option_length);
                        /* XXX - free anything? */
                        return false;
                    }
                    /*  Don't cast a uint8_t * into a uint64_t *--the
                     *  uint8_t * may not point to something that's
                     *  aligned correctly.
                     */
                    memcpy(&tmp64, &option_content[1], sizeof(uint64_t));
                    if (section_info->byte_swapped)
                        tmp64 = GUINT64_SWAP_LE_BE(tmp64);
                    packet_verdict.type = packet_verdict_linux_ebpf_tc;
                    packet_verdict.data.verdict_linux_ebpf_tc = tmp64;
                    break;

                case(OPT_VERDICT_TYPE_XDP):
                    if (option_length != 9) {
                        *err = WTAP_ERR_BAD_FILE;
                        *err_info = ws_strdup_printf("pcapng: packet block XDP verdict option length %u is != 9",
                                                    option_length);
                        /* XXX - free anything? */
                        return false;
                    }
                    /*  Don't cast a uint8_t * into a uint64_t *--the
                     *  uint8_t * may not point to something that's
                     *  aligned correctly.
                     */
                    memcpy(&tmp64, &option_content[1], sizeof(uint64_t));
                    if (section_info->byte_swapped)
                        tmp64 = GUINT64_SWAP_LE_BE(tmp64);
                    packet_verdict.type = packet_verdict_linux_ebpf_xdp;
                    packet_verdict.data.verdict_linux_ebpf_xdp = tmp64;
                    break;

                default:
                    /* Silently ignore unknown verdict types */
                    return true;
            }
            wtap_block_add_packet_verdict_option(wblock->block, option_code, &packet_verdict);
            wtap_packet_verdict_free(&packet_verdict);
            ws_debug("verdict type %u, data len %u",
                     option_content[0], option_length - 1);
            break;
        default:
            if (!pcapng_process_unhandled_option(wblock, BT_INDEX_PBS,
                                                 section_info, option_code,
                                                 option_length, option_content,
                                                 err, err_info))
                return false;
            break;
    }
    return true;
}

static bool
pcapng_read_packet_block(FILE_T fh, pcapng_block_header_t *bh,
                         section_info_t *section_info,
                         wtapng_block_t *wblock,
                         int *err, char **err_info, bool enhanced)
{
    unsigned block_read;
    unsigned opt_cont_buf_len;
    pcapng_enhanced_packet_block_t epb;
    pcapng_packet_block_t pb;
    wtapng_packet_t packet;
    uint32_t padding;
    uint32_t flags;
    uint64_t tmp64;
    interface_info_t iface_info;
    uint64_t ts;
    int pseudo_header_len;
    int fcslen;

    wblock->block = wtap_block_create(WTAP_BLOCK_PACKET);

    /* "(Enhanced) Packet Block" read fixed part */
    if (enhanced) {
        /*
         * Is this block long enough to be an EPB?
         */
        if (bh->block_total_length < MIN_EPB_SIZE) {
            /*
             * No.
             */
            *err = WTAP_ERR_BAD_FILE;
            *err_info = ws_strdup_printf("pcapng: total block length %u of an EPB is less than the minimum EPB size %u",
                                        bh->block_total_length, MIN_EPB_SIZE);
            return false;
        }
        if (!wtap_read_bytes(fh, &epb, sizeof epb, err, err_info)) {
            ws_debug("failed to read packet data");
            return false;
        }
        block_read = (unsigned)sizeof epb;

        if (section_info->byte_swapped) {
            packet.interface_id        = GUINT32_SWAP_LE_BE(epb.interface_id);
            packet.drops_count         = 0xFFFF; /* invalid */
            packet.ts_high             = GUINT32_SWAP_LE_BE(epb.timestamp_high);
            packet.ts_low              = GUINT32_SWAP_LE_BE(epb.timestamp_low);
            packet.cap_len             = GUINT32_SWAP_LE_BE(epb.captured_len);
            packet.packet_len          = GUINT32_SWAP_LE_BE(epb.packet_len);
        } else {
            packet.interface_id        = epb.interface_id;
            packet.drops_count         = 0xFFFF; /* invalid */
            packet.ts_high             = epb.timestamp_high;
            packet.ts_low              = epb.timestamp_low;
            packet.cap_len             = epb.captured_len;
            packet.packet_len          = epb.packet_len;
        }
        ws_debug("EPB on interface_id %d, cap_len %d, packet_len %d",
                 packet.interface_id, packet.cap_len, packet.packet_len);
    } else {
        /*
         * Is this block long enough to be a PB?
         */
        if (bh->block_total_length < MIN_PB_SIZE) {
            /*
             * No.
             */
            *err = WTAP_ERR_BAD_FILE;
            *err_info = ws_strdup_printf("pcapng: total block length %u of a PB is less than the minimum PB size %u",
                                        bh->block_total_length, MIN_PB_SIZE);
            return false;
        }
        if (!wtap_read_bytes(fh, &pb, sizeof pb, err, err_info)) {
            ws_debug("failed to read packet data");
            return false;
        }
        block_read = (unsigned)sizeof pb;

        if (section_info->byte_swapped) {
            packet.interface_id        = GUINT16_SWAP_LE_BE(pb.interface_id);
            packet.drops_count         = GUINT16_SWAP_LE_BE(pb.drops_count);
            packet.ts_high             = GUINT32_SWAP_LE_BE(pb.timestamp_high);
            packet.ts_low              = GUINT32_SWAP_LE_BE(pb.timestamp_low);
            packet.cap_len             = GUINT32_SWAP_LE_BE(pb.captured_len);
            packet.packet_len          = GUINT32_SWAP_LE_BE(pb.packet_len);
        } else {
            packet.interface_id        = pb.interface_id;
            packet.drops_count         = pb.drops_count;
            packet.ts_high             = pb.timestamp_high;
            packet.ts_low              = pb.timestamp_low;
            packet.cap_len             = pb.captured_len;
            packet.packet_len          = pb.packet_len;
        }
        ws_debug("PB on interface_id %d, cap_len %d, packet_len %d",
                 packet.interface_id, packet.cap_len, packet.packet_len);
    }

    /*
     * How much padding is there at the end of the packet data?
     */
    if ((packet.cap_len % 4) != 0)
        padding = 4 - (packet.cap_len % 4);
    else
        padding = 0;

    /*
     * Is this block long enough to hold the packet data?
     */
    if (enhanced) {
        if (bh->block_total_length <
            MIN_EPB_SIZE + packet.cap_len + padding) {
            /*
             * No.
             */
            *err = WTAP_ERR_BAD_FILE;
            *err_info = ws_strdup_printf("pcapng: total block length %u of an EPB is too small for %u bytes of packet data",
                                        bh->block_total_length, packet.cap_len);
            return false;
        }
    } else {
        if (bh->block_total_length <
            MIN_PB_SIZE + packet.cap_len + padding) {
            /*
             * No.
             */
            *err = WTAP_ERR_BAD_FILE;
            *err_info = ws_strdup_printf("pcapng: total block length %u of a PB is too small for %u bytes of packet data",
                                        bh->block_total_length, packet.cap_len);
            return false;
        }
    }

    ws_debug("packet data: packet_len %u captured_len %u interface_id %u",
             packet.packet_len,
             packet.cap_len,
             packet.interface_id);

    if (packet.interface_id >= section_info->interfaces->len) {
        *err = WTAP_ERR_BAD_FILE;
        *err_info = ws_strdup_printf("pcapng: interface index %u is not less than section interface count %u",
                                    packet.interface_id,
                                    section_info->interfaces->len);
        return false;
    }
    iface_info = g_array_index(section_info->interfaces, interface_info_t,
                               packet.interface_id);

    if (packet.cap_len > wtap_max_snaplen_for_encap(iface_info.wtap_encap)) {
        *err = WTAP_ERR_BAD_FILE;
        *err_info = ws_strdup_printf("pcapng: cap_len %u is larger than %u",
                                    packet.cap_len,
                                    wtap_max_snaplen_for_encap(iface_info.wtap_encap));
        return false;
    }

    wblock->rec->rec_type = REC_TYPE_PACKET;
    wblock->rec->presence_flags = WTAP_HAS_TS|WTAP_HAS_CAP_LEN|WTAP_HAS_INTERFACE_ID;

    ws_debug("encapsulation = %d (%s), pseudo header size = %d.",
             iface_info.wtap_encap,
             wtap_encap_description(iface_info.wtap_encap),
             pcap_get_phdr_size(iface_info.wtap_encap, &wblock->rec->rec_header.packet_header.pseudo_header));
    wblock->rec->rec_header.packet_header.interface_id = packet.interface_id;
    wblock->rec->rec_header.packet_header.pkt_encap = iface_info.wtap_encap;
    wblock->rec->tsprec = iface_info.tsprecision;

    memset((void *)&wblock->rec->rec_header.packet_header.pseudo_header, 0, sizeof(union wtap_pseudo_header));
    pseudo_header_len = pcap_process_pseudo_header(fh,
                                                   false, /* not a Nokia pcap - not a pcap at all */
                                                   iface_info.wtap_encap,
                                                   packet.cap_len,
                                                   wblock->rec,
                                                   err,
                                                   err_info);
    if (pseudo_header_len < 0) {
        return false;
    }
    block_read += pseudo_header_len;
    wblock->rec->rec_header.packet_header.caplen = packet.cap_len - pseudo_header_len;
    wblock->rec->rec_header.packet_header.len = packet.packet_len - pseudo_header_len;

    /* Combine the two 32-bit pieces of the timestamp into one 64-bit value */
    ts = (((uint64_t)packet.ts_high) << 32) | ((uint64_t)packet.ts_low);

    /* Convert it to seconds and nanoseconds. */
    wblock->rec->ts.secs = (time_t)(ts / iface_info.time_units_per_second);
    wblock->rec->ts.nsecs = (int)(((ts % iface_info.time_units_per_second) * 1000000000) / iface_info.time_units_per_second);

    /* Add the time stamp offset. */
    wblock->rec->ts.secs = (time_t)(wblock->rec->ts.secs + iface_info.tsoffset);

    /* "(Enhanced) Packet Block" read capture data */
    if (!wtap_read_packet_bytes(fh, wblock->frame_buffer,
                                packet.cap_len - pseudo_header_len, err, err_info))
        return false;
    block_read += packet.cap_len - pseudo_header_len;

    /* jump over potential padding bytes at end of the packet data */
    if (padding != 0) {
        if (!wtap_read_bytes(fh, NULL, padding, err, err_info))
            return false;
        block_read += padding;
    }

    /* FCS length default */
    fcslen = iface_info.fcslen;

    /* Options */
    opt_cont_buf_len = bh->block_total_length -
        (int)sizeof(pcapng_block_header_t) -
        block_read -    /* fixed and variable part, including padding */
        (int)sizeof(bh->block_total_length);
    if (!pcapng_process_options(fh, wblock, section_info, opt_cont_buf_len,
                                pcapng_process_packet_block_option,
                                OPT_SECTION_BYTE_ORDER, err, err_info))
        return false;

    /*
     * Did we get a packet flags option?
     */
    if (WTAP_OPTTYPE_SUCCESS == wtap_block_get_uint32_option_value(wblock->block, OPT_PKT_FLAGS, &flags)) {
        if (PACK_FLAGS_FCS_LENGTH(flags) != 0) {
            /*
             * The FCS length is present, but in units of octets, not
             * bits; convert it to bits.
             */
            fcslen = PACK_FLAGS_FCS_LENGTH(flags)*8;
        }
    }
    /*
     * How about a drop_count option? If not, set it from other sources
     */
    if (WTAP_OPTTYPE_SUCCESS != wtap_block_get_uint64_option_value(wblock->block, OPT_PKT_DROPCOUNT, &tmp64) && packet.drops_count != 0xFFFF) {
        wtap_block_add_uint64_option(wblock->block, OPT_PKT_DROPCOUNT, (uint64_t)packet.drops_count);
    }

    pcap_read_post_process(false, iface_info.wtap_encap,
                           wblock->rec, ws_buffer_start_ptr(wblock->frame_buffer),
                           section_info->byte_swapped, fcslen);

    /*
     * We return these to the caller in pcapng_read().
     */
    wblock->internal = false;

    /*
     * We want dissectors (particularly packet_frame) to be able to
     * access packet comments and whatnot that are in the block. wblock->block
     * will be unref'd by pcapng_seek_read(), so move the block to where
     * dissectors can find it.
     */
    wblock->rec->block = wblock->block;
    wblock->block = NULL;

    return true;
}


static bool
pcapng_read_simple_packet_block(FILE_T fh, pcapng_block_header_t *bh,
                                const section_info_t *section_info,
                                wtapng_block_t *wblock,
                                int *err, char **err_info)
{
    interface_info_t iface_info;
    pcapng_simple_packet_block_t spb;
    wtapng_simple_packet_t simple_packet;
    uint32_t padding;
    int pseudo_header_len;

    /*
     * Is this block long enough to be an SPB?
     */
    if (bh->block_total_length < MIN_SPB_SIZE) {
        /*
         * No.
         */
        *err = WTAP_ERR_BAD_FILE;
        *err_info = ws_strdup_printf("pcapng: total block length %u of an SPB is less than the minimum SPB size %u",
                                    bh->block_total_length, MIN_SPB_SIZE);
        return false;
    }

    /* "Simple Packet Block" read fixed part */
    if (!wtap_read_bytes(fh, &spb, sizeof spb, err, err_info)) {
        ws_debug("failed to read packet data");
        return false;
    }

    if (0 >= section_info->interfaces->len) {
        *err = WTAP_ERR_BAD_FILE;
        *err_info = g_strdup("pcapng: SPB appeared before any IDBs in the section");
        return false;
    }
    iface_info = g_array_index(section_info->interfaces, interface_info_t, 0);

    if (section_info->byte_swapped) {
        simple_packet.packet_len   = GUINT32_SWAP_LE_BE(spb.packet_len);
    } else {
        simple_packet.packet_len   = spb.packet_len;
    }

    /*
     * The captured length is not a field in the SPB; it can be
     * calculated as the minimum of the snapshot length from the
     * IDB and the packet length, as per the pcapng spec. An IDB
     * snapshot length of 0 means no limit.
     */
    simple_packet.cap_len = simple_packet.packet_len;
    if (simple_packet.cap_len > iface_info.snap_len && iface_info.snap_len != 0)
        simple_packet.cap_len = iface_info.snap_len;

    /*
     * How much padding is there at the end of the packet data?
     */
    if ((simple_packet.cap_len % 4) != 0)
        padding = 4 - (simple_packet.cap_len % 4);
    else
        padding = 0;

    /*
     * Is this block long enough to hold the packet data?
     */
    if (bh->block_total_length < MIN_SPB_SIZE + simple_packet.cap_len + padding) {
        /*
         * No.  That means that the problem is with the packet
         * length; the snapshot length can be bigger than the amount
         * of packet data in the block, as it's a *maximum* length,
         * not a *minimum* length.
         */
        *err = WTAP_ERR_BAD_FILE;
        *err_info = ws_strdup_printf("pcapng: total block length %u of an SPB is too small for %u bytes of packet data",
                                    bh->block_total_length, simple_packet.packet_len);
        return false;
    }

    if (simple_packet.cap_len > wtap_max_snaplen_for_encap(iface_info.wtap_encap)) {
        *err = WTAP_ERR_BAD_FILE;
        *err_info = ws_strdup_printf("pcapng: cap_len %u is larger than %u",
                                    simple_packet.cap_len,
                                    wtap_max_snaplen_for_encap(iface_info.wtap_encap));
        return false;
    }
    ws_debug("packet data: packet_len %u",
             simple_packet.packet_len);

    ws_debug("Need to read pseudo header of size %d",
             pcap_get_phdr_size(iface_info.wtap_encap, &wblock->rec->rec_header.packet_header.pseudo_header));

    /* No time stamp in a simple packet block; no options, either */
    wblock->rec->rec_type = REC_TYPE_PACKET;
    wblock->rec->presence_flags = WTAP_HAS_CAP_LEN|WTAP_HAS_INTERFACE_ID;
    wblock->rec->rec_header.packet_header.interface_id = 0;
    wblock->rec->rec_header.packet_header.pkt_encap = iface_info.wtap_encap;
    wblock->rec->tsprec = iface_info.tsprecision;
    wblock->rec->ts.secs = 0;
    wblock->rec->ts.nsecs = 0;
    wblock->rec->rec_header.packet_header.interface_id = 0;

    memset((void *)&wblock->rec->rec_header.packet_header.pseudo_header, 0, sizeof(union wtap_pseudo_header));
    pseudo_header_len = pcap_process_pseudo_header(fh,
                                                   false,
                                                   iface_info.wtap_encap,
                                                   simple_packet.cap_len,
                                                   wblock->rec,
                                                   err,
                                                   err_info);
    if (pseudo_header_len < 0) {
        return false;
    }
    wblock->rec->rec_header.packet_header.caplen = simple_packet.cap_len - pseudo_header_len;
    wblock->rec->rec_header.packet_header.len = simple_packet.packet_len - pseudo_header_len;

    memset((void *)&wblock->rec->rec_header.packet_header.pseudo_header, 0, sizeof(union wtap_pseudo_header));

    /* "Simple Packet Block" read capture data */
    if (!wtap_read_packet_bytes(fh, wblock->frame_buffer,
                                simple_packet.cap_len, err, err_info))
        return false;

    /* jump over potential padding bytes at end of the packet data */
    if ((simple_packet.cap_len % 4) != 0) {
        if (!wtap_read_bytes(fh, NULL, 4 - (simple_packet.cap_len % 4), err, err_info))
            return false;
    }

    pcap_read_post_process(false, iface_info.wtap_encap,
                           wblock->rec, ws_buffer_start_ptr(wblock->frame_buffer),
                           section_info->byte_swapped, iface_info.fcslen);

    /*
     * We return these to the caller in pcapng_read().
     */
    wblock->internal = false;

    return true;
}

#define NRES_ENDOFRECORD 0
#define NRES_IP4RECORD 1
#define NRES_IP6RECORD 2
#define PADDING4(x) ((((x + 3) >> 2) << 2) - x)
/* IPv6 + MAXNAMELEN */
#define INITIAL_NRB_REC_SIZE (16 + 64)

/*
 * Find the end of the NUL-terminated name the beginning of which is pointed
 * to by p; record_len is the number of bytes remaining in the record.
 *
 * Return the length of the name, including the terminating NUL.
 *
 * If we don't find a terminating NUL, return -1 and set *err and
 * *err_info appropriately.
 */
static int
name_resolution_block_find_name_end(const char *p, unsigned record_len, int *err,
                                    char **err_info)
{
    int namelen;

    namelen = 0;
    for (;;) {
        if (record_len == 0) {
            /*
             * We ran out of bytes in the record without
             * finding a NUL.
             */
            *err = WTAP_ERR_BAD_FILE;
            *err_info = g_strdup("pcapng: NRB record has non-null-terminated host name");
            return -1;
        }
        if (*p == '\0')
            break;  /* that's the terminating NUL */
        p++;
        record_len--;
        namelen++;      /* count this byte */
    }

    /* Include the NUL in the name length. */
    return namelen + 1;
}

static bool
pcapng_process_name_resolution_block_option(wtapng_block_t *wblock,
                                            const section_info_t *section_info,
                                            uint16_t option_code,
                                            uint16_t option_length,
                                            const uint8_t *option_content,
                                            int *err, char **err_info)
{
    /*
     * Handle option content.
     *
     * ***DO NOT*** add any items to this table that are not
     * standardized option codes in either section 3.5 "Options"
     * of the current pcapng spec, at
     *
     *    https://pcapng.github.io/pcapng/draft-ietf-opsawg-pcapng.html#name-options
     *
     * or in the list of options in section 4.1 "Section Header Block"
     * of the current pcapng spec, at
     *
     *    https://pcapng.github.io/pcapng/draft-ietf-opsawg-pcapng.html#name-section-header-block
     *
     * All option codes in this switch statement here must be listed
     * in one of those places as standardized option types.
     */
    switch (option_code) {
        /* TODO:
         * ns_dnsname     2
         * ns_dnsIP4addr  3
         * ns_dnsIP6addr  4
         */
        default:
            if (!pcapng_process_unhandled_option(wblock, BT_INDEX_NRB,
                                                 section_info, option_code,
                                                 option_length, option_content,
                                                 err, err_info))
                return false;
            break;
    }
    return true;
}

static bool
pcapng_read_name_resolution_block(FILE_T fh, pcapng_block_header_t *bh,
                                  section_info_t *section_info,
                                  wtapng_block_t *wblock,
                                  int *err, char **err_info)
{
    int block_read;
    int to_read;
    pcapng_name_resolution_block_t nrb;
    Buffer nrb_rec;
    uint32_t v4_addr;
    unsigned record_len, opt_cont_buf_len;
    char *namep;
    int namelen;
    wtapng_nrb_mandatory_t *nrb_mand;

    /*
     * Is this block long enough to be an NRB?
     */
    if (bh->block_total_length < MIN_NRB_SIZE) {
        /*
         * No.
         */
        *err = WTAP_ERR_BAD_FILE;
        *err_info = ws_strdup_printf("pcapng: total block length %u of an NRB is less than the minimum NRB size %u",
                                    bh->block_total_length, MIN_NRB_SIZE);
        return false;
    }

    to_read = bh->block_total_length - 8 - 4; /* We have read the header and should not read the final block_total_length */

    ws_debug("total %d bytes", bh->block_total_length);

    /* Ensure we have a name resolution block */
    if (wblock->block == NULL) {
        wblock->block = wtap_block_create(WTAP_BLOCK_NAME_RESOLUTION);
    }

    /*
     * Set the mandatory values for the block.
     */
    nrb_mand = (wtapng_nrb_mandatory_t *)wtap_block_get_mandatory_data(wblock->block);

    /*
     * Start out with a buffer big enough for an IPv6 address and one
     * 64-byte name; we'll make the buffer bigger if necessary.
     */
    ws_buffer_init(&nrb_rec, INITIAL_NRB_REC_SIZE);
    block_read = 0;
    while (block_read < to_read) {
        /*
         * There must be at least one record's worth of data
         * here.
         */
        if ((size_t)(to_read - block_read) < sizeof nrb) {
            ws_buffer_free(&nrb_rec);
            *err = WTAP_ERR_BAD_FILE;
            *err_info = ws_strdup_printf("pcapng: %d bytes left in the block < NRB record header size %u",
                                        to_read - block_read,
                                        (unsigned)sizeof nrb);
            return false;
        }
        if (!wtap_read_bytes(fh, &nrb, sizeof nrb, err, err_info)) {
            ws_buffer_free(&nrb_rec);
            ws_debug("failed to read record header");
            return false;
        }
        block_read += (int)sizeof nrb;

        if (section_info->byte_swapped) {
            nrb.record_type = GUINT16_SWAP_LE_BE(nrb.record_type);
            nrb.record_len  = GUINT16_SWAP_LE_BE(nrb.record_len);
        }

        if (to_read - block_read < nrb.record_len + PADDING4(nrb.record_len)) {
            ws_buffer_free(&nrb_rec);
            *err = WTAP_ERR_BAD_FILE;
            *err_info = ws_strdup_printf("pcapng: %d bytes left in the block < NRB record length + padding %u",
                                        to_read - block_read,
                                        nrb.record_len + PADDING4(nrb.record_len));
            return false;
        }
        switch (nrb.record_type) {
            case NRES_ENDOFRECORD:
                /* There shouldn't be any more data - but there MAY be options */
                goto read_options;
                break;
            case NRES_IP4RECORD:
                /*
                 * The smallest possible record must have
                 * a 4-byte IPv4 address, hence a minimum
                 * of 4 bytes.
                 *
                 * (The pcapng spec really indicates
                 * that it must be at least 5 bytes,
                 * as there must be at least one name,
                 * and it really must be at least 6
                 * bytes, as the name mustn't be null,
                 * but there's no need to fail if there
                 * aren't any names at all, and we
                 * should report a null name as such.)
                 */
                if (nrb.record_len < 4) {
                    ws_buffer_free(&nrb_rec);
                    *err = WTAP_ERR_BAD_FILE;
                    *err_info = ws_strdup_printf("pcapng: NRB record length for IPv4 record %u < minimum length 4",
                                                nrb.record_len);
                    return false;
                }
                ws_buffer_assure_space(&nrb_rec, nrb.record_len);
                if (!wtap_read_bytes(fh, ws_buffer_start_ptr(&nrb_rec),
                                     nrb.record_len, err, err_info)) {
                    ws_buffer_free(&nrb_rec);
                    ws_debug("failed to read IPv4 record data");
                    return false;
                }
                block_read += nrb.record_len;

                /*
                 * Scan through all the names in
                 * the record and add them.
                 */
                memcpy(&v4_addr,
                       ws_buffer_start_ptr(&nrb_rec), 4);
                /* IPv4 address is in big-endian order in the file always, which is how we store
                   it internally as well, so don't byte-swap it */
                for (namep = (char *)ws_buffer_start_ptr(&nrb_rec) + 4, record_len = nrb.record_len - 4;
                     record_len != 0;
                     namep += namelen, record_len -= namelen) {
                    /*
                     * Scan forward for a null
                     * byte.
                     */
                    namelen = name_resolution_block_find_name_end(namep, record_len, err, err_info);
                    if (namelen == -1) {
                        ws_buffer_free(&nrb_rec);
                        return false;      /* fail */
                    }
                    hashipv4_t *tp = g_new0(hashipv4_t, 1);
                    tp->addr = v4_addr;
                    (void) g_strlcpy(tp->name, namep, MAXNAMELEN);
                    nrb_mand->ipv4_addr_list = g_list_prepend(nrb_mand->ipv4_addr_list, tp);
                }

                if (!wtap_read_bytes(fh, NULL, PADDING4(nrb.record_len), err, err_info)) {
                    ws_buffer_free(&nrb_rec);
                    return false;
                }
                block_read += PADDING4(nrb.record_len);
                break;
            case NRES_IP6RECORD:
                /*
                 * The smallest possible record must have
                 * a 16-byte IPv6 address, hence a minimum
                 * of 16 bytes.
                 *
                 * (The pcapng spec really indicates
                 * that it must be at least 17 bytes,
                 * as there must be at least one name,
                 * and it really must be at least 18
                 * bytes, as the name mustn't be null,
                 * but there's no need to fail if there
                 * aren't any names at all, and we
                 * should report a null name as such.)
                 */
                if (nrb.record_len < 16) {
                    ws_buffer_free(&nrb_rec);
                    *err = WTAP_ERR_BAD_FILE;
                    *err_info = ws_strdup_printf("pcapng: NRB record length for IPv6 record %u < minimum length 16",
                                                nrb.record_len);
                    return false;
                }
                if (to_read < nrb.record_len) {
                    ws_buffer_free(&nrb_rec);
                    *err = WTAP_ERR_BAD_FILE;
                    *err_info = ws_strdup_printf("pcapng: NRB record length for IPv6 record %u > remaining data in NRB",
                                                nrb.record_len);
                    return false;
                }
                ws_buffer_assure_space(&nrb_rec, nrb.record_len);
                if (!wtap_read_bytes(fh, ws_buffer_start_ptr(&nrb_rec),
                                     nrb.record_len, err, err_info)) {
                    ws_buffer_free(&nrb_rec);
                    return false;
                }
                block_read += nrb.record_len;

                for (namep = (char *)ws_buffer_start_ptr(&nrb_rec) + 16, record_len = nrb.record_len - 16;
                     record_len != 0;
                     namep += namelen, record_len -= namelen) {
                    /*
                     * Scan forward for a null
                     * byte.
                     */
                    namelen = name_resolution_block_find_name_end(namep, record_len, err, err_info);
                    if (namelen == -1) {
                        ws_buffer_free(&nrb_rec);
                        return false;      /* fail */
                    }
                    hashipv6_t *tp = g_new0(hashipv6_t, 1);
                    memcpy(tp->addr, ws_buffer_start_ptr(&nrb_rec), sizeof tp->addr);
                    (void) g_strlcpy(tp->name, namep, MAXNAMELEN);
                    nrb_mand->ipv6_addr_list = g_list_prepend(nrb_mand->ipv6_addr_list, tp);
                }

                if (!wtap_read_bytes(fh, NULL, PADDING4(nrb.record_len), err, err_info)) {
                    ws_buffer_free(&nrb_rec);
                    return false;
                }
                block_read += PADDING4(nrb.record_len);
                break;
            default:
                ws_debug("unknown record type 0x%x", nrb.record_type);
                if (!wtap_read_bytes(fh, NULL, nrb.record_len + PADDING4(nrb.record_len), err, err_info)) {
                    ws_buffer_free(&nrb_rec);
                    return false;
                }
                block_read += nrb.record_len + PADDING4(nrb.record_len);
                break;
        }
    }

read_options:
    to_read -= block_read;

    /* Options */
    opt_cont_buf_len = to_read;
    if (!pcapng_process_options(fh, wblock, section_info, opt_cont_buf_len,
                                pcapng_process_name_resolution_block_option,
                                OPT_SECTION_BYTE_ORDER, err, err_info))
        return false;

    ws_buffer_free(&nrb_rec);

    /*
     * We don't return these to the caller in pcapng_read().
     */
    wblock->internal = true;

    return true;
}

static bool
pcapng_process_interface_statistics_block_option(wtapng_block_t *wblock,
                                                 const section_info_t *section_info,
                                                 uint16_t option_code,
                                                 uint16_t option_length,
                                                 const uint8_t *option_content,
                                                 int *err, char **err_info)
{
    /*
     * Handle option content.
     *
     * ***DO NOT*** add any items to this table that are not
     * standardized option codes in either section 3.5 "Options"
     * of the current pcapng spec, at
     *
     *    https://pcapng.github.io/pcapng/draft-ietf-opsawg-pcapng.html#name-options
     *
     * or in the list of options in section 4.1 "Section Header Block"
     * of the current pcapng spec, at
     *
     *    https://pcapng.github.io/pcapng/draft-ietf-opsawg-pcapng.html#name-section-header-block
     *
     * All option codes in this switch statement here must be listed
     * in one of those places as standardized option types.
     */
    switch (option_code) {
        case(OPT_ISB_STARTTIME): /* isb_starttime */
            pcapng_process_timestamp_option(wblock, section_info,
                                            OPT_SECTION_BYTE_ORDER,
                                            option_code, option_length,
                                            option_content);
            break;
        case(OPT_ISB_ENDTIME): /* isb_endtime */
            pcapng_process_timestamp_option(wblock, section_info,
                                            OPT_SECTION_BYTE_ORDER,
                                            option_code, option_length,
                                            option_content);
            break;
        case(OPT_ISB_IFRECV): /* isb_ifrecv */
            pcapng_process_uint64_option(wblock, section_info,
                                         OPT_SECTION_BYTE_ORDER,
                                         option_code, option_length,
                                         option_content);
            break;
        case(OPT_ISB_IFDROP): /* isb_ifdrop */
            pcapng_process_uint64_option(wblock, section_info,
                                         OPT_SECTION_BYTE_ORDER,
                                         option_code, option_length,
                                         option_content);
            break;
        case(OPT_ISB_FILTERACCEPT): /* isb_filteraccept 6 */
            pcapng_process_uint64_option(wblock, section_info,
                                         OPT_SECTION_BYTE_ORDER,
                                         option_code, option_length,
                                         option_content);
            break;
        case(OPT_ISB_OSDROP): /* isb_osdrop 7 */
            pcapng_process_uint64_option(wblock, section_info,
                                         OPT_SECTION_BYTE_ORDER,
                                         option_code, option_length,
                                         option_content);
            break;
        case(OPT_ISB_USRDELIV): /* isb_usrdeliv 8  */
            pcapng_process_uint64_option(wblock, section_info,
                                         OPT_SECTION_BYTE_ORDER,
                                         option_code, option_length,
                                         option_content);
            break;
        default:
            if (!pcapng_process_unhandled_option(wblock, BT_INDEX_ISB,
                                                 section_info, option_code,
                                                 option_length, option_content,
                                                 err, err_info))
                return false;
            break;
    }
    return true;
}

static bool
pcapng_read_interface_statistics_block(FILE_T fh, pcapng_block_header_t *bh,
                                       section_info_t *section_info,
                                       wtapng_block_t *wblock,
                                       int *err, char **err_info)
{
    unsigned opt_cont_buf_len;
    pcapng_interface_statistics_block_t isb;
    wtapng_if_stats_mandatory_t* if_stats_mand;

    /*
     * Is this block long enough to be an ISB?
     */
    if (bh->block_total_length < MIN_ISB_SIZE) {
        /*
         * No.
         */
        *err = WTAP_ERR_BAD_FILE;
        *err_info = ws_strdup_printf("pcapng: total block length %u of an ISB is too small (< %u)",
                                    bh->block_total_length, MIN_ISB_SIZE);
        return false;
    }

    /* "Interface Statistics Block" read fixed part */
    if (!wtap_read_bytes(fh, &isb, sizeof isb, err, err_info)) {
        ws_debug("failed to read packet data");
        return false;
    }

    /*
     * Set wblock->block to a newly-allocated interface statistics block.
     */
    wblock->block = wtap_block_create(WTAP_BLOCK_IF_STATISTICS);

    /*
     * Set the mandatory values for the block.
     */
    if_stats_mand = (wtapng_if_stats_mandatory_t*)wtap_block_get_mandatory_data(wblock->block);
    if (section_info->byte_swapped) {
        if_stats_mand->interface_id = GUINT32_SWAP_LE_BE(isb.interface_id);
        if_stats_mand->ts_high      = GUINT32_SWAP_LE_BE(isb.timestamp_high);
        if_stats_mand->ts_low       = GUINT32_SWAP_LE_BE(isb.timestamp_low);
    } else {
        if_stats_mand->interface_id = isb.interface_id;
        if_stats_mand->ts_high      = isb.timestamp_high;
        if_stats_mand->ts_low       = isb.timestamp_low;
    }
    ws_debug("interface_id %u", if_stats_mand->interface_id);

    /* Options */
    opt_cont_buf_len = bh->block_total_length -
        (MIN_BLOCK_SIZE + (unsigned)sizeof isb);    /* fixed and variable part, including padding */
    if (!pcapng_process_options(fh, wblock, section_info, opt_cont_buf_len,
                                pcapng_process_interface_statistics_block_option,
                                OPT_SECTION_BYTE_ORDER, err, err_info))
        return false;

    /*
     * We don't return these to the caller in pcapng_read().
     */
    wblock->internal = true;

    return true;
}

#define NFLX_BLOCK_TYPE_EVENT   1
#define NFLX_BLOCK_TYPE_SKIP    2

typedef struct pcapng_nflx_custom_block_s {
    uint32_t nflx_type;
} pcapng_nflx_custom_block_t;

#define MIN_NFLX_CB_SIZE ((uint32_t)(MIN_CB_SIZE + sizeof(pcapng_nflx_custom_block_t)))

static bool
pcapng_read_nflx_custom_block(FILE_T fh, pcapng_block_header_t *bh,
                              section_info_t *section_info,
                              wtapng_block_t *wblock,
                              int *err, char **err_info)
{
    pcapng_nflx_custom_block_t nflx_cb;
    unsigned opt_cont_buf_len;
    uint32_t type, skipped;

    if (bh->block_total_length < MIN_NFLX_CB_SIZE) {
        *err = WTAP_ERR_BAD_FILE;
        *err_info = ws_strdup_printf("pcapng: total block length %u of a Netflix CB is too small (< %u)",
                                    bh->block_total_length, MIN_NFLX_CB_SIZE);
        return false;
    }

    wblock->rec->rec_type = REC_TYPE_CUSTOM_BLOCK;
    wblock->rec->rec_header.custom_block_header.pen = PEN_NFLX;
    /* "NFLX Custom Block" read fixed part */
    if (!wtap_read_bytes(fh, &nflx_cb, sizeof nflx_cb, err, err_info)) {
        ws_debug("Failed to read nflx type");
        return false;
    }
    type = GUINT32_FROM_LE(nflx_cb.nflx_type);
    ws_debug("BBLog type: %u", type);
    switch (type) {
        case NFLX_BLOCK_TYPE_EVENT:
            /*
             * The fixed-length portion is MIN_NFLX_CB_SIZE bytes.
             * We already know we have that much data in the block.
             */
            wblock->rec->rec_header.custom_block_header.custom_data_header.nflx_custom_data_header.type = BBLOG_TYPE_EVENT_BLOCK;
            opt_cont_buf_len = bh->block_total_length - MIN_NFLX_CB_SIZE;
            ws_debug("event");
            break;
        case NFLX_BLOCK_TYPE_SKIP:
            /*
             * The fixed-length portion is MIN_NFLX_CB_SIZE bytes plus a
             * 32-bit value.
             *
             * Make sure we have that much data in the block.
             */
            if (bh->block_total_length < MIN_NFLX_CB_SIZE + (uint32_t)sizeof(uint32_t)) {
                *err = WTAP_ERR_BAD_FILE;
                *err_info = ws_strdup_printf("pcapng: total block length %u of a Netflix skip CB is too small (< %u)",
                                            bh->block_total_length,
                                            MIN_NFLX_CB_SIZE + (uint32_t)sizeof(uint32_t));
                return false;
            }
            if (!wtap_read_bytes(fh, &skipped, sizeof(uint32_t), err, err_info)) {
                ws_debug("Failed to read skipped");
                return false;
            }
            wblock->rec->presence_flags = 0;
            wblock->rec->rec_header.custom_block_header.length = 4;
            wblock->rec->rec_header.custom_block_header.custom_data_header.nflx_custom_data_header.type = BBLOG_TYPE_SKIPPED_BLOCK;
            wblock->rec->rec_header.custom_block_header.custom_data_header.nflx_custom_data_header.skipped = GUINT32_FROM_LE(skipped);
            wblock->internal = false;
            opt_cont_buf_len = bh->block_total_length - MIN_NFLX_CB_SIZE - sizeof(uint32_t);
            ws_debug("skipped: %u", wblock->rec->rec_header.custom_block_header.custom_data_header.nflx_custom_data_header.skipped);
            break;
        default:
            ws_debug("Unknown type %u", type);
            return false;
    }

    /* Options */
    if (!pcapng_process_options(fh, wblock, section_info, opt_cont_buf_len,
                                NULL, OPT_LITTLE_ENDIAN, err, err_info))
        return false;

    return true;
}

static bool
pcapng_handle_generic_custom_block(FILE_T fh, pcapng_block_header_t *bh,
                                   uint32_t pen, wtapng_block_t *wblock,
                                   int *err, char **err_info)
{
    unsigned to_read;

    ws_debug("unknown pen %u", pen);
    if (bh->block_total_length % 4) {
        to_read = bh->block_total_length + 4 - (bh->block_total_length % 4);
    } else {
        to_read = bh->block_total_length;
    }
    to_read -= MIN_CB_SIZE;
    wblock->rec->rec_type = REC_TYPE_CUSTOM_BLOCK;
    wblock->rec->presence_flags = 0;
    wblock->rec->rec_header.custom_block_header.length = bh->block_total_length - MIN_CB_SIZE;
    wblock->rec->rec_header.custom_block_header.pen = pen;
    wblock->rec->rec_header.custom_block_header.copy_allowed = (bh->block_type == BLOCK_TYPE_CB_COPY);
    if (!wtap_read_packet_bytes(fh, wblock->frame_buffer, to_read, err, err_info)) {
        return false;
    }
    /*
     * We return these to the caller in pcapng_read().
     */
    wblock->internal = false;
    return true;
}

static bool
pcapng_read_custom_block(FILE_T fh, pcapng_block_header_t *bh,
                         section_info_t *section_info,
                         wtapng_block_t *wblock,
                         int *err, char **err_info)
{
    pcapng_custom_block_t cb;
    uint32_t pen;

    /* Is this block long enough to be an CB? */
    if (bh->block_total_length < MIN_CB_SIZE) {
        /*
         * No.
         */
        *err = WTAP_ERR_BAD_FILE;
        *err_info = ws_strdup_printf("pcapng: total block length %u of a CB is too small (< %u)",
                                    bh->block_total_length, MIN_CB_SIZE);
        return false;
    }

    wblock->block = wtap_block_create(WTAP_BLOCK_CUSTOM);

    /* Custom block read fixed part */
    if (!wtap_read_bytes(fh, &cb, sizeof cb, err, err_info)) {
        ws_debug("failed to read pen");
        return false;
    }
    if (section_info->byte_swapped) {
        pen = GUINT32_SWAP_LE_BE(cb.pen);
    } else {
        pen = cb.pen;
    }
    ws_debug("pen %u, custom data and option length %u", pen, bh->block_total_length - MIN_CB_SIZE);

    switch (pen) {
        case PEN_NFLX:
            if (!pcapng_read_nflx_custom_block(fh, bh, section_info, wblock, err, err_info))
                return false;
            break;
        default:
            if (!pcapng_handle_generic_custom_block(fh, bh, pen, wblock, err, err_info)) {
                return false;
            }
            break;
    }

    wblock->rec->block = wblock->block;
    wblock->block = NULL;
    wblock->internal = false;

    return true;
}

static bool
pcapng_read_sysdig_event_block(wtap *wth, FILE_T fh, pcapng_block_header_t *bh,
                               const section_info_t *section_info,
                               wtapng_block_t *wblock,
                               int *err, char **err_info)
{
    unsigned block_read;
    uint16_t cpu_id;
    uint64_t wire_ts;
    uint64_t ts;
    uint64_t thread_id;
    uint32_t event_len;
    uint16_t event_type;
    uint32_t nparams = 0;
    unsigned min_event_size;

    switch (bh->block_type) {
        case BLOCK_TYPE_SYSDIG_EVENT_V2_LARGE:
        case BLOCK_TYPE_SYSDIG_EVENT_V2:
            min_event_size = MIN_SYSDIG_EVENT_V2_SIZE;
            break;
        default:
            min_event_size = MIN_SYSDIG_EVENT_SIZE;
            break;
    }

    if (bh->block_total_length < min_event_size) {
        *err = WTAP_ERR_BAD_FILE;
        *err_info = ws_strdup_printf("pcapng: total block length %u of a Sysdig event block is too small (< %u)",
                                    bh->block_total_length, min_event_size);
        return false;
    }

    wblock->rec->rec_type = REC_TYPE_SYSCALL;
    wblock->rec->rec_header.syscall_header.record_type = bh->block_type;
    wblock->rec->presence_flags = WTAP_HAS_CAP_LEN /*|WTAP_HAS_INTERFACE_ID */;
    wblock->rec->tsprec = WTAP_TSPREC_NSEC;

    if (!wtap_read_bytes(fh, &cpu_id, sizeof cpu_id, err, err_info)) {
        ws_debug("failed to read sysdig event cpu id");
        return false;
    }
    if (!wtap_read_bytes(fh, &wire_ts, sizeof wire_ts, err, err_info)) {
        ws_debug("failed to read sysdig event timestamp");
        return false;
    }
    if (!wtap_read_bytes(fh, &thread_id, sizeof thread_id, err, err_info)) {
        ws_debug("failed to read sysdig event thread id");
        return false;
    }
    if (!wtap_read_bytes(fh, &event_len, sizeof event_len, err, err_info)) {
        ws_debug("failed to read sysdig event length");
        return false;
    }
    if (!wtap_read_bytes(fh, &event_type, sizeof event_type, err, err_info)) {
        ws_debug("failed to read sysdig event type");
        return false;
    }
    if (bh->block_type == BLOCK_TYPE_SYSDIG_EVENT_V2 || bh->block_type == BLOCK_TYPE_SYSDIG_EVENT_V2_LARGE) {
        if (!wtap_read_bytes(fh, &nparams, sizeof nparams, err, err_info)) {
            ws_debug("failed to read sysdig number of parameters");
            return false;
        }
    }

    wblock->rec->rec_header.syscall_header.pathname = wth->pathname;
    wblock->rec->rec_header.syscall_header.byte_order = G_BYTE_ORDER;

    /* XXX Use Gxxx_FROM_LE macros instead? */
    if (section_info->byte_swapped) {
        wblock->rec->rec_header.syscall_header.byte_order =
#if G_BYTE_ORDER == G_LITTLE_ENDIAN
            G_BIG_ENDIAN;
#else
            G_LITTLE_ENDIAN;
#endif
        wblock->rec->rec_header.syscall_header.cpu_id = GUINT16_SWAP_LE_BE(cpu_id);
        ts = GUINT64_SWAP_LE_BE(wire_ts);
        wblock->rec->rec_header.syscall_header.thread_id = GUINT64_SWAP_LE_BE(thread_id);
        wblock->rec->rec_header.syscall_header.event_len = GUINT32_SWAP_LE_BE(event_len);
        wblock->rec->rec_header.syscall_header.event_type = GUINT16_SWAP_LE_BE(event_type);
        wblock->rec->rec_header.syscall_header.nparams = GUINT32_SWAP_LE_BE(nparams);
    } else {
        wblock->rec->rec_header.syscall_header.cpu_id = cpu_id;
        ts = wire_ts;
        wblock->rec->rec_header.syscall_header.thread_id = thread_id;
        wblock->rec->rec_header.syscall_header.event_len = event_len;
        wblock->rec->rec_header.syscall_header.event_type = event_type;
        wblock->rec->rec_header.syscall_header.nparams = nparams;
    }

    if (ts) {
        wblock->rec->presence_flags |= WTAP_HAS_TS;
    }

    wblock->rec->ts.secs = (time_t) (ts / 1000000000);
    wblock->rec->ts.nsecs = (int) (ts % 1000000000);

    block_read = bh->block_total_length - min_event_size;

    wblock->rec->rec_header.syscall_header.event_filelen = block_read;

    /* "Sysdig Event Block" read event data */
    if (!wtap_read_packet_bytes(fh, wblock->frame_buffer,
                                block_read, err, err_info))
        return false;

    /* XXX Read comment? */

    /*
     * We return these to the caller in pcapng_read().
     */
    wblock->internal = false;

    return true;
}

static bool
pcapng_read_systemd_journal_export_block(wtap *wth, FILE_T fh, pcapng_block_header_t *bh, pcapng_t *pn _U_, wtapng_block_t *wblock, int *err, char **err_info)
{
    uint32_t entry_length;
    uint64_t rt_ts;
    bool have_ts = false;

    if (bh->block_total_length < MIN_SYSTEMD_JOURNAL_EXPORT_BLOCK_SIZE) {
        *err = WTAP_ERR_BAD_FILE;
        *err_info = ws_strdup_printf("pcapng: total block length %u of a systemd journal export block is too small (< %u)",
                                    bh->block_total_length, MIN_SYSTEMD_JOURNAL_EXPORT_BLOCK_SIZE);
        return false;
    }

    entry_length = bh->block_total_length - MIN_BLOCK_SIZE;

    /* Includes padding bytes. */
    if (!wtap_read_packet_bytes(fh, wblock->frame_buffer,
                                entry_length, err, err_info)) {
        return false;
    }

    /*
     * We don't have memmem available everywhere, so we get to add space for
     * a trailing \0 for strstr below.
     */
    ws_buffer_assure_space(wblock->frame_buffer, entry_length+1);

    char *buf_ptr = (char *) ws_buffer_start_ptr(wblock->frame_buffer);
    while (entry_length > 0 && buf_ptr[entry_length-1] == '\0') {
        entry_length--;
    }

    if (entry_length < MIN_SYSTEMD_JOURNAL_EXPORT_ENTRY_SIZE) {
        *err = WTAP_ERR_BAD_FILE;
        *err_info = ws_strdup_printf("pcapng: entry length %u is too small (< %u)",
                                    bh->block_total_length, MIN_SYSTEMD_JOURNAL_EXPORT_ENTRY_SIZE);
        return false;
    }

    ws_debug("entry_length %u", entry_length);

    size_t rt_ts_len = strlen(SDJ__REALTIME_TIMESTAMP);

    buf_ptr[entry_length] = '\0';
    char *ts_pos = strstr(buf_ptr, SDJ__REALTIME_TIMESTAMP);

    if (!ts_pos) {
        ws_debug("no timestamp");
    } else if (ts_pos+rt_ts_len >= (char *) buf_ptr+entry_length) {
        ws_debug("timestamp past end of buffer");
    } else {
        const char *ts_end;
        have_ts = ws_strtou64(ts_pos+rt_ts_len, &ts_end, &rt_ts);

        if (!have_ts) {
            ws_debug("invalid timestamp");
        }
    }

    wblock->rec->rec_type = REC_TYPE_SYSTEMD_JOURNAL_EXPORT;
    wblock->rec->rec_header.systemd_journal_export_header.record_len = entry_length;
    wblock->rec->presence_flags = WTAP_HAS_CAP_LEN;
    if (have_ts) {
        wblock->rec->presence_flags |= WTAP_HAS_TS;
        wblock->rec->tsprec = WTAP_TSPREC_USEC;
        wblock->rec->ts.secs = (time_t) (rt_ts / 1000000);
        wblock->rec->ts.nsecs = (rt_ts % 1000000) * 1000;
    }

    /*
     * We return these to the caller in pcapng_read().
     */
    wblock->internal = false;

    if (wth->file_encap == WTAP_ENCAP_NONE) {
        /*
         * Nothing (most notably an IDB) has set a file encap at this point.
         * Do so here.
         * XXX Should we set WTAP_ENCAP_SYSTEMD_JOURNAL if appropriate?
         */
        wth->file_encap = WTAP_ENCAP_PER_PACKET;
    }

    return true;
}

static bool
pcapng_read_unknown_block(FILE_T fh, pcapng_block_header_t *bh,
#ifdef HAVE_PLUGINS
    const section_info_t *section_info,
#else
    const section_info_t *section_info _U_,
#endif
    wtapng_block_t *wblock,
    int *err, char **err_info)
{
    uint32_t block_read;
#ifdef HAVE_PLUGINS
    block_handler *handler;
#endif

    if (bh->block_total_length < MIN_BLOCK_SIZE) {
        *err = WTAP_ERR_BAD_FILE;
        *err_info = ws_strdup_printf("pcapng: total block length %u of an unknown block type is less than the minimum block size %u",
                                    bh->block_total_length, MIN_BLOCK_SIZE);
        return false;
    }

    block_read = bh->block_total_length - MIN_BLOCK_SIZE;

#ifdef HAVE_PLUGINS
    /*
     * Do we have a handler for this block type?
     */
    if (block_handlers != NULL &&
        (handler = (block_handler *)g_hash_table_lookup(block_handlers,
                                                        GUINT_TO_POINTER(bh->block_type))) != NULL) {
        /* Yes - call it to read this block type. */
        if (!handler->reader(fh, block_read, section_info->byte_swapped, wblock,
                             err, err_info))
            return false;
    } else
#endif
    {
        /* No.  Skip over this unknown block. */
        if (!wtap_read_bytes(fh, NULL, block_read, err, err_info)) {
            return false;
        }

        /*
         * We're skipping this, so we won't return these to the caller
         * in pcapng_read().
         */
        wblock->internal = true;
    }

    return true;
}

static bool
pcapng_read_and_check_block_trailer(FILE_T fh, pcapng_block_header_t *bh,
                                    section_info_t *section_info,
                                    int *err, char **err_info)
{
    uint32_t block_total_length;

    /* sanity check: first and second block lengths must match */
    if (!wtap_read_bytes(fh, &block_total_length, sizeof block_total_length,
                         err, err_info)) {
        ws_debug("couldn't read second block length");
        return false;
    }

    if (section_info->byte_swapped)
        block_total_length = GUINT32_SWAP_LE_BE(block_total_length);

    /*
     * According to the pcapng spec, this should equal the block total
     * length value at the beginning of the block, which MUST (in the
     * IANA sense) be a multiple of 4.
     *
     * We round the value at the beginning of the block to a multiple
     * of 4, so do so with this value as well.  This *does* mean that
     * the two values, if they're not both multiples of 4, can differ
     * and this code won't detect that, but we're already not detecting
     * non-multiple-of-4 total lengths.
     */
    block_total_length = ROUND_TO_4BYTE(block_total_length);

    if (block_total_length != bh->block_total_length) {
        *err = WTAP_ERR_BAD_FILE;
        *err_info = ws_strdup_printf("pcapng: total block lengths (first %u and second %u) don't match",
                                    bh->block_total_length, block_total_length);
        return false;
    }
    return true;
}

static bool
pcapng_read_block(wtap *wth, FILE_T fh, pcapng_t *pn,
                  section_info_t *section_info,
                  section_info_t *new_section_info,
                  wtapng_block_t *wblock,
                  int *err, char **err_info)
{
    block_return_val ret;
    pcapng_block_header_t bh;

    wblock->block = NULL;

    /* Try to read the (next) block header */
    if (!wtap_read_bytes_or_eof(fh, &bh, sizeof bh, err, err_info)) {
        ws_debug("wtap_read_bytes_or_eof() failed, err = %d.", *err);
        return false;
    }

    /*
     * SHBs have to be treated differently from other blocks, because
     * the byte order of the fields in the block can only be determined
     * by looking at the byte-order magic number inside the block, not
     * by using the byte order of the section to which it belongs, as
     * it is the block that *defines* the byte order of the section to
     * which it belongs.
     */
    if (bh.block_type == BLOCK_TYPE_SHB) {
        /*
         * BLOCK_TYPE_SHB has the same value regardless of byte order,
         * so we don't need to byte-swap it.
         *
         * We *might* need to byte-swap the total length, but we
         * can't determine whether we do until we look inside the
         * block and find the byte-order magic number, so we rely
         * on pcapng_read_section_header_block() to do that and
         * to swap the total length (as it needs to get the total
         * length in the right byte order in order to read the
         * entire block).
         */
        wblock->type = bh.block_type;

        ws_debug("block_type BLOCK_TYPE_SHB (0x%08x)", bh.block_type);

        /*
         * Fill in the section_info_t passed to us for use when
         * there's a new SHB; don't overwrite the existing SHB,
         * if there is one.
         */
        ret = pcapng_read_section_header_block(fh, &bh, new_section_info,
                                               wblock, err, err_info);
        if (ret != PCAPNG_BLOCK_OK) {
            return false;
        }

        /*
         * This is the current section; use its byte order, not that
         * of the section pointed to by section_info (which could be
         * null).
         */
        section_info = new_section_info;
    } else {
        /*
         * Not an SHB.
         */
        if (section_info->byte_swapped) {
            bh.block_type         = GUINT32_SWAP_LE_BE(bh.block_type);
            bh.block_total_length = GUINT32_SWAP_LE_BE(bh.block_total_length);
        }

        /*
         * Add padding bytes to the block total length.
         * (The "block total length" fields of some example files
         * don't contain the packet data padding bytes!)
         *
         * For all block types currently defined in the pcapng
         * specification, the portion of the block that precedes
         * the options is, if necessary, padded to be a multiple
         * of 4 octets, the header of an option is 4 octets long,
         * and the value of an option is also padded to be a
         * multiple of 4 octets, so the total length of a block
         * is always a multiple of 4 octets.
         *
         * If you have defined a block where that is not true, you
         * have violated the pcapng specification - hwere it says
         * that "[The value fo the Block Total Length] MUST be a
         * multiple of 4.", with MUST as described in BCP 14 (RFC 2119/
         * RFC 8174).
         *
         * Therefore, if adjusting the block total length causes the
         * code to read your block type not to work, that's your
         * problem.  It's bad enough that some blocks were written
         * out with the block total length not including the padding.
         * (Please note that libpcap is less forgiving that we are;
         * it reports an error if the block total length isn't a
         * multiple of 4.)
         */
        bh.block_total_length = ROUND_TO_4BYTE(bh.block_total_length);

        wblock->type = bh.block_type;

        ws_noisy("block_type 0x%08x", bh.block_type);

        /* Don't try to allocate memory for a huge number of options, as
           that might fail and, even if it succeeds, it might not leave
           any address space or memory+backing store for anything else.

           We do that by imposing a maximum block size of MAX_BLOCK_SIZE. */
        if (bh.block_total_length > MAX_BLOCK_SIZE) {
            *err = WTAP_ERR_BAD_FILE;
            *err_info = ws_strdup_printf("pcapng: total block length %u is too large (> %u)",
                                        bh.block_total_length, MAX_BLOCK_SIZE);
            return false;
        }

        /*
         * ***DO NOT*** add any items to this table that are not
         * standardized block types in the current pcapng spec at
         *
         *    https://pcapng.github.io/pcapng/draft-ietf-opsawg-pcapng.html
         *
         * All block types in this switch statement here must be
         * listed there as standardized block types, ideally with
         * a description.
         */
        switch (bh.block_type) {
            case(BLOCK_TYPE_IDB):
                if (!pcapng_read_if_descr_block(wth, fh, &bh, section_info, wblock, err, err_info))
                    return false;
                break;
            case(BLOCK_TYPE_PB):
                if (!pcapng_read_packet_block(fh, &bh, section_info, wblock, err, err_info, false))
                    return false;
                break;
            case(BLOCK_TYPE_SPB):
                if (!pcapng_read_simple_packet_block(fh, &bh, section_info, wblock, err, err_info))
                    return false;
                break;
            case(BLOCK_TYPE_EPB):
                if (!pcapng_read_packet_block(fh, &bh, section_info, wblock, err, err_info, true))
                    return false;
                break;
            case(BLOCK_TYPE_NRB):
                if (!pcapng_read_name_resolution_block(fh, &bh, section_info, wblock, err, err_info))
                    return false;
                break;
            case(BLOCK_TYPE_ISB):
                if (!pcapng_read_interface_statistics_block(fh, &bh, section_info, wblock, err, err_info))
                    return false;
                break;
            case(BLOCK_TYPE_DSB):
                if (!pcapng_read_decryption_secrets_block(fh, &bh, section_info, wblock, err, err_info))
                    return false;
                break;
            case BLOCK_TYPE_SYSDIG_MI:
            case BLOCK_TYPE_SYSDIG_PL_V1:
            case BLOCK_TYPE_SYSDIG_FDL_V1:
            case BLOCK_TYPE_SYSDIG_IL_V1:
            case BLOCK_TYPE_SYSDIG_UL_V1:
            case BLOCK_TYPE_SYSDIG_PL_V2:
            case BLOCK_TYPE_SYSDIG_PL_V3:
            case BLOCK_TYPE_SYSDIG_PL_V4:
            case BLOCK_TYPE_SYSDIG_PL_V5:
            case BLOCK_TYPE_SYSDIG_PL_V6:
            case BLOCK_TYPE_SYSDIG_PL_V7:
            case BLOCK_TYPE_SYSDIG_PL_V8:
            case BLOCK_TYPE_SYSDIG_PL_V9:
            case BLOCK_TYPE_SYSDIG_FDL_V2:
            case BLOCK_TYPE_SYSDIG_IL_V2:
            case BLOCK_TYPE_SYSDIG_UL_V2:
                if (!pcapng_read_meta_event_block(fh, &bh, wblock, err, err_info))
                    return false;
                break;
            case(BLOCK_TYPE_CB_COPY):
            case(BLOCK_TYPE_CB_NO_COPY):
                if (!pcapng_read_custom_block(fh, &bh, section_info, wblock, err, err_info))
                    return false;
                break;
            case(BLOCK_TYPE_SYSDIG_EVENT):
            case(BLOCK_TYPE_SYSDIG_EVENT_V2):
            case(BLOCK_TYPE_SYSDIG_EVENT_V2_LARGE):
            /* case(BLOCK_TYPE_SYSDIG_EVF): */
                if (!pcapng_read_sysdig_event_block(wth, fh, &bh, section_info, wblock, err, err_info))
                    return false;
                break;
            case(BLOCK_TYPE_SYSTEMD_JOURNAL_EXPORT):
                if (!pcapng_read_systemd_journal_export_block(wth, fh, &bh, pn, wblock, err, err_info))
                    return false;
                break;
            default:
                ws_debug("Unknown block_type: 0x%08x (block ignored), block total length %d",
                         bh.block_type, bh.block_total_length);
                if (!pcapng_read_unknown_block(fh, &bh, section_info, wblock, err, err_info))
                    return false;
                break;
        }
    }

    /*
     * Read and check the block trailer.
     */
    if (!pcapng_read_and_check_block_trailer(fh, &bh, section_info, err, err_info)) {
        /* Not readable or not valid. */
        return false;
    }
    return true;
}

/* Process an IDB that we've just read. The contents of wblock are copied as needed. */
static void
pcapng_process_idb(wtap *wth, section_info_t *section_info,
                   wtapng_block_t *wblock)
{
    wtap_block_t int_data = wtap_block_create(WTAP_BLOCK_IF_ID_AND_INFO);
    interface_info_t iface_info;
    wtapng_if_descr_mandatory_t *if_descr_mand = (wtapng_if_descr_mandatory_t*)wtap_block_get_mandatory_data(int_data),
                                *wblock_if_descr_mand = (wtapng_if_descr_mandatory_t*)wtap_block_get_mandatory_data(wblock->block);
    uint8_t if_fcslen;

    wtap_block_copy(int_data, wblock->block);

    /* XXX if_tsoffset; opt 14  A 64 bits integer value that specifies an offset (in seconds)...*/
    /* Interface statistics */
    if_descr_mand->num_stat_entries = 0;
    if_descr_mand->interface_statistics = NULL;

    wtap_add_idb(wth, int_data);

    iface_info.wtap_encap = wblock_if_descr_mand->wtap_encap;
    iface_info.snap_len = wblock_if_descr_mand->snap_len;
    iface_info.time_units_per_second = wblock_if_descr_mand->time_units_per_second;
    iface_info.tsprecision = wblock_if_descr_mand->tsprecision;

    /*
     * Did we get an FCS length option?
     */
    if (wtap_block_get_uint8_option_value(wblock->block, OPT_IDB_FCSLEN,
                                          &if_fcslen) == WTAP_OPTTYPE_SUCCESS) {
        /*
         * Yes.
         */
        iface_info.fcslen = if_fcslen;
    } else {
        /*
         * No.  Mark the FCS length as unknown.
         */
        iface_info.fcslen = -1;
    }

    /*
     * Did we get a time stamp offset option?
     */
    if (wtap_block_get_int64_option_value(wblock->block, OPT_IDB_TSOFFSET,
                                          &iface_info.tsoffset) == WTAP_OPTTYPE_SUCCESS) {
        /*
         * Yes.
         *
         * Remove the option, as the time stamps we provide will be
         * absolute time stamps, with the offset added in, so it will
         * appear as if there were no such option.
         */
        wtap_block_remove_option(wblock->block, OPT_IDB_TSOFFSET);
    } else {
        /*
         * No.  Default to 0, meahing that time stamps in the file are
         * absolute time stamps.
         */
        iface_info.tsoffset = 0;
    }

    g_array_append_val(section_info->interfaces, iface_info);
}

/* Process an NRB that we have just read. */
static void
pcapng_process_nrb(wtap *wth, wtapng_block_t *wblock)
{
    wtapng_process_nrb(wth, wblock->block);

    if (wth->nrbs == NULL) {
        wth->nrbs = g_array_new(false, false, sizeof(wtap_block_t));
    }
    /* Store NRB such that it can be saved by the dumper. */
    g_array_append_val(wth->nrbs, wblock->block);
}

/* Process a DSB that we have just read. */
static void
pcapng_process_dsb(wtap *wth, wtapng_block_t *wblock)
{
    wtapng_process_dsb(wth, wblock->block);

    /* Store DSB such that it can be saved by the dumper. */
    g_array_append_val(wth->dsbs, wblock->block);
}

/* Process a Sysdig meta event block that we have just read. */
static void
pcapng_process_meta_event(wtap *wth, wtapng_block_t *wblock)
{
    // XXX add wtapng_process_meta_event(wth, wblock->block);

    /* Store meta event such that it can be saved by the dumper. */
    g_array_append_val(wth->meta_events, wblock->block);
}

static void
pcapng_process_internal_block(wtap *wth, pcapng_t *pcapng, section_info_t *current_section, section_info_t new_section, wtapng_block_t *wblock, const int64_t *data_offset)
{
    wtap_block_t wtapng_if_descr;
    wtap_block_t if_stats;
    wtapng_if_stats_mandatory_t *if_stats_mand_block, *if_stats_mand;
    wtapng_if_descr_mandatory_t *wtapng_if_descr_mand;

    switch (wblock->type) {

        case(BLOCK_TYPE_SHB):
            ws_debug("another section header block");

            /*
             * Add this SHB to the table of SHBs.
             */
            g_array_append_val(wth->shb_hdrs, wblock->block);
            g_array_append_val(wth->shb_iface_to_global, wth->interface_data->len);

            /*
             * Update the current section number, and add
             * the updated section_info_t to the array of
             * section_info_t's for this file.
             */
            pcapng->current_section_number++;
            new_section.interfaces = g_array_new(false, false, sizeof(interface_info_t));
            new_section.shb_off = *data_offset;
            g_array_append_val(pcapng->sections, new_section);
            break;

        case(BLOCK_TYPE_IDB):
            /* A new interface */
            ws_debug("block type BLOCK_TYPE_IDB");
            pcapng_process_idb(wth, current_section, wblock);
            wtap_block_unref(wblock->block);
            break;

        case(BLOCK_TYPE_DSB):
            /* Decryption secrets. */
            ws_debug("block type BLOCK_TYPE_DSB");
            pcapng_process_dsb(wth, wblock);
            /* Do not free wblock->block, it is consumed by pcapng_process_dsb */
            break;

        case(BLOCK_TYPE_NRB):
            /* More name resolution entries */
            ws_debug("block type BLOCK_TYPE_NRB");
            pcapng_process_nrb(wth, wblock);
            /* Do not free wblock->block, it is consumed by pcapng_process_nrb */
            break;

        case(BLOCK_TYPE_ISB):
            /*
             * Another interface statistics report
             *
             * XXX - given that they're reports, we should be
             * supplying them in read calls, and displaying them
             * in the "packet" list, so you can see what the
             * statistics were *at the time when the report was
             * made*.
             *
             * The statistics from the *last* ISB could be displayed
             * in the summary, but if there are packets after the
             * last ISB, that could be misleading.
             *
             * If we only display them if that ISB has an isb_endtime
             * option, which *should* only appear when capturing ended
             * on that interface (so there should be no more packet
             * blocks or ISBs for that interface after that point,
             * that would be the best way of showing "summary"
             * statistics.
             */
            ws_debug("block type BLOCK_TYPE_ISB");
            if_stats_mand_block = (wtapng_if_stats_mandatory_t*)wtap_block_get_mandatory_data(wblock->block);
            if (wth->interface_data->len <= if_stats_mand_block->interface_id) {
                ws_debug("BLOCK_TYPE_ISB wblock.if_stats.interface_id %u >= number_of_interfaces",
                         if_stats_mand_block->interface_id);
            } else {
                /* Get the interface description */
                wtapng_if_descr = g_array_index(wth->interface_data, wtap_block_t, if_stats_mand_block->interface_id);
                wtapng_if_descr_mand = (wtapng_if_descr_mandatory_t*)wtap_block_get_mandatory_data(wtapng_if_descr);
                if (wtapng_if_descr_mand->num_stat_entries == 0) {
                    /* First ISB found, no previous entry */
                    ws_debug("block type BLOCK_TYPE_ISB. First ISB found, no previous entry");
                    wtapng_if_descr_mand->interface_statistics = g_array_new(false, false, sizeof(wtap_block_t));
                }

                if_stats = wtap_block_create(WTAP_BLOCK_IF_STATISTICS);
                if_stats_mand = (wtapng_if_stats_mandatory_t*)wtap_block_get_mandatory_data(if_stats);
                if_stats_mand->interface_id  = if_stats_mand_block->interface_id;
                if_stats_mand->ts_high       = if_stats_mand_block->ts_high;
                if_stats_mand->ts_low        = if_stats_mand_block->ts_low;

                wtap_block_copy(if_stats, wblock->block);
                g_array_append_val(wtapng_if_descr_mand->interface_statistics, if_stats);
                wtapng_if_descr_mand->num_stat_entries++;
            }
            wtap_block_unref(wblock->block);
            break;

        case BLOCK_TYPE_SYSDIG_MI:
        case BLOCK_TYPE_SYSDIG_PL_V1:
        case BLOCK_TYPE_SYSDIG_FDL_V1:
        case BLOCK_TYPE_SYSDIG_IL_V1:
        case BLOCK_TYPE_SYSDIG_UL_V1:
        case BLOCK_TYPE_SYSDIG_PL_V2:
        case BLOCK_TYPE_SYSDIG_PL_V3:
        case BLOCK_TYPE_SYSDIG_PL_V4:
        case BLOCK_TYPE_SYSDIG_PL_V5:
        case BLOCK_TYPE_SYSDIG_PL_V6:
        case BLOCK_TYPE_SYSDIG_PL_V7:
        case BLOCK_TYPE_SYSDIG_PL_V8:
        case BLOCK_TYPE_SYSDIG_PL_V9:
        case BLOCK_TYPE_SYSDIG_FDL_V2:
        case BLOCK_TYPE_SYSDIG_IL_V2:
        case BLOCK_TYPE_SYSDIG_UL_V2:
            /* Meta events */
            ws_debug("block type Sysdig meta event");
            pcapng_process_meta_event(wth, wblock);
            /* Do not free wblock->block, it is consumed by pcapng_process_sysdig_meb */
            break;

        default:
            /* XXX - improve handling of "unknown" blocks */
            ws_debug("Unknown block type 0x%08x", wblock->type);
            break;
    }
}

/* classic wtap: open capture file */
wtap_open_return_val
pcapng_open(wtap *wth, int *err, char **err_info)
{
    wtapng_block_t wblock;
    pcapng_t *pcapng;
    pcapng_block_header_t bh;
    int64_t saved_offset;
    section_info_t first_section, new_section, *current_section;

    ws_debug("opening file");
    /*
     * Read first block.
     *
     * First, try to read the block header.
     */
    if (!wtap_read_bytes_or_eof(wth->fh, &bh, sizeof bh, err, err_info)) {
        ws_debug("wtap_read_bytes_or_eof() failed, err = %d.", *err);
        if (*err == 0 || *err == WTAP_ERR_SHORT_READ) {
            /*
             * Short read or EOF.
             *
             * We're reading this as part of an open, so
             * the file is too short to be a pcapng file.
             */
            *err = 0;
            g_free(*err_info);
            *err_info = NULL;
            return WTAP_OPEN_NOT_MINE;
        }
        return WTAP_OPEN_ERROR;
    }

    /*
     * If this is a pcapng file, the first block must be a
     * Section Header Block.
     */
    if (bh.block_type != BLOCK_TYPE_SHB) {
        /*
         * Not an SHB, so this isn't a pcapng file.
         *
         * XXX - check for damage from transferring a file
         * between Windows and UN*X as text rather than
         * binary data?
         */
        ws_debug("first block type 0x%08x not SHB", bh.block_type);
        return WTAP_OPEN_NOT_MINE;
    }

    ws_debug("got an SHB");

    /*
     * Now try to read the block body, filling in the section_info_t
     * for the first section.
     */
    wblock.type = bh.block_type;
    wblock.block = NULL;
    /* we don't expect any packet blocks yet */
    wblock.frame_buffer = NULL;
    wblock.rec = NULL;

    switch (pcapng_read_section_header_block(wth->fh, &bh, &first_section,
                                             &wblock, err, err_info)) {
    case PCAPNG_BLOCK_OK:
        /* No problem */
        break;

    case PCAPNG_BLOCK_NOT_SHB:
        /* This doesn't look like an SHB, so this isn't a pcapng file. */
        wtap_block_unref(wblock.block);
        *err = 0;
        g_free(*err_info);
        *err_info = NULL;
        return WTAP_OPEN_NOT_MINE;

    case PCAPNG_BLOCK_ERROR:
        wtap_block_unref(wblock.block);
        if (*err == WTAP_ERR_SHORT_READ) {
            /*
             * Short read.
             *
             * We're reading this as part of an open, so
             * the file is too short to be a pcapng file.
             */
            *err = 0;
            g_free(*err_info);
            *err_info = NULL;
            return WTAP_OPEN_NOT_MINE;
        }
        /* An I/O error. */
        return WTAP_OPEN_ERROR;
    }

    /*
     * Read and check the block trailer.
     */
    if (!pcapng_read_and_check_block_trailer(wth->fh, &bh, &first_section, err, err_info)) {
        /* Not readable or not valid. */
        wtap_block_unref(wblock.block);
        return WTAP_OPEN_ERROR;
    }

    /*
     * At this point, we've decided this is a pcapng file, not
     * some other type of file, so we can't return WTAP_OPEN_NOT_MINE
     * past this point.
     *
     * Copy the SHB that we just read to the first entry in the table of
     * SHBs for this file.
     */
    wtap_block_copy(g_array_index(wth->shb_hdrs, wtap_block_t, 0), wblock.block);
    wtap_block_unref(wblock.block);
    wblock.block = NULL;

    wth->file_encap = WTAP_ENCAP_NONE;
    wth->snapshot_length = 0;
    wth->file_tsprec = WTAP_TSPREC_UNKNOWN;
    pcapng = g_new(pcapng_t, 1);
    wth->priv = (void *)pcapng;
    /*
     * We're currently processing the first section; as this is written
     * in C, that's section 0. :-)
     */
    pcapng->current_section_number = 0;

    /*
     * Create the array of interfaces for the first section.
     */
    first_section.interfaces = g_array_new(false, false, sizeof(interface_info_t));

    /*
     * The first section is at the very beginning of the file.
     */
    first_section.shb_off = 0;

    /*
     * Allocate the sections table with space reserved for the first
     * section, and add that section.
     */
    pcapng->sections = g_array_sized_new(false, false, sizeof(section_info_t), 1);
    g_array_append_val(pcapng->sections, first_section);

    wth->subtype_read = pcapng_read;
    wth->subtype_seek_read = pcapng_seek_read;
    wth->subtype_close = pcapng_close;
    wth->file_type_subtype = pcapng_file_type_subtype;

    /* Always initialize the lists of Decryption Secret Blocks, Name
     * Resolution Blocks, and Sysdig meta event blocks such that a
     * wtap_dumper can refer to them right after opening the capture
     * file. */
    wth->dsbs = g_array_new(false, false, sizeof(wtap_block_t));
    wth->nrbs = g_array_new(false, false, sizeof(wtap_block_t));
    wth->meta_events = g_array_new(false, false, sizeof(wtap_block_t));

    /* Most other capture types (such as pcap) support a single link-layer
     * type, indicated in the header, and don't support WTAP_ENCAP_PER_PACKET.
     * Most programs that write such capture files want to know the link-layer
     * type when initially opening the destination file, and (unlike Wireshark)
     * don't want to read the entire source file to find all the link-layer
     * types before writing (particularly if reading from a pipe or FIFO.)
     *
     * In support of this, read all the internally-processed, non packet
     * blocks that appear before the first packet block (EPB or SPB).
     *
     * Note that such programs will still have issues when trying to read
     * a pcapng that has a new link-layer type in an IDB in the middle of
     * the file, as they will discover in the middle that no, they can't
     * successfully write the output file as desired.
     */
    while (1) {
        /* peek at next block */
        /* Try to read the (next) block header */
        saved_offset = file_tell(wth->fh);
        if (!wtap_read_bytes_or_eof(wth->fh, &bh, sizeof bh, err, err_info)) {
            if (*err == 0) {
                /* EOF */
                ws_debug("No more blocks available...");
                break;
            }
            ws_debug("Check for more initial blocks, wtap_read_bytes_or_eof() failed, err = %d.",
                     *err);
            return WTAP_OPEN_ERROR;
        }

        /* go back to where we were */
        file_seek(wth->fh, saved_offset, SEEK_SET, err);

        /*
         * Get a pointer to the current section's section_info_t.
         */
        current_section = &g_array_index(pcapng->sections, section_info_t,
                                         pcapng->current_section_number);

        if (current_section->byte_swapped) {
            bh.block_type         = GUINT32_SWAP_LE_BE(bh.block_type);
        }

        ws_debug("Check for more initial internal blocks, block_type 0x%08x",
                 bh.block_type);

        if (!get_block_type_internal(bh.block_type)) {
            break;  /* Next block has to be returned in pcap_read */
        }
        /* Note that some custom block types, unlike packet blocks,
         * don't need to be preceded by an IDB and so theoretically
         * we could skip past them here. However, then there's no good
         * way to both later return those blocks in pcap_read() and
         * ensure that we don't read and process the IDBs (and other
         * internal block types) a second time.
         *
         * pcapng_read_systemd_journal_export_block() sets the file level
         * link-layer type if it's still UNKNOWN. We could do the same here
         * for it and possibly other types based on block type, even without
         * reading them.
         */
        if (!pcapng_read_block(wth, wth->fh, pcapng, current_section,
                              &new_section, &wblock, err, err_info)) {
            wtap_block_unref(wblock.block);
            if (*err == 0) {
                ws_debug("No more initial blocks available...");
                break;
            } else {
                ws_debug("couldn't read block");
                return WTAP_OPEN_ERROR;
            }
        }
        pcapng_process_internal_block(wth, pcapng, current_section, new_section, &wblock, &saved_offset);
        ws_debug("Read IDB number_of_interfaces %u, wtap_encap %i",
                 wth->interface_data->len, wth->file_encap);
    }
    return WTAP_OPEN_MINE;
}

/* classic wtap: read packet */
static bool
pcapng_read(wtap *wth, wtap_rec *rec, Buffer *buf, int *err,
            char **err_info, int64_t *data_offset)
{
    pcapng_t *pcapng = (pcapng_t *)wth->priv;
    section_info_t *current_section, new_section;
    wtapng_block_t wblock;

    wblock.frame_buffer  = buf;
    wblock.rec = rec;

    /* read next block */
    while (1) {
        *data_offset = file_tell(wth->fh);
        ws_noisy("data_offset is %" PRId64, *data_offset);

        /*
         * Get the section_info_t for the current section.
         */
        current_section = &g_array_index(pcapng->sections, section_info_t,
                                         pcapng->current_section_number);

        /*
         * Read the next block.
         */
        if (!pcapng_read_block(wth, wth->fh, pcapng, current_section,
                               &new_section, &wblock, err, err_info)) {
            ws_noisy("data_offset is finally %" PRId64, *data_offset);
            ws_debug("couldn't read packet block");
            wtap_block_unref(wblock.block);
            return false;
        }

        if (!wblock.internal) {
            /*
             * This is a block type we return to the caller to process.
             */
            ws_noisy("rec_type %u", wblock.rec->rec_type);
            break;
        }

        /*
         * This is a block type we process internally, rather than
         * returning it for the caller to process.
         */
        pcapng_process_internal_block(wth, pcapng, current_section, new_section, &wblock, data_offset);
    }

    /*ws_debug("Read length: %u Packet length: %u", bytes_read, rec->rec_header.packet_header.caplen);*/
    ws_noisy("data_offset is finally %" PRId64, *data_offset);

    /* Provide the section number */
    rec->presence_flags |= WTAP_HAS_SECTION_NUMBER;
    rec->section_number = pcapng->current_section_number;

    return true;
}

/* classic wtap: seek to file position and read packet */
static bool
pcapng_seek_read(wtap *wth, int64_t seek_off,
                 wtap_rec *rec, Buffer *buf,
                 int *err, char **err_info)
{
    pcapng_t *pcapng = (pcapng_t *)wth->priv;
    section_info_t *section_info, new_section;
    wtapng_block_t wblock;


    /* seek to the right file position */
    if (file_seek(wth->random_fh, seek_off, SEEK_SET, err) < 0) {
        return false;   /* Seek error */
    }
    ws_noisy("reading at offset %" PRIu64, seek_off);

    /*
     * Find the section_info_t for the section in which this block
     * appears.
     *
     * First, make sure we have at least one section; if we don't, that's
     * an internal error.
     */
    ws_assert(pcapng->sections->len >= 1);

    /*
     * Now scan backwards through the array to find the first section
     * that begins at or before the offset of the block we're reading.
     *
     * Yes, that's O(n) in the number of blocks, but we're unlikely to
     * have many blocks and pretty unlikely to have more than one.
     */
    unsigned section_number = pcapng->sections->len - 1;
    for (;;) {
        section_info = &g_array_index(pcapng->sections, section_info_t,
                                      section_number);
        if (section_info->shb_off <= seek_off)
            break;

        /*
         * If that's section 0, something's wrong; that section should
         * have an offset of 0.
         */
        ws_assert(section_number != 0);
        section_number--;
    }

    wblock.frame_buffer = buf;
    wblock.rec = rec;

    /* read the block */
    if (!pcapng_read_block(wth, wth->random_fh, pcapng, section_info,
                           &new_section, &wblock, err, err_info)) {
        ws_debug("couldn't read packet block (err=%d).", *err);
        wtap_block_unref(wblock.block);
        return false;
    }

    /* block must not be one we process internally rather than supplying */
    if (wblock.internal) {
        ws_debug("block type 0x%08x is not one we return",
                 wblock.type);
        wtap_block_unref(wblock.block);
        return false;
    }

    wtap_block_unref(wblock.block);

    /* Provide the section number */
    rec->presence_flags |= WTAP_HAS_SECTION_NUMBER;
    rec->section_number = section_number;

    return true;
}

/* classic wtap: close capture file */
static void
pcapng_close(wtap *wth)
{
    pcapng_t *pcapng = (pcapng_t *)wth->priv;

    ws_debug("closing file");

    /*
     * Free up the interfaces tables for all the sections.
     */
    for (unsigned i = 0; i < pcapng->sections->len; i++) {
        section_info_t *section_info = &g_array_index(pcapng->sections,
                                                      section_info_t, i);
        g_array_free(section_info->interfaces, true);
    }
    g_array_free(pcapng->sections, true);
}

typedef uint32_t (*compute_option_size_func)(wtap_block_t, unsigned, wtap_opttype_e, wtap_optval_t*);

typedef struct compute_options_size_t
{
    uint32_t size;
    compute_option_size_func compute_option_size;
} compute_options_size_t;

/*
 * As it says at the top of the file, an option sizer "calculates how many
 * bytes the option's data requires, not including any padding bytes."
 * Callers are responsible for rounding up to multiples of 4 bytes.
 * compute_block_options_size() does that for each option in the block;
 * option writers that call an option sizer (which helps ensure that the
 * sizes are internally consistent) should do the same.
 */

static uint32_t pcapng_compute_string_option_size(wtap_optval_t *optval)
{
    uint32_t size = 0;

    size = (uint32_t)strlen(optval->stringval) & 0xffff;

    return size;
}

#if 0
static uint32_t pcapng_compute_bytes_option_size(wtap_optval_t *optval)
{
    uint32_t size = 0;

    size = (uint32_t)g_bytes_get_size(optval->byteval) & 0xffff;

    return size;
}
#endif

static uint32_t pcapng_compute_if_filter_option_size(wtap_optval_t *optval)
{
    if_filter_opt_t* filter = &optval->if_filterval;
    uint32_t size;

    if (filter->type == if_filter_pcap) {
        size = (uint32_t)(strlen(filter->data.filter_str) + 1) & 0xffff;
    } else if (filter->type == if_filter_bpf) {
        size = (uint32_t)((filter->data.bpf_prog.bpf_prog_len * 8) + 1) & 0xffff;
    } else {
        /* Unknown type; don't write it */
        size = 0;
    }
    return size;
}

static uint32_t pcapng_compute_custom_option_size(wtap_optval_t *optval)
{
    size_t size;

    /* PEN */
    size = sizeof(uint32_t);
    switch (optval->custom_opt.pen) {
    case PEN_NFLX:
        /* NFLX type */
        size += sizeof(uint32_t);
        size += optval->custom_opt.data.nflx_data.custom_data_len;
        break;
    default:
        size += optval->custom_opt.data.generic_data.custom_data_len;
        break;
    }
    if (size > 65535) {
        size = 65535;
    }

    return (uint32_t)size;
}

static uint32_t pcapng_compute_packet_hash_option_size(wtap_optval_t *optval)
{
    packet_hash_opt_t* hash = &optval->packet_hash;
    uint32_t size;

    switch (hash->type) {
    case OPT_HASH_CRC32:
        size = 4;
        break;
    case OPT_HASH_MD5:
        size = 16;
        break;
    case OPT_HASH_SHA1:
        size = 20;
        break;
    case OPT_HASH_TOEPLITZ:
        size = 4;
        break;
    default:
        /* 2COMP and XOR size not defined in standard (yet) */
        size = hash->hash_bytes->len;
        break;
    }
    /* XXX - What if the size of the hash bytes doesn't match the
     * expected size? We can:
     * 1) Return 0, and omit it when writing
     * 2) Return hash_bytes->len, and write it out exactly as we have it
     * 3) Return the correct size here, and when writing err or possibly
     * truncate.
     */
    /* Account for the size of the algorithm type field. */
    size += 1;

    return size;
}

static uint32_t pcapng_compute_packet_verdict_option_size(wtap_optval_t *optval)
{
    packet_verdict_opt_t* verdict = &optval->packet_verdictval;
    uint32_t size;

    switch (verdict->type) {

    case packet_verdict_hardware:
        size = verdict->data.verdict_bytes->len;
        break;

    case packet_verdict_linux_ebpf_tc:
        size = 8;
        break;

    case packet_verdict_linux_ebpf_xdp:
        size = 8;
        break;

    default:
        size = 0;
        break;
    }
    /* Account for the type octet */
    if (size) {
        size += 1;
    }

    return size;
}

static bool
compute_block_option_size(wtap_block_t block _U_, unsigned option_id, wtap_opttype_e option_type, wtap_optval_t *optval, void *user_data)
{
    compute_options_size_t* options_size = (compute_options_size_t*)user_data;
    uint32_t size = 0;

    /*
     * Process the option IDs that are the same for all block types here;
     * call the block-type-specific compute_size function for others.
     */
    switch(option_id)
    {
    case OPT_COMMENT:
        size = pcapng_compute_string_option_size(optval);
        break;
    case OPT_CUSTOM_STR_COPY:
    case OPT_CUSTOM_BIN_COPY:
        size = pcapng_compute_custom_option_size(optval);
        break;
    case OPT_CUSTOM_STR_NO_COPY:
    case OPT_CUSTOM_BIN_NO_COPY:
        /*
         * Do not count these, as they're not supposed to be copied to
         * new files.
         *
         * XXX - what if we're writing out a file that's *not* based on
         * another file, so that we're *not* copying it from that file?
         */
        break;
    default:
        /* Block-type dependent; call the callback. */
        size = (*options_size->compute_option_size)(block, option_id, option_type, optval);
        break;
    }

    /*
     * Are we writing this option?
     */
    /*
     * XXX: The option length field is 16 bits. If size > 65535 (how?
     * was the block was obtained from some format other than pcapng?),
     * are we going to silently omit the option (in which case we shouldn't
     * add the size here), or err out when writing it (in which case
     * it's probably fine to add the size or not?) Adding it here and
     * then omitting it when writing, as some of the routines do, means
     * creating a corrupt file.
     */
    if (size != 0) {
        /*
         * Yes.  Add the size of the option header to the size of the
         * option data.
         */
        options_size->size += 4;

        /* Now add the size of the option value. */
        options_size->size += size;

        /* Add optional padding to 32 bits */
        if ((size & 0x03) != 0)
        {
            options_size->size += 4 - (size & 0x03);
        }
    }
    return true; /* we always succeed */
}

static uint32_t
compute_options_size(wtap_block_t block, compute_option_size_func compute_option_size)
{
    compute_options_size_t compute_options_size;

    /*
     * Compute the total size of all the options in the block.
     * This always succeeds, so we don't check the return value.
     */
    compute_options_size.size = 0;
    compute_options_size.compute_option_size = compute_option_size;
    wtap_block_foreach_option(block, compute_block_option_size, &compute_options_size);

    /* Are we writing any options? */
    if (compute_options_size.size != 0) {
        /* Yes, add the size of the End-of-options tag. */
        compute_options_size.size += 4;
    }
    return compute_options_size.size;
}

static uint32_t compute_shb_option_size(wtap_block_t block _U_, unsigned option_id, wtap_opttype_e option_type _U_, wtap_optval_t* optval)
{
    uint32_t size;

    switch(option_id)
    {
    case OPT_SHB_HARDWARE:
    case OPT_SHB_OS:
    case OPT_SHB_USERAPPL:
        size = pcapng_compute_string_option_size(optval);
        break;
    default:
        /* Unknown options - size by datatype? */
        size = 0;
        break;
    }
    return size;
}

typedef bool (*write_option_func)(wtap_dumper *, wtap_block_t, unsigned, wtap_opttype_e, wtap_optval_t*, int*);

typedef struct write_options_t
{
    wtap_dumper *wdh;
    int *err;
    write_option_func write_option;
}
write_options_t;

static bool pcapng_write_option_eofopt(wtap_dumper *wdh, int *err)
{
    struct pcapng_option_header option_hdr;

    /* Write end of options */
    option_hdr.type = OPT_EOFOPT;
    option_hdr.value_length = 0;
    if (!wtap_dump_file_write(wdh, &option_hdr, 4, err))
        return false;
    return true;
}

static bool pcapng_write_uint8_option(wtap_dumper *wdh, unsigned option_id, wtap_optval_t *optval, int *err)
{
    struct pcapng_option_header option_hdr;
    const uint32_t zero_pad = 0;

    option_hdr.type         = (uint16_t)option_id;
    option_hdr.value_length = (uint16_t)1;
    if (!wtap_dump_file_write(wdh, &option_hdr, 4, err))
        return false;

    if (!wtap_dump_file_write(wdh, &optval->uint8val, 1, err))
        return false;

    if (!wtap_dump_file_write(wdh, &zero_pad, 3, err))
        return false;

    return true;
}

static bool pcapng_write_uint32_option(wtap_dumper *wdh, unsigned option_id, wtap_optval_t *optval, int *err)
{
    struct pcapng_option_header option_hdr;

    option_hdr.type         = (uint16_t)option_id;
    option_hdr.value_length = (uint16_t)4;
    if (!wtap_dump_file_write(wdh, &option_hdr, 4, err))
        return false;

    if (!wtap_dump_file_write(wdh, &optval->uint32val, 4, err))
        return false;

    return true;
}

static bool pcapng_write_uint64_option(wtap_dumper *wdh, unsigned option_id, wtap_optval_t *optval, int *err)
{
    struct pcapng_option_header option_hdr;

    option_hdr.type         = (uint16_t)option_id;
    option_hdr.value_length = (uint16_t)8;
    if (!wtap_dump_file_write(wdh, &option_hdr, 4, err))
        return false;

    if (!wtap_dump_file_write(wdh, &optval->uint64val, 8, err))
        return false;

    return true;
}

static bool pcapng_write_timestamp_option(wtap_dumper *wdh, unsigned option_id, wtap_optval_t *optval, int *err)
{
    struct pcapng_option_header option_hdr;
    uint32_t high, low;

    option_hdr.type         = (uint16_t)option_id;
    option_hdr.value_length = (uint16_t)8;
    if (!wtap_dump_file_write(wdh, &option_hdr, 4, err))
        return false;

    high = (uint32_t)(optval->uint64val >> 32);
    low = (uint32_t)(optval->uint64val >> 0);
    if (!wtap_dump_file_write(wdh, &high, 4, err))
        return false;
    if (!wtap_dump_file_write(wdh, &low, 4, err))
        return false;

    return true;
}

static bool pcapng_write_string_option(wtap_dumper *wdh, unsigned option_id, wtap_optval_t *optval, int *err)
{
    struct pcapng_option_header option_hdr;
    size_t size = strlen(optval->stringval);
    const uint32_t zero_pad = 0;
    uint32_t pad;

    if (size == 0)
        return true;
    if (size > 65535) {
        /*
         * Too big to fit in the option.
         * Don't write anything.
         *
         * XXX - truncate it?  Report an error?
         */
        return true;
    }

    /* String options don't consider pad bytes part of the length */
    option_hdr.type         = (uint16_t)option_id;
    option_hdr.value_length = (uint16_t)size;
    if (!wtap_dump_file_write(wdh, &option_hdr, 4, err))
        return false;

    if (!wtap_dump_file_write(wdh, optval->stringval, size, err))
        return false;

    if ((size % 4)) {
        pad = 4 - (size % 4);
    } else {
        pad = 0;
    }

    /* write padding (if any) */
    if (pad != 0) {
        if (!wtap_dump_file_write(wdh, &zero_pad, pad, err))
            return false;
    }

    return true;
}

#if 0
static bool pcapng_write_bytes_option(wtap_dumper *wdh, unsigned option_id, wtap_optval_t *optval, int *err)
{
    struct pcapng_option_header option_hdr;
    size_t size = g_bytes_get_size(optval->byteval);
    const uint32_t zero_pad = 0;
    uint32_t pad;

    if (size == 0)
        return true;
    if (size > 65535) {
        /*
         * Too big to fit in the option.
         * Don't write anything.
         *
         * XXX - truncate it?  Report an error?
         */
        return true;
    }

    /* Bytes options don't consider pad bytes part of the length */
    option_hdr.type         = (uint16_t)option_id;
    option_hdr.value_length = (uint16_t)size;
    if (!wtap_dump_file_write(wdh, &option_hdr, 4, err))
        return false;

    if (!wtap_dump_file_write(wdh, optval->stringval, size, err))
        return false;

    if ((size % 4)) {
        pad = 4 - (size % 4);
    } else {
        pad = 0;
    }

    /* write padding (if any) */
    if (pad != 0) {
        if (!wtap_dump_file_write(wdh, &zero_pad, pad, err))
            return false;
    }

    return true;
}

static bool pcapng_write_ipv4_option(wtap_dumper *wdh, unsigned option_id, wtap_optval_t *optval, int *err)
{
    struct pcapng_option_header option_hdr;

    option_hdr.type         = (uint16_t)option_id;
    option_hdr.value_length = (uint16_t)4;
    if (!wtap_dump_file_write(wdh, &option_hdr, 4, err))
        return false;

    if (!wtap_dump_file_write(wdh, &optval->ipv4val, 1, err))
        return false;

    return true;
}

static bool pcapng_write_ipv6_option(wtap_dumper *wdh, unsigned option_id, wtap_optval_t *optval, int *err)
{
    struct pcapng_option_header option_hdr;

    option_hdr.type         = (uint16_t)option_id;
    option_hdr.value_length = (uint16_t)IPv6_ADDR_SIZE;
    if (!wtap_dump_file_write(wdh, &option_hdr, 4, err))
        return false;

    if (!wtap_dump_file_write(wdh, &optval->ipv6val.bytes, IPv6_ADDR_SIZE, err))
        return false;

    return true;
}
#endif

static bool pcapng_write_if_filter_option(wtap_dumper *wdh, unsigned option_id, wtap_optval_t *optval, int *err)
{
    if_filter_opt_t* filter = &optval->if_filterval;
    uint32_t size, pad;
    uint8_t filter_type;
    size_t filter_data_len;
    struct pcapng_option_header option_hdr;
    const uint32_t zero_pad = 0;

    switch (filter->type) {

    case if_filter_pcap:
        filter_type = 0; /* pcap filter string */
        filter_data_len = strlen(filter->data.filter_str);
        if (filter_data_len > 65534) {
            /*
             * Too big to fit in the option.
             * Don't write anything.
             *
             * XXX - truncate it?  Report an error?
             */
            return true;
        }
        break;

    case if_filter_bpf:
        filter_type = 1; /* BPF filter program */
        filter_data_len = filter->data.bpf_prog.bpf_prog_len*8;
        if (filter_data_len > 65528) {
            /*
             * Too big to fit in the option.  (The filter length
             * must be a multiple of 8, as that's the length
             * of a BPF instruction.)  Don't write anything.
             *
             * XXX - truncate it?  Report an error?
             */
            return true;
        }
        break;

    default:
        /* Unknown filter type; don't write anything. */
        return true;
    }
    size = (uint32_t)(filter_data_len + 1);
    if ((size % 4)) {
        pad = 4 - (size % 4);
    } else {
        pad = 0;
    }

    option_hdr.type         = option_id;
    option_hdr.value_length = size;
    if (!wtap_dump_file_write(wdh, &option_hdr, 4, err))
        return false;

    /* Write the filter type */
    if (!wtap_dump_file_write(wdh, &filter_type, 1, err))
        return false;

    switch (filter->type) {

    case if_filter_pcap:
        /* Write the filter string */
        if (!wtap_dump_file_write(wdh, filter->data.filter_str, filter_data_len, err))
            return false;
        break;

    case if_filter_bpf:
        if (!wtap_dump_file_write(wdh, filter->data.bpf_prog.bpf_prog, filter_data_len, err))
            return false;
        break;

    default:
        ws_assert_not_reached();
        return true;
    }

    /* write padding (if any) */
    if (pad != 0) {
        if (!wtap_dump_file_write(wdh, &zero_pad, pad, err))
            return false;
    }
    return true;
}

static bool pcapng_write_custom_option(wtap_dumper *wdh, unsigned option_id, wtap_optval_t *optval, int *err)
{
    struct pcapng_option_header option_hdr;
    size_t pad;
    size_t size;
    const uint32_t zero_pad = 0;
    uint32_t pen, type;
    bool use_little_endian;

    if ((option_id == OPT_CUSTOM_STR_NO_COPY) ||
        (option_id == OPT_CUSTOM_BIN_NO_COPY))
        return true;
    ws_debug("PEN %d", optval->custom_opt.pen);
    switch (optval->custom_opt.pen) {
    case PEN_NFLX:
        size = sizeof(uint32_t) + sizeof(uint32_t) + optval->custom_opt.data.nflx_data.custom_data_len;
        use_little_endian = optval->custom_opt.data.nflx_data.use_little_endian;
        break;
    default:
        size = sizeof(uint32_t) + optval->custom_opt.data.generic_data.custom_data_len;
        use_little_endian = false;
        break;
    }
    ws_debug("use_little_endian %d", use_little_endian);
    if (size > 65535) {
        /*
         * Too big to fit in the option.
         * Don't write anything.
         *
         * XXX - truncate it?  Report an error?
         */
        return true;
    }

    /* write option header */
    option_hdr.type         = (uint16_t)option_id;
    option_hdr.value_length = (uint16_t)size;
    if (use_little_endian) {
        option_hdr.type = GUINT16_TO_LE(option_hdr.type);
        option_hdr.value_length = GUINT16_TO_LE(option_hdr.value_length);
    }
    if (!wtap_dump_file_write(wdh, &option_hdr, sizeof(struct pcapng_option_header), err))
        return false;

    /* write PEN */
    pen = optval->custom_opt.pen;
    if (use_little_endian) {
        pen = GUINT32_TO_LE(pen);
    }
    if (!wtap_dump_file_write(wdh, &pen, sizeof(uint32_t), err))
        return false;

    switch (optval->custom_opt.pen) {
    case PEN_NFLX:
        /* write NFLX type */
        type = GUINT32_TO_LE(optval->custom_opt.data.nflx_data.type);
        ws_debug("type=%d", type);
        if (!wtap_dump_file_write(wdh, &type, sizeof(uint32_t), err))
            return false;
        /* write custom data */
        if (!wtap_dump_file_write(wdh, optval->custom_opt.data.nflx_data.custom_data, optval->custom_opt.data.nflx_data.custom_data_len, err)) {
            return false;
        }
        break;
    default:
        /* write custom data */
        if (!wtap_dump_file_write(wdh, optval->custom_opt.data.generic_data.custom_data, optval->custom_opt.data.generic_data.custom_data_len, err)) {
            return false;
        }
        break;
    }

    /* write padding (if any) */
    if (size % 4 != 0) {
        pad = 4 - (size % 4);
    } else {
        pad = 0;
    }
    if (pad != 0) {
        if (!wtap_dump_file_write(wdh, &zero_pad, pad, err)) {
            return false;
        }
    }
    ws_debug("Wrote custom option: type %u, length %u", option_hdr.type, option_hdr.value_length);

    return true;
}

static bool pcapng_write_packet_verdict_option(wtap_dumper *wdh, unsigned option_id, wtap_optval_t *optval, int *err)
{
    packet_verdict_opt_t* verdict = &optval->packet_verdictval;
    struct pcapng_option_header option_hdr;
    uint8_t type;
    size_t size;
    const uint32_t zero_pad = 0;
    uint32_t pad;

    size = pcapng_compute_packet_verdict_option_size(optval);

    switch (verdict->type) {

    case packet_verdict_hardware:
        if (size > 65535) {
            /*
             * Too big to fit in the option.
             * Don't write anything.
             *
             * XXX - truncate it?  Report an error?
             */
            return true;
        }
        option_hdr.type         = option_id;
        option_hdr.value_length = (uint16_t)size;
        if (!wtap_dump_file_write(wdh, &option_hdr, 4, err))
            return false;

        type = packet_verdict_hardware;
        if (!wtap_dump_file_write(wdh, &type, sizeof(uint8_t), err))
            return false;

        if (!wtap_dump_file_write(wdh, verdict->data.verdict_bytes->data,
                                  verdict->data.verdict_bytes->len, err))
            return false;
        break;

    case packet_verdict_linux_ebpf_tc:
        option_hdr.type         = option_id;
        option_hdr.value_length = (uint16_t)size;
        if (!wtap_dump_file_write(wdh, &option_hdr, 4, err))
            return false;

        type = packet_verdict_linux_ebpf_tc;
        if (!wtap_dump_file_write(wdh, &type, sizeof(uint8_t), err))
            return false;

        if (!wtap_dump_file_write(wdh, &verdict->data.verdict_linux_ebpf_tc,
                                  sizeof(uint64_t), err))
            return false;
        break;

    case packet_verdict_linux_ebpf_xdp:
        option_hdr.type         = option_id;
        option_hdr.value_length = (uint16_t)size;
        if (!wtap_dump_file_write(wdh, &option_hdr, 4, err))
            return false;

        type = packet_verdict_linux_ebpf_xdp;
        if (!wtap_dump_file_write(wdh, &type, sizeof(uint8_t), err))
            return false;

        if (!wtap_dump_file_write(wdh, &verdict->data.verdict_linux_ebpf_xdp,
                                  sizeof(uint64_t), err))
            return false;
        break;

    default:
        /* Unknown - don't write it out. */
        return true;
    }

    /* write padding (if any) */
    if ((size % 4)) {
        pad = 4 - (size % 4);
        if (!wtap_dump_file_write(wdh, &zero_pad, pad, err))
            return false;
    }
    return true;
}

static bool pcapng_write_packet_hash_option(wtap_dumper *wdh, unsigned option_id, wtap_optval_t *optval, int *err)
{
    packet_hash_opt_t* hash = &optval->packet_hash;
    struct pcapng_option_header option_hdr;
    uint8_t type;
    size_t size;
    const uint32_t zero_pad = 0;
    uint32_t pad;

    size = pcapng_compute_packet_hash_option_size(optval);

    if (size > 65535) {
        /*
         * Too big to fit in the option.
         * Don't write anything.
         *
         * XXX - truncate it?  Report an error?
         */
        return true;
    }

    if (size > hash->hash_bytes->len + 1) {
        /*
         * We don't have enough bytes to write.
         * pcapng_compute_packet_hash_option_size() should return 0 if
         * we want to silently omit the option instead, or should return
         * the length if we want to blindly copy it.
         * XXX - Is this the best error type?
         */
        *err = WTAP_ERR_UNWRITABLE_REC_DATA;
        return false;
    }

    type = hash->type;

    option_hdr.type         = option_id;
    /* Include type byte */
    option_hdr.value_length = (uint16_t)size;
    if (!wtap_dump_file_write(wdh, &option_hdr, 4, err))
        return false;

    if (!wtap_dump_file_write(wdh, &type, sizeof(uint8_t), err))
        return false;

    if (!wtap_dump_file_write(wdh, hash->hash_bytes->data, size - 1,
                              err))
        return false;

    /* write padding (if any) */
    if ((size % 4)) {
        pad = 4 - (size % 4);
        if (!wtap_dump_file_write(wdh, &zero_pad, pad, err))
            return false;
    }
    return true;
}

static bool write_block_option(wtap_block_t block, unsigned option_id, wtap_opttype_e option_type _U_, wtap_optval_t *optval, void* user_data)
{
    write_options_t* options = (write_options_t*)user_data;

    /*
     * Process the option IDs that are the same for all block types here;
     * call the block-type-specific compute_size function for others.
     */
    switch(option_id)
    {
    case OPT_COMMENT:
        if (!pcapng_write_string_option(options->wdh, option_id, optval, options->err))
            return false;
        break;
    case OPT_CUSTOM_STR_COPY:
    case OPT_CUSTOM_BIN_COPY:
        if (!pcapng_write_custom_option(options->wdh, option_id, optval, options->err))
            return false;
        break;
    case OPT_CUSTOM_STR_NO_COPY:
    case OPT_CUSTOM_BIN_NO_COPY:
        /*
         * Do not write these, as they're not supposed to be copied to
         * new files.
         *
         * XXX - what if we're writing out a file that's *not* based on
         * another file, so that we're *not* copying it from that file?
         */
        break;
    default:
        /* Block-type dependent; call the callback, if we have one. */
        if (options->write_option != NULL &&
            !(*options->write_option)(options->wdh, block, option_id, option_type, optval, options->err))
            return false;
        break;
    }
    return true;
}

static bool
write_options(wtap_dumper *wdh, wtap_block_t block, write_option_func write_option, int *err)
{
    write_options_t options;

    options.wdh = wdh;
    options.err = err;
    options.write_option = write_option;
    if (!wtap_block_foreach_option(block, write_block_option, &options))
        return false;

    /* Write end of options */
    return pcapng_write_option_eofopt(wdh, err);
}

static bool write_wtap_shb_option(wtap_dumper *wdh, wtap_block_t block _U_, unsigned option_id, wtap_opttype_e option_type _U_, wtap_optval_t *optval, int *err)
{
    switch(option_id)
    {
    case OPT_SHB_HARDWARE:
    case OPT_SHB_OS:
    case OPT_SHB_USERAPPL:
        if (!pcapng_write_string_option(wdh, option_id, optval, err))
            return false;
        break;
    default:
        /* Unknown options - write by datatype? */
        break;
    }
    return true; /* success */
}

/* Write a section header block.
 * If we don't have a section block header already, create a default
 * one with no options.
 */
static bool
pcapng_write_section_header_block(wtap_dumper *wdh, int *err)
{
    pcapng_block_header_t bh;
    pcapng_section_header_block_t shb;
    uint32_t options_size;
    wtap_block_t wdh_shb = NULL;

    if (wdh->shb_hdrs && (wdh->shb_hdrs->len > 0)) {
        wdh_shb = g_array_index(wdh->shb_hdrs, wtap_block_t, 0);
    }

    bh.block_total_length = (uint32_t)(sizeof(bh) + sizeof(shb) + 4);
    options_size = 0;
    if (wdh_shb) {
        ws_debug("Have shb_hdr");

        /* Compute size of all the options */
        options_size = compute_options_size(wdh_shb, compute_shb_option_size);

        bh.block_total_length += options_size;
    }

    ws_debug("Total len %u", bh.block_total_length);

    /* write block header */
    bh.block_type = BLOCK_TYPE_SHB;

    if (!wtap_dump_file_write(wdh, &bh, sizeof bh, err))
        return false;

    /* write block fixed content */
    shb.magic = 0x1A2B3C4D;
    shb.version_major = 1;
    shb.version_minor = 0;
    if (wdh_shb) {
        wtapng_section_mandatory_t* section_data = (wtapng_section_mandatory_t*)wtap_block_get_mandatory_data(wdh_shb);
        shb.section_length = section_data->section_length;
    } else {
        shb.section_length = -1;
    }

    if (!wtap_dump_file_write(wdh, &shb, sizeof shb, err))
        return false;

    if (wdh_shb) {
        /* Write options, if we have any */
        if (options_size != 0) {
            if (!write_options(wdh, wdh_shb, write_wtap_shb_option, err))
                return false;
        }
    }

    /* write block footer */
    if (!wtap_dump_file_write(wdh, &bh.block_total_length,
                              sizeof bh.block_total_length, err))
        return false;

    return true;
}

/* options defined in Section 2.5 (Options)
 * Name           Code Length     Description
 * opt_comment    1    variable   A UTF-8 string containing a comment that is associated to the current block.
 *
 * Enhanced Packet Block options
 * epb_flags      2    4          A flags word containing link-layer information. A complete specification of
 *                                the allowed flags can be found in Appendix A (Packet Block Flags Word).
 * epb_hash       3    variable   This option contains a hash of the packet. The first byte specifies the hashing algorithm,
 *                                while the following bytes contain the actual hash, whose size depends on the hashing algorithm,
 *                                                                and hence from the value in the first bit. The hashing algorithm can be: 2s complement
 *                                                                (algorithm byte = 0, size=XXX), XOR (algorithm byte = 1, size=XXX), CRC32 (algorithm byte = 2, size = 4),
 *                                                                MD-5 (algorithm byte = 3, size=XXX), SHA-1 (algorithm byte = 4, size=XXX).
 *                                                                The hash covers only the packet, not the header added by the capture driver:
 *                                                                this gives the possibility to calculate it inside the network card.
 *                                                                The hash allows easier comparison/merging of different capture files, and reliable data transfer between the
 *                                                                data acquisition system and the capture library.
 * epb_dropcount   4   8          A 64bit integer value specifying the number of packets lost (by the interface and the operating system)
 *                                between this packet and the preceding one.
 * epb_packetid    5   8          The epb_packetid option is a 64-bit unsigned integer that
 *                                uniquely identifies the packet.  If the same packet is seen
 *                                by multiple interfaces and there is a way for the capture
 *                                application to correlate them, the same epb_packetid value
 *                                must be used.  An example could be a router that captures
 *                                packets on all its interfaces in both directions.  When a
 *                                packet hits interface A on ingress, an EPB entry gets
 *                                created, TTL gets decremented, and right before it egresses
 *                                on interface B another EPB entry gets created in the trace
 *                                file.  In this case, two packets are in the capture file,
 *                                which are not identical but the epb_packetid can be used to
 *                                correlate them.
 * epb_queue       6   4          The epb_queue option is a 32-bit unsigned integer that
 *                                identifies on which queue of the interface the specific
 *                                packet was received.
 * epb_verdict     7   variable   The epb_verdict option stores a verdict of the packet.  The
 *                                verdict indicates what would be done with the packet after
 *                                processing it.  For example, a firewall could drop the
 *                                packet.  This verdict can be set by various components, i.e.
 *                                Hardware, Linux's eBPF TC or XDP framework, etc.  etc.  The
 *                                first octet specifies the verdict type, while the following
 *                                octets contain the actual verdict data, whose size depends on
 *                                the verdict type, and hence from the value in the first
 *                                octet.  The verdict type can be: Hardware (type octet = 0,
 *                                size = variable), Linux_eBPF_TC (type octet = 1, size = 8
 *                                (64-bit unsigned integer), value = TC_ACT_* as defined in the
 *                                Linux pck_cls.h include), Linux_eBPF_XDP (type octet = 2,
 *                                size = 8 (64-bit unsigned integer), value = xdp_action as
 *                                defined in the Linux pbf.h include).
 * opt_endofopt    0   0          It delimits the end of the optional fields. This block cannot be repeated within a given list of options.
 */
static uint32_t
compute_epb_option_size(wtap_block_t block _U_, unsigned option_id, wtap_opttype_e option_type _U_, wtap_optval_t* optval)
{
    uint32_t size;

    switch(option_id)
    {
    case OPT_EPB_FLAGS:
        size = 4;
        break;
    case OPT_EPB_DROPCOUNT:
        size = 8;
        break;
    case OPT_EPB_PACKETID:
        size = 8;
        break;
    case OPT_EPB_QUEUE:
        size = 4;
        break;
    case OPT_EPB_VERDICT:
        size = pcapng_compute_packet_verdict_option_size(optval);
        break;
    case OPT_EPB_HASH:
        size = pcapng_compute_packet_hash_option_size(optval);
        break;
    default:
        /* Unknown options - size by datatype? */
        size = 0;
        break;
    }
    return size;
}

static bool write_wtap_epb_option(wtap_dumper *wdh, wtap_block_t block _U_, unsigned option_id, wtap_opttype_e option_type _U_, wtap_optval_t *optval, int *err)
{
    switch(option_id)
    {
    case OPT_PKT_FLAGS:
        if (!pcapng_write_uint32_option(wdh, OPT_EPB_FLAGS, optval, err))
            return false;
        break;
    case OPT_PKT_DROPCOUNT:
        if (!pcapng_write_uint64_option(wdh, OPT_EPB_DROPCOUNT, optval, err))
            return false;
        break;
    case OPT_PKT_PACKETID:
        if (!pcapng_write_uint64_option(wdh, OPT_EPB_PACKETID, optval, err))
            return false;
        break;
    case OPT_PKT_QUEUE:
        if (!pcapng_write_uint32_option(wdh, OPT_EPB_QUEUE, optval, err))
            return false;
        break;
    case OPT_PKT_VERDICT:
        if (!pcapng_write_packet_verdict_option(wdh, OPT_EPB_VERDICT, optval,
                                                err))
            return false;
        break;
    case OPT_PKT_HASH:
        if (!pcapng_write_packet_hash_option(wdh, OPT_EPB_HASH, optval,
                                             err))
            return false;
        break;
    default:
        /* Unknown options - write by datatype? */
        break;
    }
    return true; /* success */
}

static bool
pcapng_write_simple_packet_block(wtap_dumper* wdh, const wtap_rec* rec,
                                 const uint8_t* pd, int* err, char** err_info _U_)
{
    const union wtap_pseudo_header* pseudo_header = &rec->rec_header.packet_header.pseudo_header;
    pcapng_block_header_t bh;
    pcapng_simple_packet_block_t spb;
    const uint32_t zero_pad = 0;
    uint32_t pad_len;
    uint32_t phdr_len;

    /* Don't write anything we're not willing to read. */
    if (rec->rec_header.packet_header.caplen > wtap_max_snaplen_for_encap(wdh->file_encap)) {
        *err = WTAP_ERR_PACKET_TOO_LARGE;
        return false;
    }

    phdr_len = (uint32_t)pcap_get_phdr_size(rec->rec_header.packet_header.pkt_encap, pseudo_header);
    if ((phdr_len + rec->rec_header.packet_header.caplen) % 4) {
        pad_len = 4 - ((phdr_len + rec->rec_header.packet_header.caplen) % 4);
    }
    else {
        pad_len = 0;
    }

    /* write (simple) packet block header */
    bh.block_type = BLOCK_TYPE_SPB;
    bh.block_total_length = (uint32_t)sizeof(bh) + (uint32_t)sizeof(spb) + phdr_len + rec->rec_header.packet_header.caplen + pad_len + 4;

    if (!wtap_dump_file_write(wdh, &bh, sizeof bh, err))
        return false;

    /* write block fixed content */
    spb.packet_len = rec->rec_header.packet_header.len + phdr_len;

    if (!wtap_dump_file_write(wdh, &spb, sizeof spb, err))
        return false;

    /* write pseudo header */
    if (!pcap_write_phdr(wdh, rec->rec_header.packet_header.pkt_encap, pseudo_header, err)) {
        return false;
    }

    /* write packet data */
    if (!wtap_dump_file_write(wdh, pd, rec->rec_header.packet_header.caplen, err))
        return false;

    /* write padding (if any) */
    if (pad_len != 0) {
        if (!wtap_dump_file_write(wdh, &zero_pad, pad_len, err))
            return false;
    }

    /* write block footer */
    if (!wtap_dump_file_write(wdh, &bh.block_total_length,
        sizeof bh.block_total_length, err))
        return false;

    return true;
}

static bool
pcapng_write_enhanced_packet_block(wtap_dumper *wdh, const wtap_rec *rec,
                                   const uint8_t *pd, int *err, char **err_info)
{
    const union wtap_pseudo_header *pseudo_header = &rec->rec_header.packet_header.pseudo_header;
    pcapng_block_header_t bh;
    pcapng_enhanced_packet_block_t epb;
    uint32_t options_size = 0;
    uint64_t ts;
    const uint32_t zero_pad = 0;
    uint32_t pad_len;
    uint32_t phdr_len;
    uint32_t options_total_length = 0;
    wtap_block_t int_data;
    wtapng_if_descr_mandatory_t *int_data_mand;

    /* Don't write anything we're not willing to read. */
    if (rec->rec_header.packet_header.caplen > wtap_max_snaplen_for_encap(wdh->file_encap)) {
        *err = WTAP_ERR_PACKET_TOO_LARGE;
        return false;
    }

    phdr_len = (uint32_t)pcap_get_phdr_size(rec->rec_header.packet_header.pkt_encap, pseudo_header);
    if ((phdr_len + rec->rec_header.packet_header.caplen) % 4) {
        pad_len = 4 - ((phdr_len + rec->rec_header.packet_header.caplen) % 4);
    } else {
        pad_len = 0;
    }

    if (rec->block != NULL) {
        /* Compute size of all the options */
        options_size = compute_options_size(rec->block, compute_epb_option_size);
    }

    /*
     * Check the interface ID. Do this before writing the header,
     * in case we need to add a new IDB.
     */
    if (rec->presence_flags & WTAP_HAS_INTERFACE_ID) {
        epb.interface_id        = rec->rec_header.packet_header.interface_id;
        if (rec->presence_flags & WTAP_HAS_SECTION_NUMBER && wdh->shb_iface_to_global) {
            /*
             * In the extremely unlikely event this overflows we give the
             * wrong interface ID.
             */
            epb.interface_id += g_array_index(wdh->shb_iface_to_global, unsigned, rec->section_number);
        }
    } else {
        /*
         * The source isn't sending us IDBs. See if we already have a
         * matching interface, and use it if so.
         */
        for (epb.interface_id = 0; epb.interface_id < wdh->interface_data->len; ++epb.interface_id) {
            int_data = g_array_index(wdh->interface_data, wtap_block_t,
                                     epb.interface_id);
            int_data_mand = (wtapng_if_descr_mandatory_t*)wtap_block_get_mandatory_data(int_data);
            if (int_data_mand->wtap_encap == rec->rec_header.packet_header.pkt_encap) {
                if (int_data_mand->tsprecision == rec->tsprec || (!(rec->presence_flags & WTAP_HAS_TS))) {
                    break;
                }
            }
        }
        if (epb.interface_id == wdh->interface_data->len) {
            /*
             * We don't have a matching IDB. Generate a new one
             * and write it to the file.
             */
            int_data = wtap_rec_generate_idb(rec);
            g_array_append_val(wdh->interface_data, int_data);
            if (!pcapng_write_if_descr_block(wdh, int_data, err)) {
                return false;
            }
        }
    }
    if (epb.interface_id >= wdh->interface_data->len) {
        /*
         * Our caller is doing something bad.
         */
        *err = WTAP_ERR_INTERNAL;
        *err_info = ws_strdup_printf("pcapng: epb.interface_id (%u) >= wdh->interface_data->len (%u)",
                                    epb.interface_id, wdh->interface_data->len);
        return false;
    }
    int_data = g_array_index(wdh->interface_data, wtap_block_t,
                             epb.interface_id);
    int_data_mand = (wtapng_if_descr_mandatory_t*)wtap_block_get_mandatory_data(int_data);
    if (int_data_mand->wtap_encap != rec->rec_header.packet_header.pkt_encap) {
        /*
         * Our caller is doing something bad.
         */
        *err = WTAP_ERR_INTERNAL;
        *err_info = ws_strdup_printf("pcapng: interface %u encap %d != packet encap %d",
                                    epb.interface_id,
                                    int_data_mand->wtap_encap,
                                    rec->rec_header.packet_header.pkt_encap);
        return false;
    }

    /* write (enhanced) packet block header */
    bh.block_type = BLOCK_TYPE_EPB;
    bh.block_total_length = (uint32_t)sizeof(bh) + (uint32_t)sizeof(epb) + phdr_len + rec->rec_header.packet_header.caplen + pad_len + options_total_length + options_size + 4;

    if (!wtap_dump_file_write(wdh, &bh, sizeof bh, err))
        return false;

    /* write block fixed content */
    /* Calculate the time stamp as a 64-bit integer. */
    ts = ((uint64_t)rec->ts.secs) * int_data_mand->time_units_per_second +
        (((uint64_t)rec->ts.nsecs) * int_data_mand->time_units_per_second) / 1000000000;
    /*
     * Split the 64-bit timestamp into two 32-bit pieces, using
     * the time stamp resolution for the interface.
     */
    epb.timestamp_high      = (uint32_t)(ts >> 32);
    epb.timestamp_low       = (uint32_t)ts;
    epb.captured_len        = rec->rec_header.packet_header.caplen + phdr_len;
    epb.packet_len          = rec->rec_header.packet_header.len + phdr_len;

    if (!wtap_dump_file_write(wdh, &epb, sizeof epb, err))
        return false;

    /* write pseudo header */
    if (!pcap_write_phdr(wdh, rec->rec_header.packet_header.pkt_encap, pseudo_header, err)) {
        return false;
    }

    /* write packet data */
    if (!wtap_dump_file_write(wdh, pd, rec->rec_header.packet_header.caplen, err))
        return false;

    /* write padding (if any) */
    if (pad_len != 0) {
        if (!wtap_dump_file_write(wdh, &zero_pad, pad_len, err))
            return false;
    }

    /* Write options, if we have any */
    if (options_size != 0) {
        if (!write_options(wdh, rec->block, write_wtap_epb_option, err))
            return false;
    }

    /* write block footer */
    if (!wtap_dump_file_write(wdh, &bh.block_total_length,
                              sizeof bh.block_total_length, err))
        return false;

    return true;
}

static bool
pcapng_write_sysdig_event_block(wtap_dumper *wdh, const wtap_rec *rec,
                                const uint8_t *pd, int *err)
{
    pcapng_block_header_t bh;
    const uint32_t zero_pad = 0;
    uint32_t pad_len;
#if 0
    bool have_options = false;
    struct pcapng_option option_hdr;
    uint32_t comment_len = 0, comment_pad_len = 0;
#endif
    uint32_t options_total_length = 0;
    uint16_t cpu_id;
    uint64_t hdr_ts;
    uint64_t ts;
    uint64_t thread_id;
    uint32_t event_len;
    uint16_t event_type;

    /* Don't write anything we're not willing to read. */
    if (rec->rec_header.syscall_header.event_filelen > WTAP_MAX_PACKET_SIZE_STANDARD) {
        *err = WTAP_ERR_PACKET_TOO_LARGE;
        return false;
    }

    if (rec->rec_header.syscall_header.event_filelen % 4) {
        pad_len = 4 - (rec->rec_header.syscall_header.event_filelen % 4);
    } else {
        pad_len = 0;
    }

#if 0
    /* Check if we should write comment option */
    if (rec->opt_comment) {
        have_options = true;
        comment_len = (uint32_t)strlen(rec->opt_comment) & 0xffff;
        if ((comment_len % 4)) {
            comment_pad_len = 4 - (comment_len % 4);
        } else {
            comment_pad_len = 0;
        }
        options_total_length = options_total_length + comment_len + comment_pad_len + 4 /* comment options tag */ ;
    }
    if (have_options) {
        /* End-of options tag */
        options_total_length += 4;
    }
#endif

    /* write sysdig event block header */
    bh.block_type = BLOCK_TYPE_SYSDIG_EVENT;
    bh.block_total_length = (uint32_t)sizeof(bh) + SYSDIG_EVENT_HEADER_SIZE + rec->rec_header.syscall_header.event_filelen + pad_len + options_total_length + 4;

    if (!wtap_dump_file_write(wdh, &bh, sizeof bh, err))
        return false;

    /* Sysdig is always LE? */
    cpu_id = GUINT16_TO_LE(rec->rec_header.syscall_header.cpu_id);
    hdr_ts = (((uint64_t)rec->ts.secs) * 1000000000) + rec->ts.nsecs;
    ts = GUINT64_TO_LE(hdr_ts);
    thread_id = GUINT64_TO_LE(rec->rec_header.syscall_header.thread_id);
    event_len = GUINT32_TO_LE(rec->rec_header.syscall_header.event_len);
    event_type = GUINT16_TO_LE(rec->rec_header.syscall_header.event_type);

    if (!wtap_dump_file_write(wdh, &cpu_id, sizeof cpu_id, err))
        return false;

    if (!wtap_dump_file_write(wdh, &ts, sizeof ts, err))
        return false;

    if (!wtap_dump_file_write(wdh, &thread_id, sizeof thread_id, err))
        return false;

    if (!wtap_dump_file_write(wdh, &event_len, sizeof event_len, err))
        return false;

    if (!wtap_dump_file_write(wdh, &event_type, sizeof event_type, err))
        return false;

    /* write event data */
    if (!wtap_dump_file_write(wdh, pd, rec->rec_header.syscall_header.event_filelen, err))
        return false;

    /* write padding (if any) */
    if (pad_len != 0) {
        if (!wtap_dump_file_write(wdh, &zero_pad, pad_len, err))
            return false;
    }

    /* XXX Write comment? */

    /* write block footer */
    if (!wtap_dump_file_write(wdh, &bh.block_total_length,
                              sizeof bh.block_total_length, err))
        return false;

    return true;

}

static bool
pcapng_write_systemd_journal_export_block(wtap_dumper *wdh, const wtap_rec *rec,
                                const uint8_t *pd, int *err)
{
    pcapng_block_header_t bh;
    const uint32_t zero_pad = 0;
    uint32_t pad_len;

    /* Don't write anything we're not willing to read. */
    if (rec->rec_header.systemd_journal_export_header.record_len > WTAP_MAX_PACKET_SIZE_STANDARD) {
        *err = WTAP_ERR_PACKET_TOO_LARGE;
        return false;
    }

    if (rec->rec_header.systemd_journal_export_header.record_len % 4) {
        pad_len = 4 - (rec->rec_header.systemd_journal_export_header.record_len % 4);
    } else {
        pad_len = 0;
    }

    /* write systemd journal export block header */
    bh.block_type = BLOCK_TYPE_SYSTEMD_JOURNAL_EXPORT;
    bh.block_total_length = (uint32_t)sizeof(bh) + rec->rec_header.systemd_journal_export_header.record_len + pad_len + 4;

    ws_debug("writing %u bytes, %u padded",
             rec->rec_header.systemd_journal_export_header.record_len,
             bh.block_total_length);

    if (!wtap_dump_file_write(wdh, &bh, sizeof bh, err))
        return false;

    /* write entry data */
    if (!wtap_dump_file_write(wdh, pd, rec->rec_header.systemd_journal_export_header.record_len, err))
        return false;

    /* write padding (if any) */
    if (pad_len != 0) {
        if (!wtap_dump_file_write(wdh, &zero_pad, pad_len, err))
            return false;
    }

    /* write block footer */
    if (!wtap_dump_file_write(wdh, &bh.block_total_length,
                              sizeof bh.block_total_length, err))
        return false;

    return true;

}

static bool
pcapng_write_custom_block(wtap_dumper *wdh, const wtap_rec *rec,
                          const uint8_t *pd, int *err)
{
    pcapng_block_header_t bh;
    pcapng_custom_block_t cb;
    const uint32_t zero_pad = 0;
    uint32_t pad_len;

    /* Don't write anything we are not supposed to. */
    if (!rec->rec_header.custom_block_header.copy_allowed) {
        return true;
    }

    /* Don't write anything we're not willing to read. */
    if (rec->rec_header.custom_block_header.length > WTAP_MAX_PACKET_SIZE_STANDARD) {
        *err = WTAP_ERR_PACKET_TOO_LARGE;
        return false;
    }

    if (rec->rec_header.custom_block_header.length % 4) {
        pad_len = 4 - (rec->rec_header.custom_block_header.length % 4);
    } else {
        pad_len = 0;
    }

    /* write block header */
    bh.block_type = BLOCK_TYPE_CB_COPY;
    bh.block_total_length = (uint32_t)sizeof(bh) + (uint32_t)sizeof(cb) + rec->rec_header.custom_block_header.length + pad_len + 4;
    ws_debug("writing %u bytes, %u padded, PEN %u",
             rec->rec_header.custom_block_header.length,
             bh.block_total_length, rec->rec_header.custom_block_header.pen);
    if (!wtap_dump_file_write(wdh, &bh, sizeof bh, err)) {
        return false;
    }

    /* write custom block header */
    cb.pen = rec->rec_header.custom_block_header.pen;
    if (!wtap_dump_file_write(wdh, &cb, sizeof cb, err)) {
        return false;
    }
    ws_debug("wrote PEN = %u", cb.pen);

    /* write custom data */
    if (!wtap_dump_file_write(wdh, pd, rec->rec_header.custom_block_header.length, err)) {
        return false;
    }

    /* write padding (if any) */
    if (pad_len > 0) {
        if (!wtap_dump_file_write(wdh, &zero_pad, pad_len, err)) {
            return false;
        }
    }

    /* write block footer */
    if (!wtap_dump_file_write(wdh, &bh.block_total_length,
                              sizeof bh.block_total_length, err)) {
        return false;
    }

    return true;
}

static bool
pcapng_write_bblog_block(wtap_dumper *wdh, const wtap_rec *rec,
                         const uint8_t *pd _U_, int *err)
{
    pcapng_block_header_t bh;
    uint32_t options_size = 0;
    uint32_t pen, skipped, type;

    /* Compute size of all the options */
    options_size = compute_options_size(rec->block, compute_epb_option_size);

    /* write block header */
    bh.block_type = BLOCK_TYPE_CB_COPY;
    bh.block_total_length = (uint32_t)(sizeof(bh) + sizeof(uint32_t) + sizeof(uint32_t) + options_size + 4);
    if (rec->rec_header.custom_block_header.custom_data_header.nflx_custom_data_header.type == BBLOG_TYPE_SKIPPED_BLOCK) {
        bh.block_total_length += (uint32_t)sizeof(uint32_t);
    }
    ws_debug("writing %u bytes, type %u",
             bh.block_total_length, rec->rec_header.custom_block_header.custom_data_header.nflx_custom_data_header.type);
    if (!wtap_dump_file_write(wdh, &bh, sizeof(bh), err)) {
        return false;
    }

    /* write PEN */
    pen = PEN_NFLX;
    if (!wtap_dump_file_write(wdh, &pen, sizeof(uint32_t), err)) {
        return false;
    }
    ws_debug("wrote PEN = %u", pen);

    /* write type */
    type = GUINT32_TO_LE(rec->rec_header.custom_block_header.custom_data_header.nflx_custom_data_header.type);
    if (!wtap_dump_file_write(wdh, &type, sizeof(uint32_t), err)) {
        return false;
    }
    ws_debug("wrote type = %u", rec->rec_header.custom_block_header.custom_data_header.nflx_custom_data_header.type);

    if (rec->rec_header.custom_block_header.custom_data_header.nflx_custom_data_header.type == BBLOG_TYPE_SKIPPED_BLOCK) {
        skipped = GUINT32_TO_LE(rec->rec_header.custom_block_header.custom_data_header.nflx_custom_data_header.skipped);
        if (!wtap_dump_file_write(wdh, &skipped, sizeof(uint32_t), err)) {
            return false;
        }
        ws_debug("wrote skipped = %u", rec->rec_header.custom_block_header.custom_data_header.nflx_custom_data_header.skipped);
    }

    /* Write options, if we have any */
    if (options_size != 0) {
        /*
         * This block type supports only comments and custom options,
         * so it doesn't need a callback.
         */
        if (!write_options(wdh, rec->block, NULL, err))
            return false;
    }

    /* write block footer */
    if (!wtap_dump_file_write(wdh, &bh.block_total_length,
                              sizeof bh.block_total_length, err)) {
        return false;
    }

    return true;
}

static bool
pcapng_write_decryption_secrets_block(wtap_dumper *wdh, wtap_block_t sdata, int *err)
{
    pcapng_block_header_t bh;
    pcapng_decryption_secrets_block_t dsb;
    wtapng_dsb_mandatory_t *mand_data = (wtapng_dsb_mandatory_t *)wtap_block_get_mandatory_data(sdata);
    unsigned pad_len = (4 - (mand_data->secrets_len & 3)) & 3;

    /* write block header */
    bh.block_type = BLOCK_TYPE_DSB;
    bh.block_total_length = MIN_DSB_SIZE + mand_data->secrets_len + pad_len;
    ws_debug("Total len %u", bh.block_total_length);

    if (!wtap_dump_file_write(wdh, &bh, sizeof bh, err))
        return false;

    /* write block fixed content */
    dsb.secrets_type = mand_data->secrets_type;
    dsb.secrets_len = mand_data->secrets_len;
    if (!wtap_dump_file_write(wdh, &dsb, sizeof dsb, err))
        return false;

    if (!wtap_dump_file_write(wdh, mand_data->secrets_data, mand_data->secrets_len, err))
        return false;
    if (pad_len) {
        const uint32_t zero_pad = 0;
        if (!wtap_dump_file_write(wdh, &zero_pad, pad_len, err))
            return false;
    }

    /* write block footer */
    if (!wtap_dump_file_write(wdh, &bh.block_total_length,
                              sizeof bh.block_total_length, err))
        return false;

    return true;
}

static bool
pcapng_write_meta_event_block(wtap_dumper *wdh, wtap_block_t mev_data, int *err)
{
    pcapng_block_header_t bh;
    wtapng_meta_event_mandatory_t *mand_data = (wtapng_meta_event_mandatory_t *)wtap_block_get_mandatory_data(mev_data);
    unsigned pad_len = (4 - (mand_data->mev_data_len & 3)) & 3;

    /* write block header */
    bh.block_type = mand_data->mev_block_type;
    bh.block_total_length = MIN_BLOCK_SIZE + mand_data->mev_data_len + pad_len;
    ws_debug("Sysdig mev total len %u", bh.block_total_length);

    if (!wtap_dump_file_write(wdh, &bh, sizeof bh, err))
        return false;

    /* write block fixed content */
    if (!wtap_dump_file_write(wdh, mand_data->mev_data, mand_data->mev_data_len, err))
        return false;

    if (pad_len) {
        const uint32_t zero_pad = 0;
        if (!wtap_dump_file_write(wdh, &zero_pad, pad_len, err))
            return false;
    }

    /* write block footer */
    if (!wtap_dump_file_write(wdh, &bh.block_total_length,
                              sizeof bh.block_total_length, err))
        return false;

    return true;
}

/*
 * libpcap's maximum pcapng block size is currently 16MB.
 *
 * The maximum pcapng block size in macOS's private pcapng reading code
 * is 1MB.  (Yes, this means that a program using the standard pcap
 * code to read pcapng files can handle bigger blocks than can programs
 * using the private code, such as Apple's tcpdump, can handle.)
 *
 * The pcapng reading code here can handle NRBs of arbitrary size (less
 * than 4GB, obviously), as they read each NRB record independently,
 * rather than reading the entire block into memory.
 *
 * So, for now, we set the maximum NRB block size we write as 1 MB.
 *
 * (Yes, for the benefit of the fussy, "MB" is really "MiB".)
 */

#define NRES_BLOCK_MAX_SIZE (1024*1024)

static uint32_t
compute_nrb_option_size(wtap_block_t block _U_, unsigned option_id, wtap_opttype_e option_type _U_, wtap_optval_t* optval)
{
    uint32_t size;

    switch(option_id)
    {
    case OPT_NS_DNSNAME:
        size = pcapng_compute_string_option_size(optval);
        break;
    case OPT_NS_DNSIP4ADDR:
        size = 4;
        break;
    case OPT_NS_DNSIP6ADDR:
        size = 16;
        break;
    default:
        /* Unknown options - size by datatype? */
        size = 0;
        break;
    }
    return size;
}

static bool
put_nrb_option(wtap_block_t block _U_, unsigned option_id, wtap_opttype_e option_type _U_, wtap_optval_t* optval, void* user_data)
{
    uint8_t **opt_ptrp = (uint8_t **)user_data;
    uint32_t size = 0;
    struct pcapng_option_header option_hdr;
    uint32_t pad;

    switch(option_id)
    {
    case OPT_COMMENT:
    case OPT_NS_DNSNAME:
        /* String options don't consider pad bytes part of the length */
        size = (uint32_t)strlen(optval->stringval) & 0xffff;
        option_hdr.type         = (uint16_t)option_id;
        option_hdr.value_length = (uint16_t)size;
        memcpy(*opt_ptrp, &option_hdr, 4);
        *opt_ptrp += 4;

        memcpy(*opt_ptrp, optval->stringval, size);
        *opt_ptrp += size;

        if ((size % 4)) {
            pad = 4 - (size % 4);
        } else {
            pad = 0;
        }

        /* put padding (if any) */
        if (pad != 0) {
            memset(*opt_ptrp, 0, pad);
            *opt_ptrp += pad;
        }
        break;
    case OPT_CUSTOM_STR_COPY:
    case OPT_CUSTOM_BIN_COPY:
        /* Custom options don't consider pad bytes part of the length */
        size = (uint32_t)(optval->custom_opt.data.generic_data.custom_data_len + sizeof(uint32_t)) & 0xffff;
        option_hdr.type         = (uint16_t)option_id;
        option_hdr.value_length = (uint16_t)size;
        memcpy(*opt_ptrp, &option_hdr, 4);
        *opt_ptrp += 4;

        memcpy(*opt_ptrp, &optval->custom_opt.pen, sizeof(uint32_t));
        *opt_ptrp += sizeof(uint32_t);

        memcpy(*opt_ptrp, optval->custom_opt.data.generic_data.custom_data, optval->custom_opt.data.generic_data.custom_data_len);
        *opt_ptrp += optval->custom_opt.data.generic_data.custom_data_len;

        if ((size % 4)) {
            pad = 4 - (size % 4);
        } else {
            pad = 0;
        }

        /* put padding (if any) */
        if (pad != 0) {
            memset(*opt_ptrp, 0, pad);
            *opt_ptrp += pad;
        }
        break;
    case OPT_NS_DNSIP4ADDR:
        option_hdr.type         = (uint16_t)option_id;
        option_hdr.value_length = 4;
        memcpy(*opt_ptrp, &option_hdr, 4);
        *opt_ptrp += 4;

        memcpy(*opt_ptrp, &optval->ipv4val, 4);
        *opt_ptrp += 4;
        break;
    case OPT_NS_DNSIP6ADDR:
        option_hdr.type         = (uint16_t)option_id;
        option_hdr.value_length = 16;
        memcpy(*opt_ptrp, &option_hdr, 4);
        *opt_ptrp += 4;

        memcpy(*opt_ptrp, &optval->ipv6val, 16);
        *opt_ptrp += 16;
        break;
    default:
        /* Unknown options - size by datatype? */
        break;
    }
    return true; /* we always succeed */
}

static void
put_nrb_options(wtap_dumper *wdh _U_, wtap_block_t nrb, uint8_t *opt_ptr)
{
    struct pcapng_option option_hdr;

    wtap_block_foreach_option(nrb, put_nrb_option, &opt_ptr);

    /* Put end of options */
    option_hdr.type = OPT_EOFOPT;
    option_hdr.value_length = 0;
    memcpy(opt_ptr, &option_hdr, 4);
}

static bool
pcapng_write_name_resolution_block(wtap_dumper *wdh, wtap_block_t sdata, int *err)
{
    pcapng_block_header_t bh;
    pcapng_name_resolution_block_t nrb;
    wtapng_nrb_mandatory_t *mand_data = (wtapng_nrb_mandatory_t *)wtap_block_get_mandatory_data(sdata);
    uint32_t options_size;
    size_t max_rec_data_size;
    uint8_t *block_data;
    uint32_t block_off;
    size_t hostnamelen;
    uint16_t namelen;
    uint32_t tot_rec_len;
    hashipv4_t *ipv4_hash_list_entry;
    hashipv6_t *ipv6_hash_list_entry;
    int i;

    if (!mand_data) {
        /*
         * No name/address pairs to write.
         * XXX - what if we have options?
         */
        return true;
    }

    /* Calculate the space needed for options. */
    options_size = compute_options_size(sdata, compute_nrb_option_size);

    /*
     * Make sure we can fit at least one maximum-sized record, plus
     * an end-of-records record, plus the options, into a maximum-sized
     * block.
     *
     * That requires that there be enough space for the block header
     * (8 bytes), a maximum-sized record (2 bytes of record type, 2
     * bytes of record value length, 65535 bytes of record value,
     * and 1 byte of padding), an end-of-records record (4 bytes),
     * the options (options_size bytes), and the block trailer (4
     * bytes).
     */
    if (8 + 2 + 2 + 65535 + 1 + 4 + options_size + 4 > NRES_BLOCK_MAX_SIZE) {
        /*
         * XXX - we can't even fit the options in the largest NRB size
         * we're willing to write and still have room enough for a
         * maximum-sized record.  Just discard the information for now.
         */
        return true;
    }

    /*
     * Allocate a buffer for the largest block we'll write.
     */
    block_data = (uint8_t *)g_malloc(NRES_BLOCK_MAX_SIZE);

    /*
     * Calculate the maximum amount of record data we'll be able to
     * fit into such a block, after taking into account the block header
     * (8 bytes), the end-of-records record (4 bytes), the options
     * (options_size bytes), and the block trailer (4 bytes).
     */
    max_rec_data_size = NRES_BLOCK_MAX_SIZE - (8 + 4 + options_size + 4);

    block_off = 8; /* block type + block total length */
    bh.block_type = BLOCK_TYPE_NRB;
    bh.block_total_length = 12; /* block header + block trailer */

    /*
     * Write out the IPv4 resolved addresses, if any.
     */
    if (mand_data->ipv4_addr_list){
        i = 0;
        ipv4_hash_list_entry = (hashipv4_t *)g_list_nth_data(mand_data->ipv4_addr_list, i);
        while(ipv4_hash_list_entry != NULL){

            nrb.record_type = NRES_IP4RECORD;
            hostnamelen = strlen(ipv4_hash_list_entry->name);
            if (hostnamelen > (UINT16_MAX - 4) - 1) {
                /*
                 * This won't fit in the largest possible NRB record;
                 * discard it.
                 */
                i++;
                ipv4_hash_list_entry = (hashipv4_t *)g_list_nth_data(mand_data->ipv4_addr_list, i);
                continue;
            }
            namelen = (uint16_t)(hostnamelen + 1);
            nrb.record_len = 4 + namelen;  /* 4 bytes IPv4 address length */
            /* 2 bytes record type, 2 bytes length field */
            tot_rec_len = 4 + nrb.record_len + PADDING4(nrb.record_len);

            if (block_off + tot_rec_len > max_rec_data_size) {
                /*
                 * This record would overflow our maximum size for Name
                 * Resolution Blocks; write out all the records we created
                 * before it, and start a new NRB.
                 */

                /* Append the end-of-records record */
                memset(block_data + block_off, 0, 4);
                block_off += 4;
                bh.block_total_length += 4;

                /*
                 * Put the options into the block.
                 */
                put_nrb_options(wdh, sdata, block_data + block_off);
                block_off += options_size;
                bh.block_total_length += options_size;

                /* Copy the block header. */
                memcpy(block_data, &bh, sizeof(bh));

                /* Copy the block trailer. */
                memcpy(block_data + block_off, &bh.block_total_length, sizeof(bh.block_total_length));

                ws_debug("Write bh.block_total_length bytes %d, block_off %u",
                         bh.block_total_length, block_off);

                if (!wtap_dump_file_write(wdh, block_data, bh.block_total_length, err)) {
                    g_free(block_data);
                    return false;
                }

                /*Start a new NRB */
                block_off = 8; /* block type + block total length */
                bh.block_type = BLOCK_TYPE_NRB;
                bh.block_total_length = 12; /* block header + block trailer */
            }

            bh.block_total_length += tot_rec_len;
            memcpy(block_data + block_off, &nrb, sizeof(nrb));
            block_off += 4;
            memcpy(block_data + block_off, &(ipv4_hash_list_entry->addr), 4);
            block_off += 4;
            memcpy(block_data + block_off, ipv4_hash_list_entry->name, namelen);
            block_off += namelen;
            memset(block_data + block_off, 0, PADDING4(namelen));
            block_off += PADDING4(namelen);
            ws_debug("added IPv4 record for %s", ipv4_hash_list_entry->name);

            i++;
            ipv4_hash_list_entry = (hashipv4_t *)g_list_nth_data(mand_data->ipv4_addr_list, i);
        }
    }

    if (mand_data->ipv6_addr_list){
        i = 0;
        ipv6_hash_list_entry = (hashipv6_t *)g_list_nth_data(mand_data->ipv6_addr_list, i);
        while(ipv6_hash_list_entry != NULL){

            nrb.record_type = NRES_IP6RECORD;
            hostnamelen = strlen(ipv6_hash_list_entry->name);
            if (hostnamelen > (UINT16_MAX - 16) - 1) {
                /*
                 * This won't fit in the largest possible NRB record;
                 * discard it.
                 */
                i++;
                ipv6_hash_list_entry = (hashipv6_t *)g_list_nth_data(mand_data->ipv6_addr_list, i);
                continue;
            }
            namelen = (uint16_t)(hostnamelen + 1);
            nrb.record_len = 16 + namelen;  /* 16 bytes IPv6 address length */
            /* 2 bytes record type, 2 bytes length field */
            tot_rec_len = 4 + nrb.record_len + PADDING4(nrb.record_len);

            if (block_off + tot_rec_len > max_rec_data_size) {
                /*
                 * This record would overflow our maximum size for Name
                 * Resolution Blocks; write out all the records we created
                 * before it, and start a new NRB.
                 */

                /* Append the end-of-records record */
                memset(block_data + block_off, 0, 4);
                block_off += 4;
                bh.block_total_length += 4;

                /*
                 * Put the options into the block.
                 */
                put_nrb_options(wdh, sdata, block_data + block_off);
                block_off += options_size;
                bh.block_total_length += options_size;

                /* Copy the block header. */
                memcpy(block_data, &bh, sizeof(bh));

                /* Copy the block trailer. */
                memcpy(block_data + block_off, &bh.block_total_length, sizeof(bh.block_total_length));

                ws_debug("write bh.block_total_length bytes %d, block_off %u",
                         bh.block_total_length, block_off);

                if (!wtap_dump_file_write(wdh, block_data, bh.block_total_length, err)) {
                    g_free(block_data);
                    return false;
                }

                /*Start a new NRB */
                block_off = 8; /* block type + block total length */
                bh.block_type = BLOCK_TYPE_NRB;
                bh.block_total_length = 12; /* block header + block trailer */
            }

            bh.block_total_length += tot_rec_len;
            memcpy(block_data + block_off, &nrb, sizeof(nrb));
            block_off += 4;
            memcpy(block_data + block_off, &(ipv6_hash_list_entry->addr), 16);
            block_off += 16;
            memcpy(block_data + block_off, ipv6_hash_list_entry->name, namelen);
            block_off += namelen;
            memset(block_data + block_off, 0, PADDING4(namelen));
            block_off += PADDING4(namelen);
            ws_debug("added IPv6 record for %s", ipv6_hash_list_entry->name);

            i++;
            ipv6_hash_list_entry = (hashipv6_t *)g_list_nth_data(mand_data->ipv6_addr_list, i);
        }
    }

    /* Append the end-of-records record */
    memset(block_data + block_off, 0, 4);
    block_off += 4;
    bh.block_total_length += 4;

    /*
     * Put the options into the block.
     */
    put_nrb_options(wdh, sdata, block_data + block_off);
    block_off += options_size;
    bh.block_total_length += options_size;

    /* Copy the block header. */
    memcpy(block_data, &bh, sizeof(bh));

    /* Copy the block trailer. */
    memcpy(block_data + block_off, &bh.block_total_length, sizeof(bh.block_total_length));

    ws_debug("Write bh.block_total_length bytes %d, block_off %u",
             bh.block_total_length, block_off);

    if (!wtap_dump_file_write(wdh, block_data, bh.block_total_length, err)) {
        g_free(block_data);
        return false;
    }

    g_free(block_data);

    return true;
}

static uint32_t compute_isb_option_size(wtap_block_t block _U_, unsigned option_id, wtap_opttype_e option_type _U_, wtap_optval_t *optval _U_)
{
    uint32_t size;

    switch(option_id)
    {
    case OPT_ISB_STARTTIME:
    case OPT_ISB_ENDTIME:
        size = 8;
        break;
    case OPT_ISB_IFRECV:
    case OPT_ISB_IFDROP:
    case OPT_ISB_FILTERACCEPT:
    case OPT_ISB_OSDROP:
    case OPT_ISB_USRDELIV:
        size = 8;
        break;
    default:
        /* Unknown options - size by datatype? */
        size = 0;
        break;
    }
    return size;
}

static bool write_wtap_isb_option(wtap_dumper *wdh, wtap_block_t block _U_, unsigned option_id, wtap_opttype_e option_type _U_, wtap_optval_t *optval, int *err)
{
    switch(option_id)
    {
    case OPT_ISB_STARTTIME:
    case OPT_ISB_ENDTIME:
        if (!pcapng_write_timestamp_option(wdh, option_id, optval, err))
            return false;
        break;
    case OPT_ISB_IFRECV:
    case OPT_ISB_IFDROP:
    case OPT_ISB_FILTERACCEPT:
    case OPT_ISB_OSDROP:
    case OPT_ISB_USRDELIV:
        if (!pcapng_write_uint64_option(wdh, option_id, optval, err))
            return false;
        break;
    default:
        /* Unknown options - write by datatype? */
        break;
    }
    return true; /* success */
}

static bool
pcapng_write_interface_statistics_block(wtap_dumper *wdh, wtap_block_t if_stats, int *err)
{
    pcapng_block_header_t bh;
    pcapng_interface_statistics_block_t isb;
    uint32_t options_size;
    wtapng_if_stats_mandatory_t* mand_data = (wtapng_if_stats_mandatory_t*)wtap_block_get_mandatory_data(if_stats);

    ws_debug("entering function");

    /* Compute size of all the options */
    options_size = compute_options_size(if_stats, compute_isb_option_size);

    /* write block header */
    bh.block_type = BLOCK_TYPE_ISB;
    bh.block_total_length = (uint32_t)(sizeof(bh) + sizeof(isb) + options_size + 4);
    ws_debug("Total len %u", bh.block_total_length);

    if (!wtap_dump_file_write(wdh, &bh, sizeof bh, err))
        return false;

    /* write block fixed content */
    isb.interface_id                = mand_data->interface_id;
    isb.timestamp_high              = mand_data->ts_high;
    isb.timestamp_low               = mand_data->ts_low;

    if (!wtap_dump_file_write(wdh, &isb, sizeof isb, err))
        return false;

    /* Write options */
    if (options_size != 0) {
        if (!write_options(wdh, if_stats, write_wtap_isb_option, err))
            return false;
    }

    /* write block footer */
    if (!wtap_dump_file_write(wdh, &bh.block_total_length,
                              sizeof bh.block_total_length, err))
        return false;
    return true;
}

static uint32_t compute_idb_option_size(wtap_block_t block _U_, unsigned option_id, wtap_opttype_e option_type _U_, wtap_optval_t *optval)
{
    uint32_t size;

    switch(option_id)
    {
    case OPT_IDB_NAME:
    case OPT_IDB_DESCRIPTION:
    case OPT_IDB_OS:
    case OPT_IDB_HARDWARE:
        size = pcapng_compute_string_option_size(optval);
        break;
    case OPT_IDB_SPEED:
        size = 8;
        break;
    case OPT_IDB_TSRESOL:
        size = 1;
        break;
    case OPT_IDB_FILTER:
        size = pcapng_compute_if_filter_option_size(optval);
        break;
    case OPT_IDB_FCSLEN:
        size = 1;
        break;
    case OPT_IDB_TSOFFSET:
        /*
         * The time stamps handed to us when writing a file are
         * absolute time staps, so the time stamp offset is
         * zero.
         *
         * We do not adjust them when writing, so we should not
         * write if_tsoffset options; that is interpreted as
         * the offset is zero, i.e. the time stamps in the file
         * are absolute.
         */
        size = 0;
        break;
    default:
        /* Unknown options - size by datatype? */
        size = 0;
        break;
    }
    return size;
}

static bool write_wtap_idb_option(wtap_dumper *wdh, wtap_block_t block _U_, unsigned option_id, wtap_opttype_e option_type _U_, wtap_optval_t *optval, int *err)
{
    switch(option_id)
    {
    case OPT_IDB_NAME:
    case OPT_IDB_DESCRIPTION:
    case OPT_IDB_OS:
    case OPT_IDB_HARDWARE:
        if (!pcapng_write_string_option(wdh, option_id, optval, err))
            return false;
        break;
    case OPT_IDB_SPEED:
        if (!pcapng_write_uint64_option(wdh, option_id, optval, err))
            return false;
        break;
    case OPT_IDB_TSRESOL:
        if (!pcapng_write_uint8_option(wdh, option_id, optval, err))
            return false;
        break;
    case OPT_IDB_FILTER:
        if (!pcapng_write_if_filter_option(wdh, option_id, optval, err))
            return false;
        break;
    case OPT_IDB_FCSLEN:
        if (!pcapng_write_uint8_option(wdh, option_id, optval, err))
            return false;
        break;
    case OPT_IDB_TSOFFSET:
        /*
         * As noted above, we discard these.
         */
        break;
    default:
        /* Unknown options - size by datatype? */
        break;
    }
    return true;
}

static bool
pcapng_write_if_descr_block(wtap_dumper *wdh, wtap_block_t int_data, int *err)
{
    pcapng_block_header_t bh;
    pcapng_interface_description_block_t idb;
    uint32_t options_size;
    wtapng_if_descr_mandatory_t* mand_data = (wtapng_if_descr_mandatory_t*)wtap_block_get_mandatory_data(int_data);
    int link_type;

    ws_debug("encap = %d (%s), snaplen = %d",
             mand_data->wtap_encap,
             wtap_encap_description(mand_data->wtap_encap),
             mand_data->snap_len);

    link_type = wtap_wtap_encap_to_pcap_encap(mand_data->wtap_encap);
    if (link_type == -1) {
        if (!pcapng_encap_is_ft_specific(mand_data->wtap_encap)) {
            *err = WTAP_ERR_UNWRITABLE_ENCAP;
            return false;
        }
    }

    /* Compute size of all the options */
    options_size = compute_options_size(int_data, compute_idb_option_size);

    /* write block header */
    bh.block_type = BLOCK_TYPE_IDB;
    bh.block_total_length = (uint32_t)(sizeof(bh) + sizeof(idb) + options_size + 4);
    ws_debug("Total len %u", bh.block_total_length);

    if (!wtap_dump_file_write(wdh, &bh, sizeof bh, err))
        return false;

    /* write block fixed content */
    idb.linktype    = link_type;
    idb.reserved    = 0;
    idb.snaplen     = mand_data->snap_len;

    if (!wtap_dump_file_write(wdh, &idb, sizeof idb, err))
        return false;

    if (options_size != 0) {
        /* Write options */
        if (!write_options(wdh, int_data, write_wtap_idb_option, err))
            return false;
    }

    /* write block footer */
    if (!wtap_dump_file_write(wdh, &bh.block_total_length,
                              sizeof bh.block_total_length, err))
        return false;

    return true;
}

static bool pcapng_add_idb(wtap_dumper *wdh, wtap_block_t idb,
                               int *err, char **err_info _U_)
{
	wtap_block_t idb_copy;

	/*
	 * Add a copy of this IDB to our array of IDBs.
	 */
	idb_copy = wtap_block_create(WTAP_BLOCK_IF_ID_AND_INFO);
	wtap_block_copy(idb_copy, idb);
	g_array_append_val(wdh->interface_data, idb_copy);

	/*
	 * And write it to the output file.
	 */
	return pcapng_write_if_descr_block(wdh, idb_copy, err);
}

static bool pcapng_write_internal_blocks(wtap_dumper *wdh, int *err)
{

    /* Write (optional) Decryption Secrets Blocks that were collected while
     * reading packet blocks. */
    if (wdh->dsbs_growing) {
        for (unsigned i = wdh->dsbs_growing_written; i < wdh->dsbs_growing->len; i++) {
            ws_debug("writing DSB %u", i);
            wtap_block_t dsb = g_array_index(wdh->dsbs_growing, wtap_block_t, i);
            if (!pcapng_write_decryption_secrets_block(wdh, dsb, err)) {
                return false;
            }
            ++wdh->dsbs_growing_written;
        }
    }

    /* Write (optional) Sysdig Meta Event Blocks that were collected while
     * reading packet blocks. */
    if (wdh->mevs_growing) {
        for (unsigned i = wdh->mevs_growing_written; i < wdh->mevs_growing->len; i++) {
            ws_debug("writing Sysdig mev %u", i);
            wtap_block_t mev = g_array_index(wdh->mevs_growing, wtap_block_t, i);
            if (!pcapng_write_meta_event_block(wdh, mev, err)) {
                return false;
            }
            ++wdh->mevs_growing_written;
        }
    }

    /* Write any hostname resolution info from wtap_dump_set_addrinfo_list() */
    if (!wtap_addrinfo_list_empty(wdh->addrinfo_lists)) {
        /*
         * XXX: get_addrinfo_list() returns a list of all known and used
         * resolved addresses, regardless of origin: existing NRBs, externally
         * resolved, DNS packet data, a hosts file, and manual host resolution
         * through the GUI. It does not include the source for each.
         *
         * If it did, we could instead create multiple NRBs, one for each
         * server (as the options can only be included once per block.)
         * Instead, we copy the options from the first already existing NRB
         * (if there is one), since some of the name resolutions may be
         * from that block.
         */
        wtap_block_t nrb;
        if (wdh->nrbs_growing && wdh->nrbs_growing->len) {
            nrb = wtap_block_make_copy(g_array_index(wdh->nrbs_growing, wtap_block_t, 0));
        } else {
            nrb = wtap_block_create(WTAP_BLOCK_NAME_RESOLUTION);
        }
        wtapng_nrb_mandatory_t *mand_data = (wtapng_nrb_mandatory_t *)wtap_block_get_mandatory_data(nrb);
        mand_data->ipv4_addr_list = wdh->addrinfo_lists->ipv4_addr_list;
        mand_data->ipv6_addr_list = wdh->addrinfo_lists->ipv6_addr_list;

        if (!pcapng_write_name_resolution_block(wdh, nrb, err)) {
            return false;
        }
        mand_data->ipv4_addr_list = NULL;
        mand_data->ipv6_addr_list = NULL;
        wtap_block_unref(nrb);
        g_list_free(wdh->addrinfo_lists->ipv4_addr_list);
        wdh->addrinfo_lists->ipv4_addr_list = NULL;
        g_list_free(wdh->addrinfo_lists->ipv6_addr_list);
        wdh->addrinfo_lists->ipv6_addr_list = NULL;
        /* Since the addrinfo lists include information from existing NRBs,
         * avoid writing them to avoid duplication.
         *
         * XXX: Perhaps we don't want to include information from the NRBs
         * in get_addrinfo_list at all, so that we could write existing
         * NRBs as-is.
         *
         * This is still not well oriented for one-pass programs, where we
         * don't have addrinfo_lists until we've already written the
         * NRBs. We should not write both in such a situation. See bug 15502.
         */
        wtap_dump_discard_name_resolution(wdh);
    }

    /* Write (optional) Name Resolution Blocks that were collected while
     * reading packet blocks. */
    if (wdh->nrbs_growing) {
        for (unsigned i = wdh->nrbs_growing_written; i < wdh->nrbs_growing->len; i++) {
            wtap_block_t nrb = g_array_index(wdh->nrbs_growing, wtap_block_t, i);
            if (!pcapng_write_name_resolution_block(wdh, nrb, err)) {
                return false;
            }
            ++wdh->nrbs_growing_written;
        }
    }

    return true;
}

static bool pcapng_dump(wtap_dumper *wdh,
                            const wtap_rec *rec,
                            const uint8_t *pd, int *err, char **err_info)
{
#ifdef HAVE_PLUGINS
    block_handler *handler;
#endif

    if (!pcapng_write_internal_blocks(wdh, err)) {
        return false;
    }

    ws_debug("encap = %d (%s) rec type = %u",
             rec->rec_header.packet_header.pkt_encap,
             wtap_encap_description(rec->rec_header.packet_header.pkt_encap),
             rec->rec_type);

    switch (rec->rec_type) {

        case REC_TYPE_PACKET:
            /* Write Simple Packet Block if appropriate, Enhanced Packet Block otherwise. */
            if (!(rec->presence_flags & WTAP_HAS_TS) &&
                (!(rec->presence_flags & WTAP_HAS_INTERFACE_ID) || rec->rec_header.packet_header.interface_id == 0) &&
                (!(rec->presence_flags & WTAP_HAS_CAP_LEN) || rec->rec_header.packet_header.len == rec->rec_header.packet_header.caplen) &&
                (rec->block == NULL || compute_options_size(rec->block, compute_epb_option_size) == 0)) {
                if (!pcapng_write_simple_packet_block(wdh, rec, pd, err, err_info)) {
                    return false;
                }
            }
            else {
                if (!pcapng_write_enhanced_packet_block(wdh, rec, pd, err, err_info)) {
                    return false;
                }
            }
            break;

        case REC_TYPE_FT_SPECIFIC_EVENT:
        case REC_TYPE_FT_SPECIFIC_REPORT:
#ifdef HAVE_PLUGINS
            /*
             * Do we have a handler for this block type?
             */
            if (block_handlers != NULL &&
                (handler = (block_handler *)g_hash_table_lookup(block_handlers,
                                                                GUINT_TO_POINTER(rec->rec_header.ft_specific_header.record_type))) != NULL) {
                /* Yes. Call it to write out this record. */
                if (!handler->writer(wdh, rec, pd, err))
                    return false;
            } else
#endif
            {
                /* No. */
                *err = WTAP_ERR_UNWRITABLE_REC_TYPE;
                return false;
            }
            break;

        case REC_TYPE_SYSCALL:
            if (!pcapng_write_sysdig_event_block(wdh, rec, pd, err)) {
                return false;
            }
            break;

        case REC_TYPE_SYSTEMD_JOURNAL_EXPORT:
            if (!pcapng_write_systemd_journal_export_block(wdh, rec, pd, err)) {
                return false;
            }
            break;

        case REC_TYPE_CUSTOM_BLOCK:
            switch (rec->rec_header.custom_block_header.pen) {
            case PEN_NFLX:
                if (!pcapng_write_bblog_block(wdh, rec, pd, err)) {
                    return false;
                }
                break;
            default:
                if (!pcapng_write_custom_block(wdh, rec, pd, err)) {
                    return false;
                }
                break;
            }
            break;

        default:
            /* We don't support writing this record type. */
            *err = WTAP_ERR_UNWRITABLE_REC_TYPE;
            return false;
    }

    return true;
}

/* Finish writing to a dump file.
   Returns true on success, false on failure. */
static bool pcapng_dump_finish(wtap_dumper *wdh, int *err,
                                   char **err_info _U_)
{
    unsigned i, j;

    /* Flush any hostname resolution or decryption secrets info we may have */
    if (!pcapng_write_internal_blocks(wdh, err)) {
        return false;
    }

    for (i = 0; i < wdh->interface_data->len; i++) {

        /* Get the interface description */
        wtap_block_t int_data;
        wtapng_if_descr_mandatory_t *int_data_mand;

        int_data = g_array_index(wdh->interface_data, wtap_block_t, i);
        int_data_mand = (wtapng_if_descr_mandatory_t*)wtap_block_get_mandatory_data(int_data);

        for (j = 0; j < int_data_mand->num_stat_entries; j++) {
            wtap_block_t if_stats;

            if_stats = g_array_index(int_data_mand->interface_statistics, wtap_block_t, j);
            ws_debug("write ISB for interface %u",
                     ((wtapng_if_stats_mandatory_t*)wtap_block_get_mandatory_data(if_stats))->interface_id);
            if (!pcapng_write_interface_statistics_block(wdh, if_stats, err)) {
                return false;
            }
        }
    }

    ws_debug("leaving function");
    return true;
}

/* Returns true on success, false on failure; sets "*err" to an error code on
   failure */
static bool
pcapng_dump_open(wtap_dumper *wdh, int *err, char **err_info _U_)
{
    unsigned i;

    ws_debug("entering function");
    /* This is a pcapng file */
    wdh->subtype_add_idb = pcapng_add_idb;
    wdh->subtype_write = pcapng_dump;
    wdh->subtype_finish = pcapng_dump_finish;

    /* write the section header block */
    if (!pcapng_write_section_header_block(wdh, err)) {
        return false;
    }
    ws_debug("wrote section header block.");

    /* Write the Interface description blocks */
    ws_debug("Number of IDBs to write (number of interfaces) %u",
             wdh->interface_data->len);

    for (i = 0; i < wdh->interface_data->len; i++) {

        /* Get the interface description */
        wtap_block_t idb;

        idb = g_array_index(wdh->interface_data, wtap_block_t, i);

        if (!pcapng_write_if_descr_block(wdh, idb, err)) {
            return false;
        }

    }

    /* Write (optional) fixed Decryption Secrets Blocks. */
    if (wdh->dsbs_initial) {
        for (i = 0; i < wdh->dsbs_initial->len; i++) {
            wtap_block_t dsb = g_array_index(wdh->dsbs_initial, wtap_block_t, i);
            if (!pcapng_write_decryption_secrets_block(wdh, dsb, err)) {
                return false;
            }
        }
    }

    return true;
}

/* Returns 0 if we could write the specified encapsulation type,
   an error indication otherwise. */
static int pcapng_dump_can_write_encap(int wtap_encap)
{
    ws_debug("encap = %d (%s)",
             wtap_encap,
             wtap_encap_description(wtap_encap));

    /* Per-packet encapsulation is supported. */
    if (wtap_encap == WTAP_ENCAP_PER_PACKET)
        return 0;

    /* No encapsulation type (yet) is supported. */
    if (wtap_encap == WTAP_ENCAP_NONE)
        return 0;

    /* Is it a filetype-specific encapsulation that we support? */
    if (pcapng_encap_is_ft_specific(wtap_encap)) {
        return 0;
    }

    /* Make sure we can figure out this DLT type */
    if (wtap_wtap_encap_to_pcap_encap(wtap_encap) == -1)
        return WTAP_ERR_UNWRITABLE_ENCAP;

    return 0;
}

/*
 * Returns true if the specified encapsulation type is filetype-specific
 * and one that we support.
 */
bool pcapng_encap_is_ft_specific(int encap)
{
    switch (encap) {
    case WTAP_ENCAP_SYSTEMD_JOURNAL:
        return true;
    }
    return false;
}

/*
 * pcapng supports several block types, and supports more than one
 * of them.
 *
 * It also supports comments for many block types, as well as other
 * option types.
 */

/* Options for section blocks. */
static const struct supported_option_type section_block_options_supported[] = {
    { OPT_COMMENT, MULTIPLE_OPTIONS_SUPPORTED },
    { OPT_CUSTOM_STR_COPY, MULTIPLE_OPTIONS_SUPPORTED },
    { OPT_CUSTOM_BIN_COPY, MULTIPLE_OPTIONS_SUPPORTED },
    { OPT_CUSTOM_STR_NO_COPY, MULTIPLE_OPTIONS_SUPPORTED },
    { OPT_CUSTOM_BIN_NO_COPY, MULTIPLE_OPTIONS_SUPPORTED },
    { OPT_SHB_HARDWARE, ONE_OPTION_SUPPORTED },
    { OPT_SHB_USERAPPL, ONE_OPTION_SUPPORTED }
};

/* Options for interface blocks. */
static const struct supported_option_type interface_block_options_supported[] = {
    { OPT_COMMENT, MULTIPLE_OPTIONS_SUPPORTED },
    { OPT_CUSTOM_STR_COPY, MULTIPLE_OPTIONS_SUPPORTED },
    { OPT_CUSTOM_BIN_COPY, MULTIPLE_OPTIONS_SUPPORTED },
    { OPT_CUSTOM_STR_NO_COPY, MULTIPLE_OPTIONS_SUPPORTED },
    { OPT_CUSTOM_BIN_NO_COPY, MULTIPLE_OPTIONS_SUPPORTED },
    { OPT_IDB_NAME, ONE_OPTION_SUPPORTED },
    { OPT_IDB_DESCRIPTION, ONE_OPTION_SUPPORTED },
    { OPT_IDB_IP4ADDR, MULTIPLE_OPTIONS_SUPPORTED },
    { OPT_IDB_IP6ADDR, MULTIPLE_OPTIONS_SUPPORTED },
    { OPT_IDB_MACADDR, ONE_OPTION_SUPPORTED },
    { OPT_IDB_EUIADDR, ONE_OPTION_SUPPORTED },
    { OPT_IDB_SPEED, ONE_OPTION_SUPPORTED },
    { OPT_IDB_TSRESOL, ONE_OPTION_SUPPORTED },
    { OPT_IDB_TZONE, ONE_OPTION_SUPPORTED },
    { OPT_IDB_FILTER, ONE_OPTION_SUPPORTED },
    { OPT_IDB_OS, ONE_OPTION_SUPPORTED },
    { OPT_IDB_FCSLEN, ONE_OPTION_SUPPORTED },
    { OPT_IDB_TSOFFSET, ONE_OPTION_SUPPORTED },
    { OPT_IDB_HARDWARE, ONE_OPTION_SUPPORTED }
};

/* Options for name resolution blocks. */
static const struct supported_option_type name_resolution_block_options_supported[] = {
    { OPT_COMMENT, MULTIPLE_OPTIONS_SUPPORTED },
    { OPT_CUSTOM_STR_COPY, MULTIPLE_OPTIONS_SUPPORTED },
    { OPT_CUSTOM_BIN_COPY, MULTIPLE_OPTIONS_SUPPORTED },
    { OPT_CUSTOM_STR_NO_COPY, MULTIPLE_OPTIONS_SUPPORTED },
    { OPT_CUSTOM_BIN_NO_COPY, MULTIPLE_OPTIONS_SUPPORTED },
    { OPT_NS_DNSNAME, ONE_OPTION_SUPPORTED },
    { OPT_NS_DNSIP4ADDR, ONE_OPTION_SUPPORTED },
    { OPT_NS_DNSIP6ADDR, ONE_OPTION_SUPPORTED }
};

/* Options for interface statistics blocks. */
static const struct supported_option_type interface_statistics_block_options_supported[] = {
    { OPT_COMMENT, MULTIPLE_OPTIONS_SUPPORTED },
    { OPT_CUSTOM_STR_COPY, MULTIPLE_OPTIONS_SUPPORTED },
    { OPT_CUSTOM_BIN_COPY, MULTIPLE_OPTIONS_SUPPORTED },
    { OPT_CUSTOM_STR_NO_COPY, MULTIPLE_OPTIONS_SUPPORTED },
    { OPT_CUSTOM_BIN_NO_COPY, MULTIPLE_OPTIONS_SUPPORTED },
    { OPT_ISB_STARTTIME, ONE_OPTION_SUPPORTED },
    { OPT_ISB_ENDTIME, ONE_OPTION_SUPPORTED },
    { OPT_ISB_IFRECV, ONE_OPTION_SUPPORTED },
    { OPT_ISB_IFDROP, ONE_OPTION_SUPPORTED },
    { OPT_ISB_FILTERACCEPT, ONE_OPTION_SUPPORTED },
    { OPT_ISB_OSDROP, ONE_OPTION_SUPPORTED },
    { OPT_ISB_USRDELIV, ONE_OPTION_SUPPORTED }
};

/* Options for decryption secrets blocks. */
static const struct supported_option_type decryption_secrets_block_options_supported[] = {
    { OPT_COMMENT, MULTIPLE_OPTIONS_SUPPORTED },
    { OPT_CUSTOM_STR_COPY, MULTIPLE_OPTIONS_SUPPORTED },
    { OPT_CUSTOM_BIN_COPY, MULTIPLE_OPTIONS_SUPPORTED },
    { OPT_CUSTOM_STR_NO_COPY, MULTIPLE_OPTIONS_SUPPORTED },
    { OPT_CUSTOM_BIN_NO_COPY, MULTIPLE_OPTIONS_SUPPORTED }
};

/* Options for meta event blocks. */
static const struct supported_option_type meta_events_block_options_supported[] = {
    { OPT_COMMENT, MULTIPLE_OPTIONS_SUPPORTED },
    { OPT_CUSTOM_STR_COPY, MULTIPLE_OPTIONS_SUPPORTED },
    { OPT_CUSTOM_BIN_COPY, MULTIPLE_OPTIONS_SUPPORTED },
    { OPT_CUSTOM_STR_NO_COPY, MULTIPLE_OPTIONS_SUPPORTED },
    { OPT_CUSTOM_BIN_NO_COPY, MULTIPLE_OPTIONS_SUPPORTED }
};

/* Options for packet blocks. */
static const struct supported_option_type packet_block_options_supported[] = {
    { OPT_COMMENT, MULTIPLE_OPTIONS_SUPPORTED },
    { OPT_PKT_FLAGS, ONE_OPTION_SUPPORTED },
    { OPT_PKT_DROPCOUNT, ONE_OPTION_SUPPORTED },
    { OPT_PKT_PACKETID, ONE_OPTION_SUPPORTED },
    { OPT_PKT_QUEUE, ONE_OPTION_SUPPORTED },
    { OPT_PKT_HASH, MULTIPLE_OPTIONS_SUPPORTED },
    { OPT_PKT_VERDICT, MULTIPLE_OPTIONS_SUPPORTED },
    { OPT_CUSTOM_STR_COPY, MULTIPLE_OPTIONS_SUPPORTED },
    { OPT_CUSTOM_BIN_COPY, MULTIPLE_OPTIONS_SUPPORTED },
    { OPT_CUSTOM_STR_NO_COPY, MULTIPLE_OPTIONS_SUPPORTED },
    { OPT_CUSTOM_BIN_NO_COPY, MULTIPLE_OPTIONS_SUPPORTED }
};

/* Options for file-type-specific reports. */
static const struct supported_option_type ft_specific_report_block_options_supported[] = {
    { OPT_COMMENT, MULTIPLE_OPTIONS_SUPPORTED },
    { OPT_CUSTOM_STR_COPY, MULTIPLE_OPTIONS_SUPPORTED },
    { OPT_CUSTOM_BIN_COPY, MULTIPLE_OPTIONS_SUPPORTED },
    { OPT_CUSTOM_STR_NO_COPY, MULTIPLE_OPTIONS_SUPPORTED },
    { OPT_CUSTOM_BIN_NO_COPY, MULTIPLE_OPTIONS_SUPPORTED }
};

/* Options for file-type-specific event. */
static const struct supported_option_type ft_specific_event_block_options_supported[] = {
    { OPT_COMMENT, MULTIPLE_OPTIONS_SUPPORTED },
    { OPT_CUSTOM_STR_COPY, MULTIPLE_OPTIONS_SUPPORTED },
    { OPT_CUSTOM_BIN_COPY, MULTIPLE_OPTIONS_SUPPORTED },
    { OPT_CUSTOM_STR_NO_COPY, MULTIPLE_OPTIONS_SUPPORTED },
    { OPT_CUSTOM_BIN_NO_COPY, MULTIPLE_OPTIONS_SUPPORTED }
};

/* Options for systemd journal entry. */
static const struct supported_option_type systemd_journal_export_block_options_supported[] = {
    { OPT_COMMENT, MULTIPLE_OPTIONS_SUPPORTED },
    { OPT_CUSTOM_STR_COPY, MULTIPLE_OPTIONS_SUPPORTED },
    { OPT_CUSTOM_BIN_COPY, MULTIPLE_OPTIONS_SUPPORTED },
    { OPT_CUSTOM_STR_NO_COPY, MULTIPLE_OPTIONS_SUPPORTED },
    { OPT_CUSTOM_BIN_NO_COPY, MULTIPLE_OPTIONS_SUPPORTED }
};

static const struct supported_block_type pcapng_blocks_supported[] = {
    /* Multiple sections. */
    { WTAP_BLOCK_SECTION, MULTIPLE_BLOCKS_SUPPORTED, OPTION_TYPES_SUPPORTED(section_block_options_supported) },

    /* Multiple interfaces. */
    { WTAP_BLOCK_IF_ID_AND_INFO, MULTIPLE_BLOCKS_SUPPORTED, OPTION_TYPES_SUPPORTED(interface_block_options_supported) },

    /* Multiple blocks of name resolution information */
    { WTAP_BLOCK_NAME_RESOLUTION, MULTIPLE_BLOCKS_SUPPORTED, OPTION_TYPES_SUPPORTED(name_resolution_block_options_supported) },

    /* Multiple blocks of interface statistics. */
    { WTAP_BLOCK_IF_STATISTICS, MULTIPLE_BLOCKS_SUPPORTED, OPTION_TYPES_SUPPORTED(interface_statistics_block_options_supported) },

    /* Multiple blocks of decryption secrets. */
    { WTAP_BLOCK_DECRYPTION_SECRETS, MULTIPLE_BLOCKS_SUPPORTED, OPTION_TYPES_SUPPORTED(decryption_secrets_block_options_supported) },

    /* Multiple blocks of decryption secrets. */
    { WTAP_BLOCK_META_EVENT, MULTIPLE_BLOCKS_SUPPORTED, OPTION_TYPES_SUPPORTED(meta_events_block_options_supported) },

    /* And, obviously, multiple packets. */
    { WTAP_BLOCK_PACKET, MULTIPLE_BLOCKS_SUPPORTED, OPTION_TYPES_SUPPORTED(packet_block_options_supported) },

    /* Multiple file-type specific reports (including local ones). */
    { WTAP_BLOCK_FT_SPECIFIC_REPORT, MULTIPLE_BLOCKS_SUPPORTED, OPTION_TYPES_SUPPORTED(ft_specific_report_block_options_supported) },

    /* Multiple file-type specific events (including local ones). */
    { WTAP_BLOCK_FT_SPECIFIC_EVENT, MULTIPLE_BLOCKS_SUPPORTED, OPTION_TYPES_SUPPORTED(ft_specific_event_block_options_supported) },

    /* Multiple systemd journal export records. */
    { WTAP_BLOCK_SYSTEMD_JOURNAL_EXPORT, MULTIPLE_BLOCKS_SUPPORTED, OPTION_TYPES_SUPPORTED(systemd_journal_export_block_options_supported) },

    /* Multiple custom blocks. */
    { WTAP_BLOCK_CUSTOM, MULTIPLE_BLOCKS_SUPPORTED, NO_OPTIONS_SUPPORTED },
};

static const struct file_type_subtype_info pcapng_info = {
    "Wireshark/... - pcapng", "pcapng", "pcapng", "scap;ntar",
    false, BLOCKS_SUPPORTED(pcapng_blocks_supported),
    pcapng_dump_can_write_encap, pcapng_dump_open, NULL
};

void register_pcapng(void)
{
    pcapng_file_type_subtype = wtap_register_file_type_subtype(&pcapng_info);

    wtap_register_backwards_compatibility_lua_name("PCAPNG",
                                                   pcapng_file_type_subtype);
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
