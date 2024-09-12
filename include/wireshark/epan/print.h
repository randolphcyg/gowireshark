/** @file
 * Definitions for printing packet analysis trees.
 *
 * Gilbert Ramirez <gram@alumni.rice.edu>
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef __PRINT_H__
#define __PRINT_H__

#include <stdio.h>

#include <epan/epan.h>
#include <epan/packet.h>
#include <epan/print_stream.h>

#include <wsutil/json_dumper.h>

#include "include/ws_symbol_export.h"

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

/* print output format */
typedef enum {
  PR_FMT_TEXT,    /* plain text */
  PR_FMT_PS       /* postscript */
} print_format_e;

/* print_dissections, enum how the dissections should be printed */
typedef enum {
  print_dissections_none,         /* no dissections at all */
  print_dissections_collapsed,    /* no dissection details */
  print_dissections_as_displayed, /* details as displayed */
  print_dissections_expanded      /* all dissection details */
} print_dissections_e;


typedef enum {
  FORMAT_CSV,     /* CSV */
  FORMAT_JSON,    /* JSON */
  FORMAT_EK,      /* JSON bulk insert to Elasticsearch */
  FORMAT_XML      /* PDML output */
} fields_format;

typedef enum {
  PF_NONE = 0x00,
  PF_INCLUDE_CHILDREN = 0x01
} pf_flags;

/*
 * Print user selected list of fields
 */
struct _output_fields;
typedef struct _output_fields output_fields_t;

typedef GSList* (*proto_node_children_grouper_func)(proto_node *node);

WS_DLL_PUBLIC output_fields_t* output_fields_new(void);
WS_DLL_PUBLIC void output_fields_free(output_fields_t* info);
WS_DLL_PUBLIC void output_fields_add(output_fields_t* info, const char* field);
WS_DLL_PUBLIC GSList * output_fields_valid(output_fields_t* info);
WS_DLL_PUBLIC size_t output_fields_num_fields(output_fields_t* info);
WS_DLL_PUBLIC bool output_fields_set_option(output_fields_t* info, char* option);
WS_DLL_PUBLIC void output_fields_list_options(FILE *fh);
WS_DLL_PUBLIC bool output_fields_add_protocolfilter(output_fields_t* info, const char* field, pf_flags filter_flags);
WS_DLL_PUBLIC bool output_fields_has_cols(output_fields_t* info);
WS_DLL_PUBLIC void output_fields_prime_edt(struct epan_dissect *edt, output_fields_t* info);

/*
 * Higher-level packet-printing code.
 */

WS_DLL_PUBLIC bool proto_tree_print(print_dissections_e print_dissections,
                                        bool print_hex_data,
                                        epan_dissect_t *edt,
                                        GHashTable *output_only_tables,
                                        print_stream_t *stream);

/*
 * Hexdump option for displaying data sources:
 */

#define HEXDUMP_SOURCE_MASK           (0x0004U)
#define HEXDUMP_SOURCE_OPTION(option) ((option) & HEXDUMP_SOURCE_MASK)

#define HEXDUMP_SOURCE_MULTI          (0x0000U) /* create hexdumps for all data sources assigned to a frame (legacy tshark behaviour) */
#define HEXDUMP_SOURCE_PRIMARY        (0x0004U) /* create hexdumps for only the frame data */

WS_DLL_PUBLIC bool print_hex_data(print_stream_t *stream, epan_dissect_t *edt, unsigned hexdump_options);

WS_DLL_PUBLIC void write_pdml_preamble(FILE *fh, const char* filename);
WS_DLL_PUBLIC void write_pdml_proto_tree(output_fields_t* fields, epan_dissect_t *edt, column_info *cinfo, FILE *fh, bool use_color);
WS_DLL_PUBLIC void write_pdml_finale(FILE *fh);

// Implementations of proto_node_children_grouper_func
// Groups each child separately
WS_DLL_PUBLIC GSList *proto_node_group_children_by_unique(proto_node *node);
// Groups children by json key (children with the same json key get put in the same group
WS_DLL_PUBLIC GSList *proto_node_group_children_by_json_key(proto_node *node);

WS_DLL_PUBLIC json_dumper write_json_preamble(FILE *fh);
WS_DLL_PUBLIC void write_json_proto_tree(output_fields_t* fields,
                                         print_dissections_e print_dissections,
                                         bool print_hex_data,
                                         epan_dissect_t *edt,
                                         column_info *cinfo,
                                         proto_node_children_grouper_func node_children_grouper,
                                         json_dumper *dumper);
WS_DLL_PUBLIC void write_json_finale(json_dumper *dumper);

WS_DLL_PUBLIC void write_ek_proto_tree(output_fields_t* fields,
                                       bool print_summary,
                                       bool print_hex_data,
                                       epan_dissect_t *edt,
                                       column_info *cinfo, FILE *fh);

WS_DLL_PUBLIC void write_psml_preamble(column_info *cinfo, FILE *fh);
WS_DLL_PUBLIC void write_psml_columns(epan_dissect_t *edt, FILE *fh, bool use_color);
WS_DLL_PUBLIC void write_psml_finale(FILE *fh);

WS_DLL_PUBLIC void write_csv_column_titles(column_info *cinfo, FILE *fh);
WS_DLL_PUBLIC void write_csv_columns(epan_dissect_t *edt, FILE *fh);

WS_DLL_PUBLIC void write_carrays_hex_data(uint32_t num, FILE *fh, epan_dissect_t *edt);

WS_DLL_PUBLIC void write_fields_preamble(output_fields_t* fields, FILE *fh);
WS_DLL_PUBLIC void write_fields_proto_tree(output_fields_t* fields, epan_dissect_t *edt, column_info *cinfo, FILE *fh);
WS_DLL_PUBLIC void write_fields_finale(output_fields_t* fields, FILE *fh);

WS_DLL_PUBLIC char* get_node_field_value(field_info* fi, epan_dissect_t* edt);

extern void print_cache_field_handles(void);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* print.h */
