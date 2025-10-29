/** @file
 * A counter tree API for Wireshark dissectors
 * 2005, Luis E. G. Ontanon
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
#ifndef __STATS_TREE_H
#define __STATS_TREE_H

#include <epan/epan.h>
#include <epan/packet_info.h>
#include <epan/tap.h>
#include <epan/stat_groups.h>
#include "ws_symbol_export.h"

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

#define STAT_TREE_ROOT "root"
#define STATS_TREE_MENU_SEPARATOR "//"

/* stats_tree specific flags. When registering, these are used together
 * with the TL_ flags defined in tap.h, so make sure they don't overlap!
 * (Yes, that applies even to the flags that apply to nodes instead of
 * the entire tree, and should not be passed in stats_tree_register.
 * XXX - Why? These flags should be reworked at some point.)
 */

/* Flags on child nodes for internal use only */
#define ST_FLG_AVERAGE      0x10000000  /* Calculate averages for nodes, rather than totals */
#define ST_FLG_ROOTCHILD    0x20000000  /* This node is a direct child of the root node */

/* Flags set on child nodes via stat_node_set_flags */
#define ST_FLG_DEF_NOEXPAND 0x01000000  /* This node should not be expanded by default */
#define ST_FLG_SORT_TOP     0x00400000  /* When sorting always keep these lines on of list */

/* Flags for the entire stat_tree, set via stats_tree_register[_plugin] */
#define ST_FLG_SORT_DESC    0x00800000  /* When sorting, sort descending instead of ascending */
#define ST_FLG_SRTCOL_MASK  0x000F0000  /* Mask for sort column ID */
#define ST_FLG_SRTCOL_SHIFT 16          /* Number of bits to shift masked result */

#define ST_FLG_MASK         (ST_FLG_AVERAGE|ST_FLG_ROOTCHILD|ST_FLG_DEF_NOEXPAND| \
                             ST_FLG_SORT_TOP|ST_FLG_SORT_DESC|ST_FLG_SRTCOL_MASK)

#define ST_SORT_COL_NAME      1         /* Sort nodes by node names */
#define ST_SORT_COL_COUNT     2         /* Sort nodes by node count */
#define ST_SORT_COL_AVG       3         /* Sort nodes by node average */
#define ST_SORT_COL_MIN       4         /* Sort nodes by minimum node value */
#define ST_SORT_COL_MAX       5         /* Sort nodes by maximum node value */
#define ST_SORT_COL_BURSTRATE 6         /* Sort nodes by burst rate */

/* obscure information regarding the stats_tree */
typedef struct _stats_tree stats_tree;

/* tap packet callback for stats_tree */
typedef tap_packet_status (*stat_tree_packet_cb)(stats_tree*,
                                                 packet_info *,
                                                 epan_dissect_t *,
                                                 const void *,
                                                 tap_flags_t flags);

/* stats_tree initialization callback */
typedef void  (*stat_tree_init_cb)(stats_tree *);

/* stats_tree cleanup callback */
typedef void  (*stat_tree_cleanup_cb)(stats_tree *);

typedef enum _stat_node_datatype {
    STAT_DT_INT,
    STAT_DT_FLOAT
} stat_node_datatype;

typedef struct _stats_tree_cfg stats_tree_cfg;

/**
 * Registers a new stats tree with default group REGISTER_STAT_GROUP_UNSORTED.
 * @param abbr tree abbr (used for tshark -z option)
 * @param path tree display name in GUI menu and window (use "//" for submenus)
 * @param flags tap listener flags for per-packet callback
 * @param packet per packet callback
 * @param init tree initialization callback
 * @param cleanup cleanup callback
 * @return A stats tree configuration pointer.
 */
WS_DLL_PUBLIC stats_tree_cfg *stats_tree_register(const char *tapname,
                                       const char *abbr,
                                       const char *path,
                                       unsigned flags,
                                       stat_tree_packet_cb packet,
                                       stat_tree_init_cb init,
                                       stat_tree_cleanup_cb cleanup);

/**
 * Registers a new stats tree with default group REGISTER_STAT_GROUP_UNSORTED from a plugin.
 * @param abbr tree abbr (used for tshark -z option)
 * @param path tree display name in GUI menu and window (use "//" for submenus)
 * @param flags tap listener flags for per-packet callback
 * @param packet per packet callback
 * @param init tree initialization callback
 * @param cleanup cleanup callback
 * @return A stats tree configuration pointer.
 */
WS_DLL_PUBLIC stats_tree_cfg *stats_tree_register_plugin(const char *tapname,
                                              const char *abbr,
                                              const char *path,
                                              unsigned flags,
                                              stat_tree_packet_cb packet,
                                              stat_tree_init_cb init,
                                              stat_tree_cleanup_cb cleanup);

/**
 * Set the menu statistics group for a stats tree.
 * @param stat_group A menu group.
 */
WS_DLL_PUBLIC void stats_tree_set_group(stats_tree_cfg *st_config, register_stat_group_t stat_group);

/**
 * Set the name a stats tree's first column.
 * Default is "Topic / Item".
 * @param column_name The new column name.
 */
WS_DLL_PUBLIC void stats_tree_set_first_column_name(stats_tree_cfg *st_config, const char *column_name);


WS_DLL_PUBLIC int stats_tree_parent_id_by_name(stats_tree *st, const char *parent_name);

/* Creates a node in the tree (to be used in the in init_cb)
 * st: the stats_tree in which to create it
 * name: the name of the new node
 * parent_name: the name of the parent_node (NULL for root)
 * datatype: datatype used for the value of the node
 * with_children: true if this node will have "dynamically created" children
 */
WS_DLL_PUBLIC int stats_tree_create_node(stats_tree *st,
                                         const char *name,
                                         int parent_id,
                                         stat_node_datatype datatype,
                                         bool with_children);

/* creates a node using its parent's tree name */
WS_DLL_PUBLIC int stats_tree_create_node_by_pname(stats_tree *st,
                                                  const char *name,
                                                  const char *parent_name,
                                                  stat_node_datatype datatype,
                                                  bool with_children);

/* creates a node in the tree, that will contain a ranges list.
   example:
   stats_tree_create_range_node(st,name,parent,
   "-99","100-199","200-299","300-399","400-", NULL);
*/
WS_DLL_PUBLIC int stats_tree_create_range_node(stats_tree *st,
                                               const char *name,
                                               int parent_id,
                                               ...);

WS_DLL_PUBLIC int stats_tree_create_range_node_string(stats_tree *st,
                                                      const char *name,
                                                      int parent_id,
                                                      int num_str_ranges,
                                                      char** str_ranges);

WS_DLL_PUBLIC int stats_tree_range_node_with_pname(stats_tree *st,
                                                   const char *name,
                                                   const char *parent_name,
                                                   ...);

/* increases by one the ranged node and the sub node to whose range the value belongs */
WS_DLL_PUBLIC int stats_tree_tick_range(stats_tree *st,
                                        const char *name,
                                        int parent_id,
                                        int value_in_range);

#define stats_tree_tick_range_by_pname(st,name,parent_name,value_in_range) \
    stats_tree_tick_range((st),(name),stats_tree_parent_id_by_name((st),(parent_name),(value_in_range)))

/* */
WS_DLL_PUBLIC int stats_tree_create_pivot(stats_tree *st,
                                          const char *name,
                                          int parent_id);

WS_DLL_PUBLIC int stats_tree_create_pivot_by_pname(stats_tree *st,
                                                   const char *name,
                                                   const char *parent_name);

WS_DLL_PUBLIC int stats_tree_tick_pivot(stats_tree *st,
                                        int pivot_id,
                                        const char *pivot_value);

extern void stats_tree_cleanup(void);


/*
 * manipulates the value of the node whose name is given
 * if the node does not exist yet it's created (with counter=1)
 * using parent_name as parent node (NULL for root).
 * with_children=true to indicate that the created node will be a parent
 */
typedef enum _manip_node_mode {
    MN_INCREASE,
    MN_SET,
    MN_AVERAGE,
    MN_AVERAGE_NOTICK,
    MN_SET_FLAGS,
    MN_CLEAR_FLAGS
} manip_node_mode;
WS_DLL_PUBLIC int stats_tree_manip_node_int(manip_node_mode mode,
                                        stats_tree *st,
                                        const char *name,
                                        int parent_id,
                                        bool with_children,
                                        int value);

WS_DLL_PUBLIC int stats_tree_manip_node_float(manip_node_mode mode,
                                        stats_tree *st,
                                        const char *name,
                                        int parent_id,
                                        bool with_children,
                                        float value);

#define increase_stat_node(st,name,parent_id,with_children,value)       \
    (stats_tree_manip_node_int(MN_INCREASE,(st),(name),(parent_id),(with_children),(value)))

#define tick_stat_node(st,name,parent_id,with_children)                 \
    (stats_tree_manip_node_int(MN_INCREASE,(st),(name),(parent_id),(with_children),1))

#define set_stat_node(st,name,parent_id,with_children,value)            \
    (stats_tree_manip_node_int(MN_SET,(st),(name),(parent_id),(with_children),value))

#define zero_stat_node(st,name,parent_id,with_children)                 \
    (stats_tree_manip_node_int(MN_SET,(st),(name),(parent_id),(with_children),0))

/*
 * Add value to average calculation WITHOUT ticking node. Node MUST be ticked separately!
 *
 * Intention is to allow code to separately tick node (backward compatibility for plugin)
 * and set value to use for averages. Older versions without average support will then at
 * least show a count instead of 0.
 */
#define avg_stat_node_add_value_notick(st,name,parent_id,with_children,value) \
    (stats_tree_manip_node_int(MN_AVERAGE_NOTICK,(st),(name),(parent_id),(with_children),value))

/* Tick node and add a new value to the average calculation for this stats node. */
#define avg_stat_node_add_value_int(st,name,parent_id,with_children,value)  \
    (stats_tree_manip_node_int(MN_AVERAGE,(st),(name),(parent_id),(with_children),value))

#define avg_stat_node_add_value_float(st,name,parent_id,with_children,value)  \
    (stats_tree_manip_node_float(MN_AVERAGE,(st),(name),(parent_id),(with_children),value))

/* Set flags for this node. Node created if it does not yet exist. */
#define stat_node_set_flags(st,name,parent_id,with_children,flags)      \
    (stats_tree_manip_node_int(MN_SET_FLAGS,(st),(name),(parent_id),(with_children),flags))

/* Clear flags for this node. Node created if it does not yet exist. */
#define stat_node_clear_flags(st,name,parent_id,with_children,flags)    \
    (stats_tree_manip_node_int(MN_CLEAR_FLAGS,(st),(name),(parent_id),(with_children),flags))

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* __STATS_TREE_H */

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
