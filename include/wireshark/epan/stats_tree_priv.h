/** @file
 * implementor's API for stats_tree
 * 2005, Luis E. G. Ontanon
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef __STATS_TREE_PRIV_H
#define  __STATS_TREE_PRIV_H

#include "stats_tree.h"
#include "include/ws_symbol_export.h"

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

#define INDENT_MAX 32
#define NUM_BUF_SIZE 32

/** implementations should define this to contain its own node related data
 * as well as some operations on it */
typedef struct _st_node_pres st_node_pres;

/** implementations should define this to contain its own dynamic tree related data
* as well as some operations on it */
typedef struct _tree_pres tree_pres;

/** implementations should define this to contain its own static tree related data
* as well as some operations on it */
typedef struct _tree_cfg_pres tree_cfg_pres;


typedef struct _stat_node stat_node;
typedef struct _stats_tree_cfg stats_tree_cfg;

typedef struct _range_pair {
	int floor;
	int ceil;
} range_pair_t;

typedef struct _burst_bucket burst_bucket;
struct _burst_bucket {
	burst_bucket	*next;
	burst_bucket	*prev;
	int			count;
	double			bucket_no;
	double			start_time;
};

struct _stat_node {
	char*				name;
	int					id;
	stat_node_datatype	datatype;

	/** the counter it keeps */
	int			counter;
	/** total of all values submitted - for computing averages */
	union {
		int64_t	int_total;
		double	float_total;
	} total;
	union {
		int	int_min;
		float	float_min;
	} minvalue;
	union {
		int	int_max;
		float	float_max;
	} maxvalue;

	int			st_flags;

	/** fields for burst rate calculation */
	int			bcount;
	burst_bucket	*bh, *bt;
	int			max_burst;
	double			burst_time;

	/** children nodes by name */
	GHashTable		*hash;

	/** the owner of this node */
	stats_tree		*st;

	/** relatives */
	stat_node		*parent;
	stat_node		*children;
	stat_node		*next;

	/** used to check if value is within range */
	range_pair_t		*rng;

	/** node presentation data */
	st_node_pres		*pr;
};

struct _stats_tree {
	/** the "class" from which it's derived */
	stats_tree_cfg		*cfg;

	char			*filter;

	/* times */
	double			start;
	double			elapsed;
	double			now;

	int				st_flags;
	int			num_columns;
	char			*display_name;

   /** used to lookup named parents:
	*    key: parent node name
	*  value: parent node
	*/
	GHashTable		*names;

   /** used for quicker lookups of parent nodes */
	GPtrArray		*parents;

	/**
	 *  tree representation
	 * 	to be defined (if needed) by the implementations
	 */
	tree_pres		*pr;

	/** every tree in nature has one */
	stat_node		root;
};

struct _stats_tree_cfg {
	char			*abbr;
	char			*path;
	char			*title;
	char			*tapname;
	char			*first_column_name;
	register_stat_group_t	stat_group;

	bool plugin;

	/** dissector defined callbacks */
	stat_tree_packet_cb packet;
	stat_tree_init_cb init;
	stat_tree_cleanup_cb cleanup;

	/** tap listener flags for the per-packet callback */
	unsigned flags;

	/*
	 * node presentation callbacks
	 */

	/** last to be called at node creation */
	void (*setup_node_pr)(stat_node*);

	/**
	 * tree presentation callbacks
	 */
	tree_cfg_pres *pr;


	tree_pres *(*new_tree_pr)(stats_tree*);
	void (*free_tree_pr)(stats_tree*);

	/** flags for the stats tree (sorting etc.) default values to new trees */
	unsigned st_flags;
};

/* guess what, this is it! */
WS_DLL_PUBLIC void stats_tree_presentation(void (*registry_iterator)(void *,void *,void *),
				    void (*setup_node_pr)(stat_node*),
				    void (*free_tree_pr)(stats_tree*),
				    void *data);

WS_DLL_PUBLIC stats_tree *stats_tree_new(stats_tree_cfg *cfg, tree_pres *pr, const char *filter);

/** callback for taps */
WS_DLL_PUBLIC tap_packet_status stats_tree_packet(void*, packet_info*, epan_dissect_t*, const void *, tap_flags_t flags);

/** callback for reset */
WS_DLL_PUBLIC void stats_tree_reset(void *p_st);

/** callback for clear */
WS_DLL_PUBLIC void stats_tree_reinit(void *p_st);

/* callback for destroy */
WS_DLL_PUBLIC void stats_tree_free(stats_tree *st);

/** given an ws_optarg splits the abbr part
   and returns a newly allocated buffer containing it */
WS_DLL_PUBLIC char *stats_tree_get_abbr(const char *ws_optarg);

/** obtains a stats tree from the registry given its abbr */
WS_DLL_PUBLIC stats_tree_cfg *stats_tree_get_cfg_by_abbr(const char *abbr);

/** obtains a stats tree list from the registry
    caller should free returned list with  g_list_free() */
WS_DLL_PUBLIC GList *stats_tree_get_cfg_list(void);

/** used to calculate the size of the indentation and the longest string */
WS_DLL_PUBLIC unsigned stats_tree_branch_max_namelen(const stat_node *node, unsigned indent);

/** a text representation of a node,
   if buffer is NULL returns a newly allocated string */
WS_DLL_PUBLIC char *stats_tree_node_to_str(const stat_node *node,
					char *buffer, unsigned len);

/** get the display name for the stats_tree (or node name) based on the
    st_sort_showfullname preference. If not set remove everything before
    last unescaped backslash. Caller must free the result */
WS_DLL_PUBLIC char* stats_tree_get_displayname (char* fullname);

/** returns the column number of the default column to sort on */
WS_DLL_PUBLIC int stats_tree_get_default_sort_col (stats_tree *st);

/** returns the default sort order to use */
WS_DLL_PUBLIC bool stats_tree_is_default_sort_DESC (stats_tree *st);

/** returns the column name for a given column index */
WS_DLL_PUBLIC const char* stats_tree_get_column_name (stats_tree_cfg *st_config, int col_index);

/** returns the maximum number of characters in the value of a column */
WS_DLL_PUBLIC int stats_tree_get_column_size (int col_index);

/** returns the formatted column values for the current node
  as array of char*. Caller must free entries and free array */
WS_DLL_PUBLIC char** stats_tree_get_values_from_node (const stat_node* node);

/** function to compare two nodes for sort, based on sort_column. */
WS_DLL_PUBLIC int stats_tree_sort_compare (const stat_node *a,
					const stat_node *b,
					int sort_column,
					bool sort_descending);

/** wrapper for stats_tree_sort_compare() function that can be called from array sort. */
WS_DLL_PUBLIC int stat_node_array_sortcmp (const void *a,
					const void *b,
					void *user_data);

/** function to copy stats_tree into GString. format determines output format */
WS_DLL_PUBLIC GString* stats_tree_format_as_str(const stats_tree* st,
					st_format_type format_type,
					int sort_column,
					bool sort_descending);

/** helper funcation to add note to formatted stats_tree */
WS_DLL_PUBLIC void stats_tree_format_node_as_str(const stat_node *node,
					GString *s,
					st_format_type format_type,
					unsigned indent,
					const char *path,
					int maxnamelen,
					int sort_column,
					bool sort_descending);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* __STATS_TREE_PRIV_H */
