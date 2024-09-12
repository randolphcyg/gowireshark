/*
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 2001 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "config.h"

#include "gencode.h"
#include "dfvm.h"
#include "syntax-tree.h"
#include "sttype-field.h"
#include "sttype-slice.h"
#include "sttype-op.h"
#include "sttype-set.h"
#include "sttype-function.h"
#include "ftypes/ftypes.h"
#include <wsutil/ws_assert.h>

static void
fixup_jumps(void *data, void *user_data);

static dfvm_value_t *
gencode(dfwork_t *dfw, stnode_t *st_node);

static dfvm_value_t *
gen_entity(dfwork_t *dfw, stnode_t *st_arg, GSList **jumps_ptr);

static dfvm_opcode_t
select_opcode(dfvm_opcode_t op, stmatch_t how)
{
	if (how == STNODE_MATCH_DEF)
		return op;

	switch (op) {
		case DFVM_ALL_EQ:
		case DFVM_ALL_NE:
		case DFVM_ALL_GT:
		case DFVM_ALL_GE:
		case DFVM_ALL_LT:
		case DFVM_ALL_LE:
		case DFVM_ALL_CONTAINS:
		case DFVM_ALL_MATCHES:
		case DFVM_SET_ALL_IN:
		case DFVM_SET_ALL_NOT_IN:
			return how == STNODE_MATCH_ALL ? op : op + 1;
		case DFVM_ANY_EQ:
		case DFVM_ANY_NE:
		case DFVM_ANY_GT:
		case DFVM_ANY_GE:
		case DFVM_ANY_LT:
		case DFVM_ANY_LE:
		case DFVM_ANY_CONTAINS:
		case DFVM_ANY_MATCHES:
		case DFVM_SET_ANY_IN:
		case DFVM_SET_ANY_NOT_IN:
			return how == STNODE_MATCH_ANY ? op : op - 1;
		default:
			ASSERT_DFVM_OP_NOT_REACHED(op);
	}
	ws_assert_not_reached();
}

static void
dfw_append_insn(dfwork_t *dfw, dfvm_insn_t *insn)
{
	insn->id = dfw->next_insn_id;
	dfw->next_insn_id++;
	g_ptr_array_add(dfw->insns, insn);
}

static void
dfw_append_stack_push(dfwork_t *dfw, dfvm_value_t *arg1)
{
	dfvm_insn_t	*insn;

	insn = dfvm_insn_new(DFVM_STACK_PUSH);
	insn->arg1 = dfvm_value_ref(arg1);
	dfw_append_insn(dfw, insn);
}

static void
dfw_append_stack_pop(dfwork_t *dfw, unsigned count)
{
	dfvm_insn_t	*insn;
	dfvm_value_t	*val;

	insn = dfvm_insn_new(DFVM_STACK_POP);
	val = dfvm_value_new_uint(count);
	insn->arg1 = dfvm_value_ref(val);
	dfw_append_insn(dfw, insn);
}

static void
dfw_append_set_add_range(dfwork_t *dfw, dfvm_value_t *arg1, dfvm_value_t *arg2)
{
	dfvm_insn_t	*insn;

	insn = dfvm_insn_new(DFVM_SET_ADD_RANGE);
	insn->arg1 = dfvm_value_ref(arg1);
	insn->arg2 = dfvm_value_ref(arg2);
	dfw_append_insn(dfw, insn);
}

static void
dfw_append_set_add(dfwork_t *dfw, dfvm_value_t *arg1)
{
	dfvm_insn_t	*insn;

	insn = dfvm_insn_new(DFVM_SET_ADD);
	insn->arg1 = dfvm_value_ref(arg1);
	dfw_append_insn(dfw, insn);
}

static dfvm_value_t *
dfw_append_jump(dfwork_t *dfw)
{
	dfvm_insn_t	*insn;
	dfvm_value_t	*jmp;

	insn = dfvm_insn_new(DFVM_IF_FALSE_GOTO);
	jmp = dfvm_value_new(INSN_NUMBER);
	insn->arg1 = dfvm_value_ref(jmp);
	dfw_append_insn(dfw, insn);
	return jmp;
}

/* returns register number */
static dfvm_value_t *
dfw_append_read_tree(dfwork_t *dfw, header_field_info *hfinfo,
						drange_t *range,
						bool raw)
{
	dfvm_insn_t	*insn;
	int		reg = -1;
	dfvm_value_t	*reg_val, *val1, *val3;
	bool	added_new_hfinfo = false;
	GHashTable *loaded_fields;
	void *loaded_key;

	/* Rewind to find the first field of this name. */
	while (hfinfo->same_name_prev_id != -1) {
		hfinfo = proto_registrar_get_nth(hfinfo->same_name_prev_id);
	}

	if (raw)
		loaded_fields = dfw->loaded_raw_fields;
	else
		loaded_fields = dfw->loaded_fields;

	/* Keep track of which registers
	 * were used for which hfinfo's so that we
	 * can re-use registers. */
	/* Re-use only if we are not using a range (layer filter). */
	loaded_key = g_hash_table_lookup(loaded_fields, hfinfo);
	if (loaded_key != NULL) {
		if (range == NULL) {
			/*
			 * Reg's are stored in has as reg+1, so
			 * that the non-existence of a hfinfo in
			 * the hash, or 0, can be differentiated from
			 * a hfinfo being loaded into register #0.
			 */
			reg = GPOINTER_TO_INT(loaded_key) - 1;
		}
		else {
			reg = dfw->next_register++;
		}
	}
	else {
		reg = dfw->next_register++;
		g_hash_table_insert(loaded_fields,
			hfinfo, GINT_TO_POINTER(reg + 1));

		added_new_hfinfo = true;
	}

	val1 = dfvm_value_new_hfinfo(hfinfo, raw);
	reg_val = dfvm_value_new_register(reg);
	if (range) {
		val3 = dfvm_value_new_drange(range);
		insn = dfvm_insn_new(DFVM_READ_TREE_R);
	}
	else {
		val3 = NULL;
		insn = dfvm_insn_new(DFVM_READ_TREE);
	}
	insn->arg1 = dfvm_value_ref(val1);
	insn->arg2 = dfvm_value_ref(reg_val);
	insn->arg3 = dfvm_value_ref(val3);
	dfw_append_insn(dfw, insn);

	if (added_new_hfinfo) {
		while (hfinfo) {
			/* Record the FIELD_ID in hash of interesting fields. */
			g_hash_table_add(dfw->interesting_fields, &hfinfo->id);
			hfinfo = hfinfo->same_name_next;
		}
	}

	return reg_val;
}

/* returns register number */
static dfvm_value_t *
dfw_append_read_reference(dfwork_t *dfw, header_field_info *hfinfo,
						drange_t *range,
						bool raw)
{
	dfvm_insn_t	*insn;
	dfvm_value_t	*reg_val, *val1, *val3;
	GPtrArray	*refs_array;

	/* Rewind to find the first field of this name. */
	while (hfinfo->same_name_prev_id != -1) {
		hfinfo = proto_registrar_get_nth(hfinfo->same_name_prev_id);
	}

	/* We can't reuse registers with a filter so just skip
	 * that optimization and don't reuse them at all. */
	val1 = dfvm_value_new_hfinfo(hfinfo, raw);
	reg_val = dfvm_value_new_register(dfw->next_register++);
	if (range) {
		val3 = dfvm_value_new_drange(range);
		insn = dfvm_insn_new(DFVM_READ_REFERENCE_R);
	}
	else {
		val3 = NULL;
		insn = dfvm_insn_new(DFVM_READ_REFERENCE);
	}
	insn->arg1 = dfvm_value_ref(val1);
	insn->arg2 = dfvm_value_ref(reg_val);
	insn->arg3 = dfvm_value_ref(val3);
	dfw_append_insn(dfw, insn);

	refs_array = g_ptr_array_new_with_free_func((GDestroyNotify)reference_free);
	if (raw)
		g_hash_table_insert(dfw->raw_references, hfinfo, refs_array);
	else
		g_hash_table_insert(dfw->references, hfinfo, refs_array);

	/* Record the FIELD_ID in hash of interesting fields. */
	while (hfinfo) {
		/* Record the FIELD_ID in hash of interesting fields. */
		g_hash_table_add(dfw->interesting_fields, &hfinfo->id);
		hfinfo = hfinfo->same_name_next;
	}

	return reg_val;
}

/* returns register number */
static dfvm_value_t *
dfw_append_mk_slice(dfwork_t *dfw, stnode_t *node, GSList **jumps_ptr)
{
	stnode_t                *entity;
	dfvm_insn_t		*insn;
	dfvm_value_t		*reg_val, *val1, *val3;

	entity = sttype_slice_entity(node);

	insn = dfvm_insn_new(DFVM_SLICE);
	val1 = gen_entity(dfw, entity, jumps_ptr);
	insn->arg1 = dfvm_value_ref(val1);
	reg_val = dfvm_value_new_register(dfw->next_register++);
	insn->arg2 = dfvm_value_ref(reg_val);
	val3 = dfvm_value_new_drange(sttype_slice_drange_steal(node));
	insn->arg3 = dfvm_value_ref(val3);
	sttype_slice_remove_drange(node);
	dfw_append_insn(dfw, insn);

	return reg_val;
}

/* Returns register number. This applies the value string in hfinfo to the
 * contents of the src register. */
static dfvm_value_t *
dfw_append_mk_value_string(dfwork_t *dfw, stnode_t *node, dfvm_value_t *src)
{
	dfvm_insn_t		*insn;
	dfvm_value_t		*reg_val, *val1;

	insn = dfvm_insn_new(DFVM_VALUE_STRING);
	val1 = dfvm_value_new_hfinfo(sttype_field_hfinfo(node), false);
	insn->arg1 = dfvm_value_ref(val1);
	insn->arg2 = dfvm_value_ref(src);
	reg_val = dfvm_value_new_register(dfw->next_register++);
	insn->arg3 = dfvm_value_ref(reg_val);
	dfw_append_insn(dfw, insn);

	return reg_val;
}

/* returns register number */
_U_ static dfvm_value_t *
dfw_append_put_fvalue(dfwork_t *dfw, fvalue_t *fv)
{
	dfvm_insn_t		*insn;
	dfvm_value_t		*reg_val, *val1;

	insn = dfvm_insn_new(DFVM_PUT_FVALUE);
	val1 = dfvm_value_new_fvalue(fv);
	insn->arg1 = dfvm_value_ref(val1);
	reg_val = dfvm_value_new_register(dfw->next_register++);
	insn->arg2 = dfvm_value_ref(reg_val);
	dfw_append_insn(dfw, insn);

	return reg_val;
}

/* returns register number that the length's result will be in. */
static dfvm_value_t *
dfw_append_length(dfwork_t *dfw, stnode_t *node, GSList **jumps_ptr)
{
	GSList *params;
	dfvm_insn_t	*insn;
	dfvm_value_t	*reg_val, *val_arg;

	/* Create the new DFVM instruction */
	insn = dfvm_insn_new(DFVM_LENGTH);
	/* Create input argument */
	params = sttype_function_params(node);
	ws_assert(params);
	ws_assert(g_slist_length(params) == 1);
	val_arg = gen_entity(dfw, params->data, jumps_ptr);
	insn->arg1 = dfvm_value_ref(val_arg);
	/* Destination. */
	reg_val = dfvm_value_new_register(dfw->next_register++);
	insn->arg2 = dfvm_value_ref(reg_val);

	dfw_append_insn(dfw, insn);
	return reg_val;
}

/* returns register number that the value string result will be in. */
static dfvm_value_t *
dfw_append_value_string(dfwork_t *dfw, stnode_t *node, GSList **jumps_ptr)
{
	GSList *params;

	params = sttype_function_params(node);
	ws_assert(params);
	ws_assert(g_slist_length(params) == 1);
	return gen_entity(dfw, params->data, jumps_ptr);
}

/* returns register number that the functions's result will be in. */
static dfvm_value_t *
dfw_append_function(dfwork_t *dfw, stnode_t *node, GSList **jumps_ptr)
{
	GSList		*params;
	dfvm_value_t	*jmp;
	dfvm_insn_t	*insn;
	dfvm_value_t	*reg_val, *val1, *val3, *val_arg;
	unsigned	count;
	df_func_def_t	*func;
	GSList		*params_jumps = NULL;

	func = sttype_function_funcdef(node);

	if (strcmp(func->name, "len") == 0) {
		/* Replace len() function call with DFVM_LENGTH instruction. */
		return dfw_append_length(dfw, node, jumps_ptr);
	}

	if (strcmp(func->name, "vals") == 0) {
		/* Replace vals() function call with DFVM_VALUE_STRING instruction. */
		return dfw_append_value_string(dfw, node, jumps_ptr);
	}

	/* Create the new DFVM instruction */
	insn = dfvm_insn_new(DFVM_CALL_FUNCTION);
	val1 = dfvm_value_new_funcdef(func);
	insn->arg1 = dfvm_value_ref(val1);
	reg_val = dfvm_value_new_register(dfw->next_register++);
	insn->arg2 = dfvm_value_ref(reg_val);

	/* Create input arguments */
	params = sttype_function_params(node);
	ws_assert(params);
	count = 0;
	while (params) {
		val_arg = gen_entity(dfw, params->data, &params_jumps);
		/* If a parameter fails to generate jump here.
		 * Note: stack_push NULL register is valid. */
		g_slist_foreach(params_jumps, fixup_jumps, dfw);
		g_slist_free(params_jumps);
		params_jumps = NULL;
		dfw_append_stack_push(dfw, val_arg);
		count++;
		params = params->next;
	}
	val3 = dfvm_value_new_uint(count);
	insn->arg3 = dfvm_value_ref(val3);
	dfw_append_insn(dfw, insn);
	dfw_append_stack_pop(dfw, count);

	/* We need another instruction to jump to another exit
	 * place, if the call() of our function failed for some reason */
	insn = dfvm_insn_new(DFVM_IF_FALSE_GOTO);
	jmp = dfvm_value_new(INSN_NUMBER);
	insn->arg1 = dfvm_value_ref(jmp);
	dfw_append_insn(dfw, insn);
	*jumps_ptr = g_slist_prepend(*jumps_ptr, jmp);

	return reg_val;
}

/**
 * Adds an instruction for a relation operator where the values are already
 * loaded in registers.
 */
static void
gen_relation_insn(dfwork_t *dfw, dfvm_opcode_t op,
			dfvm_value_t *arg1, dfvm_value_t *arg2,
			dfvm_value_t *arg3)
{
	dfvm_insn_t	*insn;

	insn = dfvm_insn_new(op);
	insn->arg1 = dfvm_value_ref(arg1);
	insn->arg2 = dfvm_value_ref(arg2);
	insn->arg3 = dfvm_value_ref(arg3);
	dfw_append_insn(dfw, insn);
}

static void
gen_relation(dfwork_t *dfw, dfvm_opcode_t op, stmatch_t how,
					stnode_t *st_arg1, stnode_t *st_arg2)
{
	GSList		*jumps = NULL;
	dfvm_value_t	*val1, *val2;

	/* Create code for the LHS and RHS of the relation */
	val1 = gen_entity(dfw, st_arg1, &jumps);
	val2 = gen_entity(dfw, st_arg2, &jumps);

	/* Then combine them in a DFVM instruction */
	op = select_opcode(op, how);
	gen_relation_insn(dfw, op, val1, val2, NULL);

	/* If either of the relation arguments need an "exit" instruction
	 * to jump to (on failure), mark them */
	g_slist_foreach(jumps, fixup_jumps, dfw);
	g_slist_free(jumps);
	jumps = NULL;
}

static void
fixup_jumps(void *data, void *user_data)
{
	dfvm_value_t *jmp = (dfvm_value_t*)data;
	dfwork_t *dfw = (dfwork_t*)user_data;

	if (jmp) {
		jmp->value.numeric = dfw->next_insn_id;
	}
}

/* Generate the code for the in operator. Pushes set values into a stack
 * and then evaluates membership in a single instruction. */
static void
gen_relation_in(dfwork_t *dfw, dfvm_opcode_t op, stmatch_t how,
				stnode_t *st_arg1, stnode_t *st_arg2)
{
	dfvm_insn_t	*insn;
	GSList		*jumps = NULL;
	GSList		*node_jumps = NULL;
	dfvm_value_t	*val1, *val2, *val3;
	stnode_t	*node1, *node2;
	GSList		*nodelist_head, *nodelist;

	/* Create code for the LHS of the relation */
	val1 = gen_entity(dfw, st_arg1, &jumps);

	/* Create code to populate the set stack */
	nodelist_head = nodelist = stnode_steal_data(st_arg2);
	while (nodelist) {
		node1 = nodelist->data;
		nodelist = g_slist_next(nodelist);
		node2 = nodelist->data;
		nodelist = g_slist_next(nodelist);

		if (node2) {
			/* Range element. */
			val2 = gen_entity(dfw, node1, &node_jumps);
			val3 = gen_entity(dfw, node2, &node_jumps);
			dfw_append_set_add_range(dfw, val2, val3);
		} else {
			/* Normal element. */
			val2 = gen_entity(dfw, node1, &node_jumps);
			dfw_append_set_add(dfw, val2);
		}

		/* If an item is not present, just jump to the next item */
		g_slist_foreach(node_jumps, fixup_jumps, dfw);
		g_slist_free(node_jumps);
		node_jumps = NULL;
	}
	set_nodelist_free(nodelist_head);

	/* Create code for the set on the RHS of the relation */
	insn = dfvm_insn_new(select_opcode(op, how));
	insn->arg1 = dfvm_value_ref(val1);
	dfw_append_insn(dfw, insn);

	/* Add instruction to clear the whole stack */
	insn = dfvm_insn_new(DFVM_SET_CLEAR);
	dfw_append_insn(dfw, insn);

	/* Jump here if the LHS entity was not present */
	g_slist_foreach(jumps, fixup_jumps, dfw);
	g_slist_free(jumps);
	jumps = NULL;
}

static dfvm_value_t *
gen_arithmetic(dfwork_t *dfw, stnode_t *st_arg, GSList **jumps_ptr)
{
	stnode_t	*left, *right;
	stnode_op_t	st_op;
	dfvm_value_t	*reg_val, *val1, *val2 = NULL;
	dfvm_opcode_t	op = DFVM_NULL;

	sttype_oper_get(st_arg, &st_op, &left, &right);

	switch (st_op) {
		case STNODE_OP_UNARY_MINUS:	op = DFVM_UNARY_MINUS; break;
		case STNODE_OP_ADD:		op = DFVM_ADD; break;
		case STNODE_OP_SUBTRACT:	op = DFVM_SUBTRACT; break;
		case STNODE_OP_MULTIPLY:	op = DFVM_MULTIPLY; break;
		case STNODE_OP_DIVIDE:		op = DFVM_DIVIDE; break;
		case STNODE_OP_MODULO:		op = DFVM_MODULO; break;
		case STNODE_OP_BITWISE_AND:	op = DFVM_BITWISE_AND; break;

		/* fall-through */
		case STNODE_OP_NOT:
		case STNODE_OP_AND:
		case STNODE_OP_OR:
		case STNODE_OP_ALL_EQ:
		case STNODE_OP_ANY_EQ:
		case STNODE_OP_ALL_NE:
		case STNODE_OP_ANY_NE:
		case STNODE_OP_GT:
		case STNODE_OP_GE:
		case STNODE_OP_LT:
		case STNODE_OP_LE:
		case STNODE_OP_CONTAINS:
		case STNODE_OP_MATCHES:
		case STNODE_OP_IN:
		case STNODE_OP_NOT_IN:
		case STNODE_OP_UNINITIALIZED:
			ASSERT_STNODE_OP_NOT_REACHED(st_op);
	}

	val1 = gen_entity(dfw, left, jumps_ptr);
	if (right == NULL) {
		/* Generate unary DFVM instruction. */
		reg_val = dfvm_value_new_register(dfw->next_register++);
		gen_relation_insn(dfw, op, val1, reg_val, NULL);
		return reg_val;
	}

	val2 = gen_entity(dfw, right, jumps_ptr);
	reg_val = dfvm_value_new_register(dfw->next_register++);
	gen_relation_insn(dfw, op, val1, val2, reg_val);
	return reg_val;
}

/* Parse an entity, returning the reg that it gets put into.
 * p_jmp will be set if it has to be set by the calling code; it should
 * be set to the place to jump to, to return to the calling code,
 * if the load of a field from the proto_tree fails. */
static dfvm_value_t *
gen_entity(dfwork_t *dfw, stnode_t *st_arg, GSList **jumps_ptr)
{
	sttype_id_t       e_type;
	dfvm_value_t      *val;
	header_field_info *hfinfo;
	drange_t *range = NULL;
	bool raw;
	e_type = stnode_type_id(st_arg);

	if (e_type == STTYPE_FIELD) {
		hfinfo = sttype_field_hfinfo(st_arg);
		range = sttype_field_drange_steal(st_arg);
		raw = sttype_field_raw(st_arg);
		val = dfw_append_read_tree(dfw, hfinfo, range, raw);
		if (jumps_ptr != NULL) {
			*jumps_ptr = g_slist_prepend(*jumps_ptr, dfw_append_jump(dfw));
		}
		if (sttype_field_value_string(st_arg)) {
			val = dfw_append_mk_value_string(dfw, st_arg, val);
			if (jumps_ptr != NULL) {
				*jumps_ptr = g_slist_prepend(*jumps_ptr, dfw_append_jump(dfw));
			}
		}
	}
	else if (e_type == STTYPE_REFERENCE) {
		hfinfo = sttype_field_hfinfo(st_arg);
		range = sttype_field_drange_steal(st_arg);
		raw = sttype_field_raw(st_arg);
		val = dfw_append_read_reference(dfw, hfinfo, range, raw);
		if (jumps_ptr != NULL) {
			*jumps_ptr = g_slist_prepend(*jumps_ptr, dfw_append_jump(dfw));
		}
		if (sttype_field_value_string(st_arg)) {
			val = dfw_append_mk_value_string(dfw, st_arg, val);
			if (jumps_ptr != NULL) {
				*jumps_ptr = g_slist_prepend(*jumps_ptr, dfw_append_jump(dfw));
			}
		}
	}
	else if (e_type == STTYPE_FVALUE) {
		val = dfvm_value_new_fvalue(stnode_steal_data(st_arg));
	}
	else if (e_type == STTYPE_SLICE) {
		val = dfw_append_mk_slice(dfw, st_arg, jumps_ptr);
	}
	else if (e_type == STTYPE_FUNCTION) {
		val = dfw_append_function(dfw, st_arg, jumps_ptr);
	}
	else if (e_type == STTYPE_PCRE) {
		val = dfvm_value_new_pcre(stnode_steal_data(st_arg));
	}
	else if (e_type == STTYPE_ARITHMETIC) {
		val = gen_arithmetic(dfw, st_arg, jumps_ptr);
	}
	else {
		ws_error("Invalid sttype: %s", stnode_type_name(st_arg));
	}
	return val;
}

static void
gen_exists(dfwork_t *dfw, stnode_t *st_node)
{
	dfvm_insn_t *insn;
	dfvm_value_t *val1, *val2 = NULL;
	header_field_info *hfinfo;
	drange_t *range = NULL;

	hfinfo = sttype_field_hfinfo(st_node);
	range = sttype_field_drange_steal(st_node);

	/* Rewind to find the first field of this name. */
	while (hfinfo->same_name_prev_id != -1) {
		hfinfo = proto_registrar_get_nth(hfinfo->same_name_prev_id);
	}

	/* Ignore "rawness" for existence tests. */
	val1 = dfvm_value_new_hfinfo(hfinfo, false);
	if (range) {
		val2 = dfvm_value_new_drange(range);
	}

	if (val2) {
		insn = dfvm_insn_new(DFVM_CHECK_EXISTS_R);
		insn->arg1 = dfvm_value_ref(val1);
		insn->arg2 = dfvm_value_ref(val2);
	}
	else {
		insn = dfvm_insn_new(DFVM_CHECK_EXISTS);
		insn->arg1 = dfvm_value_ref(val1);
	}
	dfw_append_insn(dfw, insn);

	/* Record the FIELD_ID in hash of interesting fields. */
	while (hfinfo) {
		g_hash_table_add(dfw->interesting_fields, &hfinfo->id);
		hfinfo = hfinfo->same_name_next;
	}
}

static dfvm_value_t*
gen_field(dfwork_t *dfw, stnode_t *st_node)
{
	dfvm_value_t	*val1;
	GSList		*jumps = NULL;

	val1 = gen_entity(dfw, st_node, &jumps);
	g_slist_foreach(jumps, fixup_jumps, dfw);
	g_slist_free(jumps);
	return val1;
}

static dfvm_value_t*
gen_notzero(dfwork_t *dfw, stnode_t *st_node)
{
	dfvm_insn_t	*insn;
	dfvm_value_t	*val1;
	GSList		*jumps = NULL;

	val1 = gen_entity(dfw, st_node, &jumps);
	insn = dfvm_insn_new(DFVM_NOT_ALL_ZERO);
	insn->arg1 = dfvm_value_ref(val1);
	dfw_append_insn(dfw, insn);
	g_slist_foreach(jumps, fixup_jumps, dfw);
	g_slist_free(jumps);
	return val1;
}

static dfvm_value_t*
gen_notzero_slice(dfwork_t *dfw, stnode_t *st_node)
{
	dfvm_insn_t	*insn;
	dfvm_value_t	*val1, *reg_val;
	GSList		*jumps = NULL;

	val1 = gen_entity(dfw, st_node, &jumps);
	/* Compute length. */
	insn = dfvm_insn_new(DFVM_LENGTH);
	insn->arg1 = dfvm_value_ref(val1);
	reg_val = dfvm_value_new_register(dfw->next_register++);
	insn->arg2 = dfvm_value_ref(reg_val);
	dfw_append_insn(dfw, insn);
	/* Check length is not zero. */
	insn = dfvm_insn_new(DFVM_NOT_ALL_ZERO);
	insn->arg1 = dfvm_value_ref(reg_val);
	dfw_append_insn(dfw, insn);
	/* Fixup jumps. */
	g_slist_foreach(jumps, fixup_jumps, dfw);
	g_slist_free(jumps);
	return val1;
}

static void
gen_test(dfwork_t *dfw, stnode_t *st_node)
{
	stnode_op_t	st_op;
	stmatch_t	st_how;
	stnode_t	*st_arg1, *st_arg2;
	dfvm_insn_t	*insn;
	dfvm_value_t	*jmp;


	sttype_oper_get(st_node, &st_op, &st_arg1, &st_arg2);
	st_how = sttype_test_get_match(st_node);

	switch (st_op) {
		case STNODE_OP_NOT:
			gencode(dfw, st_arg1);
			insn = dfvm_insn_new(DFVM_NOT);
			dfw_append_insn(dfw, insn);
			break;

		case STNODE_OP_AND:
			gencode(dfw, st_arg1);

			insn = dfvm_insn_new(DFVM_IF_FALSE_GOTO);
			jmp = dfvm_value_new(INSN_NUMBER);
			insn->arg1 = dfvm_value_ref(jmp);
			dfw_append_insn(dfw, insn);

			gencode(dfw, st_arg2);
			jmp->value.numeric = dfw->next_insn_id;
			break;

		case STNODE_OP_OR:
			gencode(dfw, st_arg1);

			insn = dfvm_insn_new(DFVM_IF_TRUE_GOTO);
			jmp = dfvm_value_new(INSN_NUMBER);
			insn->arg1 = dfvm_value_ref(jmp);
			dfw_append_insn(dfw, insn);

			gencode(dfw, st_arg2);
			jmp->value.numeric = dfw->next_insn_id;
			break;

		case STNODE_OP_ALL_EQ:
			gen_relation(dfw, DFVM_ALL_EQ, st_how, st_arg1, st_arg2);
			break;

		case STNODE_OP_ANY_EQ:
			gen_relation(dfw, DFVM_ANY_EQ, st_how, st_arg1, st_arg2);
			break;

		case STNODE_OP_ALL_NE:
			gen_relation(dfw, DFVM_ALL_NE, st_how, st_arg1, st_arg2);
			break;

		case STNODE_OP_ANY_NE:
			gen_relation(dfw, DFVM_ANY_NE, st_how, st_arg1, st_arg2);
			break;

		case STNODE_OP_GT:
			gen_relation(dfw, DFVM_ANY_GT, st_how, st_arg1, st_arg2);
			break;

		case STNODE_OP_GE:
			gen_relation(dfw, DFVM_ANY_GE, st_how, st_arg1, st_arg2);
			break;

		case STNODE_OP_LT:
			gen_relation(dfw, DFVM_ANY_LT, st_how, st_arg1, st_arg2);
			break;

		case STNODE_OP_LE:
			gen_relation(dfw, DFVM_ANY_LE, st_how, st_arg1, st_arg2);
			break;

		case STNODE_OP_CONTAINS:
			gen_relation(dfw, DFVM_ANY_CONTAINS, st_how, st_arg1, st_arg2);
			break;

		case STNODE_OP_MATCHES:
			gen_relation(dfw, DFVM_ANY_MATCHES, st_how, st_arg1, st_arg2);
			break;

		case STNODE_OP_IN:
			gen_relation_in(dfw, DFVM_SET_ANY_IN, st_how, st_arg1, st_arg2);
			break;

		case STNODE_OP_NOT_IN:
			gen_relation_in(dfw, DFVM_SET_ANY_NOT_IN, st_how, st_arg1, st_arg2);
			break;

		case STNODE_OP_UNINITIALIZED:
		case STNODE_OP_BITWISE_AND:
		case STNODE_OP_UNARY_MINUS:
		case STNODE_OP_ADD:
		case STNODE_OP_SUBTRACT:
		case STNODE_OP_MULTIPLY:
		case STNODE_OP_DIVIDE:
		case STNODE_OP_MODULO:
			ASSERT_STNODE_OP_NOT_REACHED(st_op);
	}
}

static dfvm_value_t*
gencode(dfwork_t *dfw, stnode_t *st_node)
{
	dfvm_value_t* val = NULL;
	/* If the root of the tree is a field, load and return the
	 * values if we were asked to do so. If not, or anywhere
	 * other than the root, just test for existence.
	 */
	bool return_val = dfw->flags & DF_RETURN_VALUES;
	dfw->flags &= ~DF_RETURN_VALUES;
	switch (stnode_type_id(st_node)) {
		case STTYPE_TEST:
			gen_test(dfw, st_node);
			break;
		case STTYPE_FIELD:
			if (return_val) {
				val = gen_field(dfw, st_node);
			} else {
				gen_exists(dfw, st_node);
			}
			break;
		case STTYPE_ARITHMETIC:
		case STTYPE_FUNCTION:
			val = gen_notzero(dfw, st_node);
			break;
		case STTYPE_SLICE:
			val = gen_notzero_slice(dfw, st_node);
			break;
		default:
			ASSERT_STTYPE_NOT_REACHED(stnode_type_id(st_node));
	}
	return val;
}


static void
optimize(dfwork_t *dfw)
{
	int		id, id1, length;
	dfvm_insn_t	*insn, *insn1, *prev;
	dfvm_value_t	*arg1;

	length = dfw->insns->len;

	for (id = 0, prev = NULL; id < length; prev = insn, id++) {
		insn = (dfvm_insn_t	*)g_ptr_array_index(dfw->insns, id);
		arg1 = insn->arg1;
		if (insn->op == DFVM_IF_TRUE_GOTO || insn->op == DFVM_IF_FALSE_GOTO) {
			id1 = arg1->value.numeric;

			/* If the branch jumps to the next instruction replace it with a no-op. */
			if (id1 == id + 1) {
				dfvm_insn_replace_no_op(insn);
				continue;
			}

			/* Try to optimize branch jumps */
			dfvm_opcode_t revert = (insn->op == DFVM_IF_FALSE_GOTO) ? DFVM_IF_TRUE_GOTO : DFVM_IF_FALSE_GOTO;
			for (;;) {
				insn1 = (dfvm_insn_t*)g_ptr_array_index(dfw->insns, id1);
				if (insn1->op == revert) {
					/* Skip this one; it is always false and the branch is not taken */
					id1 = id1 +1;
					continue;
				}
				if (insn1->op == DFVM_READ_TREE && prev && prev->op == DFVM_READ_TREE &&
						prev->arg2->value.numeric == insn1->arg2->value.numeric) {
					/* Skip this one; hack if it's the same register it's the same field
					 * and it returns the same value */
					id1 = id1 +1;
					continue;
				}
				if (insn1->op == insn->op) {
					/* The branch jumps to the same branch instruction so
					 * coalesce the jumps */
					arg1 = insn1->arg1;
					id1 = arg1->value.numeric;
					continue;
				}
				/* Finished */
				arg1 = insn->arg1;
				arg1->value.numeric = id1;
				break;
			}
		}
	}
}

void
dfw_gencode(dfwork_t *dfw)
{
	dfw->insns = g_ptr_array_new();
	dfw->loaded_fields = g_hash_table_new(g_direct_hash, g_direct_equal);
	dfw->loaded_raw_fields = g_hash_table_new(g_direct_hash, g_direct_equal);
	dfw->interesting_fields = g_hash_table_new(g_int_hash, g_int_equal);
	dfvm_insn_t *insn = dfvm_insn_new(DFVM_RETURN);
	insn->arg1 = dfvm_value_ref(gencode(dfw, dfw->st_root));
	dfw_append_insn(dfw, insn);
	if (dfw->flags & DF_OPTIMIZE) {
		optimize(dfw);
	}
}


typedef struct {
	int i;
	int *fields;
} hash_key_iterator;

static void
get_hash_key(void *key, void *value _U_, void *user_data)
{
	int field_id = *(int *)key;
	hash_key_iterator *hki = (hash_key_iterator *)user_data;

	hki->fields[hki->i] = field_id;
	hki->i++;
}

int*
dfw_interesting_fields(dfwork_t *dfw, int *caller_num_fields)
{
	int num_fields = g_hash_table_size(dfw->interesting_fields);

	hash_key_iterator hki;

	if (num_fields == 0) {
		*caller_num_fields = 0;
		return NULL;
	}

	hki.fields = g_new(int, num_fields);
	hki.i = 0;

	g_hash_table_foreach(dfw->interesting_fields, get_hash_key, &hki);
	*caller_num_fields = num_fields;
	return hki.fields;
}

/*
 * Editor modelines  -  https://www.wireshark.org/tools/modelines.html
 *
 * Local variables:
 * c-basic-offset: 8
 * tab-width: 8
 * indent-tabs-mode: t
 * End:
 *
 * vi: set shiftwidth=8 tabstop=8 noexpandtab:
 * :indentSize=8:tabSize=8:noTabs=false:
 */
