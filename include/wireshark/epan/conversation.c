/* conversation.c
 * Routines for building lists of packets that are part of a "conversation"
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "config.h"

#include <string.h>

#include <glib.h>

#include <wiretap/wtap.h>

#include "packet.h"
#include "to_str.h"
#include "conversation.h"

// The conversation database is a map of maps that contain conversation_t's.
// Top-level map keys are strings that describe each conversation type.
// Second-level map keys are conversation_element_t arrays.
// {
//   "uint,endpoint": {
//     [ { type: CE_ADDR, addr_val: 10.20.30.40}, { type: CE_PORT, uint_val: 80 } ... ]: <conversation_t>
//     [ { type: CE_ADDR, addr_val: 1.1.1.1}, { type: CE_PORT, uint_val: 53 } ... ]: <conversation_t>
//   }
// }
// Instead of using strings as keys we could bit-shift conversation endpoint types
// into a uint64_t, e.g. 0x0000000102010200 for CE_ADDRESS,CE_PORT,CE_ADDRESS,CE_PORT,CE_CONVERSATION_TYPE.
// We could also use this to prepend a type+length indicator for element arrays.

/* define DEBUG_CONVERSATION for pretty debug printing */
/* #define DEBUG_CONVERSATION */
#include "conversation_debug.h"

#ifdef DEBUG_CONVERSATION
int _debug_conversation_indent;
#endif

/*
 * We could use an element list here, but this is effectively a parameter list
 * for find_conversation and is more compact.
 */
struct conversation_addr_port_endpoints {
    address addr1;
    address addr2;
    uint32_t port1;
    uint32_t port2;
    conversation_type ctype;
};

/* Element offsets for address+port conversations */
enum {
    ADDR1_IDX,
    PORT1_IDX,
    ADDR2_IDX,
    PORT2_IDX,
    ENDP_EXACT_IDX,
    EXACT_IDX_COUNT,
    ADDRS_IDX_COUNT = PORT2_IDX,
    PORT2_NO_ADDR2_IDX = ADDR2_IDX,
    ENDP_NO_ADDR2_IDX = PORT2_IDX,
    ENDP_NO_PORT2_IDX = PORT2_IDX,
    ENDP_NO_ADDR2_PORT2_IDX = ADDR2_IDX,
    NO_ADDR2_IDX_COUNT = ENDP_EXACT_IDX,
    NO_PORT2_IDX_COUNT = ENDP_EXACT_IDX,
    NO_ADDR2_PORT2_IDX_COUNT = PORT2_IDX,
    ENDP_NO_PORTS_IDX = ADDR2_IDX
};

/* Element offsets for the deinterlacer conversations */
enum {
    DEINTR_ADDR1_IDX,
    DEINTR_ADDR2_IDX,
    DEINTR_KEY1_IDX,
    DEINTR_KEY2_IDX,
    DEINTR_KEY3_IDX,
    DEINTR_ENDP_IDX
};

/* Element offsets for the deinterlaced conversations */
enum {
    DEINTD_ADDR1_IDX,
    DEINTD_ADDR2_IDX,
    DEINTD_PORT1_IDX,
    DEINTD_PORT2_IDX,
    DEINTD_ENDP_EXACT_IDX,
    DEINTD_EXACT_IDX_COUNT,
    DEINTD_ADDRS_IDX_COUNT = DEINTD_PORT2_IDX,
    DEINTD_ENDP_NO_PORTS_IDX = DEINTD_PORT1_IDX
};

/* Names for conversation_element_type values. */
static const char *type_names[] = {
    "endpoint",
    "address",
    "port",
    "string",
    "uint",
    "uint64",
    "int",
    "int64",
    "blob",
};

/*
 * Hash table of hash tables for conversations identified by element lists.
 */
static wmem_map_t *conversation_hashtable_element_list;

/*
 * Hash table for conversations based on addresses only
 */
static wmem_map_t *conversation_hashtable_exact_addr;

/*
 * Hash table for conversations with no wildcards.
 */
static wmem_map_t *conversation_hashtable_exact_addr_port;

/*
 * Hash table for conversations with one wildcard address.
 */
static wmem_map_t *conversation_hashtable_no_addr2;

/*
 * Hash table for conversations with one wildcard port.
 */
static wmem_map_t *conversation_hashtable_no_port2;

/*
 * Hash table for conversations with one wildcard address and port.
 */
static wmem_map_t *conversation_hashtable_no_addr2_or_port2;

/*
 * Hash table for conversations with a single unsigned ID number.
 */
static wmem_map_t *conversation_hashtable_id;

/*
 * Hash table for conversations with no wildcards, and an anchor
 */
static wmem_map_t *conversation_hashtable_exact_addr_port_anc = NULL;

/*
 * Hash table for conversations based on addresses only, and an anchor
 */
static wmem_map_t *conversation_hashtable_exact_addr_anc = NULL;

/*
 * Hash table for deinterlacing conversations (typically L1 or L2)
 */
static wmem_map_t *conversation_hashtable_deinterlacer = NULL;

static uint32_t new_index;

/*
 * Placeholder for address-less conversations.
 */
static address null_address_ = ADDRESS_INIT_NONE;


/* Element count including the terminating CE_CONVERSATION_TYPE */
#define MAX_CONVERSATION_ELEMENTS 8 // Arbitrary.
static size_t
conversation_element_count(conversation_element_t *elements)
{
    size_t count = 0;
    while (elements[count].type != CE_CONVERSATION_TYPE) {
        count++;
        DISSECTOR_ASSERT(count < MAX_CONVERSATION_ELEMENTS);
    }
    count++;
    // Keying on the endpoint type alone isn't very useful.
    DISSECTOR_ASSERT(count > 1);
    return count;
}

static conversation_type
conversation_get_key_type(conversation_element_t *elements)
{
    size_t count = 0;
    while (elements[count].type != CE_CONVERSATION_TYPE) {
        count++;
        DISSECTOR_ASSERT(count < MAX_CONVERSATION_ELEMENTS);
    }
    return elements[count].conversation_type_val;
}

/* Create a string based on element types. */
static char*
conversation_element_list_name(wmem_allocator_t *allocator, conversation_element_t *elements) {
    char *sep = "";
    wmem_strbuf_t *conv_hash_group = wmem_strbuf_new(allocator, "");
    size_t element_count = conversation_element_count(elements);
    for (size_t i = 0; i < element_count; i++) {
        conversation_element_t *cur_el = &elements[i];
        DISSECTOR_ASSERT(cur_el->type < array_length(type_names));
        wmem_strbuf_append_printf(conv_hash_group, "%s%s", sep, type_names[cur_el->type]);
        sep = ",";
    }
    return wmem_strbuf_finalize(conv_hash_group);
}

#if 0 // debugging
static char* conversation_element_list_values(conversation_element_t *elements) {
    char *sep = "";
    GString *value_str = g_string_new("");
    size_t element_count = conversation_element_count(elements);
    for (size_t i = 0; i < element_count; i++) {
        conversation_element_t *cur_el = &elements[i];
        g_string_append_printf(value_str, "%s%s=", sep, type_names[cur_el->type]);
        sep = ",";
        switch (cur_el->type) {
        case CE_CONVERSATION_TYPE:
            g_string_append_printf(value_str, "%d", cur_el->conversation_type_val);
            break;
        case CE_ADDRESS:
        {
            char *as = address_to_str(NULL, &cur_el->addr_val);
            g_string_append(value_str, as);
            g_free(as);
        }
            break;
        case CE_PORT:
            g_string_append_printf(value_str, "%u", cur_el->port_val);
            break;
        case CE_STRING:
            g_string_append(value_str, cur_el->str_val);
            break;
        case CE_UINT:
            g_string_append_printf(value_str, "%u", cur_el->uint_val);
            break;
        case CE_UINT64:
            g_string_append_printf(value_str, "%" PRIu64, cur_el->uint64_val);
            break;
        case CE_INT:
            g_string_append_printf(value_str, "%d", cur_el->int_val);
            break;
        case CE_INT64:
            g_string_append_printf(value_str, "%" PRId64, cur_el->int64_val);
            break;
        case CE_BLOB:
        {
            size_t l;
            uint8_t const *p;
            for (l = cur_el->blob.len, p = cur_el->blob.val; l > 0; l--, p++)
                g_string_append_printf(value_str, "%02x", *p);
        }
            break;
        }
    }
    return g_string_free(value_str, FALSE);
}
#endif

static bool
is_no_addr2_key(conversation_element_t *key)
{
    if (key[ADDR1_IDX].type == CE_ADDRESS && key[PORT1_IDX].type == CE_PORT
            && key[PORT2_NO_ADDR2_IDX].type == CE_PORT && key[ENDP_NO_ADDR2_IDX].type == CE_CONVERSATION_TYPE) {
        return true;
    }
    return false;
}

static bool
is_no_port2_key(conversation_element_t *key)
{
    if (key[ADDR1_IDX].type == CE_ADDRESS && key[PORT1_IDX].type == CE_PORT
            && key[ADDR2_IDX].type == CE_ADDRESS && key[ENDP_NO_PORT2_IDX].type == CE_CONVERSATION_TYPE) {
        return true;
    }
    return false;
}

static bool
is_no_addr2_port2_key(conversation_element_t *key)
{
    if (key[ADDR1_IDX].type == CE_ADDRESS && key[PORT1_IDX].type == CE_PORT
            && key[ENDP_NO_ADDR2_PORT2_IDX].type == CE_CONVERSATION_TYPE) {
        return true;
    }
    return false;
}

/*
 * Creates a new conversation with known endpoints based on a conversation
 * created with the CONVERSATION_TEMPLATE option while keeping the
 * conversation created with the CONVERSATION_TEMPLATE option so it can still
 * match future connections.
 *
 * Passing a pointer to a conversation whose options mask does not include
 * CONVERSATION_TEMPLATE or where the conversation's protocol type (ptype)
 * indicates a non-connnection oriented protocol will return the conversation
 * without changes.
 *
 * addr2 and port2 are used in the function if their respective conversation
 * options bits are set (NO_ADDR2 and NO_PORT2).
 */
static conversation_t *
conversation_create_from_template(conversation_t *conversation, const address *addr2, const uint32_t port2)
{
    conversation_type ctype = conversation_get_key_type(conversation->key_ptr);
    /*
     * Add a new conversation and keep the conversation template only if the
     * CONVERSATION_TEMPLATE bit is set for a connection oriented protocol.
     */
    if (conversation->options & CONVERSATION_TEMPLATE && ctype != CONVERSATION_UDP)
    {
        /*
         * Set up a new options mask where the conversation template bit and the
         * bits for absence of a second address and port pair have been removed.
         */
        conversation_t *new_conversation_from_template;
        unsigned options = conversation->options & ~(CONVERSATION_TEMPLATE | NO_ADDR2 | NO_PORT2);

        /*
         * Are both the NO_ADDR2 and NO_PORT2 wildcards set in the options mask?
         */
        if (conversation->options & NO_ADDR2 && conversation->options & NO_PORT2
                && is_no_addr2_port2_key(conversation->key_ptr))
        {
            /*
             * The conversation template was created without knowledge of both
             * the second address as well as the second port. Create a new
             * conversation with new 2nd address and 2nd port.
             */
            new_conversation_from_template =
                conversation_new(conversation->setup_frame,
                        &conversation->key_ptr[ADDR1_IDX].addr_val, addr2,
                        ctype, conversation->key_ptr[PORT1_IDX].port_val,
                        port2, options);
        }
        else if (conversation->options & NO_PORT2 && is_no_port2_key(conversation->key_ptr))
        {
            /*
             * The conversation template was created without knowledge of port 2
             * only. Create a new conversation with new 2nd port.
             */
            new_conversation_from_template =
                conversation_new(conversation->setup_frame,
                        &conversation->key_ptr[ADDR1_IDX].addr_val, &conversation->key_ptr[ADDR2_IDX].addr_val,
                        ctype, conversation->key_ptr[PORT1_IDX].port_val,
                        port2, options);
        }
        else if (conversation->options & NO_ADDR2 && is_no_addr2_key(conversation->key_ptr))
        {
            /*
             * The conversation template was created without knowledge of address
             * 2. Create a new conversation with new 2nd address.
             */
            new_conversation_from_template =
                conversation_new(conversation->setup_frame,
                        &conversation->key_ptr[ADDR1_IDX].addr_val, addr2,
                        ctype, conversation->key_ptr[PORT1_IDX].port_val,
                        conversation->key_ptr[PORT2_NO_ADDR2_IDX].port_val, options);
        }
        else
        {
            /*
             * The CONVERSATION_TEMPLATE bit was set, but no other bit that the
             * CONVERSATION_TEMPLATE bit controls is active. Just return the old
             * conversation.
             */
            return conversation;
        }

        /*
         * Set the protocol dissector used for the template conversation as
         * the handler of the new conversation as well.
         */
        new_conversation_from_template->dissector_tree = conversation->dissector_tree;

        return new_conversation_from_template;
    }
    else
    {
        return conversation;
    }
}

/*
 * Compute the hash value for two given element lists if the match
 * is to be exact.
 */
/* https://web.archive.org/web/20070615045827/http://eternallyconfuzzled.com/tuts/algorithms/jsw_tut_hashing.aspx#existing
 * (formerly at http://eternallyconfuzzled.com/tuts/algorithms/jsw_tut_hashing.aspx#existing)
 * One-at-a-Time hash
 */
static unsigned
conversation_hash_element_list(const void *v)
{
    const conversation_element_t *element = (const conversation_element_t*)v;
    unsigned hash_val = 0;

    for (;;) {
        // XXX We could use a hash_arbitrary_bytes routine. Abuse add_address_to_hash in the mean time.
        address tmp_addr;
        switch (element->type) {
        case CE_ADDRESS:
            hash_val = add_address_to_hash(hash_val, &element->addr_val);
            break;
        case CE_PORT:
            tmp_addr.len = (int) sizeof(element->port_val);
            tmp_addr.data = &element->port_val;
            hash_val = add_address_to_hash(hash_val, &tmp_addr);
            break;
        case CE_STRING:
            tmp_addr.len = (int) strlen(element->str_val);
            tmp_addr.data = element->str_val;
            hash_val = add_address_to_hash(hash_val, &tmp_addr);
            break;
        case CE_UINT:
            tmp_addr.len = (int) sizeof(element->uint_val);
            tmp_addr.data = &element->uint_val;
            hash_val = add_address_to_hash(hash_val, &tmp_addr);
            break;
        case CE_UINT64:
            tmp_addr.len = (int) sizeof(element->uint64_val);
            tmp_addr.data = &element->uint64_val;
            hash_val = add_address_to_hash(hash_val, &tmp_addr);
            break;
        case CE_INT:
            tmp_addr.len = (int) sizeof(element->int_val);
            tmp_addr.data = &element->int_val;
            hash_val = add_address_to_hash(hash_val, &tmp_addr);
            break;
        case CE_INT64:
            tmp_addr.len = (int) sizeof(element->int64_val);
            tmp_addr.data = &element->int64_val;
            hash_val = add_address_to_hash(hash_val, &tmp_addr);
            break;
        case CE_BLOB:
            tmp_addr.len = (int) element->blob.len;
            tmp_addr.data = element->blob.val;
            hash_val = add_address_to_hash(hash_val, &tmp_addr);
            break;
        case CE_CONVERSATION_TYPE:
            tmp_addr.len = (int) sizeof(element->conversation_type_val);
            tmp_addr.data = &element->conversation_type_val;
            hash_val = add_address_to_hash(hash_val, &tmp_addr);
            goto done;
            break;
        }
        element++;
    }

done:
    hash_val += ( hash_val << 3 );
    hash_val ^= ( hash_val >> 11 );
    hash_val += ( hash_val << 15 );

    return hash_val;
}

/*
 * Compare two conversation keys for an exact match.
 */
static gboolean
conversation_match_element_list(const void *v1, const void *v2)
{
    const conversation_element_t *element1 = (const conversation_element_t*)v1;
    const conversation_element_t *element2 = (const conversation_element_t*)v2;

    for (;;) {
        if (element1->type != element2->type) {
            return FALSE;
        }

        switch (element1->type) {
        case CE_ADDRESS:
            if (!addresses_equal(&element1->addr_val, &element2->addr_val)) {
                return FALSE;
            }
            break;
        case CE_PORT:
            if (element1->port_val != element2->port_val) {
                return FALSE;
            }
            break;
        case CE_STRING:
            if (strcmp(element1->str_val, element2->str_val)) {
                return FALSE;
            }
            break;
        case CE_UINT:
            if (element1->uint_val != element2->uint_val) {
                return FALSE;
            }
            break;
        case CE_UINT64:
            if (element1->uint64_val != element2->uint64_val) {
                return FALSE;
            }
            break;
        case CE_INT:
            if (element1->int_val != element2->int_val) {
                return FALSE;
            }
            break;
        case CE_INT64:
            if (element1->int64_val != element2->int64_val) {
                return FALSE;
            }
            break;
        case CE_BLOB:
            if (element1->blob.len != element2->blob.len ||
                (element1->blob.len > 0 && memcmp(element1->blob.val, element2->blob.val, element1->blob.len) != 0)) {
                return FALSE;
            }
            break;
        case CE_CONVERSATION_TYPE:
            if (element1->conversation_type_val != element2->conversation_type_val) {
                return FALSE;
            }
            goto done;
            break;
        }
        element1++;
        element2++;
    }

    done:
    // Everything matched so far.
    return TRUE;
}

/**
 * Create a new hash tables for conversations.
 */
void
conversation_init(void)
{
    /*
     * Free up any space allocated for conversation protocol data
     * areas.
     *
     * We can free the space, as the structures it contains are
     * pointed to by conversation data structures that were freed
     * above.
     */
    conversation_hashtable_element_list = wmem_map_new(wmem_epan_scope(), wmem_str_hash, g_str_equal);

    conversation_element_t exact_elements[EXACT_IDX_COUNT] = {
        { CE_ADDRESS, .addr_val = ADDRESS_INIT_NONE },
        { CE_PORT, .port_val = 0 },
        { CE_ADDRESS, .addr_val = ADDRESS_INIT_NONE },
        { CE_PORT, .port_val = 0 },
        { CE_CONVERSATION_TYPE, .conversation_type_val = CONVERSATION_NONE }
    };
    char *exact_map_key = conversation_element_list_name(wmem_epan_scope(), exact_elements);
    conversation_hashtable_exact_addr_port = wmem_map_new_autoreset(wmem_epan_scope(), wmem_file_scope(),
                                                                    conversation_hash_element_list,
                                                                    conversation_match_element_list);
    wmem_map_insert(conversation_hashtable_element_list, wmem_strdup(wmem_epan_scope(), exact_map_key),
                    conversation_hashtable_exact_addr_port);

    conversation_element_t addrs_elements[ADDRS_IDX_COUNT] = {
        { CE_ADDRESS, .addr_val = ADDRESS_INIT_NONE },
        { CE_ADDRESS, .addr_val = ADDRESS_INIT_NONE },
        { CE_CONVERSATION_TYPE, .conversation_type_val = CONVERSATION_NONE }
    };
    char *addrs_map_key = conversation_element_list_name(wmem_epan_scope(), addrs_elements);
    conversation_hashtable_exact_addr = wmem_map_new_autoreset(wmem_epan_scope(), wmem_file_scope(),
                                                                    conversation_hash_element_list,
                                                                    conversation_match_element_list);
    wmem_map_insert(conversation_hashtable_element_list, wmem_strdup(wmem_epan_scope(), addrs_map_key),
                    conversation_hashtable_exact_addr);

    conversation_element_t no_addr2_elements[NO_ADDR2_IDX_COUNT] = {
        { CE_ADDRESS, .addr_val = ADDRESS_INIT_NONE },
        { CE_PORT, .port_val = 0 },
        { CE_PORT, .port_val = 0 },
        { CE_CONVERSATION_TYPE, .conversation_type_val = CONVERSATION_NONE }
    };
    char *no_addr2_map_key = conversation_element_list_name(wmem_epan_scope(), no_addr2_elements);
    conversation_hashtable_no_addr2 = wmem_map_new_autoreset(wmem_epan_scope(), wmem_file_scope(),
                                                       conversation_hash_element_list,
                                                       conversation_match_element_list);
    wmem_map_insert(conversation_hashtable_element_list, wmem_strdup(wmem_epan_scope(), no_addr2_map_key),
                    conversation_hashtable_no_addr2);

    conversation_element_t no_port2_elements[NO_PORT2_IDX_COUNT] = {
        { CE_ADDRESS, .addr_val = ADDRESS_INIT_NONE },
        { CE_PORT, .port_val = 0 },
        { CE_ADDRESS, .addr_val = ADDRESS_INIT_NONE },
        { CE_CONVERSATION_TYPE, .conversation_type_val = CONVERSATION_NONE }
    };
    char *no_port2_map_key = conversation_element_list_name(wmem_epan_scope(), no_port2_elements);
    conversation_hashtable_no_port2 = wmem_map_new_autoreset(wmem_epan_scope(), wmem_file_scope(),
                                                       conversation_hash_element_list,
                                                       conversation_match_element_list);
    wmem_map_insert(conversation_hashtable_element_list, wmem_strdup(wmem_epan_scope(), no_port2_map_key),
                    conversation_hashtable_no_port2);

    conversation_element_t no_addr2_or_port2_elements[NO_ADDR2_PORT2_IDX_COUNT] = {
        { CE_ADDRESS, .addr_val = ADDRESS_INIT_NONE },
        { CE_PORT, .port_val = 0 },
        { CE_CONVERSATION_TYPE, .conversation_type_val = CONVERSATION_NONE }
    };
    char *no_addr2_or_port2_map_key = conversation_element_list_name(wmem_epan_scope(), no_addr2_or_port2_elements);
    conversation_hashtable_no_addr2_or_port2 = wmem_map_new_autoreset(wmem_epan_scope(), wmem_file_scope(),
                                                                    conversation_hash_element_list,
                                                                    conversation_match_element_list);
    wmem_map_insert(conversation_hashtable_element_list, wmem_strdup(wmem_epan_scope(), no_addr2_or_port2_map_key),
                    conversation_hashtable_no_addr2_or_port2);

    conversation_element_t id_elements[2] = {
        { CE_UINT, .uint_val = 0 },
        { CE_CONVERSATION_TYPE, .conversation_type_val = CONVERSATION_NONE }
    };
    char *id_map_key = conversation_element_list_name(wmem_epan_scope(), id_elements);
    conversation_hashtable_id = wmem_map_new_autoreset(wmem_epan_scope(), wmem_file_scope(),
                                                       conversation_hash_element_list,
                                                       conversation_match_element_list);
    wmem_map_insert(conversation_hashtable_element_list, wmem_strdup(wmem_epan_scope(), id_map_key),
                    conversation_hashtable_id);

    /*
     * Initialize the "deinterlacer" table, which is used as the basis for the
     * deinterlacing process, and in conjunction with the "anchor" tables
     *
     * Typically the elements are:
     *   ETH address 1
     *   ETH address 2
     *   Interface id
     *   VLAN id
     *   not used yet
     *
     * By the time of implementation, these table is invoked through the
     * conversation_deinterlacing_key user preference.
     */
    conversation_element_t deinterlacer_elements[EXACT_IDX_COUNT+1] = {
        { CE_ADDRESS, .addr_val = ADDRESS_INIT_NONE },
        { CE_ADDRESS, .addr_val = ADDRESS_INIT_NONE },
        { CE_UINT, .port_val = 0 },
        { CE_UINT, .port_val = 0 },
        { CE_UINT, .uint_val = 0 },
        { CE_CONVERSATION_TYPE, .conversation_type_val = CONVERSATION_NONE }
    };
    char *deinterlacer_map_key = conversation_element_list_name(wmem_epan_scope(), deinterlacer_elements);
    conversation_hashtable_deinterlacer = wmem_map_new_autoreset(wmem_epan_scope(), wmem_file_scope(),
                                                                    conversation_hash_element_list,
                                                                    conversation_match_element_list);
    wmem_map_insert(conversation_hashtable_element_list, wmem_strdup(wmem_epan_scope(), deinterlacer_map_key),
                    conversation_hashtable_deinterlacer);

    /*
     * Initialize the "_anc" tables, which are very similar to their standard counterparts
     * but contain an additional "anchor" materialized as an integer. This value is supposed
     * to indicate a stream ID of the underlying protocol, thus attaching two conversations
     * of two protocols together.
     *
     * By the time of implementation, these table is invoked through the
     * conversation_deinterlacing_key user preference.
     */
    conversation_element_t exact_elements_anc[EXACT_IDX_COUNT+1] = {
        { CE_ADDRESS, .addr_val = ADDRESS_INIT_NONE },
        { CE_ADDRESS, .addr_val = ADDRESS_INIT_NONE },
        { CE_PORT, .port_val = 0 },
        { CE_PORT, .port_val = 0 },
        { CE_UINT, .uint_val = 0 },
        { CE_CONVERSATION_TYPE, .conversation_type_val = CONVERSATION_NONE }
    };
    char *exact_anc_map_key = conversation_element_list_name(wmem_epan_scope(), exact_elements_anc);
    conversation_hashtable_exact_addr_port_anc = wmem_map_new_autoreset(wmem_epan_scope(), wmem_file_scope(),
                                                                    conversation_hash_element_list,
                                                                    conversation_match_element_list);
    wmem_map_insert(conversation_hashtable_element_list, wmem_strdup(wmem_epan_scope(), exact_anc_map_key),
                    conversation_hashtable_exact_addr_port_anc);

    conversation_element_t addrs_elements_anc[ADDRS_IDX_COUNT+1] = {
        { CE_ADDRESS, .addr_val = ADDRESS_INIT_NONE },
        { CE_ADDRESS, .addr_val = ADDRESS_INIT_NONE },
        { CE_UINT, .uint_val = 0 },
        { CE_CONVERSATION_TYPE, .conversation_type_val = CONVERSATION_NONE }
    };
    char *addrs_anc_map_key = conversation_element_list_name(wmem_epan_scope(), addrs_elements_anc);
    conversation_hashtable_exact_addr_anc = wmem_map_new_autoreset(wmem_epan_scope(), wmem_file_scope(),
                                                                    conversation_hash_element_list,
                                                                    conversation_match_element_list);
    wmem_map_insert(conversation_hashtable_element_list, wmem_strdup(wmem_epan_scope(), addrs_anc_map_key),
                    conversation_hashtable_exact_addr_anc);

}

/**
 * Initialize some variables every time a file is loaded or re-loaded.
 */
void
conversation_epan_reset(void)
{
    /*
     * Start the conversation indices over at 0.
     */
    new_index = 0;
}

/*
 * Does the right thing when inserting into one of the conversation hash tables,
 * taking into account ordering and hash chains and all that good stuff.
 *
 * Mostly adapted from the old conversation_new().
 */
static void
conversation_insert_into_hashtable(wmem_map_t *hashtable, conversation_t *conv)
{
    conversation_t *chain_head, *chain_tail, *cur, *prev;

    chain_head = (conversation_t *)wmem_map_lookup(hashtable, conv->key_ptr);

    if (NULL==chain_head) {
        /* New entry */
        conv->next = NULL;
        conv->last = conv;

        wmem_map_insert(hashtable, conv->key_ptr, conv);
        DPRINT(("created a new conversation chain"));
    }
    else {
        /* There's an existing chain for this key */
        DPRINT(("there's an existing conversation chain"));

        chain_tail = chain_head->last;

        if (conv->setup_frame >= chain_tail->setup_frame) {
            /* This convo belongs at the end of the chain */
            conv->next = NULL;
            conv->last = NULL;
            chain_tail->next = conv;
            chain_head->last = conv;
        }
        else {
            /* Loop through the chain to find the right spot */
            cur = chain_head;
            prev = NULL;

            for (; (conv->setup_frame > cur->setup_frame) && cur->next; prev=cur, cur=cur->next)
                ;

            if (NULL==prev) {
                /* Changing the head of the chain */
                conv->next = chain_head;
                conv->last = chain_tail;
                chain_head->last = NULL;
                wmem_map_insert(hashtable, conv->key_ptr, conv);
            }
            else {
                /* Inserting into the middle of the chain */
                conv->next = cur;
                conv->last = NULL;
                prev->next = conv;
            }
        }
    }
}

/*
 * Does the right thing when removing from one of the conversation hash tables,
 * taking into account ordering and hash chains and all that good stuff.
 */
static void
conversation_remove_from_hashtable(wmem_map_t *hashtable, conversation_t *conv)
{
    conversation_t *chain_head, *cur, *prev;

    chain_head = (conversation_t *)wmem_map_lookup(hashtable, conv->key_ptr);

    if (conv == chain_head) {
        /* We are currently the front of the chain */
        if (NULL == conv->next) {
            /* We are the only conversation in the chain, no need to
             * update next pointer, but do not call
             * wmem_map_remove() either because the conv data
             * will be re-inserted. */
            wmem_map_steal(hashtable, conv->key_ptr);
        }
        else {
            /* Update the head of the chain */
            chain_head = conv->next;
            chain_head->last = conv->last;

            if (conv->latest_found == conv)
                chain_head->latest_found = NULL;
            else
                chain_head->latest_found = conv->latest_found;

            wmem_map_insert(hashtable, chain_head->key_ptr, chain_head);
        }
    }
    else {
        /* We are not the front of the chain. Loop through to find us.
         * Start loop at chain_head->next rather than chain_head because
         * we already know we're not at the head. */
        cur = chain_head->next;
        prev = chain_head;

        for (; (cur != conv) && cur->next; prev=cur, cur=cur->next)
            ;

        if (cur != conv) {
            /* XXX: Conversation not found. Wrong hashtable? */
            return;
        }

        prev->next = conv->next;

        if (NULL == conv->next) {
            /* We're at the very end of the list. */
            chain_head->last = prev;
        }

        if (chain_head->latest_found == conv)
            chain_head->latest_found = prev;
    }
}

conversation_t *conversation_new_full(const uint32_t setup_frame, conversation_element_t *elements)
{
    DISSECTOR_ASSERT(elements);

    char *el_list_map_key = conversation_element_list_name(wmem_epan_scope(), elements);
    wmem_map_t *el_list_map = (wmem_map_t *) wmem_map_lookup(conversation_hashtable_element_list, el_list_map_key);
    if (!el_list_map) {
        el_list_map = wmem_map_new_autoreset(wmem_epan_scope(), wmem_file_scope(), conversation_hash_element_list,
                conversation_match_element_list);
        wmem_map_insert(conversation_hashtable_element_list, wmem_strdup(wmem_epan_scope(), el_list_map_key), el_list_map);
    }

    size_t element_count = conversation_element_count(elements);
    conversation_element_t *conv_key = wmem_memdup(wmem_file_scope(), elements, sizeof(conversation_element_t) * element_count);
    for (size_t i = 0; i < element_count; i++) {
        if (conv_key[i].type == CE_ADDRESS) {
            copy_address_wmem(wmem_file_scope(), &conv_key[i].addr_val, &elements[i].addr_val);
        } else if (conv_key[i].type == CE_STRING) {
            conv_key[i].str_val = wmem_strdup(wmem_file_scope(), elements[i].str_val);
        } else if (conv_key[i].type == CE_BLOB) {
            conv_key[i].blob.val = wmem_memdup(wmem_file_scope(), elements[i].blob.val, elements[i].blob.len);
        }
    }

    conversation_t *conversation = wmem_new0(wmem_file_scope(), conversation_t);
    conversation->conv_index = new_index;
    conversation->setup_frame = conversation->last_frame = setup_frame;

    new_index++;

    conversation->key_ptr = conv_key;
    conversation_insert_into_hashtable(el_list_map, conversation);
    return conversation;
}

/*
 * Given two address/port pairs for a packet, create a new conversation
 * to contain packets between those address/port pairs.
 *
 * The options field is used to specify whether the address 2 value
 * and/or port 2 value are not given and any value is acceptable
 * when searching for this conversation.
 */
conversation_t *
conversation_new(const uint32_t setup_frame, const address *addr1, const address *addr2,
        const conversation_type ctype, const uint32_t port1, const uint32_t port2, const unsigned options)
{
    /*
       DISSECTOR_ASSERT(!(options | CONVERSATION_TEMPLATE) || ((options | (NO_ADDR2 | NO_PORT2 | NO_PORT2_FORCE))) &&
       "A conversation template may not be constructed without wildcard options");
     */
    wmem_map_t* hashtable;
    conversation_t *conversation = NULL;
    /*
     * Verify that the correct options are used, if any.
     */
    DISSECTOR_ASSERT_HINT(!(options & NO_MASK_B), "Use NO_ADDR2 and/or NO_PORT2 or NO_PORT2_FORCE as option");

#ifdef DEBUG_CONVERSATION
    char *addr1_str, *addr2_str;
    if (addr1 == NULL) {
        /*
         * No address 1.
         */
        if (options & NO_ADDR2) {
            /*
             * Neither address 1 nor address 2.
             */
            if (options & NO_PORT2) {
                /*
                 * Port 1 but not port 2.
                 */
                DPRINT(("creating conversation for frame #%u: ID %u (ctype=%d)",
                            setup_frame, port1, ctype));
            } else {
                /*
                 * Ports 1 and 2.
                 */
                DPRINT(("creating conversation for frame #%u: %u -> %u (ctype=%d)",
                            setup_frame, port1, port2, ctype));
            }
        } else {
            /*
             * Address 2 but not address 1.
             */
            addr2_str = address_to_str(NULL, addr2);
            if (options & NO_PORT2) {
                /*
                 * Port 1 but not port 2.
                 */
                DPRINT(("creating conversation for frame #%u: ID %u, address %s (ctype=%d)",
                            setup_frame, port1, addr2_str, ctype));
            } else {
                /*
                 * Ports 1 and 2.
                 */
                DPRINT(("creating conversation for frame #%u: %u -> %s:%u (ctype=%d)",
                            setup_frame, port1, addr2_str, port2, ctype));
            }
            wmem_free(NULL, addr2_str);
        }
    } else {
        /*
         * Address 1.
         */
        addr1_str = address_to_str(NULL, addr1);
        if (options & NO_ADDR2) {
            /*
             * Address 1 but no address 2.
             */
            if (options & NO_PORT2) {
                /*
                 * Port 1 but not port 2.
                 */
                DPRINT(("creating conversation for frame #%u: %s:%u (ctype=%d)",
                            setup_frame, addr1_str, port1, ctype));
            } else {
                /*
                 * Ports 1 and 2.
                 */
                DPRINT(("creating conversation for frame #%u: %s:%u -> %u (ctype=%d)",
                            setup_frame, addr1_str, port1, port2, ctype));
            }
        } else {
            /*
             * Addresses 1 and 2.
             */
            addr2_str = address_to_str(NULL, addr2);
            if (options & NO_PORT2) {
                /*
                 * Port 1 but not port 2.
                 */
                DPRINT(("creating conversation for frame #%u: %s:%u -> %s (ctype=%d)",
                            setup_frame, addr1_str, port1, addr2_str, ctype));
            } else if (options & NO_PORTS) {
                /*
                 * No Ports.
                 */
                DPRINT(("creating conversation for frame #%u: %s -> %s (ctype=%d)",
                            setup_frame, addr1_str, addr2_str, ctype));
            } else {
                /*
                 * Ports 1 and 2.
                 */
                DPRINT(("creating conversation for frame #%u: %s:%u -> %s:%u (ctype=%d)",
                            setup_frame, addr1_str, port1, addr2_str, port2, ctype));
            }
            wmem_free(NULL, addr2_str);
        }
        wmem_free(NULL, addr1_str);
    }
#endif

    // Always allocate an "exact"-sized key in case we call conversation_set_port2
    // or conversation_set_addr2 later.
    conversation_element_t *new_key = wmem_alloc(wmem_file_scope(), sizeof(conversation_element_t) * EXACT_IDX_COUNT);
    size_t addr2_idx = 0;
    size_t port2_idx = 0;
    size_t endp_idx;

    new_key[ADDR1_IDX].type = CE_ADDRESS;
    if (addr1 != NULL) {
        copy_address_wmem(wmem_file_scope(), &new_key[ADDR1_IDX].addr_val, addr1);
    } else {
        clear_address(&new_key[ADDR1_IDX].addr_val);
    }

    if (!(options & NO_PORTS)) {
        new_key[PORT1_IDX].type = CE_PORT;
        new_key[PORT1_IDX].port_val = port1;
    }

    if (options & NO_ADDR2) {
        if (options & (NO_PORT2|NO_PORT2_FORCE)) {
            hashtable = conversation_hashtable_no_addr2_or_port2;
            endp_idx = ENDP_NO_ADDR2_PORT2_IDX;
        } else {
            hashtable = conversation_hashtable_no_addr2;
            port2_idx = PORT2_NO_ADDR2_IDX;
            endp_idx = ENDP_NO_ADDR2_IDX;
        }
    } else {
        if (options & (NO_PORT2|NO_PORT2_FORCE)) {
            hashtable = conversation_hashtable_no_port2;
            addr2_idx = ADDR2_IDX;
            endp_idx = ENDP_NO_PORT2_IDX;
        } else if (options & NO_PORTS) {
            hashtable = conversation_hashtable_exact_addr;
            addr2_idx = PORT1_IDX;
            endp_idx = ENDP_NO_PORTS_IDX;
        } else {
            hashtable = conversation_hashtable_exact_addr_port;
            addr2_idx = ADDR2_IDX;
            port2_idx = PORT2_IDX;
            endp_idx = ENDP_EXACT_IDX;
        }
    }

    if (addr2_idx) {
        new_key[addr2_idx].type = CE_ADDRESS;
        if (addr2 != NULL) {
            copy_address_wmem(wmem_file_scope(), &new_key[addr2_idx].addr_val, addr2);
        } else {
            clear_address(&new_key[addr2_idx].addr_val);
        }
    }

    if (port2_idx) {
        new_key[port2_idx].type = CE_PORT;
        new_key[port2_idx].port_val = port2;
    }

    new_key[endp_idx].type = CE_CONVERSATION_TYPE;
    new_key[endp_idx].conversation_type_val = ctype;

    conversation = wmem_new0(wmem_file_scope(), conversation_t);

    conversation->conv_index = new_index;
    conversation->setup_frame = conversation->last_frame = setup_frame;

    /* set the options and key pointer */
    conversation->options = options;
    conversation->key_ptr = new_key;

    new_index++;

    DINDENT();
    conversation_insert_into_hashtable(hashtable, conversation);
    DENDENT();

    return conversation;
}

conversation_t *
conversation_new_strat(packet_info *pinfo, const conversation_type ctype, const unsigned options)
{
    conversation_t *conversation = NULL;
    bool is_ordinary_conv = true;

    if(prefs.conversation_deinterlacing_key>0) {
        conversation_t *underlying_conv = find_conversation_deinterlacer_pinfo(pinfo);
        if(underlying_conv) {
            is_ordinary_conv = false;
            conversation = conversation_new_deinterlaced(pinfo->num, &pinfo->src, &pinfo->dst, ctype,
                                        pinfo->srcport, pinfo->destport, underlying_conv->conv_index, options);
        }
    }

    if(is_ordinary_conv) {
        conversation = conversation_new(pinfo->num, &pinfo->src, &pinfo->dst, ctype, pinfo->srcport, pinfo->destport, options);
    }

    return conversation;
}

conversation_t *
conversation_new_by_id(const uint32_t setup_frame, const conversation_type ctype, const uint32_t id)
{
    conversation_t *conversation = wmem_new0(wmem_file_scope(), conversation_t);
    conversation->conv_index = new_index;
    conversation->setup_frame = conversation->last_frame = setup_frame;

    new_index++;

    conversation_element_t *elements = wmem_alloc(wmem_file_scope(), sizeof(conversation_element_t) * 2);
    elements[0].type = CE_UINT;
    elements[0].uint_val = id;
    elements[1].type = CE_CONVERSATION_TYPE;
    elements[1].conversation_type_val = ctype;
    conversation->key_ptr = elements;
    conversation_insert_into_hashtable(conversation_hashtable_id, conversation);

    return conversation;
}

conversation_t *
conversation_new_deinterlacer(const uint32_t setup_frame, const address *addr1, const address *addr2,
        const conversation_type ctype, const uint32_t key1, const uint32_t key2, const uint32_t key3)
{

    conversation_t *conversation = wmem_new0(wmem_file_scope(), conversation_t);
    conversation->conv_index = new_index;
    conversation->setup_frame = conversation->last_frame = setup_frame;

    conversation_element_t *new_key = wmem_alloc(wmem_file_scope(), sizeof(conversation_element_t) * (DEINTR_ENDP_IDX+1));

    new_key[DEINTR_ADDR1_IDX].type = CE_ADDRESS;
    if (addr1 != NULL) {
        copy_address_wmem(wmem_file_scope(), &new_key[DEINTR_ADDR1_IDX].addr_val, addr1);
    }
    else {
        clear_address(&new_key[DEINTR_ADDR1_IDX].addr_val);
    }

    new_key[DEINTR_ADDR2_IDX].type = CE_ADDRESS;
    if (addr2 != NULL) {
        copy_address_wmem(wmem_file_scope(), &new_key[DEINTR_ADDR2_IDX].addr_val, addr2);
    }
    else {
        clear_address(&new_key[DEINTR_ADDR2_IDX].addr_val);
    }

    new_key[DEINTR_KEY1_IDX].type = CE_UINT;
    new_key[DEINTR_KEY1_IDX].uint_val = key1;

    new_key[DEINTR_KEY2_IDX].type = CE_UINT;
    new_key[DEINTR_KEY2_IDX].uint_val = key2;

    new_key[DEINTR_KEY3_IDX].type = CE_UINT;
    new_key[DEINTR_KEY3_IDX].uint_val = key3;

    new_key[DEINTR_ENDP_IDX].type = CE_CONVERSATION_TYPE;
    new_key[DEINTR_ENDP_IDX].conversation_type_val = ctype;

    conversation->key_ptr = new_key;

    new_index++;

    conversation_insert_into_hashtable(conversation_hashtable_deinterlacer, conversation);

    return conversation;
}

conversation_t *
conversation_new_deinterlaced(const uint32_t setup_frame, const address *addr1, const address *addr2,
        const conversation_type ctype, const uint32_t port1, const uint32_t port2, const uint32_t anchor, const unsigned options)
{

    conversation_t *conversation = wmem_new0(wmem_file_scope(), conversation_t);
    conversation->conv_index = new_index;
    conversation->setup_frame = conversation->last_frame = setup_frame;

    if (options & NO_PORTS) {
        conversation_element_t *new_key = wmem_alloc(wmem_file_scope(), sizeof(conversation_element_t) * (DEINTD_ENDP_NO_PORTS_IDX+2));

        new_key[DEINTD_ADDR1_IDX].type = CE_ADDRESS;
        if (addr1 != NULL) {
            copy_address_wmem(wmem_file_scope(), &new_key[DEINTD_ADDR1_IDX].addr_val, addr1);
        }
        else {
          clear_address(&new_key[DEINTD_ADDR1_IDX].addr_val);
        }

        new_key[DEINTD_ADDR2_IDX].type = CE_ADDRESS;
        if (addr2 != NULL) {
            copy_address_wmem(wmem_file_scope(), &new_key[DEINTD_ADDR2_IDX].addr_val, addr2);
        }
        else {
          clear_address(&new_key[DEINTD_ADDR2_IDX].addr_val);
        }

        new_key[DEINTD_ENDP_NO_PORTS_IDX].type = CE_UINT;
        new_key[DEINTD_ENDP_NO_PORTS_IDX].uint_val = anchor;

        new_key[DEINTD_ENDP_NO_PORTS_IDX+ 1].type = CE_CONVERSATION_TYPE;
        new_key[DEINTD_ENDP_NO_PORTS_IDX+ 1].conversation_type_val = ctype;

        // set the options and key pointer
        conversation->options = options;
        conversation->key_ptr = new_key;

        new_index++;

        conversation_insert_into_hashtable(conversation_hashtable_exact_addr_anc, conversation);

        return conversation;
    }
    else {
        conversation_element_t *new_key = wmem_alloc(wmem_file_scope(), sizeof(conversation_element_t) * (DEINTD_EXACT_IDX_COUNT+2));

        new_key[DEINTD_ADDR1_IDX].type = CE_ADDRESS;
        if (addr1 != NULL) {
            copy_address_wmem(wmem_file_scope(), &new_key[DEINTD_ADDR1_IDX].addr_val, addr1);
        }
        else {
          clear_address(&new_key[DEINTD_ADDR1_IDX].addr_val);
        }

        new_key[DEINTD_ADDR2_IDX].type = CE_ADDRESS;
        if (addr2 != NULL) {
            copy_address_wmem(wmem_file_scope(), &new_key[DEINTD_ADDR2_IDX].addr_val, addr2);
        }
        else {
          clear_address(&new_key[DEINTD_ADDR2_IDX].addr_val);
        }

        new_key[DEINTD_PORT1_IDX].type = CE_PORT;
        new_key[DEINTD_PORT1_IDX].port_val = port1;

        new_key[DEINTD_PORT2_IDX].type = CE_PORT;
        new_key[DEINTD_PORT2_IDX].port_val = port2;

        new_key[DEINTD_ENDP_EXACT_IDX].type = CE_UINT;
        new_key[DEINTD_ENDP_EXACT_IDX].uint_val = anchor;

        new_key[DEINTD_ENDP_EXACT_IDX + 1].type = CE_CONVERSATION_TYPE;
        new_key[DEINTD_ENDP_EXACT_IDX + 1].conversation_type_val = ctype;

        // set the options and key pointer
        conversation->options = options;
        conversation->key_ptr = new_key;

        new_index++;

        conversation_insert_into_hashtable(conversation_hashtable_exact_addr_port_anc, conversation);

        return conversation;
    }
}

/*
 * Set the port 2 value in a key. Remove the original from table,
 * update the options and port values, insert the updated key.
 */
void
conversation_set_port2(conversation_t *conv, const uint32_t port)
{
    DISSECTOR_ASSERT_HINT(!(conv->options & CONVERSATION_TEMPLATE),
            "Use the conversation_create_from_template function when the CONVERSATION_TEMPLATE bit is set in the options mask");

    DPRINT(("called for port=%d", port));

    /*
     * If the port 2 value is not wildcarded, don't set it.
     */
    if ((!(conv->options & NO_PORT2)) || (conv->options & NO_PORT2_FORCE))
        return;

    DINDENT();
    if (conv->options & NO_ADDR2) {
        conversation_remove_from_hashtable(conversation_hashtable_no_addr2_or_port2, conv);
    } else {
        conversation_remove_from_hashtable(conversation_hashtable_no_port2, conv);
    }

    // Shift our endpoint element over and set our port. We assume that conv->key_ptr
    // was created with conversation_new and that we have enough element slots.
    conv->options &= ~NO_PORT2;
    if (conv->options & NO_ADDR2) {
        // addr1,port1,endp -> addr1,port1,port2,endp
        conv->key_ptr[ENDP_NO_ADDR2_IDX] = conv->key_ptr[ENDP_NO_ADDR2_PORT2_IDX];
        conv->key_ptr[PORT2_NO_ADDR2_IDX].type = CE_PORT;
        conv->key_ptr[PORT2_NO_ADDR2_IDX].port_val = port;
        conversation_insert_into_hashtable(conversation_hashtable_no_addr2, conv);
    } else {
        // addr1,port1,addr2,endp -> addr1,port1,addr2,port2,endp
        conv->key_ptr[ENDP_EXACT_IDX] = conv->key_ptr[ENDP_NO_PORT2_IDX];
        conv->key_ptr[PORT2_IDX].type = CE_PORT;
        conv->key_ptr[PORT2_IDX].port_val = port;
        conversation_insert_into_hashtable(conversation_hashtable_exact_addr_port, conv);
    }
    DENDENT();
}

/*
 * Set the address 2 value in a key.  Remove the original from
 * table, update the options and port values, insert the updated key.
 */
void
conversation_set_addr2(conversation_t *conv, const address *addr)
{
    char* addr_str;
    DISSECTOR_ASSERT_HINT(!(conv->options & CONVERSATION_TEMPLATE),
            "Use the conversation_create_from_template function when the CONVERSATION_TEMPLATE bit is set in the options mask");

    addr_str = address_to_str(NULL, addr);
    DPRINT(("called for addr=%s", addr_str));
    wmem_free(NULL, addr_str);

    /*
     * If the address 2 value is not wildcarded, don't set it.
     */
    if (!(conv->options & NO_ADDR2))
        return;

    DINDENT();
    if (conv->options & NO_PORT2) {
        conversation_remove_from_hashtable(conversation_hashtable_no_addr2_or_port2, conv);
    } else {
        conversation_remove_from_hashtable(conversation_hashtable_no_addr2, conv);
    }

    // Shift our endpoint and, if needed, our port element over and set our address.
    // We assume that conv->key_ptr was created with conversation_new and that we have
    // enough element slots.
    conv->options &= ~NO_ADDR2;
    wmem_map_t *hashtable;
    if (conv->options & NO_PORT2) {
        // addr1,port1,endp -> addr1,port1,addr2,endp
        conv->key_ptr[ENDP_NO_PORT2_IDX] = conv->key_ptr[ENDP_NO_ADDR2_PORT2_IDX];
        hashtable = conversation_hashtable_no_port2;
    } else {
        // addr1,port1,port2,endp -> addr1,port1,addr2,port2,endp
        conv->key_ptr[ENDP_EXACT_IDX] = conv->key_ptr[ENDP_NO_ADDR2_IDX];
        conv->key_ptr[PORT2_IDX] = conv->key_ptr[PORT2_NO_ADDR2_IDX];
        hashtable = conversation_hashtable_exact_addr_port;
    }
    conv->key_ptr[ADDR2_IDX].type = CE_ADDRESS;
    copy_address_wmem(wmem_file_scope(), &conv->key_ptr[ADDR2_IDX].addr_val, addr);
    conversation_insert_into_hashtable(hashtable, conv);
    DENDENT();
}

static conversation_t *conversation_lookup_hashtable(wmem_map_t *conversation_hashtable, const uint32_t frame_num, conversation_element_t *conv_key)
{
    conversation_t* convo = NULL;
    conversation_t* match = NULL;
    conversation_t* chain_head = NULL;
    chain_head = (conversation_t *)wmem_map_lookup(conversation_hashtable, conv_key);

    if (chain_head && (chain_head->setup_frame <= frame_num)) {
        match = chain_head;

        if (chain_head->last && (chain_head->last->setup_frame <= frame_num))
            return chain_head->last;

        if (chain_head->latest_found && (chain_head->latest_found->setup_frame <= frame_num))
            match = chain_head->latest_found;

        for (convo = match; convo && convo->setup_frame <= frame_num; convo = convo->next) {
            if (convo->setup_frame > match->setup_frame) {
                match = convo;
            }
        }
    }

    if (match) {
        chain_head->latest_found = match;
    }

    return match;
}

conversation_t *find_conversation_full(const uint32_t frame_num, conversation_element_t *elements)
{
    char *el_list_map_key = conversation_element_list_name(NULL, elements);
    wmem_map_t *el_list_map = (wmem_map_t *) wmem_map_lookup(conversation_hashtable_element_list, el_list_map_key);
    g_free(el_list_map_key);
    if (!el_list_map) {
        return NULL;
    }

    return conversation_lookup_hashtable(el_list_map, frame_num, elements);
}

/*
 * Search a particular hash table for a conversation with the specified
 * {addr1, port1, addr2, port2} and set up before frame_num.
 */
static conversation_t *
conversation_lookup_exact(const uint32_t frame_num, const address *addr1, const uint32_t port1,
                          const address *addr2, const uint32_t port2, const conversation_type ctype)
{
    conversation_element_t key[EXACT_IDX_COUNT] = {
        { CE_ADDRESS, .addr_val = *addr1 },
        { CE_PORT, .port_val = port1 },
        { CE_ADDRESS, .addr_val = *addr2 },
        { CE_PORT, .port_val = port2 },
        { CE_CONVERSATION_TYPE, .conversation_type_val = ctype },
    };
    return conversation_lookup_hashtable(conversation_hashtable_exact_addr_port, frame_num, key);
}

/*
 * Search a particular hash table for a conversation with the specified
 * {addr1, port1, port2} and set up before frame_num.
 */
static conversation_t *
conversation_lookup_no_addr2(const uint32_t frame_num, const address *addr1, const uint32_t port1,
                          const uint32_t port2, const conversation_type ctype)
{
    conversation_element_t key[NO_ADDR2_IDX_COUNT] = {
        { CE_ADDRESS, .addr_val = *addr1 },
        { CE_PORT, .port_val = port1 },
        { CE_PORT, .port_val = port2 },
        { CE_CONVERSATION_TYPE, .conversation_type_val = ctype },
    };
    return conversation_lookup_hashtable(conversation_hashtable_no_addr2, frame_num, key);
}

/*
 * Search a particular hash table for a conversation with the specified
 * {addr1, port1, addr2} and set up before frame_num.
 */
static conversation_t *
conversation_lookup_no_port2(const uint32_t frame_num, const address *addr1, const uint32_t port1,
                          const address *addr2, const conversation_type ctype)
{
    conversation_element_t key[NO_PORT2_IDX_COUNT] = {
        { CE_ADDRESS, .addr_val = *addr1 },
        { CE_PORT, .port_val = port1 },
        { CE_ADDRESS, .addr_val = *addr2 },
        { CE_CONVERSATION_TYPE, .conversation_type_val = ctype },
    };
    return conversation_lookup_hashtable(conversation_hashtable_no_port2, frame_num, key);
}

/*
 * Search a particular hash table for a conversation with the specified
 * {addr1, port1, addr2} and set up before frame_num.
 */
static conversation_t *
conversation_lookup_no_addr2_or_port2(const uint32_t frame_num, const address *addr1, const uint32_t port1,
                          const conversation_type ctype)
{
    conversation_element_t key[NO_ADDR2_PORT2_IDX_COUNT] = {
        { CE_ADDRESS, .addr_val = *addr1 },
        { CE_PORT, .port_val = port1 },
        { CE_CONVERSATION_TYPE, .conversation_type_val = ctype },
    };
    return conversation_lookup_hashtable(conversation_hashtable_no_addr2_or_port2, frame_num, key);
}

/*
 * Search a particular hash table for a conversation with the specified
 * {addr1, addr2} and set up before frame_num.
 */
static conversation_t *
conversation_lookup_no_ports(const uint32_t frame_num, const address *addr1,
                          const address *addr2, const conversation_type ctype)
{
    conversation_element_t key[ADDRS_IDX_COUNT] = {
        { CE_ADDRESS, .addr_val = *addr1 },
        { CE_ADDRESS, .addr_val = *addr2 },
        { CE_CONVERSATION_TYPE, .conversation_type_val = ctype },
    };
    return conversation_lookup_hashtable(conversation_hashtable_exact_addr, frame_num, key);
}

/*
 * Search a particular hash table for a conversation with the specified
 * {addr1, port1, addr2, port2, anchor} and set up before frame_num.
 */
static conversation_t *
conversation_lookup_exact_anc(const uint32_t frame_num, const address *addr1, const uint32_t port1,
                          const address *addr2, const uint32_t port2, const conversation_type ctype,
                          const uint32_t anchor)
{
    conversation_element_t key[DEINTD_EXACT_IDX_COUNT+1] = {
        { CE_ADDRESS, .addr_val = *addr1 },
        { CE_ADDRESS, .addr_val = *addr2 },
        { CE_PORT, .port_val = port1 },
        { CE_PORT, .port_val = port2 },
        { CE_UINT, .uint_val = anchor },
        { CE_CONVERSATION_TYPE, .conversation_type_val = ctype },
    };
    return conversation_lookup_hashtable(conversation_hashtable_exact_addr_port_anc, frame_num, key);
}

/*
 * Search a particular hash table for a conversation with the specified
 * {addr1, addr2, anchor} and set up before frame_num.
 */
static conversation_t *
conversation_lookup_no_ports_anc(const uint32_t frame_num, const address *addr1,
                          const address *addr2, const conversation_type ctype, const uint32_t anchor)
{
    conversation_element_t key[DEINTD_ADDRS_IDX_COUNT+1] = {
        { CE_ADDRESS, .addr_val = *addr1 },
        { CE_ADDRESS, .addr_val = *addr2 },
        { CE_UINT, .uint_val = anchor },
        { CE_CONVERSATION_TYPE, .conversation_type_val = ctype },
    };
    return conversation_lookup_hashtable(conversation_hashtable_exact_addr_anc, frame_num, key);
}

static conversation_t *
conversation_lookup_no_anc_anc(const uint32_t frame_num, const address *addr1,
                          const address *addr2, const conversation_type ctype)
{
    conversation_element_t key[ADDRS_IDX_COUNT] = {
        { CE_ADDRESS, .addr_val = *addr1 },
        { CE_ADDRESS, .addr_val = *addr2 },
        { CE_CONVERSATION_TYPE, .conversation_type_val = ctype },
    };
    return conversation_lookup_hashtable(conversation_hashtable_exact_addr_anc, frame_num, key);
}

/*
 * Search a particular hash table for a conversation with the specified
 * {addr1, addr2, key1, key2, key3} and set up before frame_num.
 * At this moment only the deinterlace table is likely to be called.
 */
static conversation_t *
conversation_lookup_deinterlacer(const uint32_t frame_num, const address *addr1,
                          const address *addr2, const conversation_type ctype,
                          const uint32_t key1, const uint32_t key2, const uint32_t key3)
{
    conversation_element_t key[DEINTR_ENDP_IDX+1] = {
        { CE_ADDRESS, .addr_val = *addr1 },
        { CE_ADDRESS, .addr_val = *addr2 },
        { CE_UINT, .uint_val = key1 },
        { CE_UINT, .uint_val = key2 },
        { CE_UINT, .uint_val = key3 },
        { CE_CONVERSATION_TYPE, .conversation_type_val = ctype },
    };
    return conversation_lookup_hashtable(conversation_hashtable_deinterlacer, frame_num, key);
}

/*
 * Given two address/port pairs for a packet, search for a conversation
 * containing packets between those address/port pairs.  Returns NULL if
 * not found.
 *
 * We try to find the most exact match that we can, and then proceed to
 * try wildcard matches on the "addr_b" and/or "port_b" argument if a more
 * exact match failed.
 *
 * Either or both of the "addr_b" and "port_b" arguments may be specified as
 * a wildcard by setting the NO_ADDR_B or NO_PORT_B flags in the "options"
 * argument.  We do only wildcard matches on addresses and ports specified
 * as wildcards.
 *
 * I.e.:
 *
 *	if neither "addr_b" nor "port_b" were specified as wildcards, we
 *	do an exact match (addr_a/port_a and addr_b/port_b) and, if that
 *	succeeds, we return a pointer to the matched conversation;
 *
 *	otherwise, if "port_b" wasn't specified as a wildcard, we try to
 *	match any address 2 with the specified port 2 (addr_a/port_a and
 *	{any}/port_b) and, if that succeeds, we return a pointer to the
 *	matched conversation;
 *
 *	otherwise, if "addr_b" wasn't specified as a wildcard, we try to
 *	match any port 2 with the specified address 2 (addr_a/port_a and
 *	addr_b/{any}) and, if that succeeds, we return a pointer to the
 *	matched conversation;
 *
 *	otherwise, we try to match any address 2 and any port 2
 *	(addr_a/port_a and {any}/{any}) and, if that succeeds, we return
 *	a pointer to the matched conversation;
 *
 *	otherwise, we found no matching conversation, and return NULL.
 */
conversation_t *
find_conversation(const uint32_t frame_num, const address *addr_a, const address *addr_b, const conversation_type ctype,
        const uint32_t port_a, const uint32_t port_b, const unsigned options)
{
    conversation_t *conversation, *other_conv;

    if (!addr_a) {
        addr_a = &null_address_;
    }

    if (!addr_b) {
        addr_b = &null_address_;
    }

    DINSTR(char *addr_a_str = address_to_str(NULL, addr_a));
    DINSTR(char *addr_b_str = address_to_str(NULL, addr_b));
    /*
     * Verify that the correct options are used, if any.
     */
    DISSECTOR_ASSERT_HINT((options == 0) || (options & NO_MASK_B), "Use NO_ADDR_B and/or NO_PORT_B as option");
    /*
     * First try an exact match, if we have two addresses and ports.
     */
    if (!(options & (NO_ADDR_B|NO_PORT_B|NO_PORTS))) {
        /*
         * Neither search address B nor search port B are wildcarded,
         * start out with an exact match.
         */
        DPRINT(("trying exact match: %s:%d -> %s:%d",
                    addr_a_str, port_a, addr_b_str, port_b));
        conversation = conversation_lookup_exact(frame_num, addr_a, port_a, addr_b, port_b, ctype);
        /*
         * Look for an alternate conversation in the opposite direction, which
         * might fit better. Note that using the helper functions such as
         * find_conversation_pinfo and find_or_create_conversation will finally
         * call this function and look for an orientation-agnostic conversation.
         * If oriented conversations had to be implemented, amend this code or
         * create new functions.
         */

        DPRINT(("trying exact match: %s:%d -> %s:%d",
                    addr_b_str, port_b, addr_a_str, port_a));
        other_conv = conversation_lookup_exact(frame_num, addr_b, port_b, addr_a, port_a, ctype);
        if (other_conv != NULL) {
            if (conversation != NULL) {
                if(other_conv->conv_index > conversation->conv_index) {
                    conversation = other_conv;
                }
            }
            else {
                conversation = other_conv;
            }
        }
        if ((conversation == NULL) && (addr_a->type == AT_FC)) {
            /* In Fibre channel, OXID & RXID are never swapped as
             * TCP/UDP ports are in TCP/IP.
             */
            DPRINT(("trying exact match: %s:%d -> %s:%d",
                        addr_b_str, port_a, addr_a_str, port_b));
            conversation = conversation_lookup_exact(frame_num, addr_b, port_a, addr_a, port_b, ctype);
        }
        DPRINT(("exact match %sfound",conversation?"":"not "));
        if (conversation != NULL)
            goto end;
    }

    /*
     * Well, that didn't find anything.  Try matches that wildcard
     * one of the addresses, if we have two ports.
     */
    if (!(options & (NO_PORT_B|NO_PORTS))) {
        /*
         * Search port B isn't wildcarded.
         *
         * First try looking for a conversation with the specified
         * address A and port A as the first address and port, and
         * with any address and the specified port B as the second
         * address and port.
         * ("addr_b" doesn't take part in this lookup.)
         */
        DPRINT(("trying wildcarded match: %s:%d -> *:%d",
                    addr_a_str, port_a, port_b));
        conversation = conversation_lookup_no_addr2(frame_num, addr_a, port_a, port_b, ctype);
        if ((conversation == NULL) && (addr_a->type == AT_FC)) {
            /* In Fibre channel, OXID & RXID are never swapped as
             * TCP/UDP ports are in TCP/IP.
             */
            DPRINT(("trying wildcarded match: %s:%d -> *:%d",
                        addr_b_str, port_a, port_b));
            conversation = conversation_lookup_no_addr2(frame_num, addr_b, port_a, port_b, ctype);
        }
        if (conversation != NULL) {
            /*
             * If search address B isn't wildcarded, and this is for a
             * connection-oriented protocol, set the second address for this
             * conversation to address B, as that's the address that matched the
             * wildcarded second address for this conversation.
             *
             * (This assumes that, for all connection oriented protocols, the
             * endpoints of a connection have only one address each, i.e. you
             * don't get packets in a given direction coming from more than one
             * address, unless the CONVERSATION_TEMPLATE option is set.)
             */
            DPRINT(("wildcarded dest address match found"));
            if (!(conversation->options & NO_ADDR2) && ctype != CONVERSATION_UDP)
            {
                if (!(conversation->options & CONVERSATION_TEMPLATE))
                {
                    conversation_set_addr2(conversation, addr_b);
                }
                else
                {
                    conversation =
                        conversation_create_from_template(conversation, addr_b, 0);
                }
            }
            goto end;
        }

        /*
         * Well, that didn't find anything.
         * If search address B was specified, try looking for a
         * conversation with the specified address B and port B as
         * the first address and port, and with any address and the
         * specified port A as the second address and port (this
         * packet may be going in the opposite direction from the
         * first packet in the conversation).
         * ("addr_a" doesn't take part in this lookup.)
         */
        if (!(options & NO_ADDR_B)) {
            DPRINT(("trying wildcarded match: %s:%d -> *:%d",
                        addr_b_str, port_b, port_a));
            conversation = conversation_lookup_no_addr2(frame_num, addr_b, port_b, port_a, ctype);
            if (conversation != NULL) {
                /*
                 * If this is for a connection-oriented
                 * protocol, set the second address for
                 * this conversation to address A, as
                 * that's the address that matched the
                 * wildcarded second address for this
                 * conversation.
                 */
                DPRINT(("match found"));
                if (ctype != CONVERSATION_UDP) {
                    if (!(conversation->options & CONVERSATION_TEMPLATE))
                    {
                        conversation_set_addr2(conversation, addr_a);
                    }
                    else
                    {
                        conversation =
                            conversation_create_from_template(conversation, addr_a, 0);
                    }
                }
                goto end;
            }
        }
    }

    /*
     * Well, that didn't find anything.  Try matches that wildcard
     * one of the ports, if we have two addresses.
     */
    if (!(options & (NO_ADDR_B|NO_PORTS))) {
        /*
         * Search address B isn't wildcarded.
         *
         * First try looking for a conversation with the specified
         * address A and port A as the first address and port, and
         * with the specified address B and any port as the second
         * address and port.
         * ("port_b" doesn't take part in this lookup.)
         */
        DPRINT(("trying wildcarded match: %s:%d -> %s:*",
                    addr_a_str, port_a, addr_b_str));
        conversation = conversation_lookup_no_port2(frame_num, addr_a, port_a, addr_b, ctype);
        if ((conversation == NULL) && (addr_a->type == AT_FC)) {
            /* In Fibre channel, OXID & RXID are never swapped as
             * TCP/UDP ports are in TCP/IP
             */
            DPRINT(("trying wildcarded match: %s:%d -> %s:*", addr_b_str, port_a, addr_a_str));
            conversation = conversation_lookup_no_port2(frame_num, addr_b, port_a, addr_a, ctype);
        }
        if (conversation != NULL) {
            /*
             * If search port B isn't wildcarded, and this is for a connection-
             * oriented protocol, set the second port for this conversation to
             * port B, as that's the port that matched the wildcarded second port
             * for this conversation.
             *
             * (This assumes that, for all connection oriented protocols, the
             * endpoints of a connection have only one port each, i.e. you don't
             * get packets in a given direction coming from more than one port,
             * unless the CONVERSATION_TEMPLATE option is set.)
             */
            DPRINT(("match found"));
            if (!(conversation->options & NO_PORT2) && ctype != CONVERSATION_UDP)
            {
                if (!(conversation->options & CONVERSATION_TEMPLATE))
                {
                    conversation_set_port2(conversation, port_b);
                }
                else
                {
                    conversation =
                        conversation_create_from_template(conversation, 0, port_b);
                }
            }
            goto end;
        }

        /*
         * Well, that didn't find anything.
         * If search port B was specified, try looking for a
         * conversation with the specified address B and port B
         * as the first address and port, and with the specified
         * address A and any port as the second address and port
         * (this packet may be going in the opposite direction
         * from the first packet in the conversation).
         * ("port_a" doesn't take part in this lookup.)
         */
        if (!(options & NO_PORT_B)) {
            DPRINT(("trying wildcarded match: %s:%d -> %s:*",
                        addr_b_str, port_b, addr_a_str));
            conversation = conversation_lookup_no_port2(frame_num, addr_b, port_b, addr_a, ctype);
            if (conversation != NULL) {
                /*
                 * If this is for a connection-oriented
                 * protocol, set the second port for
                 * this conversation to port A, as
                 * that's the address that matched the
                 * wildcarded second address for this
                 * conversation.
                 */
                DPRINT(("match found"));
                if (ctype != CONVERSATION_UDP)
                {
                    if (!(conversation->options & CONVERSATION_TEMPLATE))
                    {
                        conversation_set_port2(conversation, port_a);
                    }
                    else
                    {
                        conversation =
                            conversation_create_from_template(conversation, 0, port_a);
                    }
                }
                goto end;
            }
        }
    }

    /*
     * Well, that didn't find anything.  Try matches that wildcard
     * one address/port pair.
     *
     * First try looking for a conversation with the specified address A
     * and port A as the first address and port.
     * (Neither "addr_b" nor "port_b" take part in this lookup.)
     */
    DPRINT(("trying wildcarded match: %s:%d -> *:*", addr_a_str, port_a));
    conversation = conversation_lookup_no_addr2_or_port2(frame_num, addr_a, port_a, ctype);
    if (conversation != NULL) {
        /*
         * If this is for a connection-oriented protocol:
         *
         * if search address B isn't wildcarded, set the
         * second address for this conversation to address
         * B, as that's the address that matched the
         * wildcarded second address for this conversation;
         *
         * if search port B isn't wildcarded, set the
         * second port for this conversation to port B,
         * as that's the port that matched the wildcarded
         * second port for this conversation.
         */
        DPRINT(("match found"));
        if (ctype != CONVERSATION_UDP)
        {
            if (!(conversation->options & CONVERSATION_TEMPLATE))
            {
                if (!(conversation->options & NO_ADDR2))
                    conversation_set_addr2(conversation, addr_b);
                if (!(conversation->options & NO_PORT2))
                    conversation_set_port2(conversation, port_b);
            }
            else
            {
                conversation =
                    conversation_create_from_template(conversation, addr_b, port_b);
            }
        }
        goto end;
    }
    /* for Infiniband, don't try to look in addresses of reverse
     * direction, because it could be another different
     * valid conversation than what is being searched using
     * addr_a, port_a.
     */
    if (ctype != CONVERSATION_IBQP)
    {

        /*
         * Well, that didn't find anything.
         * If search address and port B were specified, try looking for a
         * conversation with the specified address B and port B as the
         * first address and port, and with any second address and port
         * (this packet may be going in the opposite direction from the
         * first packet in the conversation).
         * (Neither "addr_a" nor "port_a" take part in this lookup.)
         */
        if (addr_a->type == AT_FC) {
            DPRINT(("trying wildcarded match: %s:%d -> *:*",
                        addr_b_str, port_a));
            conversation = conversation_lookup_no_addr2_or_port2(frame_num, addr_b, port_a, ctype);
        } else {
            DPRINT(("trying wildcarded match: %s:%d -> *:*",
                        addr_b_str, port_b));
            conversation = conversation_lookup_no_addr2_or_port2(frame_num, addr_b, port_b, ctype);
        }
        if (conversation != NULL) {
            /*
             * If this is for a connection-oriented protocol, set the
             * second address for this conversation to address A, as
             * that's the address that matched the wildcarded second
             * address for this conversation, and set the second port
             * for this conversation to port A, as that's the port
             * that matched the wildcarded second port for this
             * conversation.
             */
            DPRINT(("match found"));
            if (ctype != CONVERSATION_UDP)
            {
                if (!(conversation->options & CONVERSATION_TEMPLATE))
                {
                    conversation_set_addr2(conversation, addr_a);
                    conversation_set_port2(conversation, port_a);
                }
                else
                {
                    conversation = conversation_create_from_template(conversation, addr_a, port_a);
                }
            }
            goto end;
        }
    }

    if (options & NO_PORT_X) {
        /*
         * Search for conversations between two addresses, strictly
         */
        DPRINT(("trying exact match: %s -> %s",
                    addr_a_str, addr_b_str));
        conversation = conversation_lookup_no_ports(frame_num, addr_a, addr_b, ctype);

        if (conversation != NULL) {
            DPRINT(("match found"));
            goto end;
        }
        else {
            conversation = conversation_lookup_no_ports(frame_num, addr_b, addr_a, ctype);
            if (conversation != NULL) {
                DPRINT(("match found"));
                goto end;
            }
        }
    }

    DPRINT(("no matches found"));

    /*
     * We found no conversation.
     */
    conversation = NULL;

end:
    DINSTR(wmem_free(NULL, addr_a_str));
    DINSTR(wmem_free(NULL, addr_b_str));
    return conversation;
}

conversation_t *
find_conversation_deinterlaced(const uint32_t frame_num, const address *addr_a, const address *addr_b, const conversation_type ctype,
        const uint32_t port_a, const uint32_t port_b, const uint32_t anchor, const unsigned options)
{
    conversation_t *conversation, *other_conv;

    if (!(options & (NO_ADDR_B|NO_PORT_B|NO_PORT_X|NO_ANC))) {
        conversation = conversation_lookup_exact_anc(frame_num, addr_a, port_a, addr_b, port_b, ctype, anchor);

        other_conv = conversation_lookup_exact_anc(frame_num, addr_b, port_b, addr_a, port_a, ctype, anchor);
        if (other_conv != NULL) {
            if (conversation != NULL) {
                if(other_conv->conv_index > conversation->conv_index) {
                    conversation = other_conv;
                }
            }
            else {
                conversation = other_conv;
            }
        }

    }
    else { /* typically : IP protocols */
        if (!(options & NO_ANC)) {
            conversation = conversation_lookup_no_ports_anc(frame_num, addr_a, addr_b, ctype, anchor);
            other_conv = conversation_lookup_no_ports_anc(frame_num, addr_b, addr_a, ctype, anchor);
            if (other_conv != NULL) {
                if (conversation != NULL) {
                    if(other_conv->conv_index > conversation->conv_index) {
                        conversation = other_conv;
                    }
                }
                else {
                    conversation = other_conv;
                }
            }
        }
        else { /* NO_ANC */
            conversation = conversation_lookup_no_anc_anc(frame_num, addr_a, addr_b, ctype);
            other_conv = conversation_lookup_no_anc_anc(frame_num, addr_b, addr_a, ctype);
            if (other_conv != NULL) {
                if (conversation != NULL) {
                    if(other_conv->conv_index > conversation->conv_index) {
                        conversation = other_conv;
                    }
                }
                else {
                    conversation = other_conv;
                }
            }
        }
    }

    return conversation;
}

conversation_t *
find_conversation_deinterlacer(const uint32_t frame_num, const address *addr_a, const address *addr_b,
        const conversation_type ctype, const uint32_t key_a, const uint32_t key_b, const uint32_t key_c)
{
    conversation_t *conversation, *other_conv;

    conversation = conversation_lookup_deinterlacer(frame_num, addr_a, addr_b, ctype, key_a, key_b, key_c);

    other_conv = conversation_lookup_deinterlacer(frame_num, addr_b, addr_a, ctype, key_a, key_b, key_c);
    if (other_conv != NULL) {
        if (conversation != NULL) {
            if(other_conv->conv_index > conversation->conv_index) {
                conversation = other_conv;
            }
        }
        else {
            conversation = other_conv;
        }
    }

    return conversation;
}

conversation_t *
find_conversation_deinterlacer_pinfo(const packet_info *pinfo)
{
  conversation_t *conv=NULL;
  unsigned dr_conv_type; /* deinterlacer conv type */
  uint32_t dtlc_iface = 0;
  uint32_t dtlc_vlan = 0;

  /* evaluate the execution context: user pref, interface, VLAN */
  if(prefs.conversation_deinterlacing_key>0) {
    if(prefs.conversation_deinterlacing_key&CONV_DEINT_KEY_INTERFACE &&
       pinfo->rec->presence_flags & WTAP_HAS_INTERFACE_ID) {

      if(prefs.conversation_deinterlacing_key&CONV_DEINT_KEY_VLAN &&
         pinfo->vlan_id>0) {

        dr_conv_type = CONVERSATION_ETH_IV;
        dtlc_vlan = pinfo->vlan_id;
      }
      else {
        dr_conv_type = CONVERSATION_ETH_IN;
      }
      dtlc_iface = pinfo->rec->rec_header.packet_header.interface_id;
    }
    else {
      if(prefs.conversation_deinterlacing_key&CONV_DEINT_KEY_VLAN &&
         pinfo->vlan_id>0) {

        dr_conv_type = CONVERSATION_ETH_NV;
        dtlc_vlan = pinfo->vlan_id;
      }
      else {
        dr_conv_type = CONVERSATION_ETH_NN;
      }
    }

    conv = find_conversation_deinterlacer(pinfo->num, &pinfo->dl_src, &pinfo->dl_dst, dr_conv_type, dtlc_iface, dtlc_vlan , 0);
  }

  return conv;
}

conversation_t *
find_conversation_by_id(const uint32_t frame, const conversation_type ctype, const uint32_t id)
{
    conversation_element_t elements[2] = {
        { CE_UINT, .uint_val = id },
        { CE_CONVERSATION_TYPE, .conversation_type_val = ctype }
    };

    return conversation_lookup_hashtable(conversation_hashtable_id, frame, elements);
}

void
conversation_add_proto_data(conversation_t *conv, const int proto, void *proto_data)
{
    if (conv == NULL) {
        REPORT_DISSECTOR_BUG("%s: Can't add proto data to a NULL conversation.", proto_get_protocol_name(proto));
    }
    /* Add it to the list of items for this conversation. */
    if (conv->data_list == NULL)
        conv->data_list = wmem_tree_new(wmem_file_scope());

    wmem_tree_insert32(conv->data_list, proto, proto_data);
}

void *
conversation_get_proto_data(const conversation_t *conv, const int proto)
{
    if (conv == NULL) {
        REPORT_DISSECTOR_BUG("%s: Can't get proto from a NULL conversation.", proto_get_protocol_name(proto));
    }
    /* No tree created yet */
    if (conv->data_list == NULL) {
        return NULL;
    }

    return wmem_tree_lookup32(conv->data_list, proto);
}

void
conversation_delete_proto_data(conversation_t *conv, const int proto)
{
    if (conv == NULL) {
        REPORT_DISSECTOR_BUG("%s: Can't delete a NULL conversation.", proto_get_protocol_name(proto));
    }
    if (conv->data_list != NULL)
        wmem_tree_remove32(conv->data_list, proto);
}

void
conversation_set_dissector_from_frame_number(conversation_t *conversation,
        const uint32_t starting_frame_num, const dissector_handle_t handle)
{
    if (!conversation->dissector_tree) {
        conversation->dissector_tree = wmem_tree_new(wmem_file_scope());
    }
    wmem_tree_insert32(conversation->dissector_tree, starting_frame_num, (void *)handle);
}

void
conversation_set_dissector(conversation_t *conversation, const dissector_handle_t handle)
{
    conversation_set_dissector_from_frame_number(conversation, 0, handle);
}

dissector_handle_t
conversation_get_dissector(conversation_t *conversation, const uint32_t frame_num)
{
    if (!conversation->dissector_tree) {
        return NULL;
    }
    return (dissector_handle_t)wmem_tree_lookup32_le(conversation->dissector_tree, frame_num);
}

static bool
try_conversation_call_dissector_helper(conversation_t *conversation, bool* dissector_success,
        tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data)
{
    if (!conversation->dissector_tree) {
        return false;
    }

    int ret;
    dissector_handle_t handle = (dissector_handle_t)wmem_tree_lookup32_le(
            conversation->dissector_tree, pinfo->num);
    if (handle == NULL) {
        return false;
    }

    ret = call_dissector_only(handle, tvb, pinfo, tree, data);

    /* Let the caller decide what to do with success or rejection */
    (*dissector_success) = (ret != 0);

    return true;
}

/*
 * Given two address/port pairs for a packet, search for a matching
 * conversation and, if found and it has a conversation dissector,
 * call that dissector and return true, otherwise return false.
 *
 * This helper uses call_dissector_only which will NOT call the default
 * "data" dissector if the packet was rejected.
 * Our caller is responsible to call the data dissector explicitly in case
 * this function returns false.
 */
bool
try_conversation_dissector(const address *addr_a, const address *addr_b, const conversation_type ctype,
        const uint32_t port_a, const uint32_t port_b, tvbuff_t *tvb, packet_info *pinfo,
        proto_tree *tree, void* data, const unsigned options)
{
    conversation_t *conversation;
    bool dissector_success;

    /*
     * Verify that the correct options are used, if any.
     */
    DISSECTOR_ASSERT_HINT((options == 0) || (options & NO_MASK_B), "Use NO_ADDR_B and/or NO_PORT_B as option");

    /* Try each mode based on option flags */
    conversation = find_conversation(pinfo->num, addr_a, addr_b, ctype, port_a, port_b, 0);
    if (conversation != NULL) {
        if (try_conversation_call_dissector_helper(conversation, &dissector_success, tvb, pinfo, tree, data))
            return dissector_success;
    }

    if (options & NO_ADDR_B) {
        conversation = find_conversation(pinfo->num, addr_a, addr_b, ctype, port_a, port_b, NO_ADDR_B);
        if (conversation != NULL) {
            if (try_conversation_call_dissector_helper(conversation, &dissector_success, tvb, pinfo, tree, data))
                return dissector_success;
        }
    }

    if (options & NO_PORT_B) {
        conversation = find_conversation(pinfo->num, addr_a, addr_b, ctype, port_a, port_b, NO_PORT_B);
        if (conversation != NULL) {
            if (try_conversation_call_dissector_helper(conversation, &dissector_success, tvb, pinfo, tree, data))
                return dissector_success;
        }
    }

    if (options & (NO_ADDR_B|NO_PORT_B)) {
        conversation = find_conversation(pinfo->num, addr_a, addr_b, ctype, port_a, port_b, NO_ADDR_B|NO_PORT_B);
        if (conversation != NULL) {
            if (try_conversation_call_dissector_helper(conversation, &dissector_success, tvb, pinfo, tree, data))
                return dissector_success;
        }
    }

    return false;
}

bool
try_conversation_dissector_by_id(const conversation_type ctype, const uint32_t id, tvbuff_t *tvb,
        packet_info *pinfo, proto_tree *tree, void* data)
{
    conversation_t *conversation;

    conversation = find_conversation_by_id(pinfo->num, ctype, id);

    if (conversation != NULL) {
        if (!conversation->dissector_tree) {
            return false;
        }

        int ret;
        dissector_handle_t handle = (dissector_handle_t)wmem_tree_lookup32_le(conversation->dissector_tree, pinfo->num);

        if (handle == NULL) {
            return false;
        }

        ret = call_dissector_only(handle, tvb, pinfo, tree, data);
        if (!ret) {
            /* this packet was rejected by the dissector
             * so return false in case our caller wants
             * to do some cleaning up.
             */
            return false;
        }
        return true;
    }
    return false;
}

/* identifies a conversation ("classic" or deinterlaced) */
conversation_t *
find_conversation_strat(const packet_info *pinfo, const conversation_type ctype, const unsigned options)
{
  conversation_t *conv=NULL;

  if(prefs.conversation_deinterlacing_key>0) {
    conversation_t *underlying_conv = find_conversation_deinterlacer_pinfo(pinfo);
    if(underlying_conv) {
        conv = find_conversation_deinterlaced(pinfo->num, &pinfo->src, &pinfo->dst, ctype, pinfo->srcport, pinfo->destport, underlying_conv->conv_index, options);
    }
  }
  else {
      conv = find_conversation(pinfo->num, &pinfo->src, &pinfo->dst, ctype, pinfo->srcport, pinfo->destport, options);
  }

  return conv;
}

/**  A helper function that calls find_conversation() using data from pinfo
 *  The frame number and addresses are taken from pinfo.
 */
conversation_t *
find_conversation_pinfo(const packet_info *pinfo, const unsigned options)
{
    conversation_t *conv = NULL;

    DINSTR(char *src_str = address_to_str(NULL, &pinfo->src));
    DINSTR(char *dst_str = address_to_str(NULL, &pinfo->dst));
    DPRINT(("called for frame #%u: %s:%d -> %s:%d (ptype=%d)",
                pinfo->num, src_str, pinfo->srcport,
                dst_str, pinfo->destport, pinfo->ptype));
    DINDENT();
    DINSTR(wmem_free(NULL, src_str));
    DINSTR(wmem_free(NULL, dst_str));

    /* Have we seen this conversation before? */
    if (pinfo->use_conv_addr_port_endpoints) {
        DISSECTOR_ASSERT(pinfo->conv_addr_port_endpoints);
        if ((conv = find_conversation(pinfo->num, &pinfo->conv_addr_port_endpoints->addr1, &pinfo->conv_addr_port_endpoints->addr2,
                        pinfo->conv_addr_port_endpoints->ctype, pinfo->conv_addr_port_endpoints->port1,
                        pinfo->conv_addr_port_endpoints->port2, 0)) != NULL) {
            DPRINT(("found previous conversation for frame #%u (last_frame=%d)",
                    pinfo->num, conv->last_frame));
            if (pinfo->num > conv->last_frame) {
                conv->last_frame = pinfo->num;
            }
        }
    } else if (pinfo->conv_elements) {
        if ((conv = find_conversation_full(pinfo->num, pinfo->conv_elements)) != NULL) {
            DPRINT(("found previous conversation elements for frame #%u (last_frame=%d)",
                        pinfo->num, conv->last_frame));
            if (pinfo->num > conv->last_frame) {
                conv->last_frame = pinfo->num;
            }
        }
    } else {
        if ((conv = find_conversation(pinfo->num, &pinfo->src, &pinfo->dst,
                        conversation_pt_to_conversation_type(pinfo->ptype), pinfo->srcport,
                        pinfo->destport, options)) != NULL) {
            DPRINT(("found previous conversation for frame #%u (last_frame=%d)",
                        pinfo->num, conv->last_frame));
            if (pinfo->num > conv->last_frame) {
                conv->last_frame = pinfo->num;
            }
        }
    }

    DENDENT();

    return conv;
}

/**  A helper function that calls find_conversation() using data from pinfo,
 *  as above, but somewhat simplified for being accessed from packet_list.
 *  The frame number and addresses are taken from pinfo.
 */
conversation_t *
find_conversation_pinfo_ro(const packet_info *pinfo, const unsigned options)
{
    conversation_t *conv = NULL;

    DINSTR(char *src_str = address_to_str(NULL, &pinfo->src));
    DINSTR(char *dst_str = address_to_str(NULL, &pinfo->dst));
    DPRINT(("called for frame #%u: %s:%d -> %s:%d (ptype=%d)",
                pinfo->num, src_str, pinfo->srcport,
                dst_str, pinfo->destport, pinfo->ptype));
    DINDENT();
    DINSTR(wmem_free(NULL, src_str));
    DINSTR(wmem_free(NULL, dst_str));

    /* Have we seen this conversation before? */
    if (pinfo->use_conv_addr_port_endpoints) {
        DISSECTOR_ASSERT(pinfo->conv_addr_port_endpoints);
        if ((conv = find_conversation(pinfo->num, &pinfo->conv_addr_port_endpoints->addr1, &pinfo->conv_addr_port_endpoints->addr2,
                        pinfo->conv_addr_port_endpoints->ctype, pinfo->conv_addr_port_endpoints->port1,
                        pinfo->conv_addr_port_endpoints->port2, 0)) != NULL) {
            DPRINT(("found previous conversation for frame #%u (last_frame=%d)",
                    pinfo->num, conv->last_frame));
        }
    } else if (pinfo->conv_elements) {
        if ((conv = find_conversation_full(pinfo->num, pinfo->conv_elements)) != NULL) {
            DPRINT(("found previous conversation elements for frame #%u (last_frame=%d)",
                        pinfo->num, conv->last_frame));
        }
    } else {
        if ((conv = find_conversation_strat(pinfo, conversation_pt_to_conversation_type(pinfo->ptype), options)) != NULL) {
            DPRINT(("found previous conversation for frame #%u (last_frame=%d)",
                        pinfo->num, conv->last_frame));
        }
        /* else: something is either not implemented or not handled,
         * ICMP Type 3/11 are good examples. */
    }

    DENDENT();

    return conv;
}

/*  A helper function that calls find_conversation() and, if a conversation is
 *  not found, calls conversation_new().
 *  The frame number and addresses are taken from pinfo.
 *  No options are used, though we could extend this API to include an options
 *  parameter.
 */
conversation_t *
find_or_create_conversation(packet_info *pinfo)
{
    conversation_t *conv=NULL;

    /* Have we seen this conversation before? */
    if ((conv = find_conversation_pinfo(pinfo, 0)) == NULL) {
        /* No, this is a new conversation. */
        DPRINT(("did not find previous conversation for frame #%u",
                    pinfo->num));
        DINDENT();
        if (pinfo->use_conv_addr_port_endpoints) {
            conv = conversation_new(pinfo->num, &pinfo->conv_addr_port_endpoints->addr1, &pinfo->conv_addr_port_endpoints->addr2,
                        pinfo->conv_addr_port_endpoints->ctype, pinfo->conv_addr_port_endpoints->port1,
                        pinfo->conv_addr_port_endpoints->port2, 0);
        } else if (pinfo->conv_elements) {
            conv = conversation_new_full(pinfo->num, pinfo->conv_elements);
        } else {
            conv = conversation_new(pinfo->num, &pinfo->src,
                    &pinfo->dst, conversation_pt_to_conversation_type(pinfo->ptype),
                    pinfo->srcport, pinfo->destport, 0);
        }
        DENDENT();
    }

    return conv;
}

conversation_t *
find_or_create_conversation_by_id(packet_info *pinfo, const conversation_type ctype, const uint32_t id)
{
    conversation_t *conv=NULL;

    /* Have we seen this conversation before? */
    if ((conv = find_conversation_by_id(pinfo->num, ctype, id)) == NULL) {
        /* No, this is a new conversation. */
        DPRINT(("did not find previous conversation for frame #%u",
                    pinfo->num));
        DINDENT();
        conv = conversation_new_by_id(pinfo->num, ctype, id);
        DENDENT();
    }

    return conv;
}

void
conversation_set_conv_addr_port_endpoints(struct _packet_info *pinfo, address* addr1, address* addr2,
        conversation_type ctype, uint32_t port1, uint32_t port2)
{
    pinfo->conv_addr_port_endpoints = wmem_new0(pinfo->pool, struct conversation_addr_port_endpoints);

    if (addr1 != NULL) {
        copy_address_wmem(pinfo->pool, &pinfo->conv_addr_port_endpoints->addr1, addr1);
    }
    if (addr2 != NULL) {
        copy_address_wmem(pinfo->pool, &pinfo->conv_addr_port_endpoints->addr2, addr2);
    }

    pinfo->conv_addr_port_endpoints->ctype = ctype;
    pinfo->conv_addr_port_endpoints->port1 = port1;
    pinfo->conv_addr_port_endpoints->port2 = port2;

    pinfo->use_conv_addr_port_endpoints = true;
}

void
conversation_set_elements_by_id(struct _packet_info *pinfo, conversation_type ctype, uint32_t id)
{
    pinfo->conv_elements = wmem_alloc0(pinfo->pool, sizeof(conversation_element_t) * 2);
    pinfo->conv_elements[0].type = CE_UINT;
    pinfo->conv_elements[0].uint_val = id;
    pinfo->conv_elements[1].type = CE_CONVERSATION_TYPE;
    pinfo->conv_elements[1].conversation_type_val = ctype;
}

uint32_t
conversation_get_id_from_elements(struct _packet_info *pinfo, conversation_type ctype, const unsigned options)
{
    if (pinfo->conv_elements == NULL) {
        return 0;
    }

    if (pinfo->conv_elements[0].type != CE_UINT || pinfo->conv_elements[1].type != CE_CONVERSATION_TYPE) {
        return 0;
    }

    if ((pinfo->conv_elements[1].conversation_type_val != ctype) && ((options & USE_LAST_ENDPOINT) != USE_LAST_ENDPOINT)) {
        return 0;
    }

    return pinfo->conv_elements[0].uint_val;
}

wmem_map_t *
get_conversation_hashtables(void)
{
    return conversation_hashtable_element_list;
}

const address*
conversation_key_addr1(const conversation_element_t *key)
{
    const address *addr = &null_address_;
    if (key[ADDR1_IDX].type == CE_ADDRESS) {
        addr = &key[ADDR1_IDX].addr_val;
    }
    return addr;
}

uint32_t
conversation_key_port1(const conversation_element_t * key)
{
    uint32_t port = 0;
    if (key[ADDR1_IDX].type == CE_ADDRESS && key[PORT1_IDX].type == CE_PORT) {
        port = key[PORT1_IDX].port_val;
    }
    return port;
}

const address*
conversation_key_addr2(const conversation_element_t * key)
{
    const address *addr = &null_address_;
    if (key[ADDR1_IDX].type == CE_ADDRESS && key[PORT1_IDX].type == CE_PORT && key[ADDR2_IDX].type == CE_ADDRESS) {
        addr = &key[ADDR2_IDX].addr_val;
    }
    return addr;
}

uint32_t
conversation_key_port2(const conversation_element_t * key)
{
    uint32_t port = 0;
    if (key[ADDR1_IDX].type == CE_ADDRESS && key[PORT1_IDX].type == CE_PORT) {
        if (key[ADDR2_IDX].type == CE_ADDRESS && key[PORT2_IDX].type == CE_PORT) {
            // Exact
            port = key[PORT2_IDX].port_val;
        } else if (key[PORT2_NO_ADDR2_IDX].type == CE_PORT) {
            // No addr 2
            port = key[PORT2_NO_ADDR2_IDX].port_val;
        }
    }
    return port;
}

WS_DLL_PUBLIC
conversation_type conversation_pt_to_conversation_type(port_type pt)
{
    switch (pt)
    {
        case PT_NONE:
            return CONVERSATION_NONE;
        case PT_SCTP:
            return CONVERSATION_SCTP;
        case PT_TCP:
            return CONVERSATION_TCP;
        case PT_UDP:
            return CONVERSATION_UDP;
        case PT_DCCP:
            return CONVERSATION_DCCP;
        case PT_IPX:
            return CONVERSATION_IPX;
        case PT_DDP:
            return CONVERSATION_DDP;
        case PT_IDP:
            return CONVERSATION_IDP;
        case PT_USB:
            return CONVERSATION_USB;
        case PT_I2C:
            /* XXX - this doesn't currently have conversations */
            return CONVERSATION_I2C;
        case PT_IBQP:
            return CONVERSATION_IBQP;
        case PT_BLUETOOTH:
            return CONVERSATION_BLUETOOTH;
        case PT_IWARP_MPA:
            return CONVERSATION_IWARP_MPA;
        case PT_MCTP:
            return CONVERSATION_MCTP;
    }

    DISSECTOR_ASSERT(false);
    return CONVERSATION_NONE;
}

WS_DLL_PUBLIC
endpoint_type conversation_pt_to_endpoint_type(port_type pt)
{
    switch (pt)
    {
        case PT_NONE:
            return ENDPOINT_NONE;
        case PT_SCTP:
            return ENDPOINT_SCTP;
        case PT_TCP:
            return ENDPOINT_TCP;
        case PT_UDP:
            return ENDPOINT_UDP;
        case PT_DCCP:
            return ENDPOINT_DCCP;
        case PT_IPX:
            return ENDPOINT_IPX;
        case PT_DDP:
            return ENDPOINT_DDP;
        case PT_IDP:
            return ENDPOINT_IDP;
        case PT_USB:
            return ENDPOINT_USB;
        case PT_I2C:
            /* XXX - this doesn't have ports */
            return ENDPOINT_I2C;
        case PT_IBQP:
            return ENDPOINT_IBQP;
        case PT_BLUETOOTH:
            return ENDPOINT_BLUETOOTH;
        case PT_IWARP_MPA:
            return ENDPOINT_IWARP_MPA;
        case PT_MCTP:
            return ENDPOINT_MCTP;
    }

    DISSECTOR_ASSERT(false);
    return ENDPOINT_NONE;
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
