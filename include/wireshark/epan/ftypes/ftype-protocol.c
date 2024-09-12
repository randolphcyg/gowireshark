/*
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 2001 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "config.h"

#include <ftypes-int.h>
#include <epan/to_str.h>
#include <string.h>
#include <wsutil/array.h>

#include <epan/exceptions.h>
#include <wsutil/ws_assert.h>

static void
value_new(fvalue_t *fv)
{
	fv->value.protocol.tvb = NULL;
	fv->value.protocol.proto_string = NULL;
	fv->value.protocol.tvb_is_private = false;
	fv->value.protocol.length = -1;
}

static void
value_copy(fvalue_t *dst, const fvalue_t *src)
{
	dst->value.protocol.tvb = tvb_clone(src->value.protocol.tvb);
	dst->value.protocol.proto_string = g_strdup(src->value.protocol.proto_string);
	dst->value.protocol.tvb_is_private = true;
	dst->value.protocol.length = src->value.protocol.length;
}

static void
value_free(fvalue_t *fv)
{
	if (fv->value.protocol.tvb && fv->value.protocol.tvb_is_private) {
		tvb_free_chain(fv->value.protocol.tvb);
	}
	g_free(fv->value.protocol.proto_string);
}

static void
value_set(fvalue_t *fv, tvbuff_t *value, const char *name, int length)
{
	if (value != NULL) {
		/* Free up the old value, if we have one */
		value_free(fv);

		/* Set the protocol description and an (optional, nullable) tvbuff. */
		fv->value.protocol.tvb = value;
		fv->value.protocol.proto_string = g_strdup(name);
	}
	fv->value.protocol.length = length;
}

static bool
val_from_string(fvalue_t *fv, const char *s, size_t len, char **err_msg _U_)
{
	tvbuff_t *new_tvb;
	uint8_t *private_data;

	/* Free up the old value, if we have one */
	value_free(fv);

	if (len == 0)
		len = strlen(s);

	/* Make a tvbuff from the string. We can drop the
	 * terminating NUL. */
	private_data = (uint8_t *)g_memdup2(s, (unsigned)len);
	new_tvb = tvb_new_real_data(private_data,
			(unsigned)len, (int)len);

	/* Let the tvbuff know how to delete the data. */
	tvb_set_free_cb(new_tvb, g_free);

	/* And let us know that we need to free the tvbuff */
	fv->value.protocol.tvb_is_private = true;
	/* This "field" is a value, it has no protocol description, but
	 * we might compare it to a protocol with NULL tvb.
	 * (e.g., proto_expert) */
	fv->value.protocol.tvb = new_tvb;
	fv->value.protocol.proto_string = g_strdup("");
	fv->value.protocol.length = -1;
	return true;
}

static bool
val_from_literal(fvalue_t *fv, const char *s, bool allow_partial_value _U_, char **err_msg)
{
	GByteArray *bytes;
	tvbuff_t *new_tvb;

	/* Free up the old value, if we have one */
	value_free(fv);
	fv->value.protocol.tvb = NULL;
	fv->value.protocol.proto_string = NULL;
	fv->value.protocol.length = -1;

	/* Does this look like a byte string? */
	bytes = byte_array_from_literal(s, err_msg);
	if (bytes != NULL) {
		/* Make a tvbuff from the bytes */
		new_tvb = tvb_new_real_data(bytes->data, bytes->len, bytes->len);

		/* Let the tvbuff know how to delete the data. */
		tvb_set_free_cb(new_tvb, g_free);

		/* Free GByteArray, but keep data. */
		g_byte_array_free(bytes, false);

		/* And let us know that we need to free the tvbuff */
		fv->value.protocol.tvb_is_private = true;
		fv->value.protocol.tvb = new_tvb;

		/* This "field" is a value, it has no protocol description, but
		 * we might compare it to a protocol with NULL tvb.
		 * (e.g., proto_expert) */
		fv->value.protocol.proto_string = g_strdup("");
		return true;
	}

	/* Not a byte array, forget about it. */
	return false;
}

static bool
val_from_charconst(fvalue_t *fv, unsigned long num, char **err_msg)
{
	GByteArray *bytes;
	tvbuff_t *new_tvb;

	/* Free up the old value, if we have one */
	value_free(fv);
	fv->value.protocol.tvb = NULL;
	fv->value.protocol.proto_string = NULL;
	fv->value.protocol.length = -1;

	/* Does this look like a byte string? */
	bytes = byte_array_from_charconst(num, err_msg);
	if (bytes != NULL) {
		/* Make a tvbuff from the bytes */
		new_tvb = tvb_new_real_data(bytes->data, bytes->len, bytes->len);

		/* Let the tvbuff know how to delete the data. */
		tvb_set_free_cb(new_tvb, g_free);

		/* Free GByteArray, but keep data. */
		g_byte_array_free(bytes, false);

		/* And let us know that we need to free the tvbuff */
		fv->value.protocol.tvb_is_private = true;
		fv->value.protocol.tvb = new_tvb;

		/* This "field" is a value, it has no protocol description, but
		 * we might compare it to a protocol with NULL tvb.
		 * (e.g., proto_expert) */
		fv->value.protocol.proto_string = g_strdup("");
		return true;
	}

	/* Not a byte array, forget about it. */
	return false;
}

static char *
val_to_repr(wmem_allocator_t *scope, const fvalue_t *fv, ftrepr_t rtype, int field_display _U_)
{
	unsigned length;
	char *volatile buf = NULL;

	if (rtype != FTREPR_DFILTER)
		return NULL;

	TRY {
		if (fv->value.protocol.length >= 0)
			length = fv->value.protocol.length;
		else
			length = tvb_captured_length(fv->value.protocol.tvb);

		if (length) {
			if (rtype == FTREPR_DFILTER)
				buf = bytes_to_dfilter_repr(scope, tvb_get_ptr(fv->value.protocol.tvb, 0, length), length);
			else
				buf = bytes_to_str_punct_maxlen(scope, tvb_get_ptr(fv->value.protocol.tvb, 0, length), length, ':', 0);
		}
	}
	CATCH_ALL {
		/* nothing */
	}
	ENDTRY;
	return buf;
}

static tvbuff_t *
value_get(fvalue_t *fv)
{
	if (fv->value.protocol.length < 0)
		return fv->value.protocol.tvb;
	return tvb_new_subset_length_caplen(fv->value.protocol.tvb, 0, fv->value.protocol.length, fv->value.protocol.length);
}

static unsigned
len(fvalue_t *fv)
{
	volatile unsigned length = 0;

	TRY {
		if (fv->value.protocol.tvb) {
			if (fv->value.protocol.length >= 0)
				length = fv->value.protocol.length;
			else
				length = tvb_captured_length(fv->value.protocol.tvb);

		}
	}
	CATCH_ALL {
		/* nothing */
	}
	ENDTRY;

	return length;
}

static void
slice(fvalue_t *fv, GByteArray *bytes, unsigned offset, unsigned length)
{
	const uint8_t* data;
	volatile unsigned len = length;

	if (fv->value.protocol.tvb) {
		if (fv->value.protocol.length >= 0 && (unsigned)fv->value.protocol.length < len) {
			len = fv->value.protocol.length;
		}

		TRY {
			data = tvb_get_ptr(fv->value.protocol.tvb, offset, len);
			g_byte_array_append(bytes, data, len);
		}
		CATCH_ALL {
			/* nothing */
		}
		ENDTRY;

	}
}

static int
_tvbcmp(const protocol_value_t *a, const protocol_value_t *b)
{
	unsigned	a_len;
	unsigned	b_len;

	if (a->length < 0)
		a_len = tvb_captured_length(a->tvb);
	else
		a_len = a->length;

	if (b->length < 0)
		b_len = tvb_captured_length(b->tvb);
	else
		b_len = b->length;

	if (a_len != b_len)
		return a_len < b_len ? -1 : 1;
	return memcmp(tvb_get_ptr(a->tvb, 0, a_len), tvb_get_ptr(b->tvb, 0, a_len), a_len);
}

static enum ft_result
cmp_order(const fvalue_t *fv_a, const fvalue_t *fv_b, int *cmp)
{
	const protocol_value_t	*a = (const protocol_value_t *)&fv_a->value.protocol;
	const protocol_value_t	*b = (const protocol_value_t *)&fv_b->value.protocol;
	volatile int		c = 0;

	TRY {
		if ((a->tvb != NULL) && (b->tvb != NULL)) {
			c = _tvbcmp(a, b);
		} else {
			c = strcmp(a->proto_string, b->proto_string);
		}
	}
	CATCH_ALL {
		/* nothing */
	}
	ENDTRY;

	*cmp = c;
	return FT_OK;
}

static enum ft_result
cmp_contains(const fvalue_t *fv_a, const fvalue_t *fv_b, bool *contains)
{
	volatile bool yes = false;

	TRY {
		/* First see if tvb exists for both sides */
		if ((fv_a->value.protocol.tvb != NULL) && (fv_b->value.protocol.tvb != NULL)) {
			if (tvb_find_tvb(fv_a->value.protocol.tvb, fv_b->value.protocol.tvb, 0) > -1) {
				yes = true;
			}
		} else {
			/* Otherwise just compare strings */
			if ((strlen(fv_b->value.protocol.proto_string) != 0) &&
				strstr(fv_a->value.protocol.proto_string, fv_b->value.protocol.proto_string)) {
				yes = true;
			}
		}
	}
	CATCH_ALL {
		/* nothing */
	}
	ENDTRY;

	*contains = yes;
	return FT_OK;
}

static enum ft_result
cmp_matches(const fvalue_t *fv, const ws_regex_t *regex, bool *matches)
{
	const protocol_value_t *a = (const protocol_value_t *)&fv->value.protocol;
	volatile bool rc = false;
	const char *data = NULL; /* tvb data */
	uint32_t tvb_len; /* tvb length */

	if (! regex) {
		return FT_BADARG;
	}
	TRY {
		if (a->tvb != NULL) {
			tvb_len = tvb_captured_length(a->tvb);
			data = (const char *)tvb_get_ptr(a->tvb, 0, tvb_len);
			rc = ws_regex_matches_length(regex, data, tvb_len);
		} else {
			rc = ws_regex_matches(regex, a->proto_string);
		}
	}
	CATCH_ALL {
		rc = false;
	}
	ENDTRY;

	*matches = rc;
	return FT_OK;
}

static unsigned
val_hash(const fvalue_t *fv)
{
	const protocol_value_t *value = &fv->value.protocol;
	return g_direct_hash(value->tvb) ^ g_int_hash(&value->length) ^ g_str_hash(value->proto_string);
}

static bool
is_zero(const fvalue_t *fv)
{
	const protocol_value_t *a = &fv->value.protocol;
	return a->tvb == NULL && a->proto_string == NULL;
}

void
ftype_register_tvbuff(void)
{

	static const ftype_t protocol_type = {
		FT_PROTOCOL,			/* ftype */
		0,				/* wire_size */
		value_new,			/* new_value */
		value_copy,			/* copy_value */
		value_free,			/* free_value */
		val_from_literal,		/* val_from_literal */
		val_from_string,		/* val_from_string */
		val_from_charconst,		/* val_from_charconst */
		NULL,				/* val_from_uinteger64 */
		NULL,				/* val_from_sinteger64 */
		NULL,				/* val_from_double */
		val_to_repr,			/* val_to_string_repr */

		NULL,				/* val_to_uinteger64 */
		NULL,				/* val_to_sinteger64 */
		NULL,				/* val_to_double */

		{ .set_value_protocol = value_set },	/* union set_value */
		{ .get_value_protocol = value_get },	/* union get_value */

		cmp_order,
		cmp_contains,
		cmp_matches,

		val_hash,
		is_zero,
		NULL,
		len,
		(FvalueSlice)slice,
		NULL,
		NULL,				/* unary_minus */
		NULL,				/* add */
		NULL,				/* subtract */
		NULL,				/* multiply */
		NULL,				/* divide */
		NULL,				/* modulo */
	};


	ftype_register(FT_PROTOCOL, &protocol_type);
}

void
ftype_register_pseudofields_tvbuff(int proto)
{
	static int hf_ft_protocol;

	static hf_register_info hf_ftypes[] = {
		{ &hf_ft_protocol,
		    { "FT_PROTOCOL", "_ws.ftypes.protocol",
			FT_PROTOCOL, BASE_NONE, NULL, 0x00,
			NULL, HFILL }
		},
	};

	proto_register_field_array(proto, hf_ftypes, array_length(hf_ftypes));
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
