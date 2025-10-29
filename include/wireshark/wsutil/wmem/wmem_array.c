/* wmem_array.c
 * Wireshark Memory Manager Array
 * Copyright 2013, Evan Huus <eapache@gmail.com>
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "config.h"

#include <string.h>
#include <stdlib.h>
#include <glib.h>

#include "wmem_core.h"
#include "wmem_array.h"

/* Holds a wmem-allocated array.
 *  elem_len is the size of each element
 *  elem_count is the number of used elements
 *  alloc_count is the length (in elems) of the raw buffer pointed to by buf,
 *      regardless of how many elems are used (the contents)
 */
struct _wmem_array_t {
    wmem_allocator_t *allocator;

    uint8_t *buf;

    size_t elem_size;

    unsigned elem_count;
    unsigned alloc_count;

    bool null_terminated;
};

wmem_array_t *
wmem_array_sized_new(wmem_allocator_t *allocator, size_t elem_size,
                     unsigned alloc_count)
{
    wmem_array_t *array;

    array = wmem_new(allocator, wmem_array_t);

    array->allocator   = allocator;
    array->elem_size   = elem_size;
    array->elem_count  = 0;
    array->alloc_count = alloc_count ? alloc_count : 1;
    array->null_terminated = false;

    array->buf = (uint8_t *)wmem_alloc(array->allocator,
            array->elem_size * array->alloc_count);

    return array;
}

wmem_array_t *
wmem_array_new(wmem_allocator_t *allocator, const size_t elem_size)
{
    wmem_array_t *array;

    array = wmem_array_sized_new(allocator, elem_size, 1);

    return array;
}

void
wmem_array_grow(wmem_array_t *array, const unsigned to_add)
{
    unsigned new_alloc_count, new_count;

    new_alloc_count = array->alloc_count;
    new_count = array->elem_count + to_add;

    while (new_alloc_count < new_count) {
        new_alloc_count *= 2;
    }

    if (new_alloc_count == array->alloc_count) {
        return;
    }

    array->buf = (uint8_t *)wmem_realloc(array->allocator, array->buf,
            new_alloc_count * array->elem_size);

    array->alloc_count = new_alloc_count;
}

static void
wmem_array_write_null_terminator(wmem_array_t *array)
{
    if (array->null_terminated) {
        wmem_array_grow(array, 1);
        memset(&array->buf[array->elem_count * array->elem_size], 0x0, array->elem_size);
    }
}

void
wmem_array_set_null_terminator(wmem_array_t *array)
{
    array->null_terminated = true;
    wmem_array_write_null_terminator(array);
}

void
wmem_array_bzero(wmem_array_t *array)
{
    memset(array->buf, 0x0, array->elem_size * array->elem_count);
}

void
wmem_array_append(wmem_array_t *array, const void *in, unsigned count)
{
    wmem_array_grow(array, count);

    memcpy(&array->buf[array->elem_count * array->elem_size], in,
            count * array->elem_size);

    array->elem_count += count;

    wmem_array_write_null_terminator(array);
}

void *
wmem_array_index(wmem_array_t *array, unsigned array_index)
{
    g_assert(array_index < array->elem_count);
    return &array->buf[array_index * array->elem_size];
}

int
wmem_array_try_index(wmem_array_t *array, unsigned array_index, void *val)
{
    if (array_index >= array->elem_count)
        return -1;
    memcpy(val, &array->buf[array_index * array->elem_size], array->elem_size);
    return 0;
}

void
wmem_array_sort(wmem_array_t *array, int (*compar)(const void*,const void*))
{
    qsort(array->buf, array->elem_count, array->elem_size, compar);
}

void *
wmem_array_get_raw(wmem_array_t *array)
{
    return array->buf;
}

unsigned
wmem_array_get_count(wmem_array_t *array)
{
    if (array == NULL)
        return 0;

    return array->elem_count;
}

wmem_allocator_t*
wmem_array_get_allocator(wmem_array_t* array)
{
    if (array == NULL)
        return NULL;

    return array->allocator;
}

void *
wmem_array_finalize(wmem_array_t *array)
{
    if (array == NULL)
        return NULL;

    size_t used_size = array->null_terminated ? (array->elem_count + 1) * array->elem_size : array->elem_count * array->elem_size;
    void *ret = wmem_realloc(array->allocator, array->buf, used_size);

    wmem_free(array->allocator, array);

    return ret;
}

void
wmem_destroy_array(wmem_array_t *array)
{
    wmem_free(array->allocator, array->buf);
    wmem_free(array->allocator, array);
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
