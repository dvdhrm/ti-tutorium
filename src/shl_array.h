/*
 * shl - Dynamic Array
 *
 * Copyright (c) 2011-2012 David Herrmann <dh.herrmann@googlemail.com>
 * Copyright (c) 2011 University of Tuebingen
 *
 * Permission is hereby granted, free of charge, to any person obtaining
 * a copy of this software and associated documentation files
 * (the "Software"), to deal in the Software without restriction, including
 * without limitation the rights to use, copy, modify, merge, publish,
 * distribute, sublicense, and/or sell copies of the Software, and to
 * permit persons to whom the Software is furnished to do so, subject to
 * the following conditions:
 *
 * The above copyright notice and this permission notice shall be included
 * in all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS
 * OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.
 * IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY
 * CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT,
 * TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE
 * SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
 */

/*
 * A dynamic array implementation
 */

#ifndef SHL_ARRAY_H
#define SHL_ARRAY_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>

struct shl_array {
	size_t element_size;
	size_t length;
	size_t size;
	void *data;
};

#define SHL_ARRAY_AT(_arr, _type, _pos) \
	(&((_type*)shl_array_get_array(_arr))[(_pos)])

static inline int shl_array_new(struct shl_array **out, size_t element_size,
				size_t initial_size)
{
	struct shl_array *arr;

	if (!out || !element_size)
		return -EINVAL;

	if (!initial_size)
		initial_size = 4;

	arr = malloc(sizeof(*arr));
	if (!arr)
		return -ENOMEM;
	memset(arr, 0, sizeof(*arr));
	arr->element_size = element_size;
	arr->length = 0;
	arr->size = initial_size;

	arr->data = malloc(arr->element_size * arr->size);
	if (!arr->data) {
		free(arr);
		return -ENOMEM;
	}

	*out = arr;
	return 0;
}

static inline void shl_array_free(struct shl_array *arr)
{
	if (!arr)
		return;

	free(arr->data);
	free(arr);
}

static inline int shl_array_push(struct shl_array *arr, const void *data)
{
	void *tmp;
	size_t newsize;

	if (!arr || !data)
		return -EINVAL;

	if (arr->length >= arr->size) {
		newsize = arr->size * 2;
		tmp = realloc(arr->data, arr->element_size * newsize);
		if (!tmp)
			return -ENOMEM;

		arr->data = tmp;
		arr->size = newsize;
	}

	memcpy(((uint8_t*)arr->data) + arr->element_size * arr->length,
	       data, arr->element_size);
	++arr->length;

	return 0;
}

static inline void shl_array_pop(struct shl_array *arr)
{
	if (!arr || !arr->length)
		return;

	--arr->length;
}

static inline void shl_array_reset(struct shl_array *arr)
{
	if (!arr)
		return;

	arr->length = 0;
}

static inline void *shl_array_get_array(struct shl_array *arr)
{
	if (!arr)
		return NULL;

	return arr->data;
}

static inline size_t shl_array_get_length(struct shl_array *arr)
{
	if (!arr)
		return 0;

	return arr->length;
}

static inline size_t shl_array_get_bsize(struct shl_array *arr)
{
	if (!arr)
		return 0;

	return arr->length * arr->element_size;
}

static inline size_t shl_array_get_element_size(struct shl_array *arr)
{
	if (!arr)
		return 0;

	return arr->element_size;
}

#endif /* SHL_ARRAY_H */
