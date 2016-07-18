/*
 * DArray.h
 *
 *  Created on: Nov 18, 2014
 *      Author: wangzhiheng
 */

#ifndef DARRAY_H_
#define DARRAY_H_

#include <stdlib.h>
#include <stdio.h>

typedef struct {
	void ** data;
	int last;
	int size;
} DArray;

#if defined(__cplusplus) || defined(c_plusplus) //跨平台定义方法
extern "C"{
#endif

DArray * darray_init();

void darray_free(DArray *array);

void darray_resize(DArray *array, int size);

void * darray_get(DArray *array, int index);

void darray_set(DArray *array, int index, void *value);

void darray_push(DArray *array, void *value);

void * darray_pop(DArray *array);

DArray * darray_radix_sort(DArray *array);

#if defined(__cplusplus) || defined(c_plusplus)
}
#endif
#endif /* DARRAY_H_ */
