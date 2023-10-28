/*
 *  tst_malloc.c
 *  
 *	Copyright 2007-13 VOSTROM Holdings, Inc.  
 *  This file is part of the Distribution.  See the file COPYING for details.
 */
 
#include <stdlib.h>
#include "tst_malloc.h"
#include "logger.h"

static size_t global_allocated_counter=0;

void * tst_malloc(size_t size)
{
	void * ret;
	size_t * hdr;
	global_allocated_counter+=size+sizeof(size_t);
	hdr=(size_t *)malloc(size+sizeof(size_t));
	if(hdr == NULL)
	{
		log_printf(0, "Not enough memory. Currently allocated: %lu. Requested: %lu.\n",global_allocated_counter-size-sizeof(size_t), size);
		exit(1);
	}
	hdr[0]=size+sizeof(size_t);
	hdr++;
	ret=(void *)hdr;
	return ret;
}

void * tst_calloc(size_t count, size_t size)
{
	return tst_malloc(count * size);
}

void tst_free(void * ptr)
{
	size_t * hdr=(size_t *)ptr;
	hdr--;
	global_allocated_counter-=hdr[0];
	free((void *)hdr);
}

void * tst_realloc(void * ptr, size_t size)
{
	size_t * hdr=(size_t *)ptr;
	size_t oldsize;
	if (ptr) {
		hdr--;
		oldsize=hdr[0];
	} else
		oldsize=0;
	ptr=realloc(hdr, size+sizeof(size_t));
	if (ptr == NULL)
	{
		log_printf(0, "Not enough memory. Currently allocated: %lu. Requested: %lu.\n",global_allocated_counter, size-oldsize-(oldsize==0?sizeof(size_t):0));
		exit(1);
	}
	hdr=(size_t *)ptr;
	hdr[0]=size+sizeof(size_t);
	global_allocated_counter+=size+sizeof(size_t);
	if (oldsize>0)
		global_allocated_counter-=oldsize;
	hdr++;
	return hdr;
}

size_t tst_allocated()
{
	return global_allocated_counter;
}
