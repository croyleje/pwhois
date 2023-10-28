/*
 *  tst_malloc.h
 *  
 *	Copyright 2007-13 VOSTROM Holdings, Inc.  
 *  This file is part of the Distribution.  See the file COPYING for details.
 */

void * tst_calloc(size_t count, size_t size);
void * tst_malloc(size_t size);
void tst_free(void * ptr);
void * tst_realloc(void * ptr, size_t size);
size_t tst_allocated();
