/*
 *  logger.h
 *  
 *	Copyright 2007 VOSTROM Holdings, Inc.  
 *  This file is part of the Distribution.  See the file COPYING for details.
 */

int initLogger(char * fname);
int inc_verbose_level();
void log_printf(int level, const char *templ, ...);
void closeLogger();

/* EOF */

