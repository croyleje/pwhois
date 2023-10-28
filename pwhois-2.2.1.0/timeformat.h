/*
 *  timeformat.h
 *  
 *	Copyright 2007 VOSTROM Holdings, Inc.  
 *  This file is part of the Distribution.  See the file COPYING for details.
 */
#ifndef TIMEFORMAT_H
#define TIMEFORMAT_H

#include<time.h>

void GetDateTimeFormat(time_t clock, char * outp, int sz);
void GetRpslDateFormat(time_t clock, char * outp, int sz);
void GetCymruDateFormat(time_t clock, char * outp, int sz);
void GetSyslogDateTime(time_t clock, char * outp, int sz);
void GetCurrentSysLogDateTime(time_t clock, char * outp, int sz);
time_t CurrentTime();
int day_dates_diff(time_t clock1, time_t clock2);

#endif

/* EOF */

