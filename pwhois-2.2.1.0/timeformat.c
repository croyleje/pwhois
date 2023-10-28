/*
 *  timeformat.c
 *  
 *	Copyright 2007 VOSTROM Holdings, Inc.  
 *  This file is part of the Distribution.  See the file COPYING for details.
 */
#include "timeformat.h"


void GetDateTimeFormat(time_t clock, char * outp, int sz)
{
	struct tm tm;
    gmtime_r(&clock,&tm);
	strftime(outp, sz, "%b %d %Y %H:%M:%S", &tm);
}

void GetRpslDateFormat(time_t clock, char * outp, int sz)
{
	struct tm tm;
    gmtime_r(&clock,&tm);
	strftime(outp, sz, "%Y%m%d", &tm);
}

void GetCymruDateFormat(time_t clock, char * outp, int sz)
{
	struct tm tm;
    gmtime_r(&clock,&tm);
	strftime(outp, sz, "%Y-%m-%d %H:%M:%S", &tm);
}

int day_dates_diff(time_t clock1, time_t clock2)
{
	struct tm tm1,tm2;
    gmtime_r(&clock1,&tm1);
    gmtime_r(&clock2,&tm2);
    return (tm2.tm_year-tm1.tm_year)*365+(tm2.tm_yday-tm1.tm_yday);
}

void GetSyslogDateTime(time_t clock, char * outp, int sz)
{
	struct tm tm;
    gmtime_r(&clock,&tm);
	strftime(outp, sz, "%b %Od %Y %H:%M:%S", &tm);
}

void GetCurrentSysLogDateTime(time_t clock, char * outp, int sz)
{
	struct tm tm;
    gmtime_r(&clock,&tm);
	strftime(outp, sz, "%b %Od %Y %H:%M:%S", &tm);
}

time_t CurrentTime()
{
	time_t tm;
	time(&tm);
	return tm;
}
