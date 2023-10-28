/*
 *  logger.c
 *  
 *	Copyright 2007 VOSTROM Holdings, Inc.  
 *  This file is part of the Distribution.  See the file COPYING for details.
 */

#include <stdio.h>
#include <string.h>
#include <stdarg.h>
#include <pthread.h>
#include <errno.h>
#include <syslog.h>
#include "logger.h"
#include "timeformat.h"

static FILE * logFile=NULL;
int useSyslog=0;
int mutexInitialized=0;
int currentLevel=0;
static pthread_mutex_t mutex;
extern char PROGNAMESHORT[];

int initLogger(char * fname)
{
	int ret=0;
	if(logFile || useSyslog)
		return -1;
	if(!mutexInitialized)
	{
		pthread_mutex_init(&mutex, NULL);
		mutexInitialized=1;
	}
	pthread_mutex_lock(&mutex);
    if(strncmp(fname,"syslog",6)==0)
    {
        useSyslog=1;
        setlogmask(LOG_UPTO (LOG_NOTICE));
        openlog(PROGNAMESHORT, LOG_CONS | LOG_PID | LOG_NDELAY, LOG_LOCAL1);
        ret=0;
	}
	else if(fname && strlen(fname)>0)
	{
		logFile=fopen(fname,"at");
		if(!logFile)
		{
			ret=errno;
		}
		else
			ret=0;
	}
	else
	{
		logFile=stdout;
	}
    pthread_mutex_unlock(&mutex);
	return ret;
}

int inc_verbose_level()
{
	return ++currentLevel;
}

void log_printf(int level, const char *templ, ...)
{
	va_list ap;
	char buf[1024], tmstr[201];

	if(!logFile && !useSyslog)
		return;
	if(level>currentLevel)
		return;
	va_start (ap, templ);
	vsprintf(buf, templ, ap);
	va_end (ap);
	pthread_mutex_lock(&mutex);
	if(useSyslog) 
    {
        syslog(LOG_NOTICE, "%s", buf);
    }	
	else if(logFile)
	{
        GetCurrentSysLogDateTime(CurrentTime(), tmstr, 200);
		fprintf(logFile, "%s: %s", tmstr, buf);
		fflush(logFile);
	}
	pthread_mutex_unlock(&mutex);
}

void closeLogger()
{
	if(!logFile && !useSyslog)
		return;
	pthread_mutex_lock(&mutex);
	if(useSyslog) 
	   closelog();   
	if(logFile)
		fclose(logFile);
	logFile=NULL;
	pthread_mutex_unlock(&mutex);
}
