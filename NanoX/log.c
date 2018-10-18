#include <stdio.h>
#include <stdint.h>
#include <stdarg.h>
#include <pthread.h>
#include "minerlog.h"

pthread_mutex_t LogMutex = PTHREAD_MUTEX_INITIALIZER;
static uint32_t LogLevel = LOG_INVALID;

void Log(uint32_t MsgLevel, char *Msg, ...)
{
	va_list args;
	time_t rawtime;
	char timebuf[128];
	struct tm *curtime;
	
	if(MsgLevel <= LogLevel && LogLevel != LOG_INVALID)
	{
		time(&rawtime);
		curtime = localtime(&rawtime);
		strftime(timebuf, 128, "[%H:%M:%S] ", curtime);
		
		pthread_mutex_lock(&LogMutex);
		
		printf(timebuf);
		
		va_start(args, Msg);
		vprintf(Msg, args);
		va_end(args);
		putchar('\n');
		
		pthread_mutex_unlock(&LogMutex);
	}
	
	return;
}

void InitLogging(uint32_t DesiredLogLevel)
{
	LogLevel = DesiredLogLevel;
	return;
}
