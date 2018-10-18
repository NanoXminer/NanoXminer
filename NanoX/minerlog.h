#ifndef __MINERLOG_H
#define __MINERLOG_H

#include <stdint.h>

// Log levels
#define LOG_INVALID		0UL
#define LOG_CRITICAL	1UL
#define LOG_ERROR		2UL
#define LOG_NOTIFY		3UL
#define LOG_INFO		4UL
#define LOG_ADVINFO		5UL
#define LOG_DEBUG		6UL
#define LOG_NETDEBUG	7UL

void Log(uint32_t MsgLevel, char *Msg, ...);
void InitLogging(uint32_t DesiredLogLevel);

#endif
