#ifndef __MINER_H
#define __MINER_H

#include <stdint.h>
#include <jansson.h>
#include "ocl.h"

int32_t InitHashAlgoByName(char *HashName, AlgoContext *HashData, OCLPlatform *OCL, uint32_t DeviceIdx, json_t *AlgoSpecificOpts);

#define ERR_SUCCESS				0
#define ERR_STUPID_PARAMS		-1
#define ERR_OCL_API				-2
#define ERR_NO_SUCH_ALGO		-3

#endif
