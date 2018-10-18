#ifndef __STRATUM_H
#define __STRATUM_H

#include <stdint.h>
#include <stdbool.h>

typedef struct _JobInfo
{
	uint8_t *ID;
	uint8_t *PrevHash;
	uint8_t *Extranonce1;
	uint8_t *Coinbase1;
	uint8_t *Coinbase2;
	uint8_t **MerkleBranches;
	uint8_t *Version;
	double Diff;
	double NewDiff;
	bool DiffIsOutdated;
	uint8_t *NetworkDiff;
	uint8_t *Time;
	uint8_t *XMRBlob;
	uint32_t XMRTarget;
	uint8_t ENonce2Bytes;
	uint32_t CurrentENonce2;
	bool Initialized;
} JobInfo;

#endif
