#ifndef __MINERUTILS_H
#define __MINERUTILS_H

#include <stdlib.h>
#include <stdint.h>
#include <stdbool.h>
#include <time.h>

// Endian swapping routines
uint32_t BSWAP32(uint32_t data);
void SwapBuffer32(void *data, int chunks);

// ASCII <-> binary conversion routines
int ASCIIHexToBinary(void *restrict rawstr, const char *restrict asciistr, size_t len);
void BinaryToASCIIHex(char *restrict asciistr, const void *restrict rawstr, size_t len);

// File reading routine
size_t LoadTextFile(char **Output, char *Filename);

// Difficulty conversion & validity testing routines
void CreateTargetFromDiff(uint32_t *FullTarget, double Diff);
bool FullTest(const uint32_t *Hash, const uint32_t *FullTarget);

// Time routines

#ifdef __linux__

#define TIME_TYPE	struct timespec

#else

#define TIME_TYPE	clock_t

#endif

TIME_TYPE MinerGetCurTime(void);
double SecondsElapsed(TIME_TYPE Start, TIME_TYPE End);

#endif
