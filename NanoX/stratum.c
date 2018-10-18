#include <stdint.h>
#include <string.h>
#include "sha256.h"
#include "stratum.h"
#include "minerutils.h"

// Returns buffer that must be freed in RawCoinbase, and
// length of said buffer as the return value
void CreateRawCoinbaseHash(	uint8_t *restrict RawCoinbaseHash, const uint8_t *restrict Coinbase1, const uint8_t *restrict Coinbase2, const uint8_t *restrict Extranonce1,
							const uint8_t *restrict Extranonce2, const uint8_t ENonce2Len)
{
	uint32_t Length = 0;
	uint8_t *RawCoinbase = (uint8_t *)malloc(sizeof(uint8_t) * ((strlen(Coinbase1) + strlen(Coinbase2) + strlen(Extranonce1) + (ENonce2Len << 1)) >> 1));
	
	Length += ASCIIHexToBinary(RawCoinbase, Coinbase1, strlen(Coinbase1));
	
	Length += ASCIIHexToBinary(RawCoinbase + Length, Extranonce1, strlen(Extranonce1));
		
	memcpy(RawCoinbase + Length, Extranonce2, ENonce2Len);
	Length += ENonce2Len;
	
	Length += ASCIIHexToBinary(RawCoinbase + Length, Coinbase2, strlen(Coinbase2));
	
	sha256d(RawCoinbaseHash, RawCoinbase, Length);
	free(RawCoinbase);
}

// Job MUST be a local copy
void StratumCreateBlockHeader(uint8_t *hdr, JobInfo *job, uint32_t enonce2)
{
	uint8_t *RawCoinbase, RawCoinbaseHash[32], MerkleRoot[64], temp[64];
	uint32_t RawHeaderLen;
	
	CreateRawCoinbaseHash(RawCoinbaseHash, job->Coinbase1, job->Coinbase2, job->Extranonce1, (uint8_t *)&enonce2, job->ENonce2Bytes);
	
	RawHeaderLen = ASCIIHexToBinary(hdr, job->Version, strlen(job->Version));
	
	RawHeaderLen += ASCIIHexToBinary(hdr + RawHeaderLen, job->PrevHash, strlen(job->PrevHash));
	
	memcpy(MerkleRoot, RawCoinbaseHash, 32);
	
	if(job->MerkleBranches)
	{
		for(int i = 0; job->MerkleBranches[i]; ++i)
		{
			uint8_t RawMerkleBranch[32];
			ASCIIHexToBinary(RawMerkleBranch, job->MerkleBranches[i], 64);
			memcpy(MerkleRoot + 32, RawMerkleBranch, 32);
			sha256d(temp, MerkleRoot, 64);
			memcpy(MerkleRoot, temp, 32);
		}
	}
	
	SwapBuffer32(MerkleRoot, 8);
	memcpy(hdr + RawHeaderLen, MerkleRoot, 32);
	RawHeaderLen += 32;
	
	RawHeaderLen += ASCIIHexToBinary(hdr + RawHeaderLen, job->Time, strlen(job->Time));
	
	RawHeaderLen += ASCIIHexToBinary(hdr + RawHeaderLen, job->NetworkDiff, strlen(job->NetworkDiff));	
	
	memset(hdr + RawHeaderLen, 0x00, 4);
	RawHeaderLen += 4;
		
	ASCIIHexToBinary(hdr + RawHeaderLen, "000000800000000000000000000000000000000000000000000000000000000000000000000000000000000080020000", 48 * 2);
}
