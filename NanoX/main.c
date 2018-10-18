#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <signal.h>
#include <unistd.h>
#include <pthread.h>
#include <stdbool.h>
#include <jansson.h>
#include <stdatomic.h>

#ifdef __linux__

#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <sched.h>

#else

#include <winsock2.h>

#endif

#include <CL/cl.h>

#include "cryptonight.h"
#include "minerutils.h"
#include "minerlog.h"
#include "minernet.h"
#include "stratum.h"
#include "miner.h"
#include "ocl.h"

#define STRATUM_TIMEOUT_SECONDS			120

// I know, it's lazy.
#define STRATUM_MAX_MESSAGE_LEN_BYTES	4096

typedef struct _StatusInfo
{
	uint64_t SolvedWork;
	uint64_t RejectedWork;
	double *ThreadHashCounts;
	double *ThreadTimes;
} StatusInfo;

pthread_mutex_t StatusMutex = PTHREAD_MUTEX_INITIALIZER;
StatusInfo GlobalStatus;

typedef struct _WorkerInfo
{
	char *User;
	char *Pass;
	struct _WorkerInfo *NextWorker;
} WorkerInfo;

typedef struct _PoolInfo
{
	SOCKET sockfd;
	char *PoolName;
	WorkerInfo WorkerData;
	uint32_t MinerThreadCount;
	uint32_t *MinerThreads;
	atomic_uint_least32_t StratumID;
	char XMRAuthID[64];
} PoolInfo;

atomic_bool *RestartMining;

pthread_mutex_t Mutex = PTHREAD_MUTEX_INITIALIZER;
bool ExitFlag = false;

pthread_mutex_t JobMutex = PTHREAD_MUTEX_INITIALIZER;
JobInfo CurrentJob;

typedef struct _Share
{
	uint32_t Nonce;
	struct _Share *next;
} Share;

typedef struct _ShareQueue
{
	Share *first;
	Share *last;
} ShareQueue;

void SubmitShare(ShareQueue *queue, Share *NewShare)
{
	NewShare->next = NULL;
	
	if(!queue->first) queue->first = queue->last = NewShare;
	else queue->last = queue->last->next = NewShare;
}

Share *RemoveShare(ShareQueue *queue)
{
	Share *tmp = queue->first;
	if(queue->first) queue->first = queue->first->next;	
	return(tmp);
}

void FreeShare(Share *share)
{
	free(share);
}

ShareQueue CurrentQueue;
pthread_mutex_t QueueMutex = PTHREAD_MUTEX_INITIALIZER;

typedef struct _PoolBroadcastInfo
{
	int poolsocket;
	WorkerInfo WorkerData;
} PoolBroadcastInfo;

// WARNING/TODO/FIXME: ID needs to be a global counter with atomic accesses
// TODO/FIXME: Check various calls for error
void *PoolBroadcastThreadProc(void *Info)
{
	uint64_t id = 10;
	PoolInfo *pbinfo = (PoolInfo *)Info;
	pthread_mutex_lock(&QueueMutex);
	CurrentQueue.first = CurrentQueue.last = NULL;
	pthread_mutex_unlock(&QueueMutex);
	
	for(;;)
	{
		// TODO/FIXME: Use nanosleep().
		while(pthread_mutex_trylock(&QueueMutex)) sleep(1);
		for(Share *CurShare = RemoveShare(&CurrentQueue); CurShare; CurShare = RemoveShare(&CurrentQueue))
		{
			uint32_t ShareNonce, ShareTime, ShareExtranonce2;
			char ASCIINonce[9], ASCIIResult[65], *temp, *rawsubmitrequest;
			json_t *msg, *params;
			uint8_t HashInput[76], HashResult[32];
			int bytes, ret;
			
			ShareNonce = CurShare->Nonce;
			BinaryToASCIIHex(ASCIINonce, &ShareNonce, 4U);
			
			msg = json_object();
			params = json_object();
			
			pthread_mutex_lock(&JobMutex);
			json_object_set_new(params, "id", json_string(pbinfo->XMRAuthID));
			json_object_set_new(params, "job_id", json_string(CurrentJob.ID));
			json_object_set_new(params, "nonce", json_string(ASCIINonce));
			
			ASCIIHexToBinary(HashInput, CurrentJob.XMRBlob, 76 * 2);
			pthread_mutex_unlock(&JobMutex);
			((uint32_t *)(HashInput + 39))[0] = ShareNonce;
			cryptonight_hash(HashResult, HashInput, 76);
			BinaryToASCIIHex(ASCIIResult, HashResult, 32);
			
			json_object_set_new(params, "result", json_string(ASCIIResult));
			
			json_object_set_new(msg, "method", json_string("submit"));
			json_object_set_new(msg, "params", params);
			json_object_set_new(msg, "id", json_integer(1));
			
			pthread_mutex_lock(&StatusMutex);
			GlobalStatus.SolvedWork++;
			pthread_mutex_unlock(&StatusMutex);
			
			temp = json_dumps(msg, JSON_PRESERVE_ORDER);
			Log(LOG_NETDEBUG, "Request: %s\n", temp);
			
			// TODO/FIXME: Check for super unlikely error here
			rawsubmitrequest = malloc(strlen(temp) + 16);
			strcpy(rawsubmitrequest, temp);
			
			// No longer needed
			json_decref(msg);
			
			// Add the very important Stratum newline
			strcat(rawsubmitrequest, "\n");
			
			bytes = 0;
				
			// Send the shit - but send() might not get it all out in one go.
			do
			{
				ret = send(pbinfo->sockfd, rawsubmitrequest + bytes, strlen(rawsubmitrequest) - bytes, 0);
				if(ret == -1) return(NULL);
				
				bytes += ret;
			} while(bytes < strlen(rawsubmitrequest));
			
			free(rawsubmitrequest);
			FreeShare(CurShare);			
		}
		pthread_mutex_unlock(&QueueMutex);
	}
	return(NULL);
}

int32_t XMRSetKernelArgs(AlgoContext *HashData, void *HashInput, uint32_t Target)
{
	cl_int retval;
	cl_uint zero = 0;
	size_t GlobalThreads = HashData->GlobalSize, LocalThreads = HashData->WorkSize;
	
	if(!HashData || !HashInput) return(ERR_STUPID_PARAMS);
	
	retval = clEnqueueWriteBuffer(*HashData->CommandQueues, HashData->InputBuffer, CL_TRUE, 0, 76, HashInput, 0, NULL, NULL);
	
	if(retval != CL_SUCCESS)
	{
		Log(LOG_CRITICAL, "Error %d when calling clEnqueueWriteBuffer to fill input buffer.", retval);
		return(ERR_OCL_API);
	}
	
	/*
	retval = clSetKernelArg(HashData->Kernels[0], 0, sizeof(cl_mem), &HashData->InputBuffer);
	if(retval != CL_SUCCESS)
	{
		Log(LOG_CRITICAL, "Error %d when calling clSetKernelArg for kernel %d, argument %d.", retval, 0, 0);
		return(ERR_OCL_API);
	}
	
	// Scratchpads
	retval = clSetKernelArg(HashData->Kernels[0], 1, sizeof(cl_mem), HashData->ExtraBuffers + 0);
	
	if(retval != CL_SUCCESS)
	{
		Log(LOG_CRITICAL, "Error %d when calling clSetKernelArg for kernel %d, argument %d.", retval, 0, 1);
		return(ERR_OCL_API);
	}
	
	// States
	retval = clSetKernelArg(HashData->Kernels[0], 2, sizeof(cl_mem), HashData->ExtraBuffers + 1);
	
	if(retval != CL_SUCCESS)
	{
		Log(LOG_CRITICAL, "Error %d when calling clSetKernelArg for kernel %d, argument %d.", retval, 0, 2);
		return(ERR_OCL_API);
	}
	
	// Branch 0
	retval = clSetKernelArg(HashData->Kernels[0], 3, sizeof(cl_mem), HashData->ExtraBuffers + 2);
	
	if(retval != CL_SUCCESS)
	{
		Log(LOG_CRITICAL, "Error %d when calling clSetKernelArg for kernel %d, argument %d.", retval, 0, 3);
		return(ERR_OCL_API);
	}
	
	// Branch 1
	retval = clSetKernelArg(HashData->Kernels[0], 4, sizeof(cl_mem), HashData->ExtraBuffers + 3);
	
	if(retval != CL_SUCCESS)
	{
		Log(LOG_CRITICAL, "Error %d when calling clSetKernelArg for kernel %d, argument %d.", retval, 0, 4);
		return(ERR_OCL_API);
	}
	
	// Branch 2
	retval = clSetKernelArg(HashData->Kernels[0], 5, sizeof(cl_mem), HashData->ExtraBuffers + 4);
	
	if(retval != CL_SUCCESS)
	{
		Log(LOG_CRITICAL, "Error %d when calling clSetKernelArg for kernel %d, argument %d.", retval, 0, 5);
		return(ERR_OCL_API);
	}
	
	// Branch 3
	retval = clSetKernelArg(HashData->Kernels[0], 6, sizeof(cl_mem), HashData->ExtraBuffers + 5);
	
	if(retval != CL_SUCCESS)
	{
		Log(LOG_CRITICAL, "Error %d when calling clSetKernelArg for kernel %d, argument %d.", retval, 0, 6);
		return(ERR_OCL_API);
	}
	
	retval = clSetKernelArg(HashData->Kernels[0], 7, sizeof(cl_ulong), &GlobalThreads);
	
	if(retval != CL_SUCCESS)
	{
		Log(LOG_CRITICAL, "Error %d when calling clSetKernelArg for kernel %d, argument %d.", retval, 0, 7);
		return(ERR_OCL_API);
	}
	*/
	
	retval = clSetKernelArg(HashData->Kernels[0], 0, sizeof(cl_mem), &HashData->InputBuffer);
	if(retval != CL_SUCCESS)
	{
		Log(LOG_CRITICAL, "Error %d when calling clSetKernelArg for kernel %d, argument %d.", retval, 0, 0);
		return(ERR_OCL_API);
	}
	
	// Scratchpads
	retval = clSetKernelArg(HashData->Kernels[0], 1, sizeof(cl_mem), HashData->ExtraBuffers + 0);
	
	if(retval != CL_SUCCESS)
	{
		Log(LOG_CRITICAL, "Error %d when calling clSetKernelArg for kernel %d, argument %d.", retval, 0, 1);
		return(ERR_OCL_API);
	}
	
	// States
	retval = clSetKernelArg(HashData->Kernels[0], 2, sizeof(cl_mem), HashData->ExtraBuffers + 1);
	
	if(retval != CL_SUCCESS)
	{
		Log(LOG_CRITICAL, "Error %d when calling clSetKernelArg for kernel %d, argument %d.", retval, 0, 2);
		return(ERR_OCL_API);
	}
	
	// CN2 Kernel
	
	// Scratchpads
	retval = clSetKernelArg(HashData->Kernels[1], 0, sizeof(cl_mem), HashData->ExtraBuffers + 0);
	
	if(retval != CL_SUCCESS)
	{
		Log(LOG_CRITICAL, "Error %d when calling clSetKernelArg for kernel %d, argument %d.", retval, 1, 0);
		return(ERR_OCL_API);
	}
	
	// States
	retval = clSetKernelArg(HashData->Kernels[1], 1, sizeof(cl_mem), HashData->ExtraBuffers + 1);
	
	if(retval != CL_SUCCESS)
	{
		Log(LOG_CRITICAL, "Error %d when calling clSetKernelArg for kernel %d, argument %d.", retval, 1, 1);
		return(ERR_OCL_API);
	}
	
	// CN3 Kernel
	// Scratchpads
	retval = clSetKernelArg(HashData->Kernels[2], 0, sizeof(cl_mem), HashData->ExtraBuffers + 0);
	
	if(retval != CL_SUCCESS)
	{
		Log(LOG_CRITICAL, "Error %d when calling clSetKernelArg for kernel %d, argument %d.", retval, 2, 0);
		return(ERR_OCL_API);
	}
	
	// States
	retval = clSetKernelArg(HashData->Kernels[2], 1, sizeof(cl_mem), HashData->ExtraBuffers + 1);
	
	if(retval != CL_SUCCESS)
	{
		Log(LOG_CRITICAL, "Error %d when calling clSetKernelArg for kernel %d, argument %d.", retval, 2, 1);
		return(ERR_OCL_API);
	}
	
	// Branch 0
	retval = clSetKernelArg(HashData->Kernels[2], 2, sizeof(cl_mem), HashData->ExtraBuffers + 2);
	
	if(retval != CL_SUCCESS)
	{
		Log(LOG_CRITICAL, "Error %d when calling clSetKernelArg for kernel %d, argument %d.", retval, 2, 2);
		return(ERR_OCL_API);
	}
	
	// Branch 1
	retval = clSetKernelArg(HashData->Kernels[2], 3, sizeof(cl_mem), HashData->ExtraBuffers + 3);
	
	if(retval != CL_SUCCESS)
	{
		Log(LOG_CRITICAL, "Error %d when calling clSetKernelArg for kernel %d, argument %d.", retval, 2, 3);
		return(ERR_OCL_API);
	}
	
	// Branch 2
	retval = clSetKernelArg(HashData->Kernels[2], 4, sizeof(cl_mem), HashData->ExtraBuffers + 4);
	
	if(retval != CL_SUCCESS)
	{
		Log(LOG_CRITICAL, "Error %d when calling clSetKernelArg for kernel %d, argument %d.", retval, 2, 4);
		return(ERR_OCL_API);
	}
	
	// Branch 3
	retval = clSetKernelArg(HashData->Kernels[2], 5, sizeof(cl_mem), HashData->ExtraBuffers + 5);
	
	if(retval != CL_SUCCESS)
	{
		Log(LOG_CRITICAL, "Error %d when calling clSetKernelArg for kernel %d, argument %d.", retval, 2, 5);
		return(ERR_OCL_API);
	}
	
	retval = clSetKernelArg(HashData->Kernels[2], 6, sizeof(cl_ulong), &GlobalThreads);
	
	if(retval != CL_SUCCESS)
	{
		Log(LOG_CRITICAL, "Error %d when calling clSetKernelArg for kernel %d, argument %d.", retval, 2, 6);
		return(ERR_OCL_API);
	}
	
	for(int i = 0; i < 4; ++i)
	{
		// States
		retval = clSetKernelArg(HashData->Kernels[i + 3], 0, sizeof(cl_mem), HashData->ExtraBuffers + 1);
		
		if(retval != CL_SUCCESS)
		{
			Log(LOG_CRITICAL, "Error %d when calling clSetKernelArg for kernel %d, argument %d.", retval, i + 3, 0);
			return(ERR_OCL_API);
		}
		
		// Nonce buffer
		retval = clSetKernelArg(HashData->Kernels[i + 3], 1, sizeof(cl_mem), HashData->ExtraBuffers + (i + 2));
		
		if(retval != CL_SUCCESS)
		{
			Log(LOG_CRITICAL, "Error %d when calling clSetKernelArg for kernel %d, argument %d.", retval, i + 3, 1);
			return(ERR_OCL_API);
		}
		
		// Output
		retval = clSetKernelArg(HashData->Kernels[i + 3], 2, sizeof(cl_mem), &HashData->OutputBuffer);
		
		if(retval != CL_SUCCESS)
		{
			Log(LOG_CRITICAL, "Error %d when calling clSetKernelArg for kernel %d, argument %d.", retval, i + 3, 2);
			return(ERR_OCL_API);
		}
		
		// Target
		retval = clSetKernelArg(HashData->Kernels[i + 3], 3, sizeof(cl_uint), &Target);
		
		if(retval != CL_SUCCESS)
		{
			Log(LOG_CRITICAL, "Error %d when calling clSetKernelArg for kernel %d, argument %d.", retval, i + 3, 3);
			return(ERR_OCL_API);
		}
	}
	
	/*
	// Branch 0 - states
	retval = clSetKernelArg(HashData->Kernels[1], 0, sizeof(cl_mem), HashData->ExtraBuffers + 1);
	
	if(retval != CL_SUCCESS)
	{
		Log(LOG_CRITICAL, "Error %d when calling clSetKernelArg for kernel %d, argument %d.", retval, 1, 0);
		return(ERR_OCL_API);
	}
	
	// Branch 0 - nonce buffer
	retval = clSetKernelArg(HashData->Kernels[1], 1, sizeof(cl_mem), HashData->ExtraBuffers + 2);
	
	if(retval != CL_SUCCESS)
	{
		Log(LOG_CRITICAL, "Error %d when calling clSetKernelArg for kernel %d, argument %d.", retval, 1, 1);
		return(ERR_OCL_API);
	}
	
	// Branch 0 - output
	retval = clSetKernelArg(HashData->Kernels[1], 2, sizeof(cl_mem), &HashData->OutputBuffer);
	
	if(retval != CL_SUCCESS)
	{
		Log(LOG_CRITICAL, "Error %d when calling clSetKernelArg for kernel %d, argument %d.", retval, 1, 2);
		return(ERR_OCL_API);
	}
	
	// Branch 0 - thread count
	retval = clSetKernelArg(HashData->Kernels[1], 3, sizeof(cl_uint), &Target);
	
	if(retval != CL_SUCCESS)
	{
		Log(LOG_CRITICAL, "Error %d when calling clSetKernelArg for kernel %d, argument %d.", retval, 1, 3);
		return(ERR_OCL_API);
	}
	
	// Branch 1 - states
	retval = clSetKernelArg(HashData->Kernels[2], 0, sizeof(cl_mem), HashData->ExtraBuffers + 1);
	
	if(retval != CL_SUCCESS)
	{
		Log(LOG_CRITICAL, "Error %d when calling clSetKernelArg for kernel %d, argument %d.", retval, 2, 0);
		return(ERR_OCL_API);
	}
	
	// Branch 1 - nonce buffer
	retval = clSetKernelArg(HashData->Kernels[2], 1, sizeof(cl_mem), HashData->ExtraBuffers + 3);
	
	if(retval != CL_SUCCESS)
	{
		Log(LOG_CRITICAL, "Error %d when calling clSetKernelArg for kernel %d, argument %d.", retval, 2, 1);
		return(ERR_OCL_API);
	}
	
	// Branch 1 - output
	retval = clSetKernelArg(HashData->Kernels[2], 2, sizeof(cl_mem), &HashData->OutputBuffer);
	
	if(retval != CL_SUCCESS)
	{
		Log(LOG_CRITICAL, "Error %d when calling clSetKernelArg for kernel %d, argument %d.", retval, 2, 2);
		return(ERR_OCL_API);
	}
	
	// Branch 1 - thread count
	retval = clSetKernelArg(HashData->Kernels[2], 3, sizeof(cl_uint), &Target);
	
	if(retval != CL_SUCCESS)
	{
		Log(LOG_CRITICAL, "Error %d when calling clSetKernelArg for kernel %d, argument %d.", retval, 2, 3);
		return(ERR_OCL_API);
	}
	
	// Branch 2 - states
	retval = clSetKernelArg(HashData->Kernels[3], 0, sizeof(cl_mem), HashData->ExtraBuffers + 1);
	
	if(retval != CL_SUCCESS)
	{
		Log(LOG_CRITICAL, "Error %d when calling clSetKernelArg for kernel %d, argument %d.", retval, 3, 0);
		return(ERR_OCL_API);
	}
	
	// Branch 2 - nonce buffer
	retval = clSetKernelArg(HashData->Kernels[3], 1, sizeof(cl_mem), HashData->ExtraBuffers + 4);
	
	if(retval != CL_SUCCESS)
	{
		Log(LOG_CRITICAL, "Error %d when calling clSetKernelArg for kernel %d, argument %d.", retval, 3, 1);
		return(ERR_OCL_API);
	}
	
	// Branch 2 - output
	retval = clSetKernelArg(HashData->Kernels[3], 2, sizeof(cl_mem), &HashData->OutputBuffer);
	
	if(retval != CL_SUCCESS)
	{
		Log(LOG_CRITICAL, "Error %d when calling clSetKernelArg for kernel %d, argument %d.", retval, 3, 2);
		return(ERR_OCL_API);
	}
	
	// Branch 2 - thread count
	retval = clSetKernelArg(HashData->Kernels[3], 3, sizeof(cl_uint), &Target);
	
	if(retval != CL_SUCCESS)
	{
		Log(LOG_CRITICAL, "Error %d when calling clSetKernelArg for kernel %d, argument %d.", retval, 3, 3);
		return(ERR_OCL_API);
	}
	
	// Branch 3 - states
	retval = clSetKernelArg(HashData->Kernels[4], 0, sizeof(cl_mem), HashData->ExtraBuffers + 1);
	
	if(retval != CL_SUCCESS)
	{
		Log(LOG_CRITICAL, "Error %d when calling clSetKernelArg for kernel %d, argument %d.", retval, 4, 0);
		return(ERR_OCL_API);
	}
	
	// Branch 3 - nonce buffer
	retval = clSetKernelArg(HashData->Kernels[4], 1, sizeof(cl_mem), HashData->ExtraBuffers + 5);
	
	if(retval != CL_SUCCESS)
	{
		Log(LOG_CRITICAL, "Error %d when calling clSetKernelArg for kernel %d, argument %d.", retval, 4, 1);
		return(ERR_OCL_API);
	}
	
	// Branch 3 - output
	retval = clSetKernelArg(HashData->Kernels[4], 2, sizeof(cl_mem), &HashData->OutputBuffer);
	
	if(retval != CL_SUCCESS)
	{
		Log(LOG_CRITICAL, "Error %d when calling clSetKernelArg for kernel %d, argument %d.", retval, 4, 2);
		return(ERR_OCL_API);
	}
	
	// Branch 3 - thread count
	retval = clSetKernelArg(HashData->Kernels[4], 3, sizeof(cl_uint), &Target);
	
	if(retval != CL_SUCCESS)
	{
		Log(LOG_CRITICAL, "Error %d when calling clSetKernelArg for kernel %d, argument %d.", retval, 4, 3);
		return(ERR_OCL_API);
	}*/
	
	return(ERR_SUCCESS);
}

int32_t RunXMRTest(AlgoContext *HashData, void *HashOutput)
{
	cl_int retval;
	cl_uint zero = 0;
	size_t GlobalThreads = HashData->GlobalSize, LocalThreads = HashData->WorkSize;
	size_t BranchNonces[4];
	
	if(!HashData || !HashOutput) return(ERR_STUPID_PARAMS);
	
	for(int i = 2; i < 6; ++i)
	{
		retval = clEnqueueWriteBuffer(*HashData->CommandQueues, HashData->ExtraBuffers[i], CL_FALSE, sizeof(cl_uint) * GlobalThreads, sizeof(cl_uint), &zero, 0, NULL, NULL);
		
		if(retval != CL_SUCCESS)
		{
			Log(LOG_CRITICAL, "Error %d when calling clEnqueueWriteBuffer to zero branch buffer counter %d.", retval, i - 2);
			return(ERR_OCL_API);
		}
	}
	
	retval = clEnqueueWriteBuffer(*HashData->CommandQueues, HashData->OutputBuffer, CL_FALSE, sizeof(cl_uint) * 0xFF, sizeof(cl_uint), &zero, 0, NULL, NULL);
	
	if(retval != CL_SUCCESS)
	{
		Log(LOG_CRITICAL, "Error %d when calling clEnqueueReadBuffer to fetch results.", retval);
		return(ERR_OCL_API);
	}
	
	clFinish(*HashData->CommandQueues);
	
	/*retval = clEnqueueNDRangeKernel(*HashData->CommandQueues, HashData->Kernels[0], 1, &HashData->Nonce, &GlobalThreads, &LocalThreads, 0, NULL, NULL);
	
	if(retval != CL_SUCCESS)
	{
		Log(LOG_CRITICAL, "Error %d when calling clEnqueueNDRangeKernel for kernel %d.", retval, 0);
		return(ERR_OCL_API);
	}*/
	
	for(int i = 0; i < 3; ++i)
	{
		retval = clEnqueueNDRangeKernel(*HashData->CommandQueues, HashData->Kernels[i], 1, &HashData->Nonce, &GlobalThreads, &LocalThreads, 0, NULL, NULL);
	
		if(retval != CL_SUCCESS)
		{
			Log(LOG_CRITICAL, "Error %d when calling clEnqueueNDRangeKernel for kernel %d.", retval, i);
			return(ERR_OCL_API);
		}
	}
	
	retval = clEnqueueReadBuffer(*HashData->CommandQueues, HashData->ExtraBuffers[2], CL_FALSE, sizeof(cl_uint) * GlobalThreads, sizeof(cl_uint), BranchNonces, 0, NULL, NULL);
	
	if(retval != CL_SUCCESS)
	{
		Log(LOG_CRITICAL, "Error %d when calling clEnqueueReadBuffer to fetch results.", retval);
		return(ERR_OCL_API);
	}
	
	retval = clEnqueueReadBuffer(*HashData->CommandQueues, HashData->ExtraBuffers[3], CL_FALSE, sizeof(cl_uint) * GlobalThreads, sizeof(cl_uint), BranchNonces + 1, 0, NULL, NULL);
	
	if(retval != CL_SUCCESS)
	{
		Log(LOG_CRITICAL, "Error %d when calling clEnqueueReadBuffer to fetch results.", retval);
		return(ERR_OCL_API);
	}
	
	retval = clEnqueueReadBuffer(*HashData->CommandQueues, HashData->ExtraBuffers[4], CL_FALSE, sizeof(cl_uint) * GlobalThreads, sizeof(cl_uint), BranchNonces + 2, 0, NULL, NULL);
	
	if(retval != CL_SUCCESS)
	{
		Log(LOG_CRITICAL, "Error %d when calling clEnqueueReadBuffer to fetch results.", retval);
		return(ERR_OCL_API);
	}
	
	retval = clEnqueueReadBuffer(*HashData->CommandQueues, HashData->ExtraBuffers[5], CL_FALSE, sizeof(cl_uint) * GlobalThreads, sizeof(cl_uint), BranchNonces + 3, 0, NULL, NULL);
	
	if(retval != CL_SUCCESS)
	{
		Log(LOG_CRITICAL, "Error %d when calling clEnqueueReadBuffer to fetch results.", retval);
		return(ERR_OCL_API);
	}
	
	clFinish(*HashData->CommandQueues);
	
	for(int i = 0; i < 4; ++i)
	{
		if(BranchNonces[i])
		{
			//retval = clEnqueueNDRangeKernel(*HashData->CommandQueues, HashData->Kernels[i + 1], 1, &HashData->Nonce, BranchNonces + i, &LocalThreads, 0, NULL, NULL);
			retval = clEnqueueNDRangeKernel(*HashData->CommandQueues, HashData->Kernels[i + 3], 1, &HashData->Nonce, BranchNonces + i, &LocalThreads, 0, NULL, NULL);
			
			if(retval != CL_SUCCESS)
			{
				//Log(LOG_CRITICAL, "Error %d when calling clEnqueueNDRangeKernel for kernel %d.", retval, i + 1);
				Log(LOG_CRITICAL, "Error %d when calling clEnqueueNDRangeKernel for kernel %d.", retval, i + 3);
				return(ERR_OCL_API);
			}
		}
	}
	
	retval = clEnqueueReadBuffer(*HashData->CommandQueues, HashData->OutputBuffer, CL_TRUE, 0, sizeof(cl_uint) * 0x100, HashOutput, 0, NULL, NULL);
	
	if(retval != CL_SUCCESS)
	{
		Log(LOG_CRITICAL, "Error %d when calling clEnqueueReadBuffer to fetch results.", retval);
		return(ERR_OCL_API);
	}
	
	clFinish(*HashData->CommandQueues);
	
	HashData->Nonce += GlobalThreads;
	
	return(ERR_SUCCESS);
}

int32_t XMRCleanup(AlgoContext *HashData)
{
	//for(int i = 0; i < 5; ++i) clReleaseKernel(HashData->Kernels[i]);
	for(int i = 0; i < 7; ++i) clReleaseKernel(HashData->Kernels[i]);
	
	clReleaseProgram(HashData->Program);
	
	clReleaseMemObject(HashData->InputBuffer);
	
	for(int i = 0; i < 6; ++i) clReleaseMemObject(HashData->ExtraBuffers[i]);
	
	clReleaseMemObject(HashData->OutputBuffer);
	
	free(HashData->ExtraBuffers);
	
	clReleaseCommandQueue(*HashData->CommandQueues);
	
	free(HashData->CommandQueues);
}

int32_t SetupXMRTest(AlgoContext *HashData, OCLPlatform *OCL, uint32_t DeviceIdx)
{
	size_t len;
	cl_int retval;
	char *KernelSource, *BuildLog;
	size_t GlobalThreads = OCL->Devices[DeviceIdx].rawIntensity, LocalThreads = OCL->Devices[DeviceIdx].WorkSize;
	const cl_queue_properties CommandQueueProperties[] = { 0, 0, 0 };
	
	// Sanity checks
	if(!HashData || !OCL) return(ERR_STUPID_PARAMS);
	
	HashData->GlobalSize = GlobalThreads;
	HashData->WorkSize = LocalThreads;
	
	HashData->CommandQueues = (cl_command_queue *)malloc(sizeof(cl_command_queue));
	
	*HashData->CommandQueues = clCreateCommandQueueWithProperties(OCL->Context, OCL->Devices[DeviceIdx].DeviceID, CommandQueueProperties, &retval);
	
	if(retval != CL_SUCCESS)
	{
		Log(LOG_CRITICAL, "Error %d when calling clCreateCommandQueueWithProperties.", retval);
		return(ERR_OCL_API);
	}
	
	// One extra buffer for the scratchpads is required
	HashData->ExtraBuffers = (cl_mem *)malloc(sizeof(cl_mem) * 6);
	
	HashData->InputBuffer = clCreateBuffer(OCL->Context, CL_MEM_READ_ONLY, 80, NULL, &retval);
	
	if(retval != CL_SUCCESS)
	{
		Log(LOG_CRITICAL, "Error %d when calling clCreateBuffer to create input buffer.", retval);
		return(ERR_OCL_API);
	}
	
	// Scratchpads
	HashData->ExtraBuffers[0] = clCreateBuffer(OCL->Context, CL_MEM_READ_WRITE, (1 << 21) * GlobalThreads, NULL, &retval);
	
	if(retval != CL_SUCCESS)
	{
		Log(LOG_CRITICAL, "Error %d when calling clCreateBuffer to create hash scratchpads buffer.", retval);
		return(ERR_OCL_API);
	}
	
	// States
	HashData->ExtraBuffers[1] = clCreateBuffer(OCL->Context, CL_MEM_READ_WRITE, 200 * GlobalThreads, NULL, &retval);
	
	if(retval != CL_SUCCESS)
	{
		Log(LOG_CRITICAL, "Error %d when calling clCreateBuffer to create hash states buffer.", retval);
		return(ERR_OCL_API);
	}
	
	// Blake-256 branches
	HashData->ExtraBuffers[2] = clCreateBuffer(OCL->Context, CL_MEM_READ_WRITE, sizeof(cl_uint) * (GlobalThreads + 2), NULL, &retval);
	
	if(retval != CL_SUCCESS)
	{
		Log(LOG_CRITICAL, "Error %d when calling clCreateBuffer to create Branch 0 buffer.", retval);
		return(ERR_OCL_API);
	}
	
	// Groestl-256 branches
	HashData->ExtraBuffers[3] = clCreateBuffer(OCL->Context, CL_MEM_READ_WRITE, sizeof(cl_uint) * (GlobalThreads + 2), NULL, &retval);
	
	if(retval != CL_SUCCESS)
	{
		Log(LOG_CRITICAL, "Error %d when calling clCreateBuffer to create Branch 1 buffer.", retval);
		return(ERR_OCL_API);
	}
	
	// JH-256 branches
	HashData->ExtraBuffers[4] = clCreateBuffer(OCL->Context, CL_MEM_READ_WRITE, sizeof(cl_uint) * (GlobalThreads + 2), NULL, &retval);
	
	if(retval != CL_SUCCESS)
	{
		Log(LOG_CRITICAL, "Error %d when calling clCreateBuffer to create Branch 2 buffer.", retval);
		return(ERR_OCL_API);
	}
	
	// Skein-512 branches
	HashData->ExtraBuffers[5] = clCreateBuffer(OCL->Context, CL_MEM_READ_WRITE, sizeof(cl_uint) * (GlobalThreads + 2), NULL, &retval);
	
	if(retval != CL_SUCCESS)
	{
		Log(LOG_CRITICAL, "Error %d when calling clCreateBuffer to create Branch 3 buffer.", retval);
		return(ERR_OCL_API);
	}
	
	// Assume we may find up to 0xFF nonces in one run - it's reasonable
	HashData->OutputBuffer = clCreateBuffer(OCL->Context, CL_MEM_READ_WRITE, sizeof(cl_uint) * 0x100, NULL, &retval);
	
	if(retval != CL_SUCCESS)
	{
		Log(LOG_CRITICAL, "Error %d when calling clCreateBuffer to create output buffer.", retval);
		return(ERR_OCL_API);
	}
	
	len = LoadTextFile(&KernelSource, "cryptonight.cl");
	
	HashData->Program = clCreateProgramWithSource(OCL->Context, 1, (const char **)&KernelSource, NULL, &retval);
	
	if(retval != CL_SUCCESS)
	{
		Log(LOG_CRITICAL, "Error %d when calling clCreateProgramWithSource on the contents of %s.", retval, "cryptonight.cl");
		return(ERR_OCL_API);
	}
	
	retval = clBuildProgram(HashData->Program, 1, &OCL->Devices[DeviceIdx].DeviceID, "-I.", NULL, NULL);
	
	if(retval != CL_SUCCESS)
	{
		Log(LOG_CRITICAL, "Error %d when calling clBuildProgram.", retval);
		
		retval = clGetProgramBuildInfo(HashData->Program, OCL->Devices[DeviceIdx].DeviceID, CL_PROGRAM_BUILD_LOG, 0, NULL, &len);
	
		if(retval != CL_SUCCESS)
		{
			Log(LOG_CRITICAL, "Error %d when calling clGetProgramBuildInfo for length of build log output.", retval);
			return(ERR_OCL_API);
		}
		
		BuildLog = (char *)malloc(sizeof(char) * (len + 2));
		
		retval = clGetProgramBuildInfo(HashData->Program, OCL->Devices[DeviceIdx].DeviceID, CL_PROGRAM_BUILD_LOG, len, BuildLog, NULL);
		
		if(retval != CL_SUCCESS)
		{
			Log(LOG_CRITICAL, "Error %d when calling clGetProgramBuildInfo for build log.", retval);
			return(ERR_OCL_API);
		}
		
		Log(LOG_CRITICAL, "Build Log:\n%s", BuildLog);
		
		free(BuildLog);
		
		return(ERR_OCL_API);
	}
	
	cl_build_status status;
	
	do
	{
		retval = clGetProgramBuildInfo(HashData->Program, OCL->Devices[DeviceIdx].DeviceID, CL_PROGRAM_BUILD_STATUS, sizeof(cl_build_status), &status, NULL);
		if(retval != CL_SUCCESS)
		{
			Log(LOG_CRITICAL, "Error %d when calling clGetProgramBuildInfo for status of build.", retval);
			return(ERR_OCL_API);
		}
		
		sleep(1);
	} while(status == CL_BUILD_IN_PROGRESS);
	
	retval = clGetProgramBuildInfo(HashData->Program, OCL->Devices[DeviceIdx].DeviceID, CL_PROGRAM_BUILD_LOG, 0, NULL, &len);
	
	if(retval != CL_SUCCESS)
	{
		Log(LOG_CRITICAL, "Error %d when calling clGetProgramBuildInfo for length of build log output.", retval);
		return(ERR_OCL_API);
	}
	
	BuildLog = (char *)malloc(sizeof(char) * (len + 2));
	
	retval = clGetProgramBuildInfo(HashData->Program, OCL->Devices[DeviceIdx].DeviceID, CL_PROGRAM_BUILD_LOG, len, BuildLog, NULL);
	
	if(retval != CL_SUCCESS)
	{
		Log(LOG_CRITICAL, "Error %d when calling clGetProgramBuildInfo for build log.", retval);
		return(ERR_OCL_API);
	}
	
	Log(LOG_DEBUG, "Build Log:\n%s", BuildLog);
	
	free(BuildLog);
	free(KernelSource);
	
	//HashData->Kernels = (cl_kernel *)malloc(sizeof(cl_kernel) * 5);
	HashData->Kernels = (cl_kernel *)malloc(sizeof(cl_kernel) * 7);
	
	const char *KernelNames[] = { "cn0", "cn1", "cn2", "Blake", "Groestl", "JH", "Skein" };
	
	for(int i = 0; i < 7; ++i)
	{
		HashData->Kernels[i] = clCreateKernel(HashData->Program, KernelNames[i], &retval);
		
		if(retval != CL_SUCCESS)
		{
			Log(LOG_CRITICAL, "Error %d when calling clCreateKernel for kernel %s.", retval, KernelNames[i]);
			return(ERR_OCL_API);
		}
	}
	
	/*HashData->Kernels[0] = clCreateKernel(HashData->Program, "cryptonight", &retval);
	
	if(retval != CL_SUCCESS)
	{
		Log(LOG_CRITICAL, "Error %d when calling clCreateKernel for kernel %s.", retval, "cryptonight");
		return(ERR_OCL_API);
	}
	
	HashData->Kernels[1] = clCreateKernel(HashData->Program, "Blake", &retval);
	
	if(retval != CL_SUCCESS)
	{
		Log(LOG_CRITICAL, "Error %d when calling clCreateKernel for kernel %s.", retval, "Blake");
		return(ERR_OCL_API);
	}
	
	HashData->Kernels[2] = clCreateKernel(HashData->Program, "Groestl", &retval);
	
	if(retval != CL_SUCCESS)
	{
		Log(LOG_CRITICAL, "Error %d when calling clCreateKernel for kernel %s.", retval, "Groestl");
		return(ERR_OCL_API);
	}
	
	HashData->Kernels[3] = clCreateKernel(HashData->Program, "JH", &retval);
	
	if(retval != CL_SUCCESS)
	{
		Log(LOG_CRITICAL, "Error %d when calling clCreateKernel for kernel %s.", retval, "JH");
		return(ERR_OCL_API);
	}
	
	HashData->Kernels[4] = clCreateKernel(HashData->Program, "Skein", &retval);
	
	if(retval != CL_SUCCESS)
	{
		Log(LOG_CRITICAL, "Error %d when calling clCreateKernel for kernel %s.", retval, "Skein");
		return(ERR_OCL_API);
	}*/
	
	HashData->Nonce = 0;
	return(ERR_SUCCESS);
}

void *StratumThreadProc(void *InfoPtr)
{
	uint64_t id = 1;
	char *workerinfo[3];
	int poolsocket, bytes, ret;
	size_t PartialMessageOffset;
	char *rawrequest, rawresponse[STRATUM_MAX_MESSAGE_LEN_BYTES], partial[STRATUM_MAX_MESSAGE_LEN_BYTES];
	PoolInfo *Pool = (PoolInfo *)InfoPtr;
	bool GotSubscriptionResponse = false, GotFirstJob = false;
	
	poolsocket = Pool->sockfd;
	
	uint8_t *temp, *rawloginrequest;
	json_t *requestobj = json_object();
	json_t *loginobj = json_object();
	
	json_object_set_new(loginobj, "login", json_string(Pool->WorkerData.User));
	json_object_set_new(loginobj, "pass", json_string(Pool->WorkerData.Pass));
	json_object_set_new(loginobj, "agent", json_string("wolf-xmr-miner/0.1"));
	
	// Current XMR pools are a hack job and make us hardcode an id of 1
	json_object_set_new(requestobj, "method", json_string("login"));
	json_object_set_new(requestobj, "params", loginobj);
	json_object_set_new(requestobj, "id", json_integer(1));
	
	temp = json_dumps(requestobj, JSON_PRESERVE_ORDER);
	Log(LOG_NETDEBUG, "Request: %s\n", temp);
	
	// TODO/FIXME: Check for super unlikely error here
	rawloginrequest = malloc(strlen(temp) + 16);
	strcpy(rawloginrequest, temp);
	
	// No longer needed
	json_decref(requestobj);
	
	// Add the very important Stratum newline
	strcat(rawloginrequest, "\n");
	
	bytes = 0;
		
	// Send the shit - but send() might not get it all out in one go.
	do
	{
		ret = send(Pool->sockfd, rawloginrequest + bytes, strlen(rawloginrequest) - bytes, 0);
		if(ret == -1) return(NULL);
		
		bytes += ret;
	} while(bytes < strlen(rawloginrequest));
	
	free(rawloginrequest);
	
	CurrentJob.Initialized = false;
	PartialMessageOffset = 0;
	
	SetNonBlockingSocket(Pool->sockfd);
	
	// Listen for work until termination.
	for(;;)
	{
		fd_set readfds;
		uint32_t bufidx;
		struct timeval timeout;
		char StratumMsg[STRATUM_MAX_MESSAGE_LEN_BYTES];
		
		timeout.tv_sec = 120;
		timeout.tv_usec = 0;
		FD_ZERO(&readfds);
		FD_SET(poolsocket, &readfds);
		
		select(poolsocket + 1, &readfds, NULL, NULL, &timeout);
		
		if(!FD_ISSET(poolsocket, &readfds))
		{
			Log(LOG_ERROR, "Stratum connection to pool timed out.");
			return(NULL);
		}
		
		// receive
		ret = recv(poolsocket, rawresponse + PartialMessageOffset, STRATUM_MAX_MESSAGE_LEN_BYTES - PartialMessageOffset, 0);
		
		rawresponse[ret] = 0x00;
		
		bufidx = 0;
		
		while(strchr(rawresponse + bufidx, '\n'))
		{
			json_t *msg, *msgid, *method;
			json_error_t err;
			
			uint32_t MsgLen = strchr(rawresponse + bufidx, '\n') - (rawresponse + bufidx) + 1;
			memcpy(StratumMsg, rawresponse + bufidx, MsgLen);
			StratumMsg[MsgLen] = 0x00;
			
			bufidx += MsgLen;
			
			Log(LOG_NETDEBUG, "Got something: %s", StratumMsg);
			msg = json_loads(StratumMsg, 0, NULL);
			
			if(!msg)
			{
				Log(LOG_CRITICAL, "Error parsing JSON from pool server.");
				closesocket(poolsocket);
				return(NULL);
			}
			
			msgid = json_object_get(msg, "id");
			
			// If the "id" field exists, it's either the reply to the
			// login, and contains the first job, or is a share
			// submission response, at least in this butchered XMR Stratum
			// The ID is also stupidly hardcoded to 1 in EVERY case.
			// No ID field means new job
			// Also, error responses to shares have no result
			if(msgid && json_integer_value(msgid))
			{
				json_t *result = json_object_get(msg, "result");
				json_t *authid = NULL;
				
				//if(!result)
				//{
				//	Log(LOG_CRITICAL, "Server sent a message with an ID and no result field.");
				//	json_decref(msg);
				//	close(poolsocket);
				//	return(NULL);
				//}
				
				// Only way to tell the two apart is that the result
				// object on a share submission response has ONLY
				// the status string.
				
				if(result) authid = json_object_get(result, "id");
				
				// Must be a share submission response if NULL
				// Otherwise, it's the first job.
				if(!authid)
				{
					double TotalHashrate = 0;
					json_t *result = json_object_get(msg, "result");
					json_t *err = json_object_get(msg, "error");
					
					pthread_mutex_lock(&StatusMutex);
					
					if(json_is_null(err) && !strcmp(json_string_value(json_object_get(result, "status")), "OK"))
					{
						Log(LOG_INFO, "Share accepted: %d/%d (%.02f%%)", GlobalStatus.SolvedWork - GlobalStatus.RejectedWork, GlobalStatus.SolvedWork, (double)(GlobalStatus.SolvedWork - GlobalStatus.RejectedWork) / GlobalStatus.SolvedWork * 100.0);
					}
					else
					{
						GlobalStatus.RejectedWork++;
						Log(LOG_INFO, "Share rejected (%s): %d/%d (%.02f%%)", json_string_value(json_object_get(result, "status")), GlobalStatus.SolvedWork - GlobalStatus.RejectedWork, GlobalStatus.SolvedWork, (double)(GlobalStatus.SolvedWork - GlobalStatus.RejectedWork) / GlobalStatus.SolvedWork * 100.0);
					}
					
					for(int i = 0; i < Pool->MinerThreadCount; ++i)
					{
						TotalHashrate += GlobalStatus.ThreadHashCounts[i] / GlobalStatus.ThreadTimes[i];
					}
					
					Log(LOG_INFO, "Total Hashrate: %.02fH/s\n", TotalHashrate);
					
					pthread_mutex_unlock(&StatusMutex);
				}
				else
				{
					json_t *job, *blob, *jid, *target;
					
					// cpuminer has it hardcoded to 64, so hell, no point
					// in handling arbitrary sizes here
					strcpy(Pool->XMRAuthID, json_string_value(authid));
					
					job = json_object_get(result, "job");
					
					if(!job)
					{
						Log(LOG_CRITICAL, "Server did not respond to login request with a job.");
						json_decref(msg);
						return(NULL);
					}
					
					blob = json_object_get(job, "blob");
					jid = json_object_get(job, "job_id");
					target = json_object_get(job, "target");
					
					if(!blob || !jid || !target)
					{
						Log(LOG_CRITICAL, "Server sent invalid first job.");
						json_decref(msg);
						return(NULL);
					}
					
					pthread_mutex_lock(&JobMutex);
					CurrentJob.XMRBlob = strdup(json_string_value(blob));
					CurrentJob.ID = strdup(json_string_value(jid));
					CurrentJob.XMRTarget = strtoul(json_string_value(target), NULL, 16);		// This is bad, and I feel bad
					CurrentJob.Initialized = 1;
					pthread_mutex_unlock(&JobMutex);
				}
				json_decref(result);
			}
			else
			{
				method = json_object_get(msg, "method");
				if(!method)
				{
					Log(LOG_CRITICAL, "Server message has no id field and doesn't seem to have a method field...");
					json_decref(msg);
					closesocket(poolsocket);
					return(NULL);
				}
				
				if(!strcmp("job", json_string_value(method)))
				{
					json_t *job, *blob, *jid, *target;
					
					job = json_object_get(msg, "params");
					
					if(!job)
					{
						Log(LOG_CRITICAL, "Job notification sent no params.");
						json_decref(msg);
						return(NULL);
					}
					
					blob = json_object_get(job, "blob");
					jid = json_object_get(job, "job_id");
					target = json_object_get(job, "target");
					
					if(!blob || !jid || !target)
					{
						Log(LOG_CRITICAL, "Server sent invalid job.");
						json_decref(msg);
						return(NULL);
					}
					
					pthread_mutex_lock(&JobMutex);
					CurrentJob.XMRBlob = strdup(json_string_value(blob));
					CurrentJob.ID = strdup(json_string_value(jid));
					CurrentJob.XMRTarget = strtoul(json_string_value(target), NULL, 16);		// This is bad, and I feel bad
					pthread_mutex_unlock(&JobMutex);
					
					// No cleanjobs param, so we flush every time
					for(int i = 0; i < Pool->MinerThreadCount; ++i)
						atomic_store(RestartMining + i, true);
						
					Log(LOG_NOTIFY, "Pool requested miner discard all previous work - probably new block on the network.");
				}	
				else
				{
					Log(LOG_NETDEBUG, "I have no idea what the fuck that message was.");
				}
				
				json_decref(msg);
			}
		}
		memmove(rawresponse, rawresponse + bufidx, ret - bufidx);
		PartialMessageOffset = ret - bufidx;
	}
}

// AlgoName must not be freed by the thread - cleanup is done by caller.
// RequestedWorksize and RequestedxIntensity should be zero if none was requested
typedef struct _MinerThreadInfo
{
	uint32_t ThreadID;
	uint32_t TotalMinerThreads;
	OCLPlatform *PlatformContext;
	AlgoContext AlgoCtx;
} MinerThreadInfo;

// Block header is 2 uint512s, 1024 bits - 128 bytes
void *MinerThreadProc(void *Info)
{
	int32_t err;
	double CurrentDiff;
	char *JobID = NULL;
	uint8_t BlockHdr[128];
	uint32_t FullTarget[8], TmpWork[20];
	MinerThreadInfo *MTInfo = (MinerThreadInfo *)Info;
	uint32_t StartNonce = (0xFFFFFFFFU / MTInfo->TotalMinerThreads) * MTInfo->ThreadID;
	uint32_t MaxNonce = StartNonce + (0xFFFFFFFFU / MTInfo->TotalMinerThreads);
	uint32_t Nonce = StartNonce, PrevNonce, platform = 0, device = 1, CurENonce2;
	
	// First time we're getting work, allocate JobID, and fill it
	// with the ID of the current job, then generate work. 
	pthread_mutex_lock(&JobMutex);
	JobID = strdup(CurrentJob.ID);
	MTInfo->AlgoCtx.Nonce = StartNonce;
	
	ASCIIHexToBinary(TmpWork, CurrentJob.XMRBlob, strlen(CurrentJob.XMRBlob));
	memset(FullTarget, 0xFF, 32);
	FullTarget[7] = __builtin_bswap32(CurrentJob.XMRTarget);
	pthread_mutex_unlock(&JobMutex);
	
	//Log(LOG_DEBUG, "Short target: %16llX", FullTarget[7]);
	
	err = XMRSetKernelArgs(&MTInfo->AlgoCtx, TmpWork, FullTarget[7]);
	if(err) return(NULL);
	
	while(!ExitFlag)
	{
		TIME_TYPE begin, end;
		
		atomic_store(RestartMining + MTInfo->ThreadID, false);
		
		// If JobID is not equal to the current job ID, generate new work
		// off the new job information.
		// If JobID is the same as the current job ID, go hash.
		pthread_mutex_lock(&JobMutex);
		if(strcmp(JobID, CurrentJob.ID))
		{
			Log(LOG_DEBUG, "Detected new job, regenerating work.");
			free(JobID);
			
			JobID = strdup(CurrentJob.ID);
			MTInfo->AlgoCtx.Nonce = StartNonce;
			
			ASCIIHexToBinary(TmpWork, CurrentJob.XMRBlob, strlen(CurrentJob.XMRBlob));
			memset(FullTarget, 0xFF, 32);
			FullTarget[7] = __builtin_bswap32(CurrentJob.XMRTarget);
			pthread_mutex_unlock(&JobMutex);
			
			err = XMRSetKernelArgs(&MTInfo->AlgoCtx, TmpWork, FullTarget[7]);
			if(err) return(NULL);
		}
		else
		{
			pthread_mutex_unlock(&JobMutex);
		}
		
		PrevNonce = MTInfo->AlgoCtx.Nonce;
		
		//clock_gettime(CLOCK_REALTIME, &begin);
		begin = MinerGetCurTime();
		
		do
		{
			cl_uint Results[0x100] = { 0 };
			
			err = RunXMRTest(&MTInfo->AlgoCtx, Results);
			if(err) return(NULL);
			
			if(atomic_load(RestartMining + MTInfo->ThreadID)) break;
			
			for(int i = 0; i < Results[0xFF]; ++i)
			{
				Log(LOG_DEBUG, "Thread %d: SHARE found (nonce 0x%.8X)!", MTInfo->ThreadID, Results[i]);
				
				Share *NewShare = (Share *)malloc(sizeof(Share));
				
				NewShare->Nonce = Results[i];
				NewShare->next = NULL;
				
				pthread_mutex_lock(&QueueMutex);
				SubmitShare(&CurrentQueue, NewShare);
				pthread_mutex_unlock(&QueueMutex);				
			}
		} while(MTInfo->AlgoCtx.Nonce < (PrevNonce + 1024));
		
		//clock_gettime(CLOCK_REALTIME, &end);
		end = MinerGetCurTime();
		
		//double NanosecondsElapsed = 1e9 * (double)(end.tv_sec - begin.tv_sec) + (double)(end.tv_nsec - begin.tv_nsec);
		double Seconds = SecondsElapsed(begin, end);
		
		pthread_mutex_lock(&StatusMutex);
		GlobalStatus.ThreadHashCounts[MTInfo->ThreadID] = MTInfo->AlgoCtx.Nonce - PrevNonce;
		GlobalStatus.ThreadTimes[MTInfo->ThreadID] = Seconds;
		pthread_mutex_unlock(&StatusMutex);
		
		Log(LOG_INFO, "Thread %d: %.02fH/s\n", MTInfo->ThreadID, ((MTInfo->AlgoCtx.Nonce - PrevNonce)) / (Seconds));
	}
	
	free(JobID);
	XMRCleanup(&MTInfo->AlgoCtx);
	
	return(NULL);
}
	
void SigHandler(int signal)
{
	pthread_mutex_lock(&Mutex);
	
	ExitFlag = true;
	
	pthread_mutex_unlock(&Mutex);
}

// Signed types indicate there is no default value
// If they are negative, do not set them.

typedef struct _DeviceSettings
{
	uint32_t Index;
	uint32_t Threads;
	uint32_t rawIntensity;
	uint32_t Worksize;
	int32_t CoreFreq;
	int32_t MemFreq;
	int32_t FanSpeedPercent;
	int32_t PowerTune;
} DeviceSettings;

// Settings structure for a group of threads mining one algo.
// These threads may be running on diff GPUs, and there may
// be multiple threads per GPU.

typedef struct _AlgoSettings
{
	char *AlgoName;
	uint32_t NumGPUs;
	DeviceSettings *GPUSettings;
	uint32_t TotalThreads;
	uint32_t PoolCount;
	char **PoolURLs;
	WorkerInfo *Workers;
	json_t *AlgoSpecificConfig;
} AlgoSettings;

int ParseConfigurationFile(char *ConfigFileName, AlgoSettings *Settings)
{
	json_t *Config;
	json_error_t Error;
	
	Config = json_load_file(ConfigFileName, JSON_REJECT_DUPLICATES, &Error);
	
	if(!Config)
	{
		Log(LOG_CRITICAL, "Error loading configuration file: %s on line %d.", Error.text, Error.line);
		return(-1);
	}
	
	json_t *AlgoObjArr = json_object_get(Config, "Algorithms");
	if(!AlgoObjArr)
	{
		Log(LOG_CRITICAL, "No 'Algorithms' array found");
		return(-1);
	}
	
	if(!json_array_size(AlgoObjArr))
	{
		Log(LOG_CRITICAL, "Algorithms array empty!");
		return(-1);
	}
	
	json_t *AlgoObj = json_array_get(AlgoObjArr, 0);
	
	json_t *AlgoName = json_object_get(AlgoObj, "name");
	
	if(!AlgoName || !json_is_string(AlgoName))
	{
		Log(LOG_CRITICAL, "Algorithm name missing or not a string.");
		return(-1);
	}
	
	json_t *DevsArr = json_object_get(AlgoObj, "devices");
	
	if(!DevsArr || !json_array_size(DevsArr))
	{
		Log(LOG_CRITICAL, "No devices specified for algorithm %s.", json_string_value(AlgoName));
		return(-1);
	}
	
	Settings->NumGPUs = json_array_size(DevsArr);
	
	Settings->GPUSettings = (DeviceSettings *)malloc(sizeof(DeviceSettings) * Settings->NumGPUs);
	Settings->TotalThreads = 0;
	
	for(int i = 0; i < Settings->NumGPUs; ++i)
	{
		json_t *DeviceObj = json_array_get(DevsArr, i);
		json_t *num = json_object_get(DeviceObj, "index");
		
		if(!num || !json_is_integer(num))
		{
			Log(LOG_CRITICAL, "Device structure #%d for algo %s has no index.", i, json_string_value(AlgoName));
			free(Settings->GPUSettings);
			return(-1);
		}
		
		Settings->GPUSettings[i].Index = json_integer_value(num);
		
		num = json_object_get(DeviceObj, "rawintensity");
		
		if(!num || !json_is_integer(num) || !json_integer_value(num))
		{
			Log(LOG_CRITICAL, "Device structure #%d for algo %s has no rawintensity, or rawintensity is set to zero.", i, json_string_value(AlgoName));
			free(Settings->GPUSettings);
			return(-1);
		}
		
		Settings->GPUSettings[i].rawIntensity = json_integer_value(num);
		
		num = json_object_get(DeviceObj, "worksize");
		
		if(!num || !json_is_integer(num) || !json_integer_value(num))
		{
			Log(LOG_CRITICAL, "Device structure #%d for algo %s has no worksize, or worksize is set to zero.", i, json_string_value(AlgoName));
			free(Settings->GPUSettings);
			return(-1);
		}
		
		Settings->GPUSettings[i].Worksize = json_integer_value(num);
		
		// Optional
		num = json_object_get(DeviceObj, "threads");
		
		if(num && !json_is_integer(num))
		{
			Log(LOG_CRITICAL, "Argument to threads in device structure #%d for algo %s is not an integer.", i, json_string_value(AlgoName));
			free(Settings->GPUSettings);
			return(-1);
		}
		
		if(num) Settings->GPUSettings[i].Threads = json_integer_value(num);
		else Settings->GPUSettings[i].Threads = 1;
		
		Settings->TotalThreads += Settings->GPUSettings[i].Threads;
		
		num = json_object_get(DeviceObj, "corefreq");
		
		if(num && !json_is_integer(num))
		{
			Log(LOG_CRITICAL, "Argument to corefreq in device structure #%d for algo %s is not an integer.", i, json_string_value(AlgoName));
			free(Settings->GPUSettings);
			return(-1);
		}
		
		if(num) Settings->GPUSettings[i].CoreFreq = json_integer_value(num);
		else Settings->GPUSettings[i].CoreFreq = -1;
		
		num = json_object_get(DeviceObj, "memfreq");
		
		if(num && !json_is_integer(num))
		{
			Log(LOG_CRITICAL, "Argument to memfreq in device structure #%d for algo %s is not an integer.", i, json_string_value(AlgoName));
			free(Settings->GPUSettings);
			return(-1);
		}
		
		if(num) Settings->GPUSettings[i].MemFreq = json_integer_value(num);
		else Settings->GPUSettings[i].MemFreq = -1;
		
		num = json_object_get(DeviceObj, "fanspeed");
		
		if(num && !json_is_integer(num))
		{
			Log(LOG_CRITICAL, "Argument to fanspeed in device structure #%d for algo %s is not an integer.", i, json_string_value(AlgoName));
			free(Settings->GPUSettings);
			return(-1);
		}
		
		if(num && ((json_integer_value(num) > 100) || (json_integer_value(num) < 0)))
		{
			Log(LOG_CRITICAL, "Argument to fanspeed in device structure #%d for algo %s is not a valid percentage (0 - 100).", i, json_string_value(AlgoName));
			free(Settings->GPUSettings);
		}
		
		if(num) Settings->GPUSettings[i].FanSpeedPercent = json_integer_value(num);
		else Settings->GPUSettings[i].FanSpeedPercent = -1;
		
		num = json_object_get(DeviceObj, "powertune");
		
		if(num && !json_is_integer(num))
		{
			Log(LOG_CRITICAL, "Argument to powertune in device structure #%d for algo %s is not an integer.", i, json_string_value(AlgoName));
			free(Settings->GPUSettings);
			return(-1);
		}
		
		if(num) Settings->GPUSettings[i].PowerTune = json_integer_value(num);
		else Settings->GPUSettings[i].PowerTune = 0;
	}
	
	// Remove the devices part from the algo object; it's
	// not part of the algo specific options.
	json_object_del(AlgoObj, "devices");
	
	json_t *PoolsArr = json_object_get(AlgoObj, "pools");
	
	if(!PoolsArr || !json_array_size(PoolsArr))
	{
		Log(LOG_CRITICAL, "No pools specified for algorithm %s.", json_string_value(AlgoName));
		return(-1);
	}
	
	Settings->PoolURLs = (char **)malloc(sizeof(char *) * (json_array_size(PoolsArr) + 1));
	Settings->Workers = (WorkerInfo *)malloc(sizeof(WorkerInfo) * ((json_array_size(PoolsArr) + 1)));
	Settings->PoolCount = json_array_size(PoolsArr);
	
	for(int i = 0; i < Settings->PoolCount; ++i)
	{
		json_t *PoolObj = json_array_get(PoolsArr, i);
		json_t *PoolURL = json_object_get(PoolObj, "url");
		json_t *PoolUser = json_object_get(PoolObj, "user");
		json_t *PoolPass = json_object_get(PoolObj, "pass");
		
		if(!PoolURL || !PoolUser || !PoolPass)
		{
			Log(LOG_CRITICAL, "Pool structure %d for algo %s is missing a URL, username, or password.", i, json_string_value(AlgoName));
			return(-1);
		}
		
		Settings->PoolURLs[i] = (char *)malloc(sizeof(char) * (strlen(json_string_value(PoolURL)) + 1));
		Settings->Workers[i].User = (char *)malloc(sizeof(char) * (strlen(json_string_value(PoolUser)) + 1));
		Settings->Workers[i].Pass = (char *)malloc(sizeof(char) * (strlen(json_string_value(PoolPass)) + 1));
		
		strcpy(Settings->PoolURLs[i], json_string_value(PoolURL));
		strcpy(Settings->Workers[i].User, json_string_value(PoolUser));
		strcpy(Settings->Workers[i].Pass, json_string_value(PoolPass));
		
		Settings->Workers[i].NextWorker = NULL;
	}
	
	// Remove the pools part from the algo object; it's
	// not part of the algo specific options.
	json_object_del(AlgoObj, "pools");
	
	Settings->AlgoSpecificConfig = AlgoObj;
	
	Settings->AlgoName = (char *)malloc(sizeof(char) * (strlen(json_string_value(AlgoName)) + 1));
	strcpy(Settings->AlgoName, json_string_value(AlgoName));
	
	return(0);
}

void FreeSettings(AlgoSettings *Settings)
{
	free(Settings->AlgoName);
	free(Settings->GPUSettings);
	
	for(int i = 0; i < Settings->PoolCount; ++i)
	{
		free(Settings->PoolURLs[i]);
		free(Settings->Workers[i].User);
		free(Settings->Workers[i].Pass);
	}
	
	free(Settings->PoolURLs);
	free(Settings->Workers);
}

// Only doing IPv4 for now.

// We should connect to the pool in the main thread,
// then give the socket to threads that need it, so
// that the connection may be cleanly closed.

// TODO: Get Platform index from somewhere else
int main(int argc, char **argv)
{
	PoolInfo Pool;
	AlgoSettings Settings;
	MinerThreadInfo *MThrInfo;
	OCLPlatform PlatformContext;
	int ret, poolsocket, PlatformIdx = 0;
	pthread_t Stratum, ADLThread, BroadcastThread, *MinerWorker;
	
	InitLogging(LOG_NETDEBUG);
	
	if(argc != 2)
	{
		Log(LOG_CRITICAL, "Usage: %s <config file>", argv[0]);
		return(0);
	}
	
	if(ParseConfigurationFile(argv[1], &Settings)) return(0);
	
	MThrInfo = (MinerThreadInfo *)malloc(sizeof(MinerThreadInfo) * Settings.TotalThreads);
	MinerWorker = (pthread_t *)malloc(sizeof(pthread_t) * Settings.TotalThreads);
	
	#ifdef __linux__
	
	struct sigaction ExitHandler;
	memset(&ExitHandler, 0, sizeof(struct sigaction));
	ExitHandler.sa_handler = SigHandler;
	
	sigaction(SIGINT, &ExitHandler, NULL);
	
	#endif
	
	RestartMining = (atomic_bool *)malloc(sizeof(atomic_bool) * Settings.TotalThreads);
	
	char *TmpPort;
	uint32_t URLOffset;
	
	if(strstr(Settings.PoolURLs[0], "stratum+tcp://"))
		URLOffset = strlen("stratum+tcp://");
	else
		URLOffset = 0;
	
	if(strrchr(Settings.PoolURLs[0] + URLOffset, ':'))
		TmpPort = strrchr(Settings.PoolURLs[0] + URLOffset, ':') + 1;
	else
		TmpPort = "3333";
	
	char *StrippedPoolURL = (char *)malloc(sizeof(char) * (strlen(Settings.PoolURLs[0]) + 1));
	
	int URLSize = URLOffset;
	
	for(; Settings.PoolURLs[0][URLSize] != ':' && Settings.PoolURLs[0][URLSize]; ++URLSize)
		StrippedPoolURL[URLSize - URLOffset] = Settings.PoolURLs[0][URLSize];
	
	StrippedPoolURL[URLSize - URLOffset] = 0x00;
	
	Log(LOG_DEBUG, "Parsed pool URL: %s", StrippedPoolURL);
	
	ret = NetworkingInit();
	
	if(ret)
	{
		Log(LOG_CRITICAL, "Failed to initialize networking with error code %d.", ret);
		return(0);
	}
	
	// TODO: Have ConnectToPool() return a Pool struct
	poolsocket = ConnectToPool(StrippedPoolURL, TmpPort);
	
	if(poolsocket == INVALID_SOCKET)
	{
		Log(LOG_CRITICAL, "Fatal error connecting to pool.");
		return(0);
	}
	
	Log(LOG_NOTIFY, "Successfully connected to pool's stratum.");
	
	// DO NOT FORGET THIS
	CurrentJob.Initialized = false;
	CurrentQueue.first = CurrentQueue.last = NULL;
	
	Pool.sockfd = poolsocket;
	Pool.WorkerData = Settings.Workers[0];
	Pool.MinerThreadCount = Settings.TotalThreads;
	Pool.MinerThreads = (uint32_t *)malloc(sizeof(uint32_t) * Pool.MinerThreadCount);
	
	for(int i = 0; i < Settings.TotalThreads; ++i) Pool.MinerThreads[i] = Settings.GPUSettings[i].Index;
	
	Pool.StratumID = ATOMIC_VAR_INIT(0);
	
	GlobalStatus.ThreadHashCounts = (double *)malloc(sizeof(double) * Settings.TotalThreads);
	GlobalStatus.ThreadTimes = (double *)malloc(sizeof(double) * Settings.TotalThreads);
	
	GlobalStatus.RejectedWork = 0;
	GlobalStatus.SolvedWork = 0;
	
	for(int i = 0; i < Settings.TotalThreads; ++i)
	{
		GlobalStatus.ThreadHashCounts[i] = 0;
		GlobalStatus.ThreadTimes[i] = 0;
	}
	
	// Initialize ADL and apply settings to card
	
	/*ADLInit();
	
	for(int i = 0; i < Settings.NumGPUs; ++i)
	{
		ADLAdapterDynInfo Info;
		
		ret = ADLGetStateInfo(Settings.GPUSettings[i].Index, &Info);
		
		if(ret)
			Log(LOG_ERROR, "ADLGetStateInfo() failed for GPU #%d with code %d.", Settings.GPUSettings[i].Index, ret);
		
		Log(LOG_INFO, "Adapter #%d - Fan Speed: %dRPM; Core Clock: %dMhz; Mem Clock: %dMhz; Core Voltage: %dmV; PowerTune: %d; Temp: %.03fC", Settings.GPUSettings[i].Index, Info.FanSpeedRPM, Info.CoreClock, Info.MemClock, Info.CoreVolts, Info.PowerTune, Info.Temp);
		
		if(Settings.GPUSettings[i].FanSpeedPercent >= 0)
		{
			ret = ADLSetFanspeed(Settings.GPUSettings[i].Index, Settings.GPUSettings[i].FanSpeedPercent);
			
			if(ret)
				Log(LOG_ERROR, "ADLSetFanspeed() failed for GPU #%d with code %d.", Settings.GPUSettings[i].Index, ret);
			else
				Log(LOG_INFO, "Setting fan speed for GPU #%d to %d%% succeeded.", Settings.GPUSettings[i].Index, Settings.GPUSettings[i].FanSpeedPercent);
		}
		
		// If either of these are positive, a call to ADLSetClocks is needed
		if((Settings.GPUSettings[i].CoreFreq >= 0) || (Settings.GPUSettings[i].MemFreq >= 0))
		{
			// If corefreq wasn't set, set memfreq. If memfreq wasn't, vice versa.
			// If both were set, then set both.
			if(Settings.GPUSettings[i].CoreFreq < 0)
				ret = ADLSetClocks(Settings.GPUSettings[i].Index, 0, Settings.GPUSettings[i].MemFreq);
			else if(Settings.GPUSettings[i].MemFreq < 0)
				ret = ADLSetClocks(Settings.GPUSettings[i].Index, Settings.GPUSettings[i].CoreFreq, 0);
			else
				ret = ADLSetClocks(Settings.GPUSettings[i].Index, Settings.GPUSettings[i].CoreFreq, Settings.GPUSettings[i].MemFreq);
			
			if(ret)
				Log(LOG_ERROR, "ADLSetClocks() failed for GPU #%d with code %d.", Settings.GPUSettings[i].Index, ret);
			else
				Log(LOG_INFO, "Setting clocks on GPU #%d to %d/%d succeeded.", Settings.GPUSettings[i].Index, Settings.GPUSettings[i].CoreFreq, Settings.GPUSettings[i].MemFreq);
		}
		
		if(Settings.GPUSettings[i].PowerTune)
		{
			ret = ADLSetPowertune(Settings.GPUSettings[i].Index, Settings.GPUSettings[i].PowerTune);
			
			if(ret < 0) Log(LOG_ERROR, "ADLSetPowertune failed for GPU #%d with code %d.", Settings.GPUSettings[i].Index, ret);
			else Log(LOG_INFO, "Setting powertune on GPU #%d to %d succeeded.", Settings.GPUSettings[i].Index, Settings.GPUSettings[i].PowerTune);
		}
	}
	
	Log(LOG_INFO, "Sleeping for 10s to allow fan to spin up/down...");
	sleep(10);*/
	
	for(int i = 0; i < Settings.TotalThreads; ++i) atomic_init(RestartMining + i, false);
	
	ret = pthread_create(&Stratum, NULL, StratumThreadProc, (void *)&Pool);
	
	if(ret)
	{
		printf("Failed to create Stratum thread.\n");
		return(0);
	}
	
	// Note to self - move this list BS into the InitOpenCLPlatformContext() routine
	uint32_t *GPUIdxList = (uint32_t *)malloc(sizeof(uint32_t) * Settings.NumGPUs);
	
	for(int i = 0; i < Settings.NumGPUs; ++i) GPUIdxList[i] = Settings.GPUSettings[i].Index;
	
	ret = InitOpenCLPlatformContext(&PlatformContext, PlatformIdx, Settings.NumGPUs, GPUIdxList);
	if(ret) return(0);
	
	free(GPUIdxList);
	
	for(int i = 0; i < Settings.NumGPUs; ++i) PlatformContext.Devices[i].rawIntensity = Settings.GPUSettings[i].rawIntensity;
	
	// Check for zero was done when parsing config
	for(int i = 0; i < Settings.NumGPUs; ++i)
	{
		if(Settings.GPUSettings[i].Worksize > PlatformContext.Devices[i].MaximumWorkSize)
		{
			Log(LOG_NOTIFY, "Worksize set for device %d is greater than its maximum; using maximum value of %d.", i, PlatformContext.Devices[i].MaximumWorkSize);
			PlatformContext.Devices[i].WorkSize = PlatformContext.Devices[i].MaximumWorkSize;
		}
		else
		{
			PlatformContext.Devices[i].WorkSize = Settings.GPUSettings[i].Worksize;
		}
	}
	
	// Wait until we've gotten work and filled
	// up the job structure before launching the
	// miner worker threads.
	for(;;)
	{
		pthread_mutex_lock(&JobMutex);
		if(CurrentJob.Initialized) break;
		pthread_mutex_unlock(&JobMutex);
		sleep(1);
	}
	
	pthread_mutex_unlock(&JobMutex);
	
	// Work is ready - time to create the broadcast and miner threads
	pthread_create(&BroadcastThread, NULL, PoolBroadcastThreadProc, (void *)&Pool);
	
	for(int ThrIdx = 0, GPUIdx = 0; ThrIdx < Settings.TotalThreads && GPUIdx < Settings.NumGPUs; ThrIdx += Settings.GPUSettings[GPUIdx].Threads, ++GPUIdx)
	{
		for(int x = 0; x < Settings.GPUSettings[GPUIdx].Threads; ++x)
		{
			SetupXMRTest(&MThrInfo[ThrIdx + x].AlgoCtx, &PlatformContext, GPUIdx);
			MThrInfo[ThrIdx + x].ThreadID = ThrIdx + x;
			MThrInfo[ThrIdx + x].TotalMinerThreads = Settings.TotalThreads;
			MThrInfo[ThrIdx + x].PlatformContext = &PlatformContext;
		}		
	}
	
	for(int i = 0; i < Settings.TotalThreads; ++i)
	{
		ret = pthread_create(MinerWorker + i, NULL, MinerThreadProc, MThrInfo + i);
		
		if(ret)
		{
			printf("Failed to create MinerWorker thread.\n");
			return(0);
		}
	}
	
	/*
	AlgoContext ctx;
	
	uint8_t TestInput[80];
	uint8_t TestOutput[64];
	
	for(int i = 0; i < 76; ++i) TestInput[i] = i;
	
	//TestInput[75] = 6;
	
	SetupXMRTest(&ctx, &PlatformContext, 0);
	RunXMRTest(&ctx, &PlatformContext, TestInput, TestOutput, 0);
	
	printf("Output: ");
	
	for(int i = 0; i < 32; ++i) printf("%02X", TestOutput[i]);
	
	putchar('\n');
	*/
	//json_decref(Settings.AlgoSpecificConfig);
	
	//pthread_create(&ADLThread, NULL, ADLInfoGatherThreadProc, NULL);
	
	while(!ExitFlag) sleep(1);
	
	//pthread_join(MinerWorker[0], NULL);
	
	pthread_cancel(Stratum);
	//pthread_cancel(ADLThread);
	
	for(int i = 0; i < Settings.TotalThreads; ++i) pthread_cancel(MinerWorker[i]);
	
	ReleaseOpenCLPlatformContext(&PlatformContext);
	
	//ADLRelease();
	
	FreeSettings(&Settings);
	free(RestartMining);
	free(Pool.MinerThreads);
	
	//pthread_cancel(BroadcastThread);
	
	closesocket(poolsocket);
	
	NetworkingShutdown();
	
	printf("Stratum thread terminated.\n");
	
	return(0);
}

