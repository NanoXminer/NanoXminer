#ifndef __OCL_H
#define __OCL_H

#include <CL/cl.h>
#include <stdint.h>

// An OCLDevice structure contains information specific to one device,
// necessary for using it for any sort of work. How many command queues
// there are and their properties go in here - the properties of a given
// command queue likely influenced by the work that will be running on it.

// One device may have multiple command queues, and may execute different
// hash algos concurrently. Each hash algo being executed will get a
// command queue - but that won't be stored here; each hash algo will
// create at least one command queue, more if it requires them.

typedef struct _OCLDevice
{
	char *DeviceName;
	double OCLVersion;
	cl_uint TotalShaders;
	cl_uint ComputeUnits;
	cl_device_id DeviceID;
	size_t MaximumWorkSize;
	size_t rawIntensity;
	size_t WorkSize;
} OCLDevice;

// An OCLPlatform structure contains information necessary to
// interact with a subset of devices in one platform. It may
// only be associated with one platform, but it MAY have
// multiple devices. This allows for simpler management,
// having one cl_context for any number of devices, and
// allows freedom in choosing how to split them up, if you
// choose to do so. 

typedef struct _OCLPlatform
{
	cl_context Context;
	cl_platform_id Platform;
	OCLDevice *Devices;
	uint32_t NumDevices;
} OCLPlatform;

// A AlgoContext structure contains information specific to one algo,
// necessary for executing the hash algorithm. How many extra command queues
// there are, their properties, what Program is loaded with, and the number
// of kernels and their arguments all depend on the hash, giving it
// flexibility in execution.

// Most hashes will require an input buffer, all will require an output
// buffer. There may be additional buffers required; this is hash-specific.
// Additional buffers can therefore be created using ExtraBuffers member,
// which must be freed in the hash-specific cleanup function.
typedef struct _AlgoContext
{
	cl_command_queue *CommandQueues;
	cl_mem InputBuffer;
	cl_mem OutputBuffer;
	int32_t (*SetKernelArgs)(struct _AlgoContext *, void *, uint64_t);
	int32_t (*Execute)(struct _AlgoContext *, size_t);
	int32_t (*GetResults)(struct _AlgoContext *, cl_uint *);
	void (*Cleanup)(struct _AlgoContext *);
	cl_mem *ExtraBuffers;
	cl_program Program;
	cl_kernel *Kernels;
	size_t GlobalSize;
	size_t WorkSize;
	void *ExtraData;
	size_t Nonce;
} AlgoContext;

int32_t InitOpenCLPlatformContext(OCLPlatform *OCL, uint32_t RequestedPlatformIdx, uint32_t NumDevicesRequested, uint32_t *RequestedDeviceIdxs);
void ReleaseOpenCLPlatformContext(OCLPlatform *OCL);

#endif
