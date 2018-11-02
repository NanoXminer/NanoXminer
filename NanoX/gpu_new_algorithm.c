#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <CL/cl.h>
#include <time.h>
#include "minerlog.h"
#include "miner.h"
#include "ocl.h"

#if defined(__linux__) && !defined(_POSIX_TIMERS)
#error "Your Linux system doesn't support timing features required."
#endif

// RequestedDeviceIdxs is a list of OpenCL device indexes
// NumDevicesRequested is number of devices in RequestedDeviceIdxs list
// Returns 0 on success, -1 on stupid params, -2 on OpenCL API error
int32_t InitOpenCLPlatformContext(OCLPlatform *OCL, uint32_t RequestedPlatformIdx, uint32_t NumDevicesRequested, uint32_t *RequestedDeviceIdxs)
{
	size_t len;
	cl_int retval;
	cl_uint entries;
	cl_device_id *DeviceIDList, *TempDeviceList;
	cl_platform_id *PlatformIDList;
	
	// Sanity checks
	if(!OCL || !NumDevicesRequested || !RequestedDeviceIdxs) return(ERR_STUPID_PARAMS);
	
	retval = clGetPlatformIDs(0, NULL, &entries);
	
	if(retval != CL_SUCCESS)
	{
		Log(LOG_CRITICAL, "Error %d when calling clGetPlatformIDs for number of platforms.", retval);
		return(ERR_OCL_API);
	}
	
	// The number of platforms naturally is the index of the
	// last platform plus one.
	if(entries <= RequestedPlatformIdx)
	{
		Log(LOG_CRITICAL, "Selected OpenCL platform index %d doesn't exist.", RequestedPlatformIdx);
		return(ERR_STUPID_PARAMS);
	}
	
	PlatformIDList = (cl_platform_id *)malloc(sizeof(cl_platform_id) * entries);
	retval = clGetPlatformIDs(entries, PlatformIDList, NULL);
	
	if(retval != CL_SUCCESS)
	{
		Log(LOG_CRITICAL, "Error %d when calling clGetPlatformIDs for platform ID information.", retval);
		free(PlatformIDList);
		return(ERR_OCL_API);
	}
	
	// Verified index sanity above
	OCL->Platform = PlatformIDList[RequestedPlatformIdx];
	free(PlatformIDList);
	
	retval = clGetDeviceIDs(OCL->Platform, CL_DEVICE_TYPE_GPU, 0, NULL, &entries);
	
	if(retval != CL_SUCCESS)
	{
		Log(LOG_CRITICAL, "Error %d when calling clGetDeviceIDs for number of devices.", retval);
		return(ERR_OCL_API);
	}
	
	// Same as the platform index sanity check, except we
	// must check all requested device indexes
	for(int i = 0; i < NumDevicesRequested; ++i)
	{
		if(entries <= RequestedDeviceIdxs[i])
		{
			printf("Selected OpenCL device index %d doesn't exist.\n", RequestedDeviceIdxs[i]);
			return(ERR_STUPID_PARAMS);
		}
	}
	
	DeviceIDList = (cl_device_id *)malloc(sizeof(cl_device_id) * entries);
	
	retval = clGetDeviceIDs(OCL->Platform, CL_DEVICE_TYPE_GPU, entries, DeviceIDList, NULL);
	
	if(retval != CL_SUCCESS)
	{
		printf("Error %d when calling clGetDeviceIDs for device ID information.\n", retval);
		free(DeviceIDList);
		return(ERR_OCL_API);
	}
	
	OCL->Devices = (OCLDevice *)malloc(sizeof(OCLDevice) * NumDevicesRequested);
	TempDeviceList = (cl_device_id *)malloc(sizeof(cl_device_id) * NumDevicesRequested);
	
	// Indexes sanity checked above
	for(int i = 0; i < NumDevicesRequested; ++i)
		TempDeviceList[i] = DeviceIDList[RequestedDeviceIdxs[i]];
		
	free(DeviceIDList);
	
	OCL->Context = clCreateContext(NULL, NumDevicesRequested, TempDeviceList, NULL, NULL, &retval);
	
	if(retval != CL_SUCCESS)
	{
		Log(LOG_CRITICAL, "Error %d when calling clCreateContext.", retval);
		return(ERR_OCL_API);
	}
	
	// Copy device IDs to structure now that we've got a context
	// While we're at it, fill in the other fields, too.
	for(int i = 0; i < NumDevicesRequested; ++i)
	{
		char *Version;
		int idx;
		
		OCL->Devices[i].DeviceID = TempDeviceList[i];
		retval = clGetDeviceInfo(OCL->Devices[i].DeviceID, CL_DEVICE_NAME, 0, NULL, &len);
		
		if(retval != CL_SUCCESS)
		{
			Log(LOG_CRITICAL, "Error %d when querying the length of the device name for a device using clGetDeviceInfo.", retval);
			return(ERR_OCL_API);
		}
		
		OCL->Devices[i].DeviceName = (char *)malloc(sizeof(char) * (len + 2));
		
		retval = clGetDeviceInfo(OCL->Devices[i].DeviceID, CL_DEVICE_NAME, len, OCL->Devices[i].DeviceName, NULL);
		
		if(retval != CL_SUCCESS)
		{
			Log(LOG_CRITICAL, "Error %d when querying the name of a device using clGetDeviceInfo.", retval);
			return(ERR_OCL_API);
		}
		
		retval = clGetDeviceInfo(OCL->Devices[i].DeviceID, CL_DEVICE_VERSION, 0, NULL, &len);
		 
		if(retval != CL_SUCCESS)
		{
			Log(LOG_CRITICAL, "Error %d when querying the length of a device version string using clGetDeviceInfo.", retval);
			return(ERR_OCL_API);
		}

		Version = (char *)malloc(sizeof(char) * (len + 2));

		retval = clGetDeviceInfo(OCL->Devices[i].DeviceID, CL_DEVICE_VERSION, len, Version, NULL);

		if(retval != CL_SUCCESS)
		{
			Log(LOG_CRITICAL, "Error %d when querying a device version string using clGetDeviceInfo.", retval);
			return(ERR_OCL_API);
		}
		
		// OpenCL spec says version format is:
		// OpenCL<space><major_version.minor_version><space><vendor-specific information>
		
		idx = 7;
		
		// 0x20 == SPACE
		while(Version[idx++] != 0x20 && idx < strlen(Version));
		
		if(idx == strlen(Version))
		{
			Log(LOG_CRITICAL, "Error parsing version string from clGetDeviceInfo. This should never happen.");
			return(ERR_OCL_API);
		}
		
		// NULL terminate the string here
		Version[idx - 1] = 0x00;
		
		// Now parse from the known start of the version number
		// to the new end of the string with strtod()
		
		OCL->Devices[i].OCLVersion = strtod(Version + 7, NULL);
		free(Version);
		
		retval = clGetDeviceInfo(OCL->Devices[i].DeviceID, CL_DEVICE_MAX_WORK_GROUP_SIZE, sizeof(size_t), &OCL->Devices[i].MaximumWorkSize, NULL);
		
		if(retval != CL_SUCCESS)
		{
			Log(LOG_CRITICAL, "Error %d when querying a device's max worksize using clGetDeviceInfo.", retval);
			return(ERR_OCL_API);
		}
		
		retval = clGetDeviceInfo(OCL->Devices[i].DeviceID, CL_DEVICE_MAX_COMPUTE_UNITS, sizeof(cl_uint), &OCL->Devices[i].ComputeUnits, NULL);
		if(retval != CL_SUCCESS)
		{
			Log(LOG_CRITICAL, "Error %d when querying a device's compute unit count using clGetDeviceInfo.", retval);
			return(ERR_OCL_API);
		}
		
		// AMD GCN cards have 64 shaders per compute unit
		OCL->Devices[i].TotalShaders = OCL->Devices[i].ComputeUnits * 64;
	}
	
	free(TempDeviceList);
	
	OCL->NumDevices = NumDevicesRequested;
	return(0);
}

void ReleaseOpenCLPlatformContext(OCLPlatform *OCL)
{
	for(int i = 0; i < OCL->NumDevices; ++i)
		free(OCL->Devices[i].DeviceName);
	
	free(OCL->Devices);
	clReleaseContext(OCL->Context);
}
