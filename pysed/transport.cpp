//-----------------------------------------------------------------------------
// Do NOT modify or remove this copyright
//
// Copyright (c) 2020 Seagate Technology LLC and/or its Affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//    http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
// ****************************************************************************
//
// \file transport.cpp
// \brief Implementation of transport class for TCG commands on top of OpenSea libraries
//
//-----------------------------------------------------------------------------
#include <fcntl.h>
#if !defined(_WINDOWS)
#include <sys/ioctl.h>
#include <scsi/sg.h>
#include <scsi/scsi_ioctl.h>
#include <linux/bsg.h>
#include <linux/kernel.h>
#include <alloca.h>
#include <unistd.h>
#endif
#include <list>
#include <stdlib.h>

#include <cmath>
#include "transport.h"
#include "drive_info.h"

#ifndef SG_SCSI_RESET_TARGET
#define SG_SCSI_RESET_TARGET 4
#endif

namespace Tcg {

	void IoStatus::operator=(uint8_t* sensebuffer) {
		if (sensebuffer[7] != 0)
			senseLen = 8 + (int)sensebuffer[7];
		else
			senseLen = 0;
		get_Sense_Key_ASC_ASCQ_FRU(sensebuffer, 252, &key, &asc, &ascq, &fru);
	}

	SeaTransport::SeaTransport(const char* devname) :
		devName(devname), device_struct(NULL), timeout(5), portNo(0) {
		if (devName == NULL)
			return;

		device_struct = (tDevice*)malloc(sizeof(tDevice));
		if (device_struct == NULL) {
			printf("Unable to allocate memory\n");
			exit(UTIL_EXIT_OPERATION_FAILURE);
		}
		memset(device_struct, 0, sizeof(tDevice));
		device_struct->sanity.size = sizeof(tDevice);
		device_struct->sanity.version = DEVICE_BLOCK_VERSION;
#if !defined(_WINDOWS)
		device_struct->os_info.fd = -1;
#else
		device_struct->os_info.fd = HANDLE(-1);
#endif
		int ret = get_Device(devName, device_struct);
		if ((device_struct->os_info.fd < 0)
			|| (ret == FAILURE || ret == PERMISSION_DENIED)) {
			printf("\nUnable to open file,Invalid device handle!\n");
			exit(UTIL_EXIT_INVALID_DEVICE_HANDLE);
		}

		// get the sas port number
		const size_t padding = 64; // extra memory required to prevent memory corruption in openseachest library call
		driveInformation* scsiDriveInfo = (driveInformation*)malloc(sizeof(driveInformation) + padding);
		if (scsiDriveInfo == NULL) {
			printf("Unable to allocate memory for scsiDriveInfo\n");
			exit(UTIL_EXIT_OPERATION_FAILURE);
		}
		memset(scsiDriveInfo, 0, sizeof(driveInformation));
		scsiDriveInfo->infoType = DRIVE_INFO_SAS_SATA;
		get_SCSI_Drive_Information(device_struct, &scsiDriveInfo->sasSata);
		portNo = scsiDriveInfo->sasSata.interfaceSpeedInfo.serialSpeed.activePortNumber;
		free(scsiDriveInfo);
	}

	SeaTransport::~SeaTransport() {
		if (device_struct != NULL) {
			close_Device(device_struct);
			free(device_struct);
		}
	}
	SeaTransport * SeaTransport::getTransport(const char * devname) {
		return new SeaTransport(devname);
	}

	int SeaTransport::send(ProtoIds protoId, void * buffer, uint32_t xfrSize) {
		int ret_send;

		/*ATA specific case for Buffer size */
		if (xfrSize < LEGACY_DRIVE_SEC_SIZE)
			xfrSize = LEGACY_DRIVE_SEC_SIZE;
		else if ((xfrSize > LEGACY_DRIVE_SEC_SIZE)
			&& (xfrSize % LEGACY_DRIVE_SEC_SIZE) != 0)
			xfrSize = static_cast<uint32_t>(ceil((double)xfrSize / LEGACY_DRIVE_SEC_SIZE)*LEGACY_DRIVE_SEC_SIZE);

		ret_send = security_Send(device_struct, extract_protoId(protoId), extract_protospecific_Id(protoId), (uint8_t *)buffer, xfrSize);
		lastStatus = device_struct->drive_info.lastCommandSenseData;
		return ret_send;
	}

	int SeaTransport::receive(ProtoIds protoId, void * buffer, uint32_t xfrSize) {
		int ret_receive;
		ret_receive = security_Receive(device_struct, extract_protoId(protoId), extract_protospecific_Id(protoId), (uint8_t *)buffer, xfrSize);
		lastStatus = device_struct->drive_info.lastCommandSenseData;
		return ret_receive;
	}

	void SeaTransport::release() {
		delete this;
	}

	void SeaTransport::reset(int level) {
		// Linux specific usage for ioctl for SCSI reset
#if !defined(_WINDOWS)
		int k = level <= 0 ? SG_SCSI_RESET_DEVICE : SG_SCSI_RESET_TARGET;
		if (ioctl(device_struct->os_info.fd, SG_SCSI_RESET, &k) < 0)
			throw TcgErrorErrno("Reset failed");
#else
		ULONG returned_data = 0;
		BOOL success = 0;
		success = DeviceIoControl(device_struct->os_info.fd,
			OBSOLETE_IOCTL_STORAGE_RESET_DEVICE,
			NULL,
			0,
			NULL,
			0,
			NULL,
			FALSE);
		if (!success)
		{
			throw TcgErrorErrno("Reset failed");
		}
#endif
	}

	int SeaTransport::tur() {
		scsiStatus returnedStatus = { 0 };
		return scsi_Test_Unit_Ready(device_struct, &returnedStatus);
	}

	int InvalidTransport::send(ProtoIds protoId, void * buffer, size_t xfrSize) {
		throw TcgError("Invalid SED Object");
	}
	int InvalidTransport::receive(ProtoIds protoId, void * buffer, size_t xfrSize) {
		throw TcgError("Invalid SED Object");
	}
	void InvalidTransport::reset(int level) {
		throw TcgError("Invalid SED Object");
	}

} // Tcg namespace
