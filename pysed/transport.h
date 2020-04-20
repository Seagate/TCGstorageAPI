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
// \file transport.h
// \brief Defines of transport class for TCG commands on top of OpenSea libraries
//
//-----------------------------------------------------------------------------
#include <stdint.h>
#include "portable_endian.h"
#include <string.h>
#include <stdio.h>
#include <stdarg.h>
#include <string>
#include "Tcg.h"
#include "operations.h"

#ifndef SEATRANSPORT_H_
#define SEATRANSPORT_H_
typedef unsigned char u_char ;
namespace Tcg
{

struct IoStatus {
	u_char			key, asc, ascq,fru;
	unsigned		senseLen;

	void operator=(uint8_t* sensebuffer);

	bool hasSense(u_char qkey, u_char qasc, u_char qascq)
	{
		if (senseLen == 0)
			return false;
		return key == qkey && asc == qasc && ascq == qascq;
	}
};

class SeaTransport{
protected:
	const char*	devName;
    tDevice*  device_struct;
	int		timeout;

    SeaTransport(const char* devname);
    virtual ~SeaTransport();

public:
    uint8_t	    portNo;
    IoStatus	lastStatus;
  enum ProtoIds {
  		SECURITY_PROTOCOL_LIST   = 0x00000000,	// SPC-4 Section 7.7 return list of supported protocols
  		CERTIFICATE_DATA         = 0x00000100,
  		SECURITY_COMPLIANCE_INFO = 0x00000200,
  		COMPACKET_IO			 = 0x01000080,
  		LEVEL0_DISCOVERY         = 0x01000180, // Identifies drive as an SED, Enterprise and if yes, calculates comID
  		GET_COM_ID 		         = 0x02000080,// Used only after IF-SEND to retrieve stack-reset status
  	};
  	inline static enum ProtoIds ComPacket(uint16_t comId) {
  		return (ProtoIds) (COMPACKET_IO | ((uint32_t) comId << 8));
  	}
  	inline static enum ProtoIds ManageComId(uint16_t comId) {
  		return (ProtoIds) (GET_COM_ID | ((uint32_t) comId << 8));
  	}
  	inline static uint8_t extract_protoId(enum ProtoIds protoId){
  		 enum ProtoIds extract_protoId = protoId;
  		  return (((1 << 8) - 1) & (extract_protoId >> (25 - 1)));
  	}
  	inline static uint16_t extract_protospecific_Id(enum ProtoIds protoId){
  		 enum ProtoIds extract_protospecificId = protoId;
  		 return (((1 << 16) - 1) & (extract_protospecificId >> (9 - 1)));
  	  	}

  static SeaTransport * getTransport(const char * devname);
  void reset(int level = 0);
  uint64_t	getWwn() 	{return device_struct->drive_info.worldWideName;}
  uint64_t	getMaxLba() {return device_struct->drive_info.deviceMaxLba;}
  uint64_t getfipsdata(){return device_struct->drive_info.IdentifyData.ata.Word159 & 1;}
  int receive(ProtoIds protoId, void * buffer, uint32_t xfrSize);
  int send(ProtoIds protoId, void * buffer, uint32_t xfrSize);
  void release();
  void setTimeout(int to) {timeout = to;}
  int tur();
};

class InvalidTransport : public SeaTransport
{
public:
	InvalidTransport()
	: SeaTransport(NULL)
	{}
protected:
	virtual int send(ProtoIds protoId, void * buffer, size_t xfrSize);
	virtual int receive(ProtoIds protoId, void * buffer, size_t xfrSize);
	virtual void reset(int level);
};

// From SPC-4 Table 517
struct FipsComplianceDescriptor
{
	beint16_t		type;		// 01
	uint16_t		reserved;
	beint32_t		length;
	uint8_t			relatedStandard;
	uint8_t			securityLevel;
	uint8_t			reserved10[6];
	char			hardwareVersion[128];
	char			descVersion[128];
	char			moduleName[256];
};

enum RelatedStandard
{
	FIPS_140_2	= 0x32,
	FIPS_140_3	= 0x33,
};


}; // Tcg namespace

typedef enum _eUtilExitCodes{
        //Generic exit codes
        UTIL_EXIT_NO_ERROR = 0,
        UTIL_EXIT_ERROR_IN_COMMAND_LINE,
        UTIL_EXIT_INVALID_DEVICE_HANDLE,
        UTIL_EXIT_OPERATION_FAILURE,
        UTIL_EXIT_OPERATION_NOT_SUPPORTED,
        UTIL_EXIT_OPERATION_ABORTED,
        UTIL_EXIT_PATH_NOT_FOUND,
        UTIL_EXIT_CANNOT_OPEN_FILE,
        UTIL_EXIT_FILE_ALREADY_EXISTS,
}eUtilExitCodes;

#endif
