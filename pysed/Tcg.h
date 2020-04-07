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
// \file Tcg.h
// \brief Defines class for Level 0 Discovery
//
//-----------------------------------------------------------------------------
#ifndef TCG_H_
#define TCG_H_
#include "support.h"

namespace Tcg {
class SeaTransport;
struct DescriptorEnum;

class Discovery {
	uint8_t		buffer[512];
	uint16_t	otherSSC;
public:

#if defined(_WINDOWS)
#pragma pack(push, 1)
#endif

	struct Hdr {
		  beint32_t     length;
		  beint32_t     version;
		  unsigned char reserved[8];
		  unsigned char vendor[32];
	} __attribute__((__packed__));

	enum FeatureCodes {
		fcEmpty				= 0x0000,
		fcTper				= 0x0001,
		fcLocking 			= 0x0002,
		fcGeometry			= 0x0003,
		fcSecureMessaging 	= 0x0004,
		fcEnterpriseSSC 	= 0x0100,
		fcOpalSSC			= 0x0200,
		fcSingleUserMode	= 0x0201,
		fcDataStore			= 0x0202,
		fcOpalv2SSC			= 0x0203,
		fcLogicalPorts		= 0xc001,
		fcNotSED			= 0xffff
	};

	struct DescHdr {
		beint16_t   featureCode;
		uint8_t	  	version :4;
		uint8_t		reserved :4;
		uint8_t		length;
	} __attribute__((__packed__));

	struct TperDesc {
		DescHdr	hdr;
		uint8_t	syncSupported:1;
		uint8_t	asynchSupported:1;
		uint8_t	ACKNACKSupported:1;
		uint8_t	bufferManagementSupported:1;
		uint8_t	streamingSupported:1;
		uint8_t	reservedb5:1;
		uint8_t	comIDManagementSupported:1;
		uint8_t	Reservedb7:1;
	} __attribute__((__packed__));

	struct LockingDesc {
		DescHdr	hdr;
		uint8_t lockingSupported:1;
		uint8_t lockingEnabled:1;
		uint8_t locked:1;
		uint8_t mediaEncryption:1;
		uint8_t MBREnabled:1;
		uint8_t MBRDone:1;
		uint8_t fipsApprovedMode:1;
		uint8_t reservedBit:1;
	} __attribute__((__packed__));

	struct GeometryDesc {
		DescHdr		hdr;
		uint8_t		align:1;
		uint8_t		reserved4;
		beint32_t	blockSize;
		beint64_t	granularity;
		beint64_t	lowestAligned;
	} __attribute__((__packed__));

	struct SecureMsgDesc {
		DescHdr		hdr;
		uint8_t		resumption:1;
		uint8_t		compression:1;
		uint8_t		renegotiation:1;
		uint8_t		serverCert:1;
		uint8_t		certRequest:1;
		uint8_t		reservedFeat:2;
		uint8_t		activated:1;
		uint8_t		reserved5[3];
		beint16_t	spCount;			// Assumed to be 2 (AdminSP, LockingSP) for browsing.
		beint64_t	sps[2];
		beint16_t	cipherSuiteCount;
		beint32_t   cipherSuites[1];
	} __attribute__((__packed__));

	struct SMCS {		// SecureMsgDesc cypherSuite construct
		beint16_t	count;
		beint32_t   suites[1];
	} __attribute__((__packed__));

	struct EnterpriseDesc {
		DescHdr		hdr;
		beint16_t   baseComId;
		beint16_t   comIdCount;
		uint8_t    	reservedA :7;
		uint8_t     rangeCrossing :1;
	} __attribute__((__packed__));

	struct OpalV2Desc {
		DescHdr		hdr;
		beint16_t   baseComId;
		beint16_t   comIdCount;
		uint8_t    	reservedA :7;
		uint8_t     rangeCrossing :1;
		beint16_t   AdminAuthCount;
		beint16_t   UserAuthCount;
		uint8_t    	InitialPin;
		uint8_t    	RevertedPin;
		uint8_t    	reserved02;
		beint32_t   reserved03;

	} __attribute__((__packed__));

	struct OpalDesc{
		DescHdr		hdr;
		beint16_t   baseComId;
		beint16_t   comIdCount;
	}__attribute__((__packed__));

	struct PortDesc {
			DescHdr		hdr;
			struct PortEntry {
				beint32_t   portIdentifier;
				uint8_t     portLocked;
				uint8_t		reserved[3];
			} __attribute__((__packed__)) portEntry[1];
	} __attribute__((__packed__));

#if defined(_WINDOWS)
#pragma pack(pop)
#endif

	Hdr *				hdr;
	TperDesc * 			tper;
	LockingDesc * 		locking;
	GeometryDesc * 		geometry;
	EnterpriseDesc *	enterprise;
	PortDesc * 			port;
	SecureMsgDesc * 	tls;
	OpalV2Desc *	    opalV2;
	OpalDesc*           opal;
	Discovery();
	void refresh(SeaTransport * transport);
	bool isSed() {return otherSSC != fcNotSED;}
    void enumDescriptors(DescriptorEnum & f);
    const char * ssc();
};

struct DescriptorEnum
{
       virtual void operator()(const Discovery::DescHdr * hdr, const void * data) = 0;
       virtual void hdr(const Discovery::Hdr * hdr) = 0;
       virtual ~DescriptorEnum() {}
};

#if defined(_WINDOWS)
#pragma pack(push, 1)
#endif

struct ComPacketHeader
{
	uint32_t		reserved;
	beint16_t		comId;
	beint16_t		comIdExt;
	beint32_t		outstandingData;
	beint32_t		minTransfer;
	beint32_t		length;		// not including header
	ComPacketHeader(uint16_t _comId = 0xffe, uint16_t comIdExt = 0)
	{
		memset(this, 0, sizeof(ComPacketHeader));
		comId = _comId;
	}
} __attribute__((__packed__));

struct PacketHeader
{
	beint32_t		tperSession;
	beint32_t		hostSession;
	beint32_t		seqNumber;
	uint16_t		reserved;
	beint16_t		ackType;
	beint32_t		acknowledgement;
	beint32_t		length;		// not including header
	PacketHeader()
	{
		memset(this, 0, sizeof(PacketHeader));
	}
} __attribute__((__packed__));
enum AckTypes {
	None	= 0,
	Ack		= 1,
	Nak		= 2,
};

struct SubPacketHeader
{
	uint8_t		reserved[6];
	beint16_t	kind;
	beint32_t	length;		// not including header
} __attribute__((__packed__));

struct TperTime {
	beint16_t	year;
	uint8_t		month;
	uint8_t		day;
	uint8_t		hour;
	uint8_t		minute;
	uint8_t		second;
	beint16_t	fraction;
	uint8_t		reserved;
} __attribute__((__packed__));

enum Tokens {
	TinyAtomZero 	= 0,
	Atom 			= 1,
	AtomDword 		= 0x84,
	AtomQuad 		= 0x88,
	AtomUid   		= 0xa8,
    StartList 		= 0xf0,
    EndList 		= 0xf1,
    StartName 		= 0xf2,
    EndName 		= 0xf3,
    Call 			= 0xf8,
    EndData 		= 0xf9,
    EndSession 		= 0xfa,
    StartTransaction = 0xfb,
    EndTransaction 	= 0xfc,
	EmptyAtom 		= 0xff,
};

enum StatusCode {
    SUCCESSCODE 			= 0x00,
    NOT_AUTHORIZED 			= 0x01,
    OBSOLETECODE 			= 0x02,
    SP_BUSY 				= 0x03,
    SP_FAILED 				= 0x04,
    SP_DISABLED 			= 0x05,
    SP_FROZEN 				= 0x06,
    NO_SESSIONS_AVAILABLE 	= 0x07,
    UNIQUENESS_CONFLICT 	= 0x08,
    INSUFFICIENT_SPACE 		= 0x09,
    INSUFFICIENT_ROWS 		= 0x0A,
    INVALID_PARAMETER 		= 0x0C,
    TPER_MALFUNCTION 		= 0x0F,
    TRANSACTION_FAILURE 	= 0x10,
    RESPONSE_OVERFLOW 		= 0x11,
    AUTHORITY_LOCKED_OUT 	= 0x12,
    FAIL 					= 0x3F,
	// Implementation return values
	TIMEOUT					= 0x40,
	UNEXPECTED_RESULTS		= 0x41,
	TLS_ALERT				= 0x42,
};

enum ExtComIdState {
	Invalid 	= 0,
	Inactive 	= 1,
	Issued		= 2,
	Associated	= 3,
};
struct ComIdRequest {
	beint16_t		comId;
	beint16_t		comIdExt;
	beint32_t		request;
} __attribute__((__packed__));

struct ComIdResponse : public ComIdRequest{
	int16_t		reserved;
	beint16_t	length;
} __attribute__((__packed__));

struct ComIdVerifyResponse : public ComIdResponse {
	beint32_t	currentState;
	TperTime		allocationTime;
	TperTime		expireTime;
	TperTime		lastReset;
} __attribute__((__packed__));

struct ComIdResetResponse : public ComIdResponse {
	beint32_t	failure;		// 0 on succcess, 1 on failure
} __attribute__((__packed__));

enum ComIdRequestCodes {
	VerifyComId		= 1,
	ResetStack		= 2,
};

#if defined(_WINDOWS)
#pragma pack(pop)
#endif

typedef uint64_t	Uid;

};	// namespace Tcg

namespace TcgUids {
using Tcg::Uid;

static const Uid		Null				= 0;
static const Uid		ThisSp 				= 1;
static const Uid		SessionManager 		= 0xff;

static const Uid		AdminSP	 			= 0x0000020500000001;
static const Uid		LockingSP			= 0x0000020500010001;

namespace Authorities {
	static const Uid	Anybody			 	= 0x0000000900000001;
}

static const Uid PortsBase = 0x0001000200000000;

namespace Methods {
	// Session Manager Methods
	static const Uid		Properties			= 0x000000000000FF01;
	static const Uid		StartSession 		= 0x000000000000FF02;
	static const Uid		SyncSession 		= 0x000000000000FF03;
	static const Uid		StartTrustedSession = 0x000000000000FF04;
	static const Uid		SyncTrustedSession	= 0x000000000000FF05;
	static const Uid		CloseSession 		= 0x000000000000FF06;
	static const Uid        StartTlsSession     = 0x000000000000FF12;
	static const Uid        SyncTlsSession      = 0x000000000000FF13;

	static const Uid		Authenticate	 	= 0x000000060000000C;

};
};

namespace TlsIds {
    static const uint16_t   TLS_DHE_PSK_WITH_AES_128_GCM_SHA256 		= 0x0AA;
    static const uint16_t   TLS_PSK_WITH_AES_128_GCM_SHA256 			= 0x0A8;
    static const uint16_t   TLS_PSK_WITH_AES_256_GCM_SHA384 			= 0x0A9;
    static const uint16_t   TLS_DHE_PSK_WITH_AES_256_GCM_SHA384 		= 0x0AB;
    static const uint16_t   TLS_PSK_WITH_AES_128_CBC_SHA256 			= 0x0AE;
    static const uint16_t   TLS_PSK_WITH_AES_256_CBC_SHA384 			= 0x0AF;
    static const uint16_t   TLS_PSK_WITH_NULL_SHA256 				= 0x0B0;
    static const uint16_t   TLS_PSK_WITH_NULL_SHA384 				= 0x0B1;
    static const uint16_t   TLS_DHE_PSK_WITH_AES_128_CBC_SHA256 		= 0x0B2;
    static const uint16_t   TLS_DHE_PSK_WITH_AES_256_CBC_SHA384 		= 0x0B3;
    static const uint16_t   TLS_DHE_PSK_WITH_NULL_SHA256 			= 0x0B4;
    static const uint16_t   TLS_DHE_PSK_WITH_NULL_SHA384 			= 0x0B5;
    static const uint16_t   TLS_PSK_WITH_AES_128_CCM 				= 0xCA4;
    static const uint16_t   TLS_PSK_WITH_AES_256_CCM 				= 0xCA5;
    static const uint16_t   TLS_DHE_PSK_WITH_AES_128_CCM 			= 0xCA6;
    static const uint16_t   TLS_DHE_PSK_WITH_AES_256_CCM 			= 0xCA7;
    static const uint16_t   TLS_ECDHE_PSK_WITH_AES_128_CBC_SHA256 	= 0xC37;
    static const uint16_t   TLS_ECDHE_PSK_WITH_AES_256_CBC_SHA384 	= 0xC38;
    static const uint16_t   TLS_ECDHE_PSK_WITH_NULL_SHA256 			= 0xC3A;
    static const uint16_t   TLS_ECDHE_PSK_WITH_NULL_SHA384 			= 0xC3B;
};

#endif /* TCG_H_ */
