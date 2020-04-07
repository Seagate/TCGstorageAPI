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
// \file TcgDrive.h
// \brief Defines the class for TCG packet operations
//
//-----------------------------------------------------------------------------
#ifndef TCGDRIVE_H_
#define TCGDRIVE_H_
#include "support.h"
#include <list>
#include "transport.h"
#include "Tcg.h"
#include "TcgScanner.h"

class ScopedGILRelease
{
public:
    ScopedGILRelease();
    ~ScopedGILRelease();

private:
    void * thstate;
};

class ScopedGILAcquire
{
public:
	ScopedGILAcquire();
	~ScopedGILAcquire();
private:
	int gstate;
};

namespace Tcg {

class Session;
class SessionPacket;
class Results;
class Packet;
class ParameterList;
class NamedParameterList;
class LoggerBase;
#if !defined(_WINDOWS)
class TlsCredentials;
#endif

class Drive {
protected:
	std::string		devname;
	SeaTransport *	transport;
	uint16_t		comId;
	uint16_t		comIdExt;
	uint8_t			ver2apis;
	Uid				authenticateUid;

public:
	Discovery		discovery;
#if !defined(_WINDOWS)
	TlsCredentials *tlsCreds[2];
	int 			tlsParameters;
#endif

	Drive(const char * devname);
	virtual ~Drive();
	virtual bool init();
	void destroyCreds();
	bool getComId();
	Session * newSession(Uid sp = 0, unsigned to = 0, bool readOnly = false);
	uint64_t getWwn() { return transport->getWwn();}
	uint64_t getMaxLba() { return transport->getMaxLba();}
	uint64_t getfipsdata()	{return transport->getfipsdata();}
	bool manageComId(ComIdRequestCodes request, void * results, size_t len);
	void stackReset();
	virtual LoggerBase &	getLogger() = 0;

	friend class Session;
	friend class TlsSession;
	friend struct PacketHeaders;
};

struct PacketHeaders {
	ComPacketHeader		comPacket;
	PacketHeader 		packet;
	SubPacketHeader		subPacket;

	void fill(Drive * const drive, Session * const session, uint32_t dataLength);
};

// Represents a block to send through the TCG transmit function.
// Packets representing function calls and parameter lists are allocated from
// this block as a stack and popped off as they are completed.
class PacketAllocator {
public:
	static const size_t	DataBlockLen = 1024;
protected:
	char		data[DataBlockLen];
	size_t		length;

	std::list<Packet *>				packetStack;

public:
	PacketAllocator();
	void * append(size_t len);
	void pushPacket(Packet * packet)	{packetStack.push_back(packet);}
	void popPacket(Packet * packet);
	void popAll();
	void reset();
	void fillHeaders(Drive * const drive, Session * const session);
	void * getBuffer() {return data;}
	void * getPayload() { return data + sizeof(PacketHeaders) - sizeof(SubPacketHeader);}
	size_t getPayloadLen() {
		size_t len = length - sizeof(PacketHeaders) + sizeof(SubPacketHeader);
		return (len % 4) ? len + 4 - len % 4:len;
	}
};

// A Packet is the base class for a small block of code representing function calls
// arguments and data structures.
class Packet {
protected:
	PacketAllocator &	pkta;

public:
	Packet(PacketAllocator & _pkta) :pkta(_pkta) { pkta.pushPacket(this); }
	virtual ~Packet();
	void * append(size_t len) {return pkta.append(len);}
	void encodeToken(Tokens token)
	{
		*static_cast<uint8_t *>(pkta.append(1)) = token;
	}
	void encodeAtom(const char * value, size_t len);
	void encodeAtom(uint64_t value);
	void encodeUid(Uid & uid);
	// Ability to add epilog code to a packet block.
	virtual void finish() {}

	void addNamedParameter(const char * name, std::string & value);
	void addOpalNamedParameter(const uint64_t name, std::string & value); //Opal Style
	void addNamedParameter(std::string name, const char * value, size_t len);
	void addNamedParameter(std::string name, std::string value)
		{ addNamedParameter(name, value.c_str(), value.size());}
	void addNamedParameter(std::string name, uint64_t value);
	void addParameter(std::string value) {encodeAtom(value.c_str(), value.size());}
	void addParameter(const char * value, size_t len) {encodeAtom(value, len);}
	void addParameter(uint64_t value)	{encodeAtom(value);}
	NamedParameterList * addNamedList(const char * name);
	void pop();
	ParameterList * addList();
};

// Represents parameters enclosed between StartList and EndList
class ParameterList : public Packet {
public:
	ParameterList(PacketAllocator & pkta);
	virtual void finish();
};

// Represents named parameter list
class NamedParameterList : public Packet {
public:
	NamedParameterList(PacketAllocator & pkta, const char * name);
	virtual void finish();
};

// Represents a method invocation.  Parameters need to be added with subsequent packet blocks.
class FunctionCall : public Packet {

#if defined(_WINDOWS)
#pragma pack(push, 1)
#endif
	struct CallPrologue {// Protocol 0 not linked to earlier send
		uint8_t		callToken;
		uint8_t		oidAtom;
		beint64_t	objectUid;
		uint8_t		cidAtom;
		beint64_t	callUid;
		uint8_t		startList;
		CallPrologue(Uid & objUid, Uid & callUid)
		: callToken(Call)
		, oidAtom(AtomUid)
		, objectUid(objUid)
		, cidAtom(AtomUid)
		, callUid(callUid)
		, startList(StartList)
		{}
	} __attribute__((__packed__));
	struct CallEpilogue {
		uint8_t		endList;
		uint8_t		endOfData;
		uint8_t		statusCodeStart;
		uint8_t		expStatus;
		uint8_t		rsvdStatus1;
		uint8_t		rsvdStatus2;
		uint8_t		statusCodeEnd;
		CallEpilogue(enum StatusCode expStatus)
		: endList(EndList)
		, endOfData(EndData)
		, statusCodeStart(StartList)
		, expStatus((uint32_t) expStatus)
		, rsvdStatus1(TinyAtomZero)
		, rsvdStatus2(TinyAtomZero)
		, statusCodeEnd(EndList)
		{}
	} __attribute__((__packed__));

#if defined(_WINDOWS)
#pragma pack(pop)
#endif
	enum StatusCode 	expStatus;
	struct NamedParameter {
		std::string	name;
		std::string	value;
	};

public:
	FunctionCall(PacketAllocator &allocator, Uid objUid, Uid callUid, enum StatusCode expStatus = SUCCESSCODE)
	: Packet(allocator)
	, expStatus(expStatus)
	{
		new(append(sizeof(CallPrologue))) CallPrologue(objUid, callUid);
	}
	virtual void finish()
	{
		new(append(sizeof(CallEpilogue))) CallEpilogue(expStatus);
	}
	void expectedStatus(enum StatusCode status) {expStatus = status;}
};

struct RcvdDataItem {
	uint8_t * 	ptr;
	size_t 		len;
	size_t		offset;
	RcvdDataItem(uint8_t * _ptr, size_t _len, size_t ofs) : ptr(_ptr), len(_len), offset(ofs) {}
};

class RcvdDataList : public std::list<RcvdDataItem>
{
public:
	void operator()(uint8_t * ptr, size_t len, size_t ofs)
	{
		push_back(RcvdDataItem(ptr, len, ofs));
	}
};

// A standard session with an SP.
class Session {
public:
	static bool dumpPackets;
protected:
	uint8_t	*		recvBuffer;
	size_t			recvBufferSize;
	Drive * const	drive;
	Uid				sp;
	uint32_t 		tperSession;
	uint32_t 		hostSession;
	uint32_t		seqNumber;
	PacketAllocator pkta;
	Uid				startSessionUid;

	static uint32_t nextHostSession;
	bool			moreData;
	unsigned        timeout;

	Session(Drive * const dr, Uid sp = 0, unsigned to = 0);
	virtual ~Session();
	virtual void startSessionEstablished() {}

public:
	void startSession(bool readOnly = false);
	virtual void close();
	bool authenticate(Uid authority, std::string credentials, bool endSession);
	int invoke(Results & results, bool endSession = false);
	virtual void getRcvdData(RcvdDataList & data);

	FunctionCall * call(Uid objUid, Uid callUid, enum StatusCode expStatus = SUCCESSCODE)
		{ return new FunctionCall(pkta, objUid, callUid, expStatus); }
	void callBack(Uid objectId, Uid methodId, boost::python::list parms);
	virtual void sendPackets(bool endSession = false);
	void receive(void * buf, size_t bufSize);
	void endSessionAck()		{ tperSession = 0; }

	uint32_t getTperSessionId() { return tperSession;}
	uint32_t getHostSessionId() { return hostSession;}
	LoggerBase & getLogger() const {return drive->getLogger();}
	void dumpPacket(const char * desc, void * buf, size_t size);
	friend class Drive;
	friend struct PacketHeaders;
	friend class ScopedSession;
};

// Session created within a frame and automatically closed when the frame terminates.
class ScopedSession
{
protected:
	Session * session;
	ScopedSession() {}

public:
	ScopedSession(Drive * const drive, Uid sp = 0, unsigned to = 0, bool useTls = false)
		{session = drive->newSession(sp, to, useTls);}
	~ScopedSession()	{session->close();}
	bool authenticate(Uid authority, std::string credentials, bool endSession = false) {return session->authenticate(authority, credentials, endSession);}
	int  invoke(Results & results, bool endSession)	{return session->invoke(results, endSession);}
	FunctionCall * call(Uid objUid, Uid callUid, enum StatusCode expStatus = SUCCESSCODE)
		{ return session->call(objUid, callUid, expStatus);}
	void clearSession() {session->tperSession = 0;}
};

}; // namespace Tcg

#endif /* TCGDRIVE_H_ */
