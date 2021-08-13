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
// \file TcgDrive.cpp
// \brief Implementation of class for TCG packet operations
//
//-----------------------------------------------------------------------------
#include <string.h>
#include "TcgDrive.h"
#include "Tcg.h"
#include "TcgScanner.h"
#include "support.h"
#if !defined(_WINDOWS)
#include "Tls.h"
#endif
#include <boost/python.hpp>
#include <boost/python/object.hpp>
#include <boost/python/list.hpp>
#include <boost/python/dict.hpp>

namespace Tcg {

using boost::python::str;
using boost::python::list;
using boost::python::dict;
using boost::python::extract;

//Pointer to an array of string characters
Drive::Drive(const char * _devname) :
		devname(_devname), transport(NULL), comId(0), comIdExt(0), ver2apis(0), authenticateUid(TcgUids::Methods::Authenticate)
#if !defined(_WINDOWS)
	, tlsParameters(-1)
#endif
{
#if !defined(_WINDOWS)
	tlsCreds[0] = tlsCreds[1] = 0;
#endif
}

Drive::~Drive() {
	if (transport) {
		transport->release();
		transport = NULL;
	}
	destroyCreds();
}

void Drive::destroyCreds() {
#if !defined(_WINDOWS)
	if (tlsCreds[0] == tlsCreds[1]) {
		if (tlsCreds[0])
			delete tlsCreds[0];
	} else {
		delete tlsCreds[0];
		if (tlsCreds[1])
			delete tlsCreds[1];
	}
	tlsCreds[0] = tlsCreds[1] = 0;
#endif
}

bool Drive::init() {
	try {
		ScopedGILRelease unlockGIL;
		transport = SeaTransport::getTransport(devname.c_str());
	} catch (...) {
		transport = new InvalidTransport();
		throw;
	}
	discovery.refresh(transport);
	if (!discovery.isSed()){
		return false;
	}

	if (!discovery.enterprise && !discovery.opalV2 &&!discovery.opal ) {
			getLogger().warning("Device %s is not an Enterprise or Opalv1/Opalv2 SED device.",
					devname.c_str());
			return false;		// not an SED drive
		}
	if (!discovery.tper || !discovery.locking) {
		getLogger().warning("Device %s is not an SED device.",
				devname.c_str());
		return false;		// not an enterprise SED drive
	}
	if (!discovery.tper->syncSupported || !discovery.tper->streamingSupported
			|| !discovery.locking->lockingSupported
			|| !discovery.locking->mediaEncryption

			|| (discovery.enterprise && discovery.enterprise->comIdCount < 2)
			|| (discovery.opalV2 && discovery.opalV2->comIdCount < 2)
			|| (discovery.opal && discovery.opal->comIdCount < 2)
	) {
		getLogger().warning("Insufficient SED functionality for device %s.",
				devname.c_str());
		return false;
	}
	if(discovery.enterprise)
	{
	comId = discovery.enterprise->baseComId
			+ transport->portNo % discovery.enterprise->comIdCount;
	}
	else if(discovery.opalV2)
	{
	comId = discovery.opalV2->baseComId
			+ transport->portNo % discovery.opalV2->comIdCount;
	}
	else if(discovery.opal)
		{
		comId = discovery.opal->baseComId
				+ transport->portNo % discovery.opal->comIdCount;
		}

	return true;
}

Session * Drive::newSession(Uid sp, unsigned to, bool useTls) {
	Session * session;
#if !defined(_WINDOWS)
	if (useTls)
	{
		session = new TlsSession(this, sp, to);
	}
	else
#endif
	{
		session = new Session(this, sp, to);
	}
	try {
		if (sp)
			session->startSession();
	} catch (ParserAbort & /*pa*/) {
		throw TcgError("Timeout waiting for startSession response.");
	}

	return session;
}

void Drive::stackReset() {
	ComIdResetResponse resp;
	for (int retry = 0; retry < 5; retry++) {
		if (manageComId(ResetStack, &resp, sizeof(resp)) && resp.failure == 0) {
			return;
		}
	}
	throw TcgErrorIoStatus(transport->lastStatus, "Sending StackReset");
}

bool Drive::manageComId(ComIdRequestCodes request, void * results, size_t len) {
	ScopedGILRelease unlockGil;
	char buffer[512];
	ComIdRequest * req = (ComIdRequest *) buffer;
	req->comId = comId;
	req->comIdExt = comIdExt;
	req->request = request;
	if (transport->send(SeaTransport::ManageComId(comId), buffer, sizeof(buffer))
			!= 0) {
		return false;
	}

	for (int retry = 0; retry < 5; retry++) {
		if (transport->receive(SeaTransport::ManageComId(comId), buffer,
				sizeof(buffer))) {
			continue;
		}
		if (len)
			memcpy(results, buffer, len);
		return true;
	}
	return false;
}

bool Session::dumpPackets = true;
uint32_t Session::nextHostSession = 100;

Session::Session(Drive * const dr, Uid sp, unsigned to) :
		recvBuffer(NULL), recvBufferSize(1024), drive(dr), sp(sp), tperSession(
				0), hostSession(0), seqNumber(1), startSessionUid(
				TcgUids::Methods::StartSession), moreData(false), timeout(
				to != 0 ? ((to + 50) / 10) : 55) {
}

Session::~Session() {
	if (recvBuffer)
		delete[] recvBuffer;
}

void Session::startSession(bool readOnly) {
	if (!sp)
		return;
	hostSession = nextHostSession++;
	bool stackResetAttempted = false;
	int resetLevel = 0;
	for (int retry = 0; retry < 10; retry++) {
		try {
			FunctionCall * start = call(TcgUids::SessionManager,
					startSessionUid);
			start->addParameter(hostSession);
			start->encodeUid(sp);
			start->addParameter(readOnly ? 0 : 1);

			Results results;
			int rv = invoke(results);
			if (tperSession != 0) {
				startSessionEstablished();
				return;
			}
			getLogger().debug("StartSession sp=%lx, rv = %d", sp, rv);
			{
				ScopedGILRelease unlockGIL;
				usleep(500000 * (retry / 3 + 1));
			}
			if (retry < 7)
				continue;		// no stack reset necessary
		} catch (TcgErrorIoStatus & e) {
			getLogger().warning(
					"StartSession: performing %s Reset due to error: %s",
					stackResetAttempted ? "I/F" : "TCG", e.what());
		}
		if (stackResetAttempted)
			try {
				ScopedGILRelease unlockGIL;
				drive->transport->reset(resetLevel++);
				usleep(500000 * (retry / 3 + 1));
				drive->transport->tur();		// clear possible unit attention
				continue;
			} catch (TcgError & e) {
				getLogger().warning("%s",e.what());
			}
		drive->stackReset();
		stackResetAttempted = true;
	}
	throw TcgError("Unable to start session");
}

#if 0
// The Keplar drive (in development in 2016) used to develop this code didn't
// use the enhanced properties, so why bother negotiating enhanced protocols.
bool Session::exchangeProperties()
{
	for (int retry = 0; retry < 3; retry++)
	{
		try {

			FunctionCall * propCall = call(TcgUids::SessionManager, TcgUids::Methods::Properties);
			NamedParameterList * hostProps = propCall->addNamedList("HostProperties");
			hostProps->addNamedParameter("MaxSubpackets", 0);
			hostProps->addNamedParameter("MaxPackets", 0);
			// Not in Enterprise SSC hostProps->addNamedParameter("ContinuedTokens", 1);
			hostProps->addNamedParameter("MaxAggTokenSize", 0);
			hostProps->addNamedParameter("MaxResponseComPacketSize", 16384);
			hostProps->addNamedParameter("MaxMethods", 5);
			hostSession = 1;

			Results results;
			if (invoke(results) == 0)
			return true;
		} catch (TcgErrorIoStatus & e) {
			if (retry > 1)
			drive->transport->reset();
		}
		drive->stackReset();
	}
	return false;
}
#endif

void Session::close() {
	if (sp != 0 && tperSession) {
		Results results;
		invoke(results, true);
	}
	delete this;
}

// Returns true on successful authentication
bool Session::authenticate(Uid authority, std::string credentials,
		bool endSession) {
	FunctionCall * auth = call(TcgUids::ThisSp, drive->authenticateUid);
	auth->encodeUid(authority);
	if(drive->discovery.enterprise)
	   auth->addNamedParameter("Challenge", credentials); //EntSSC style
	else if((drive->discovery.opalV2 ) || (drive->discovery.opal))
	   auth->addOpalNamedParameter((int)0 , credentials); //Opal style
	Results results;
	invoke(results, endSession);
	return results.getReturnCode() == 1;
}

int Session::invoke(Results & results, bool endSession) {
	if (!hostSession)
		throw TcgError("Session::invoke: session already closed");

	RcvdDataList data;
	try {
		ScopedGILRelease unlockGIL;

		pkta.popAll();
		if (endSession)
			*static_cast<uint8_t *>(pkta.append(1)) = EndSession;

		pkta.fillHeaders(drive, this);
		sendPackets(endSession);
		pkta.reset();
		getRcvdData(data);
	} catch (ParserAbort & pa) {
		results.setResultCode(pa);
		return results.getResultCode();
	}

	try {
		Scanner resultsScanner(data);
		Parser parser(resultsScanner, results, this);
		//parser.set_debug_level(1);

		parser.parse();
	} catch (ParserAbort & pa) {
		results.setResultCode(pa);
	}
	return results.getResultCode();
}

void Session::sendPackets(bool endSession) {
	dumpPacket("TCG Send", pkta.getBuffer(),
			pkta.getPayloadLen() + sizeof(PacketHeaders));
	try{
		drive->transport->send(SeaTransport::ComPacket(drive->comId),
			pkta.getBuffer(), PacketAllocator::DataBlockLen);
		}
	catch (...){
			throw TcgErrorIoStatus(drive->transport->lastStatus,
				"Error sending COM Packet");
			}
}

void Session::receive(void * buf, size_t bufSize) {
	try{
		drive->transport->receive(SeaTransport::ComPacket(drive->comId), buf,
			static_cast<uint32_t>(bufSize));
	}
	catch (...){
		throw TcgErrorIoStatus(drive->transport->lastStatus,
			"Error receiving COM Packet");
	}
}

void Session::getRcvdData(RcvdDataList & collect) {
	unsigned retry = 0;
	uint8_t * next;
	uint8_t * endOfComPacket = 0;

	if (!recvBuffer)
		recvBuffer = new uint8_t[recvBufferSize];

	moreData = true;
	while (moreData) {
		receive(recvBuffer, recvBufferSize);
		ComPacketHeader * cpHdr = reinterpret_cast<ComPacketHeader*>(recvBuffer);
		if (cpHdr->comId != drive->comId)
			throw TcgError("Received data on wrong ComID: %u, expected %u",
					(uint16_t) cpHdr->comId, drive->comId);

		if (cpHdr->length == 0) {
			if (cpHdr->outstandingData == 0 && cpHdr->minTransfer == 0) {
				if (retry++ > timeout)
					throw ParserAbort(TIMEOUT);
				usleep(retry > 10 ? 10000 : 5000);
				continue;
			}
			// instead of using a large buffer, we use a smaller buffer and adjust for the
			// few occasions when a larger one is needed.
			if (cpHdr->outstandingData > recvBufferSize) {
				size_t size = cpHdr->outstandingData;
				if (size % 1024)		// adjust to the next 1K boundary
					size += 1024 - (size % 1024);
				if (size > 1024 * 1024)
					throw TcgError("Requested IF-RECV buffer size too large");
				delete[] recvBuffer;
				recvBuffer = new uint8_t[recvBufferSize = size];
				continue;
			}
		}
		if (cpHdr->length)
			dumpPacket("TCG Receive", recvBuffer,
					cpHdr->length + sizeof(ComPacketHeader));
		next = recvBuffer + sizeof(ComPacketHeader);
		endOfComPacket = next + cpHdr->length;
		while (next < endOfComPacket - sizeof(PacketHeader)) {
			PacketHeader * phdr = reinterpret_cast<PacketHeader *>(next);
			next += sizeof(PacketHeader);
			uint8_t * end = next + phdr->length;
			while (next < end - sizeof(SubPacketHeader)) {
				SubPacketHeader * subpkt =
						reinterpret_cast<SubPacketHeader *>(next);
				next += sizeof(SubPacketHeader);
				if (subpkt->kind == 0)
					collect(next, subpkt->length, next - recvBuffer);
				next += subpkt->length;
			}
		}
		moreData = collect.size() == 0;
	}
}

void Session::callBack(Uid objectId, Uid methodId, boost::python::list parms) {
	if (objectId == TcgUids::SessionManager)
		switch (methodId) {
		case TcgUids::Methods::Properties: {
					break;
		}
		case TcgUids::Methods::SyncSession:
		case TcgUids::Methods::SyncTrustedSession:
		case TcgUids::Methods::SyncTlsSession:
			hostSession = extract<uint32_t>(parms[0]);
			tperSession = extract<uint32_t>(parms[1]);
			break;
		case TcgUids::Methods::CloseSession:		// abort session from TPer
			if (hostSession == extract<uint32_t>(parms[0])
					&& tperSession == extract<uint32_t>(parms[1]))
				hostSession = tperSession = 0;
			break;
		}
}

void Session::dumpPacket(const char * desc, void * buf, size_t size) {
	if (dumpPackets == false)
		return;

	unsigned char *bytes = (unsigned char *)buf;
	int maxbytes = size * 5 + 1;
	int lastprint = 0;
	char bytestr[maxbytes];
	bzero(bytestr, sizeof(bytestr));
	for (int i = 0; i < size; i++) {
		int currlen = strlen(bytestr);
		sprintf(bytestr + currlen, "0x%02x ", bytes[i]);
		if (strlen(bytestr) > 76) {
			getLogger().debug("%s [%d]: %s", desc, i, bytestr);
			bzero(bytestr, sizeof(bytestr));
			lastprint = i + 1;
		}
	}
	if (strlen(bytestr)) {
		// dump whatever remains in the string buffer
		getLogger().debug("dump[%s][%d]: %s", desc, lastprint, bytestr);
	}
}

void PacketHeaders::fill(Drive * const drive, Session * const session,
		uint32_t dataLength) {
	memset(this, 0, sizeof(PacketHeaders));
	subPacket.length = dataLength;
	dataLength += sizeof(SubPacketHeader);
	if (dataLength % 4)
		dataLength += 4 - dataLength % 4;		// % 4 for pad bytes
	packet.length = dataLength;
	packet.hostSession = session->hostSession;
	packet.tperSession = session->tperSession;
	packet.seqNumber = session->seqNumber++;
	comPacket.length = dataLength + sizeof(PacketHeader);
	comPacket.comId = drive->comId;
	comPacket.comIdExt = drive->comIdExt;
}

PacketAllocator::PacketAllocator() {
	reset();
}

void * PacketAllocator::append(size_t len) {
	if (length + len > DataBlockLen)
		throw TcgError("Exceeded IF-SEND buffer space");

	void * ptr = data + length;
	length += len;
	return ptr;
}

void PacketAllocator::reset() {
	memset(data, 0, sizeof(data));
	length = sizeof(PacketHeaders);
}

void PacketAllocator::popAll() {
	while (!packetStack.empty()) {
		Packet * packet = packetStack.back();
		packetStack.pop_back();
		packet->finish();
		delete packet;
	}
}

void PacketAllocator::fillHeaders(Drive * const drive,
		Session * const session) {
	PacketHeaders * headers = (PacketHeaders *) data;
	headers->fill(drive, session, static_cast<uint32_t>(length - sizeof(PacketHeaders)));
}

void PacketAllocator::popPacket(Packet * packet) {
	if (packetStack.back() == packet)
		packetStack.pop_back();
	else
		throw TcgError("Invalid use of PacketAllocator::popPacket()");
}

Packet::~Packet() {
}

void Packet::encodeAtom(const char * value, size_t len) {
	if (len < 16) {
		uint8_t * ptr = static_cast<uint8_t *>(append(1));
		*ptr = 0xa0 + static_cast<uint8_t>(len);
	} else if (len < 1024) {
		beint16_t * ptr = static_cast<beint16_t *>(append(sizeof(beint16_t)));
		*ptr = 0xd000 + static_cast<uint16_t>(len);
	} else {
		beint32_t * ptr = static_cast<beint32_t *>(append(sizeof(beint32_t)));
		*ptr = 0xe2000000 + static_cast<uint32_t>(len);
	}
	memcpy(append(len), value, len);
}

#if defined(_WINDOWS)
#pragma pack(push, 1)
#endif

struct encodeDword {
	uint8_t atomHdr;
	beint32_t value;
}__attribute__((__packed__));

struct encodeQuad {
	uint8_t atomHdr;
	beint64_t value;
}__attribute__((__packed__));

#if defined(_WINDOWS)
#pragma pack(pop)
#endif

void Packet::encodeAtom(uint64_t value) {
	if (value < 32) {
		uint8_t * ptr = static_cast<uint8_t *>(append(1));
		*ptr = static_cast<uint8_t>(value);
	} else if (value <= 0xffffffff) {
		encodeDword * ptr = static_cast<encodeDword *>(append(
				sizeof(encodeDword)));
		ptr->atomHdr = AtomDword;
		ptr->value = static_cast<uint32_t>(value);
	} else {
		encodeQuad * ptr = static_cast<encodeQuad *>(append(sizeof(encodeQuad)));
		ptr->atomHdr = AtomQuad;
		ptr->value = value;
	}
}

void Packet::encodeUid(Uid & uid) {
	encodeQuad * ptr = static_cast<encodeQuad *>(append(sizeof(encodeQuad)));
	ptr->atomHdr = AtomUid;
	ptr->value = uid;
}

void Packet::addOpalNamedParameter(const uint64_t name, std::string & value) {
	encodeToken(StartName);
	encodeAtom(name);//Opal style of using int as the "Name"
	encodeAtom(value.c_str(), value.size());
	encodeToken(EndName);
}

void Packet::addNamedParameter(const char * name, std::string & value) {
	encodeToken(StartName);
	encodeAtom(name, strlen(name));
	encodeAtom(value.c_str(), value.size());
	encodeToken(EndName);
}

void Packet::addNamedParameter(std::string name, const char * value,
		size_t len) {
	encodeToken(StartName);
	encodeAtom(name.data(), name.size());
	encodeAtom(value, len);
	encodeToken(EndName);
}

void Packet::addNamedParameter(std::string name, uint64_t value) {
	encodeToken(StartName);
	encodeAtom(name.data(), name.size());
	encodeAtom(value);
	encodeToken(EndName);
}

NamedParameterList * Packet::addNamedList(const char * name) {
	return new NamedParameterList(pkta, name);
}

ParameterList * Packet::addList() {
	return new ParameterList(pkta);
}

void Packet::pop() {
	pkta.popPacket(this);
	finish();
	delete this;
}

ParameterList::ParameterList(PacketAllocator & pkta) :
		Packet(pkta) {
	encodeToken(StartList);
}

void ParameterList::finish() {
	encodeToken(EndList);
}

NamedParameterList::NamedParameterList(PacketAllocator & pkta,
		const char * name) :
		Packet(pkta) {
	encodeToken(StartName);
	encodeAtom(name, strlen(name));
	encodeToken(StartList);
}

void NamedParameterList::finish() {
	encodeToken(EndList);
	encodeToken(EndName);
}

Discovery::Discovery() {
	memset(this, 0, sizeof(Discovery));
}

void Discovery::refresh(SeaTransport * transport) {
	if (!isSed())
		return;
	ScopedGILRelease unlockGIL;
	memset(this, 0, sizeof(Discovery));

	if (transport->receive(SeaTransport::LEVEL0_DISCOVERY, buffer,
			sizeof(buffer))) {
	    if (transport->lastStatus.hasSense(5, 0x20, 0))	// Unsupported command code
	    {
			otherSSC = fcNotSED;
			return;
		}
		throw TcgErrorIoStatus(transport->lastStatus,
				"Error performing Level 0 Discovery");
	}
	hdr = reinterpret_cast<Discovery::Hdr *>(buffer);

	uint8_t * nextHdr = buffer + sizeof(Hdr);
	const uint8_t * end = buffer + hdr->length;
	while (nextHdr < end) {
		switch (reinterpret_cast<DescHdr *>(nextHdr)->featureCode) {
		case fcTper:
			tper = reinterpret_cast<TperDesc *>(nextHdr);
			break;
		case fcLocking:
			locking = reinterpret_cast<LockingDesc *>(nextHdr);
			break;
		case fcGeometry:
			geometry = reinterpret_cast<GeometryDesc *>(nextHdr);
			break;
		case fcEnterpriseSSC:
			enterprise = reinterpret_cast<EnterpriseDesc*>(nextHdr);
			break;
		case fcLogicalPorts:
			port = reinterpret_cast<PortDesc *>(nextHdr);
			break;
		case fcSecureMessaging:
			tls = reinterpret_cast<SecureMsgDesc*>(nextHdr);
			break;
		case fcOpalv2SSC:
			opalV2 = reinterpret_cast<OpalV2Desc*>(nextHdr);
			break;
		case fcOpalSSC:
			opal = reinterpret_cast<OpalDesc*>(nextHdr);
			break;
		default:
			otherSSC = reinterpret_cast<DescHdr *>(nextHdr)->featureCode;
			break;
		}
		nextHdr = nextHdr + reinterpret_cast<DescHdr *>(nextHdr)->length
				+ sizeof(DescHdr);
	}
}

void Discovery::enumDescriptors(DescriptorEnum & f) {
	if (!hdr || otherSSC == fcNotSED)
		return;
	f.hdr(hdr);
	uint8_t * nextHdr = buffer + sizeof(Hdr);
	const uint8_t * end = buffer + hdr->length;
	while (nextHdr < end) {
		DescHdr * desc = reinterpret_cast<DescHdr *>(nextHdr);
		f(desc, nextHdr + sizeof(DescHdr));
		nextHdr = nextHdr + desc->length + sizeof(DescHdr);
	}
}

const char * Discovery::ssc() {
	if (enterprise)
		return "Enterprise";
	else if(opal)
		return "Opal";
	else if (opalV2)
		return "Opalv2";
	switch (otherSSC) {
	case fcNotSED:
		return "NotSED";
	default:
		return "Unknown";
	}
}

} // Tcg
