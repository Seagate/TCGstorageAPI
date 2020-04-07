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
// \file Tls.h
// \brief  Defines of Tls class for sending and receiving TLS packets
//
//-----------------------------------------------------------------------------
#ifndef PYSED_TLS_H_
#define PYSED_TLS_H_
#if !defined(_WINDOWS)
#include <gnutls/gnutlsxx.h>
#endif
#include "TcgDrive.h"
#include <vector>

namespace Tcg {

struct TlsPacketHeaders {
	ComPacketHeader		comPacket;
	PacketHeader 		packet;

	void fill(Drive * const drive, Session * const session, uint32_t dataLength);
};

#if defined(_WINDOWS)
#pragma pack(push, 1)
#endif

struct TlsHeader {
	uint8_t		contentType;
	uint8_t		version[2];
	beint16_t	length;
}  __attribute__((__packed__));

#if defined(_WINDOWS)
#pragma pack(pop)
#endif

class SupportedSuites
{
	std::vector<unsigned> 	suites;
	std::vector<int>		indices;
public:
	SupportedSuites();
	bool supports(unsigned cipherSuite, int * cfgNdx = NULL);
	std::string cfgString(int index);
	unsigned index2cipherSuite(int index);
};

class TlsCredentials {
public:
	gnutls_psk_client_credentials_t	creds;
	TlsCredentials(std::string user, std::string psk);
	~TlsCredentials();
};

class TlsSession : public Session, private gnutls::session {
	static const size_t DataBlockExtra = 512;					// Extra room for TCG Headers rounded to a full sector
	static const size_t	DataBlockLen = 4096 + DataBlockExtra;	// Block size needs to be 2^N for gnutls
	static const int TlsStartPadBytes = 3;

	int			pullDataRead, pullDataWrite;		// FIFO to hold encrypted data from drive (without headers and pad)
	bool		tlsEstablished;						// true when handshake complete

protected:
	virtual void startSessionEstablished();
	void writeData(uint8_t	* tlsBuffer, uint32_t & tlsBufferLength);
	bool receiveData(unsigned timeout = 0, bool once = false);

public:
	TlsSession(Drive * const dr, Uid sp = 0, unsigned to = 0);
	~TlsSession();

	// TcgSession overrides
	virtual void sendPackets(bool endSession);
	virtual void close();
	virtual void getRcvdData(RcvdDataList & collect);

	static SupportedSuites & supportedSuites() {
		static SupportedSuites	supported;
		return supported;
	}

private:
	// gnutls hooks
	static ssize_t pushFunctionStub(gnutls_transport_ptr_t _self, const giovec_t * iov, int iovcnt)
	{
		TlsSession * self = reinterpret_cast<TlsSession *>(_self);
		return self->pushData(iov, iovcnt);
	}
	static ssize_t pullFunction(gnutls_transport_ptr_t h, void * buf, size_t len);
	static int pullTimeoutFunction(gnutls_transport_ptr_t _self, unsigned int ms);
	ssize_t pushData(const giovec_t * iov, int iovcnt);
	static void logFilter(int level, const char * msg);
	static void auditLog(gnutls_session_t session, const char * msg);
};

}; // Tcg namespace

#endif /* PYSED_TLS_H_ */
