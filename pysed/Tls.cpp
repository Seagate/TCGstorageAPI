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
// \file Tls.cpp
// \brief Implementation of Tls class for sending and receiving TLS packets
//
//-----------------------------------------------------------------------------
#include <string>
#include <fcntl.h>
#include "Tls.h"
#include "Tcg.h"

struct gnutls_psk_client_credentials_st {
        gnutls_datum_t username;
        gnutls_datum_t key;
        gnutls_psk_client_credentials_function *get_function;
};

namespace Tcg {

struct gnutlsProt2Str {
	int value;
	const char * cfgStr;
};

// These tables filter the gnutls supported suites to one's we might use and
// converts the gnutls constant to the config string used to specify the component.
static gnutlsProt2Str	kxCvt[] = {
	{GNUTLS_KX_DHE_PSK, 	"DHE-PSK"},
	{GNUTLS_KX_PSK,			"PSK"},
{0, NULL}};

static gnutlsProt2Str	cipherCvt[] = {
	{GNUTLS_CIPHER_NULL,		"NULL"},
	{GNUTLS_CIPHER_AES_128_CBC, "AES-128-CBC"},
	{GNUTLS_CIPHER_AES_256_CBC, "AES-256-CBC"},
	{GNUTLS_CIPHER_AES_128_GCM, "AES-128-GCM"},
	{GNUTLS_CIPHER_AES_256_GCM, "AES-256-GCM"},
{0, NULL}};

static gnutlsProt2Str	macCvt[] = {
	{GNUTLS_MAC_SHA256, "SHA256"},
	{GNUTLS_MAC_SHA384, "SHA384"},
	{GNUTLS_MAC_AEAD,   "AEAD"},
{0, NULL}};

static const char * cfgCvt(gnutlsProt2Str * table, int value)
{
	for (int i = 0; table[i].cfgStr; i++)
		if (table[i].value == value)
			return table[i].cfgStr;
	return NULL;
}

SupportedSuites::SupportedSuites()
{
	uint8_t csid[2];
	gnutls_kx_algorithm_t kx;
    gnutls_cipher_algorithm_t cipher;
    gnutls_mac_algorithm_t mac;

	gnutls_fips140_mode_enabled();

	for (size_t i = 0; gnutls_cipher_suite_info(i, csid, &kx, &cipher, &mac, NULL); i++)
	{
		if (!cfgCvt(kxCvt, kx))
			continue;
		if (!cfgCvt(cipherCvt, cipher))
			continue;
		if (!cfgCvt(macCvt, mac))
			continue;
		suites.push_back((unsigned) csid[0] << 8 | csid[1]);
		indices.push_back(i);
	}
}

// Does the TLS stack support a cipher suite?
// cipherSuite - The cipher suite 2 byte ID
// cfgNdx      - Where to store the configuration index for this suite
bool SupportedSuites::supports(unsigned cipherSuite, int * cfgNdx)
{
	unsigned i;

	for (i = 0; i < suites.size(); i++)
		if (suites[i] == cipherSuite)
		{
			if (cfgNdx)
				*cfgNdx = indices[i];
			return true;
		}
	return false;
}

// Configure the TLS stack to use a cipher suite.
// ndx  - the cfgNdx returned by supports()
std::string SupportedSuites::cfgString(int ndx)
{
	gnutls_kx_algorithm_t kx;
    gnutls_cipher_algorithm_t cipher;
    gnutls_mac_algorithm_t mac;
    int index = (int) ndx;

	const char * kxs;
	const char * ciphers;
	const char * macs;
	gnutls_cipher_suite_info(index, NULL, &kx, &cipher, &mac, NULL);
	kxs = cfgCvt(kxCvt, kx);
	ciphers = cfgCvt(cipherCvt, cipher);
	macs = cfgCvt(macCvt, mac);
	if (!kxs || !ciphers || !macs)
		throw("Invalid cipher suite");
	char config[128];
	snprintf(config, sizeof(config), "NONE:+VERS-TLS1.2:+COMP-NULL:+%s:+%s:+%s",
			kxs, ciphers, macs);

    return config;
}

unsigned SupportedSuites::index2cipherSuite(int index)
{
	uint8_t csid[2];
	gnutls_cipher_suite_info(index, csid, NULL, NULL, NULL, NULL);
	return((unsigned) csid[0] << 8 | csid[1]);
}

TlsCredentials::TlsCredentials(std::vector<char> uid, std::string _psk)
{
	gnutls_psk_allocate_client_credentials(&creds);
	unsigned i;
	uint8_t *	userId = (uint8_t *) gnutls_malloc(8);
	for (i = 0; i<uid.size();i++)
		userId[i] = uid[i];

	uint8_t *		psk = (uint8_t *) gnutls_malloc(_psk.size() + 1);
	std::string::iterator it;
	for (it = _psk.begin(), i = 0; it != _psk.end(); it++, i++)
			psk[i] = *it;
	creds->username.data = userId;
	creds->username.size = 8;
	creds->key.data = psk;
	creds->key.size = _psk.size();
}

TlsCredentials::~TlsCredentials()
{
	gnutls_psk_free_client_credentials(creds);
}

TcgTlsAlert::TcgTlsAlert(int code)
: TcgError("TLS Alert received: %s", gnutls_alert_get_name((gnutls_alert_description_t) code))
, alert(gnutls_alert_get_name((gnutls_alert_description_t) code))
{
}


TlsSession::TlsSession(Drive * const dr, Uid sp, unsigned to)
: Session(dr, sp, to)
, gnutls::session(GNUTLS_CLIENT)
, tlsEstablished(false)
{
	startSessionUid = TcgUids::Methods::StartTlsSession;
	// Pipe used to collect TLS received data stripped of TCG headers and padding
	int fds[2];
	if (pipe(fds) < 0)
		throw TcgError("Unable to create pipe");
	pullDataRead = fds[0];
	pullDataWrite = fds[1];
	fcntl(pullDataRead, F_SETFL, fcntl(pullDataRead, F_GETFL) | O_NONBLOCK);

	gnutls_global_set_audit_log_function(auditLog);

	set_transport_ptr(this);
	set_user_ptr(this);
	set_transport_pull_function(TlsSession::pullFunction);
	gnutls_transport_set_vec_push_function(s, TlsSession::pushFunctionStub);
	gnutls_transport_set_pull_timeout_function(s, TlsSession::pullTimeoutFunction);
	set_max_size(DataBlockLen - DataBlockExtra);

	set_priority(supportedSuites().cfgString(dr->tlsParameters).c_str(), NULL);

	gnutls_credentials_set(s, GNUTLS_CRD_PSK, drive->tlsCreds[sp == TcgUids::AdminSP ? 0:1]->creds);
	gnutls_handshake_set_timeout(s, to > 5000 ? to:15000);
}

TlsSession::~TlsSession()
{
	::close(pullDataWrite);
	::close(pullDataRead);
}

void TlsSession::close()
{
	if (sp != 0 && tperSession)
	{
		Results results;
		invoke(results, true);
	}
	bye(GNUTLS_SHUT_RDWR);
	delete this;
}

void TlsSession::startSessionEstablished()
{
	ScopedGILRelease        unlockGIL;
	try {
		handshake();
	} catch (ParserAbort & e) {
		return;
	} catch (gnutls::exception & e) {
		int ecode = e.get_code();
		if (ecode == GNUTLS_E_FATAL_ALERT_RECEIVED)
			throw TcgTlsAlert(gnutls_alert_get(s));
		throw TcgError("StartSession: TLS error encountered: %s",
				gnutls_strerror(ecode));
	}
  catch (TcgErrorIoStatus & e)
    {
    	throw TcgError("StartSession: TLS transport error encountered");
    }
	tlsEstablished = true;
}

void TlsSession::sendPackets(bool endSession)
{
	if (tlsEstablished)
	{
		dumpPacket("Unencrypted data to send", pkta.getPayload(), pkta.getPayloadLen());
		ssize_t rv = send(pkta.getPayload(), pkta.getPayloadLen());
		if (rv < 0)
			throw TcgError("Error sending data");
	}
	else
		Session::sendPackets();
}

void TlsSession::writeData(	uint8_t	* tlsBuffer, uint32_t & tlsBufferLength)
{
	tlsBuffer[tlsBufferLength++] = '\0'; // ending pad
	TlsPacketHeaders * const hdrs = reinterpret_cast<TlsPacketHeaders *>(tlsBuffer);
	memset(tlsBuffer, 0, sizeof(TlsPacketHeaders) + TlsStartPadBytes);
	hdrs->packet.length = tlsBufferLength - sizeof(TlsPacketHeaders);
	hdrs->packet.hostSession = hostSession;
	hdrs->packet.tperSession = tperSession;
	hdrs->packet.seqNumber = seqNumber++;
	hdrs->comPacket.length = hdrs->packet.length + sizeof(PacketHeader);
	hdrs->comPacket.comId = drive->comId;
	hdrs->comPacket.comIdExt = drive->comIdExt;

	dumpPacket("TCG TLS Send", tlsBuffer, tlsBufferLength);
	for (int retry = 0; retry < 2; retry++)
	{

		if (drive->transport->send(SeaTransport::ComPacket(drive->comId), tlsBuffer, tlsBufferLength))
		{

			if (drive->transport->lastStatus.hasSense(5, 0x2c, 0)) 	// sequence error
				receiveData(0, true);
			else
			{
				tlsBufferLength = sizeof(TlsPacketHeaders) + TlsStartPadBytes;
				throw TcgErrorIoStatus(drive->transport->lastStatus, "Error sending COM Packet");
			}
		}
		else
			break;
	}
	//receiveData(0, true);	// try to avoid sequence errors
	tlsBufferLength = sizeof(TlsPacketHeaders) + TlsStartPadBytes;
}

// Callback from gnutls to send packets.
// Collect TLS packets to send into the TCG buffer with appropriate padding.
ssize_t TlsSession::pushData(const giovec_t * iov, int iovcnt)
{
	ssize_t	rv = 0;
	int ndx;
	uint8_t		tlsBuffer[DataBlockLen];
	uint32_t	tlsBufferLength = sizeof(TlsPacketHeaders) + TlsStartPadBytes;

	for (ndx = 0; ndx < iovcnt; ndx++)
	{
		unsigned pad = iov[ndx].iov_len % 4;
		if (pad)
			pad = 4 - pad;
		// check if we might overflow the buffer
		if (tlsBufferLength + iov[ndx].iov_len + pad >= DataBlockLen)
		{
			if (tlsBufferLength > sizeof(TlsPacketHeaders))
			{
				writeData(tlsBuffer, tlsBufferLength);
			}
			if (tlsBufferLength + iov[ndx].iov_len > DataBlockLen)
				return -EMSGSIZE;
		}

		memcpy(tlsBuffer + tlsBufferLength, iov[ndx].iov_base, iov[ndx].iov_len);
		tlsBufferLength += iov[ndx].iov_len;
		if (pad)
		{
			memset(tlsBuffer + tlsBufferLength, 0, pad);
			tlsBufferLength += pad;
		}
		rv += iov[ndx].iov_len;
	}
	writeData(tlsBuffer, tlsBufferLength);
	return rv;
}

// Request TLS data from the drive.  If any data is returned, strip headers and padding
// and post raw packet information to the FIFO.
bool TlsSession::receiveData(unsigned timeout, bool once)
{
	unsigned retry = 0;
	uint8_t		receiveBuffer[DataBlockLen];
	struct timeval start, end;
	gettimeofday(&start, NULL);

	while (true)
	{
		if (drive->transport->receive(SeaTransport::ComPacket(drive->comId), receiveBuffer, DataBlockLen))
			throw TcgErrorIoStatus(drive->transport->lastStatus, "Error receiving COM Packet");

		ComPacketHeader * cpHdr = reinterpret_cast<ComPacketHeader*>(receiveBuffer);
		if (cpHdr->comId != drive->comId)
			throw TcgError("Received data on wrong ComID: %u, expected %u", (uint16_t) cpHdr->comId, drive->comId);

		if (cpHdr->length == 0)
		{
			if (cpHdr->outstandingData <= 1 && cpHdr->minTransfer == 0)
			{
				unsigned delay = retry > 10 ? 10:5;
				if (timeout)
				{
					gettimeofday(&end, NULL);
					unsigned elapsed = (end.tv_sec - start.tv_sec) * 1000 + (end.tv_usec - start.tv_usec) / 1000;
					if (elapsed + delay > timeout)
						return false;
				}
				if (once)
					return false;
				usleep(delay * 1000);
				continue;
			}
			if (cpHdr->outstandingData > DataBlockLen)
				throw TcgError("Requested IF-RECV buffer size too large");
		}

		dumpPacket("TCG TLS Receive", receiveBuffer, cpHdr->length + sizeof(ComPacketHeader));

		uint8_t * next = receiveBuffer + sizeof(ComPacketHeader);
		uint8_t * endOfComPacket = next + cpHdr->length;
		while (next < endOfComPacket - sizeof(PacketHeader))
		{
			next += sizeof(PacketHeader) + TlsStartPadBytes;
			while (next + sizeof(TlsHeader) < endOfComPacket)
			{
				TlsHeader * tlshdr = reinterpret_cast<TlsHeader *>(next);
				size_t len = sizeof(TlsHeader) + tlshdr->length;
				if (write(pullDataWrite, next, len) < 0)
					return false;
				if (len % 4)
					len += 4 - len % 4;
				next += len;
			}
		}
		return true;
	}
}

// Retrieves decrypted data from gnutls
void TlsSession::getRcvdData(RcvdDataList & collect)
{
	if (!tlsEstablished)
	{
		Session::getRcvdData(collect);
		return;
	}

	if (!recvBuffer)
		recvBuffer = new uint8_t[recvBufferSize];

	while (true)
	{
		ssize_t rv = recv(recvBuffer, recvBufferSize);
		if (rv < 0)
			switch (rv)
			{
				case GNUTLS_E_AGAIN:
				case GNUTLS_E_INTERRUPTED:
					break;
			}
		else
		{
			if (rv < (ssize_t) sizeof(SubPacketHeader))
			{
				gnutls_alert_description_t ad = gnutls_alert_get(s);
				if (ad == GNUTLS_A_CLOSE_NOTIFY)
					tperSession = 0;
				if (collect.size() == 0)
					throw ParserAbort(TLS_ALERT);
			}
			dumpPacket("Received app data decrypted", recvBuffer, rv);
			uint8_t * next = recvBuffer;
			uint8_t * end = recvBuffer + rv;
			while (next < end - sizeof(SubPacketHeader))
			{
				SubPacketHeader * subpkt = reinterpret_cast<SubPacketHeader *>(next);
				next += sizeof(SubPacketHeader);
				if (subpkt->kind == 0)
					collect(next, subpkt->length, next - recvBuffer);
				next += subpkt->length;
			}
			if (collect.size() != 0)
				break;
		}
	}
}

// gnutls callback to request data.
// We retrieve data from the FIFO.  If the FIFO is empty, additional requests are made
// to retrive data from the drive.
ssize_t TlsSession::pullFunction(gnutls_transport_ptr_t _self, void * _buf, size_t len)
{
	TlsSession * self = reinterpret_cast<TlsSession *>(_self);
	size_t bytes_read = 0;
	uint8_t * buf = (uint8_t *) _buf;
	while (true)
	{
		ssize_t rv = read(self->pullDataRead, buf + bytes_read, len - bytes_read);
		if (rv > 0)
			bytes_read += rv;
		else if (errno == EINTR)
			continue;
		if (bytes_read == len)
			return bytes_read;
		if (self->receiveData() == false)
		{
			if (bytes_read && write(self->pullDataWrite, buf, bytes_read) < 0)
				;
			errno = EINVAL;
			return -1;
		}
	}
}

// Get data with timeout
// Should return 0 on timeout, a positive number if data can be received, and -1 on error.
int TlsSession::pullTimeoutFunction(gnutls_transport_ptr_t _self, unsigned int ms)
{
	TlsSession * self = reinterpret_cast<TlsSession *>(_self);
	fd_set rfds;
	struct timeval tv;
	int fd = self->pullDataRead;

	tv.tv_sec = 0;
	tv.tv_usec = 0;
	FD_ZERO(&rfds);
	FD_SET(fd, &rfds);

	if (select(fd + 1, &rfds, NULL, NULL, &tv) == 1 || self->receiveData(ms))
		return 1;

	return 0;
}

void TlsSession::logFilter(int level, const char * msg)
{
	fputs(msg, stderr);
}

void TlsSession::auditLog(gnutls_session_t session, const char * msg)
{
	TlsSession * self = reinterpret_cast<TlsSession *>(gnutls_transport_get_ptr(session));
	self->drive->getLogger().warning("%s",msg);
}

}; // namespace Tcg
