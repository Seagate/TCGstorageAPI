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
// \file support.cpp
// \brief Implementation of support class for TCG
//
//-----------------------------------------------------------------------------
#include <errno.h>
#include <stdio.h>
#include "support.h"
#include "Tcg.h"
#include "transport.h"

namespace Tcg {
TcgError::TcgError()
{
}

TcgError::TcgError(const char * fmtstr, ...)
{
	va_list aptr;
	char buf[128];

	va_start(aptr, fmtstr);
	vsnprintf(buf, sizeof(buf), fmtstr, aptr);
	va_end(aptr);
	msg = buf;
}

TcgErrorErrno::TcgErrorErrno(const char * fmtstr, ...)
{
	va_list aptr;
	char buf[128];

	va_start(aptr, fmtstr);
	vsnprintf(buf, sizeof(buf), fmtstr, aptr);
	va_end(aptr);
	msg = buf;

	msg += ":  ";
#if defined(_WINDOWS)
	msg += strerror_s(buf, sizeof(buf), errno);
#else
	msg += strerror_r(errno, buf, sizeof(buf));
#endif
}

TcgErrorIoStatus::TcgErrorIoStatus(IoStatus & status, const char * fmtstr, ...)
{
	va_list aptr;
	char buf[128];

	va_start(aptr, fmtstr);
	vsnprintf(buf, sizeof(buf), fmtstr, aptr);
	va_end(aptr);
	msg = buf;
	msg += '(';
	msg += buf;
	if (status.senseLen > 0)
	{
		snprintf(buf, sizeof(buf), ", Key: %x, ASC: %x, ASCQ: %x", status.key, status.asc, status.ascq);
		msg += buf;
	}
	msg += ')';
}

void LoggerBase::warning(const char * fmt, ...)
{
	va_list aptr;

	va_start(aptr, fmt);
	write(Warning, fmt, aptr);
	va_end(aptr);
}

void LoggerBase::info(const char * fmt, ...)
{
	va_list aptr;

	va_start(aptr, fmt);
	write(Info, fmt, aptr);
	va_end(aptr);
}

void LoggerBase::error(const char * fmt, ...)
{
	va_list aptr;

	va_start(aptr, fmt);
	write(Error, fmt, aptr);
	va_end(aptr);
}

void LoggerBase::debug(const char * fmt, ...)
{
	va_list aptr;

	va_start(aptr, fmt);
	write(Debug, fmt, aptr);
	va_end(aptr);
}

const char * LoggerBase::hexdigits = "0123456789ABCDEF";

std::string LoggerBase::dump(const void * buffer, size_t length, size_t ofs)
{
	size_t offset;
	unsigned char * data = (unsigned char *) buffer;
	char byteStr[18];

	std::string dump("\n");

	for (offset = 0; offset < length; offset += 16)
	{
		char * ptr = byteStr;
		size_t realOffset = offset + ofs;
		for (int i = 3; i >= 0; i--)
			*ptr++ = hexdigits[ (realOffset >> (4 * i)) % 16];
		*ptr++ = ' ';
		*ptr = '\0';
		dump += byteStr;

		byteStr[0] = ' ';
		byteStr[3] = '\0';

		for (unsigned ofs = 0; ofs < 16; ofs++)
		{
			if (offset + ofs >= length)
			{
				byteStr[1] =  ' ';
				byteStr[2] =  ' ';
			}
			else
			{
				byteStr[1] =  hexdigits[data[offset + ofs] / 16];
				byteStr[2] =  hexdigits[data[offset + ofs] % 16];
			}
			dump += byteStr;
		}
		for (unsigned ofs = 0; ofs < 16; ofs++)
			if (offset + ofs >= length)
				byteStr[1 + ofs] = ' ';
			else
				byteStr[1 + ofs] = (isprint(data[offset + ofs])) ? data[offset + ofs]:'.';
		byteStr[17] = '\0';
		dump += byteStr;
		dump += '\n';
	}
	return dump;
}

// Base implementation
void LoggerBase::write(LogType type, const char * msg)
{

}

void LoggerBase::write(LogType type, const char * msg, 	va_list parms)
{
	char buffer[2048];
	vsnprintf(buffer, sizeof(buffer), msg, parms);
	write(type, buffer);
}

}; // namespace Tcg
