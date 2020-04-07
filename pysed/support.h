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
// \file support.h
// \brief Defines support class for TCG
//
//-----------------------------------------------------------------------------
#ifndef SUPPORT_H_
#define SUPPORT_H_

#include <stdint.h>
#include <string>
#include <string.h>
#include <stdarg.h>

#include "portable_endian.h"

#if defined(_WINDOWS)
#undef __attribute__
#define __attribute__(x)

inline void usleep(unsigned usec) {
	::Sleep(usec / 1000);
}

#define strcasecmp _stricmp
#endif

#if defined(_WINDOWS)
#pragma pack(push, 1)
#endif

// Big Endian automatic conversion types
class beint16_t {
	uint16_t	value;
public:
	beint16_t() : value(0) {}
	beint16_t(uint16_t val) : value(htobe16(val)) {}
	operator uint16_t() const {return be16toh(value);}
	beint16_t operator=(uint16_t val) {value = htobe16(val); return *this;}
}__attribute__((__packed__));

class beint32_t {
	uint32_t	value;
public:
	beint32_t() : value(0) {}
	beint32_t(uint32_t val) :value(htobe32(val)) {}
	operator uint32_t() const {return be32toh(value);}
	beint32_t operator=(uint32_t val) {value = htobe32(val); return *this;}
}__attribute__((__packed__));

class beint64_t {
	uint64_t	value;
public:
	beint64_t() : value(0) {}
	beint64_t(uint64_t val) : value(htobe64(val)) {}
	operator uint64_t() const {return be64toh(value);}
	beint64_t operator=(uint64_t val) {value = htobe64(val); return *this;}
}__attribute__((__packed__));

#if defined(_WINDOWS)
#pragma pack(pop)
#endif

namespace Tcg {
class LoggerBase {

public:
	static const char * hexdigits;
	enum LogType {
		Info,
		Warning,
		Error,
		Debug,
	};
	virtual ~LoggerBase() {}
	void warning(const char * fmt, ...) __attribute__ ((format (printf, 2, 3)));
	void info(const char * fmt, ...) __attribute__ ((format (printf, 2, 3)));
	void error(const char * fmt, ...) __attribute__ ((format (printf, 2, 3)));
	void debug(const char * fmt, ...) __attribute__ ((format (printf, 2, 3)));
	static std::string dump(const void * buffer, size_t length, size_t ofs = 0);
	virtual void write(LogType type, const char * msg);
	virtual void write(LogType type, const char * msg, 	va_list parms);
};

struct IoStatus;

class TcgError
{
protected:
	std::string	msg;
	TcgError();
public:
	TcgError(const char * fmtstr, ...) __attribute__ ((format (printf, 2, 3)));
	const char * what() const {return msg.c_str();}
};

class TcgErrorErrno : public TcgError
{
public:
	TcgErrorErrno(const char * fmtstr, ...) __attribute__ ((format (printf, 2, 3)));
};

class TcgErrorIoStatus : public TcgError
{
public:
	TcgErrorIoStatus(IoStatus & status, const char * fmtstr, ...) __attribute__ ((format (printf, 3, 4)));
};

class TcgTlsAlert : public TcgError
{
public:
	TcgTlsAlert(int code);
	const char * const alert;
};

}; // namespace Tcg
#endif // SUPPORT_H
