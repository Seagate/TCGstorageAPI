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
// \file TcgScanner.h
// \brief Defines class to scan and parse the tokens
//
//-----------------------------------------------------------------------------
#ifndef TCGSCANNER_H_
#define TCGSCANNER_H_
#include <stddef.h>
#include <list>
#include <boost/python.hpp>
#include <boost/python/object.hpp>
#include <boost/python/dict.hpp>
#include <boost/python/tuple.hpp>
#include <boost/python/list.hpp>
#include <boost/python/str.hpp>
#include "TcgDrive.h"
#include "parser.tab.hpp"

namespace Tcg {
using boost::python::list;
using boost::python::dict;

class RcvdDataList;

// Lexer to decode tokens from the TCG received packets
class Scanner
{
	RcvdDataList &		data;
	uint8_t *			start;
	uint8_t *			next;
	uint8_t * 			end;
	size_t 				offset;

	Parser::symbol_type nextToken();

protected:

public:
	Scanner(RcvdDataList & _data);
	~Scanner();

	Parser::symbol_type get_next_token();
	unsigned int  getPos() {return offset + next - start;}
	//size_t getPos() {return offset + next - start;}
	std::string getBuffer();
	bool amDone();
};

struct ParserAbort {
	StatusCode 	rv;
	ParserAbort(StatusCode _rv) : rv(_rv) {}
};

class Results {
	int		resultCode;

	bool findDict(list l);
public:
	dict	returnedNamedValues;
	list		returnedValues;

	void setResultCode(long_& val);
	void setResultCode(ParserAbort & pa) {resultCode = pa.rv;}
	void setReturnedValues(object & val);
	int getResultCode() {return resultCode;}	// Get execution status (result code after EndData token)
	int getReturnCode(int index = 0);			// Get return code from return value stack
	bool findObject(const char * name, object & ob);
	bool findObject(const uint64_t name, object & ob);
	void convertNamedList(list & l, object & results);

	// retrieve named string result from return values
	const char * namedString(const char * name);
	const char * namedString(const uint64_t name);
	// retrieve named integer result from return values
	uint64_t namedValue(const char * name, uint64_t defaultValue = 0);
};

}; // namespace Tcg

#endif /* TCGSCANNER_H_ */
