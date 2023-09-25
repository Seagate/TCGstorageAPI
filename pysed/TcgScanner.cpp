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
// \file TcgScanner.cpp
// \brief Implementation of class to scan and parse tokens
//
//-----------------------------------------------------------------------------
#include "TcgScanner.h"
#include "TcgDrive.h"
#include "parser.tab.hpp"

namespace Tcg {
using boost::python::extract;
using boost::python::tuple;

Scanner::Scanner(RcvdDataList & rcvdData)
: data(rcvdData)
, next(NULL)
{
}

Scanner::~Scanner()
{
}

Parser::symbol_type Scanner::get_next_token()
{
	if (!next || next >= end)
	{
		if (data.size() == 0)
		{
			start = 0;
			end = 0;
			offset = 0;
			return Parser::make_END();
		}

		start = next = data.front().ptr;
	    end = next + data.front().len;
	    offset = data.front().offset;
	    data.pop_front();
	}
	Parser::symbol_type rv = nextToken();
	if (next > end)
		throw TcgError("Token crosses sub packet boundary");
	return rv;
}
#if !defined(_WINDOWS)
#pragma GCC diagnostic ignored "-Wuninitialized"
#endif
Parser::symbol_type Scanner::nextToken()
{
	uint8_t	* 	atomData = NULL;
	unsigned	atomLength = 0;
	bool		b = false;
	bool 		s = false;

	if (*next >= 0xf0)
	{
		switch (*next++) {
	    case StartList: 		return Parser::make_StartList();
	    case EndList:			return Parser::make_EndList();
	    case StartName:     	return Parser::make_StartName();
	    case EndName:       	return Parser::make_EndName();
	    case Call:          	return Parser::make_Call();
	    case EndData:       	return Parser::make_EndData();
		case EmptyAtom:     	return Parser::make_EmptyAtom();
		case EndSession:		return Parser::make_EndSession();
		case StartTransaction:	return Parser::make_StartTransaction();
		case EndTransaction:	return Parser::make_EndTransaction();
		}
	}
	if (*next < 0x80)
	{
		atomData = next;
		atomLength = 1;
		b = false;
		s = (*next & 0x60) != 0;
		if (s)
			*atomData = *atomData ^ 0xc000;	// set sign, reset S bit so it looks like a signed char
		next++;
	}
	else if (*next < 0xc0)
	{
		atomLength = *next & 0xf;
		atomData = next + 1;
		b = (*next & 0x20) != 0;
		s = (*next & 0x10) != 0;
		next += 1 + atomLength;
	}
	else if (*next < 0xe0)
	{
		atomLength = next[1] | (unsigned) (next[0] & 0x7) << 8;
		atomData = next + 2;
		b = (*next & 0x10) != 0;
		s = (*next & 0x08) != 0;
		next += 2 + atomLength;
	}
	else if (*next < 0xe4)
	{
		atomLength = next[3] | (unsigned) next[2] << 8 | (unsigned) next[1] << 16;
		atomData = next + 4;
		b = (*next & 0x2) != 0;
		s = (*next & 0x1) != 0;
		next += 4 + atomLength;
	}
	if (!b)
	{
		if (atomLength < 8)
		{
			uint64_t	intValue = 0;
			for (unsigned i = 0; i < atomLength; i++)
				intValue = intValue << 8 | atomData[i];
			long_ value(intValue);
			return Parser::make_AtomInt(value);
		}
	}
	if (s)
		Parser::make_AtomStringC(boost::python::object(boost::python::handle<>(PyBytes_FromStringAndSize((char *) atomData, atomLength))));
	return Parser::make_AtomString(boost::python::object(boost::python::handle<>(PyBytes_FromStringAndSize((char *) atomData, atomLength))));
}

std::string Scanner::getBuffer()
{
	if (start)
		return LoggerBase::dump(start, end - start, offset);
	return "";
}

bool Scanner::amDone()
{
	return data.size() == 0 && next > end - sizeof(SubPacketHeader);
}

void Results::setResultCode(long_& val)
{
	resultCode = extract<int>(val);
}

int Results::getReturnCode(int index)
{
	if (resultCode != 0)
		throw 	TcgError("Return code from failed operation: %d", resultCode);

	if (len(returnedValues) <= index)
		throw 	TcgError("No return value in index %d, size = %lu", index, len(returnedValues));

	return extract<int>(returnedValues[index]);
}
bool Results::findObject(const uint64_t name, object & ob)
{
	if (returnedNamedValues.has_key(name))
	{
		ob = returnedNamedValues.get(name);
		return true;
	}
	return false;
}

bool Results::findObject(const char * name, object & ob)
{
	object index(boost::python::handle<>(PyBytes_FromString(name)));
	if (returnedNamedValues.has_key(index))
	{
		ob = returnedNamedValues.get(index);
		return true;
	}
	return false;
}

bool Results::findDict(list l)
{
	ssize_t i;
	std::string results = extract<std::string>(str(l));
	for (i = 0; i < len(l); i++)
	{
		extract<dict>	item(l[i]);
		if (item.check())
		{
			returnedNamedValues = item();
			l.pop(i);
			return true;
		}
		extract<list>	litem(returnedValues[i]);
		if (litem.check() && findDict(litem()))
		{
			if (len(litem) == 0)
				l.pop(i);
			return true;
		}
	}
	return false;
}

void Results::setReturnedValues(object & val)
{
	returnedValues = extract<list>(val);	// or
	findDict(returnedValues);
}

// retrieve named string result from return values
const char * Results::namedString(const char * name)
{
	object ob;
		if (findObject(name, ob))
	        {
	            PyObject* v = ob.ptr();

	            if (PyBytes_Check(v)) {
	              char *pbuf = PyBytes_AsString(v);
	              //Py_ssize_t len = PyBytes_Size(v);
	              //cout << "Value is '" << pbuf << "' length " << (long) len << "\n";
	              return pbuf;
	             }
	             else
	               return extract<const char *>(ob);
	        }
		return NULL;
}

// retrieve named string result from return values
const char * Results::namedString(const uint64_t name)
{
	object ob;
	if (findObject(name, ob))
        {

            PyObject* v = ob.ptr();

            if (PyBytes_Check(v)) {
              //cout << "Object is PyBytes type\n";
              char *pbuf = PyBytes_AsString(v);
              //Py_ssize_t len = PyBytes_Size(v);
              //cout << "Value is '" << pbuf << "' length " << (long) len << "\n";
              return pbuf;
             }
             else
               return extract<const char *>(ob);
        }
	return NULL;
}

// retrieve named integer result from return values
uint64_t Results::namedValue(const char * name, uint64_t defaultValue)
{
	object ob;
	if (findObject(name, ob))
		return extract<uint64_t>(ob);
	return defaultValue;
}

void Results::convertNamedList(list & l, object & results)
{
	const ssize_t count = len(l);
	if (count == 0)
	{
		results = l;
		return;
	}
	dict d;
	for (ssize_t i = 0; i < count; i++)
	{
		extract<tuple> 	namedPair(l[i]);
		if (!namedPair.check())
		{
			results = l;
			return;
		}
		d[namedPair()[0]] = namedPair()[1];
	}
	results = d;
}


} // Tcg
