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
// \file pysed.h
// \brief Python extensions for Self Encrypting Drives
//
//-----------------------------------------------------------------------------
#ifndef PYSED_H_
#define PYSED_H_
#include <boost/python/tuple.hpp>
#include <boost/python/object.hpp>
#include <boost/python/list.hpp>
#include <boost/python/dict.hpp>
#include <boost/shared_ptr.hpp>
#include <string>
#include "TcgDrive.h"
#include "support.h"
class PySession;

#define TCG_TLS

// Class helping decode various Tcg identifier strings into UIDs with
// the help of Python dictionaries.
class UidLookup {
	object	lookupTable;
public:
	UidLookup operator=(object lookup) { lookupTable = lookup;return *this;}
	Tcg::Uid operator()(boost::python::object parm, Tcg::Uid _default = 0);
	Tcg::Uid operator()(const char * name);
};

// Class invoking Python code to determine default SP used for object or auth UIDs
class GetSp {
	object	pyfn;
public:
	GetSp operator=(object o) { pyfn = o;return *this;}
	Tcg::Uid operator()(Tcg::Uid obId, Tcg::Uid authId);
};

class PyLogger : public Tcg::LoggerBase {
	object logger;
public:
	void init(std::string devname, dict kwargs);
	virtual void write(LogType type, const char * msg);
};

class CipherSuites {
	object	suites;
public:
	CipherSuites(object _suites) : suites(_suites) {}
	CipherSuites operator=(object _suites) { suites = _suites;return *this;}
	std::string Name(unsigned value);
	unsigned Value(object name);
};

class Sed : public Tcg::Drive {
	std::string mSID;
	UidLookup	spIds;
	UidLookup	authIds;
	UidLookup	methodIds;
	UidLookup 	objectIds;
	GetSp		getSp;
	PyLogger	logger;
	bool		tlsEnabled;
	CipherSuites		cipherSuites;

public:
	unsigned	respTimeout;

	Sed(std::string drive, object uidTablesFn, object cipherSuites,  dict kwargs);
	~Sed();
	std::string getSSC();
	object      getmSID();
	bool 		getHasLockedRange();
	bool 		getIsEnterprise();
	unsigned 	getLifeCycle();
	object   	getPorts();
	object   	getFipsCompliance();
	bool 		getFipsApprovedMode();
	void        interfaceReset(int level = 0) {transport->reset(level);}
	object 		getCipherSuites();
	void 		usePsk(std::string uid = "", object cipherSuite = object(), object key = object(), object key2 = object());
	object      getCurrentCipherSuite();
	object 		l0discovery();
	bool        getDebugPackets();
	void		setDebugPackets(bool val);
	virtual Tcg::LoggerBase &	getLogger() {return logger;}

	static boost::python::tuple  invoke(boost::python::tuple argv, boost::python::dict kwargs);
	bool checkPIN(object auth, object cred);

	friend class PySession;
};

#endif /* PYSED_H_ */
