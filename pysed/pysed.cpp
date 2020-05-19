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
// \file pysed.cpp
// \brief Implements the Python extensions for Self Encrypting Drives
//
//-----------------------------------------------------------------------------
#include <boost/python/module.hpp>
#include <boost/python/def.hpp>
#include <boost/python/str.hpp>
#include <boost/python/extract.hpp>
#include <boost/python/class.hpp>
#include <boost/python/make_function.hpp>
#include <boost/python/enum.hpp>
#include <boost/python/return_internal_reference.hpp>
#include <boost/python/self.hpp>
#include <boost/python/raw_function.hpp>
#include <boost/python/object.hpp>
#include <boost/python/exception_translator.hpp>
#include <boost/python/call_method.hpp>
#include "pysed.h"
#include "TcgDrive.h"
#include "TcgScanner.h"
#if !defined(_WINDOWS)
#include "Tls.h"
#endif
#include <stdio.h>
#define __PYTHON3__

using namespace Tcg;
using namespace boost::python;
using std::string;

void translate(TcgError const & e) {
	PyErr_SetString(PyExc_RuntimeError, e.what());
}

#if !defined(_WINDOWS)
void translateTls(gnutls::exception const & e)
{
	string msg("TLS Error: ");
	msg += gnutls_strerror(const_cast<gnutls::exception &>(e).get_code());
	PyErr_SetString(PyExc_RuntimeError, msg.c_str());
}
#endif

// Use Python helper's to convert method/object/auth strings into Uids
Uid UidLookup::operator()(object parm, Uid _default) {
	if (parm != object())		// parameter is not None
			{
		extract<Uid> uid(parm);
		if (uid.check()) {
			Uid answer = uid();
			return answer;
		}

		else {
			string name = extract<string>(parm);
			Uid answer = extract<Uid>(lookupTable[name]);
			if (answer)
				return answer;
			if (name.length() == 8)	// Uid in byte sequence form (returned from a call)
					{
				const uint8_t * ptr = (const uint8_t *) name.c_str();
				for (unsigned i = 0; i < 8; i++)
					answer = (answer << 8) + ptr[i];

				return answer;
			}
		}
	}

	return _default;
}

Uid UidLookup::operator()(const char * name) {
	return extract<Uid>(lookupTable[name]);
}

Tcg::Uid GetSp::operator()(Tcg::Uid obId, Tcg::Uid authId) {
	return extract<Uid>(pyfn(obId, authId));
}

std::string CipherSuites::Name(unsigned value) {
	return extract<std::string>(suites.attr("Name")(value));
}

unsigned CipherSuites::Value(object name) {
	return extract<unsigned>(suites.attr("Value")(name));
}

struct beint32_to_python {
	static PyObject * convert(beint32_t const & s) {
		const uint32_t v = s;
#if defined(__FreeBSD__) || defined(__PYTHON3__)
		return PyLong_FromLong(v);
#else		
		return PyInt_FromLong(v);
#endif
	}
};

struct beint64_to_python {
	static PyObject * convert(beint64_t const & s) {
		const long v = static_cast<long>(s);
#if defined(__FreeBSD__) || defined(__PYTHON3__)
		return PyLong_FromLong(v);
#else		
		return PyInt_FromLong(v);
#endif
	}
};

static const char * logTypes[] = { "info", "warn", "error", "debug", 0 };

void PyLogger::init(string devname, dict kwargs) {
	if (kwargs.has_key("logger")) {
		logger = extract<object>(kwargs["logger"]);
	} else {
		object logging = import("logging");
		logging.attr("basicConfig")();// avoids 'No handlers could be found...'
		string subname = devname.substr(devname.length() - 5);// last 5 chars of wwn
		size_t n = subname.find('/');
		if (n != string::npos)						// or dev name (e.g. sdae)
			subname = subname.substr(n + 1);
		logger = logging.attr("getLogger")(string("sed.") + subname);
	}
}

void PyLogger::write(LogType type, const char * msg) {
	ScopedGILAcquire acquireGIL;
	call_method<void>(logger.ptr(), logTypes[type], msg);
}

ScopedGILRelease::ScopedGILRelease() {
	// unfortunately seems this call cannot be nested
	thstate = PyEval_SaveThread();
}

ScopedGILRelease::~ScopedGILRelease() {
	PyEval_RestoreThread(reinterpret_cast<PyThreadState*>(thstate));
}

ScopedGILAcquire::ScopedGILAcquire() {
	gstate = PyGILState_Ensure();
}

ScopedGILAcquire::~ScopedGILAcquire() {
	PyGILState_Release(static_cast<PyGILState_STATE>(gstate));
}

static const char * sedDocs =
		"Base class exposing a drive's TCG SED functionality.\n"
				"Sed(devicePath, uidsTableFn, cipherSuites, kwargs)\n\n"
				"Parameters:\n"
				"    devicePath  - the device to communicate with.\n"
				"    uidsTableFn - helper function to invoke to get name/UID conversion routines.\n"
				"    cipherSuites - helper object used to convert forms of cipher suites.\n"
				"Named parameters:"
				"    logger      - A Python logger instance to use for logging.\n"
				"                  If not supplied, will use the logger sed.xxxxx where xxxxx is the last\n"
				"                  five digits of the drive wwn or base device name.";
Sed::Sed(string drive, object uidTablesFn, object _cipherSuites, dict kwargs) :
		Drive(drive.c_str()), tlsEnabled(false), cipherSuites(_cipherSuites), respTimeout(
				1000) {
	logger.init(drive, kwargs);
	int retry;
	for (retry = 0; retry < 2; retry++)
		try {
			init();
			object uids = uidTablesFn(ptr(this));
			spIds = extract<object>(uids[0]);
			authIds = extract<object>(uids[1]);
			objectIds = extract<object>(uids[2]);
			methodIds = extract<object>(uids[3]);
			getSp = extract<object>(uids[4]);
			authenticateUid = methodIds("Authenticate");
			return;
		} catch (TcgError & e) {
			if (retry == 0)
				continue;
			//logger.error("Error initializing device %s: %s", devname.c_str(),
			//		e.what());
			//PyErr_SetString(PyExc_RuntimeError, e.what());
			return;
		}
}

Sed::~Sed() {
}

static const char * sscDocs =
		"Retrieve current drive's Security Subsystem Class.";
std::string Sed::getSSC() {
	return discovery.ssc();
}

static const char * msidDocs = "Retreive the drive's mSID.\n"
		"Returns the mSID as a string or None upon error";
object Sed::getmSID() {
	if (mSID.empty()) {
		try {
			const char * pin;
			ScopedSession session(this, TcgUids::AdminSP);
			FunctionCall * get = session.call(objectIds("MSID"),
					methodIds("Get"));
			get->addList();
			Results results;
			session.invoke(results, true);
			if (discovery.enterprise)
				pin = results.namedString("PIN");
			else if (discovery.opalV2)
				pin = results.namedString(3);
			else if (discovery.opal)
				pin = results.namedString(3);
			else
				pin = 0;
			if (pin)
				mSID = pin;
		} catch (TcgError & e) {
			logger.error("Unable to retrieve mSID for %s: %s", devname.c_str(),
					e.what());
			return object();
		}
	}
	return str(mSID);
}

static const char * hasLockedRangeDocs =
		"Returns True if any bands are currently locked.";
bool Sed::getHasLockedRange() {
	try {
		discovery.refresh(transport);
	} catch (TcgError & e) {
		logger.error("%s",e.what());
		PyErr_SetString(PyExc_RuntimeError, e.what());
	}
	return discovery.locking && discovery.locking->locked;
}

static const char * isEnterpriseDocs =
		"Returns True if the drive suppors the Enterprise SSC.";
bool Sed::getIsEnterprise() {
	return discovery.enterprise != 0;
}

static const char * lifeCycleDocs =
		"Value of the current SED life cycle.  128 is expected value in normal state.";
unsigned Sed::getLifeCycle() {
	if (discovery.hdr)
		return discovery.hdr->vendor[1];
	return 0;
}

static const char * portsDocs =
		"Retrieve Ports level 0 discovery information.\n"
				"Returns a dictionary with key set to the Port Uid and value set to the current locked state (boolean.)\n";
object Sed::getPorts() {
	dict ports;
	try {
		discovery.refresh(transport);
	} catch (TcgError & e) {
		logger.error("%s",e.what());
		PyErr_SetString(PyExc_RuntimeError, e.what());
	}
	if (!discovery.port)
		return ports;
	int count = discovery.port->hdr.length
			/ sizeof(Discovery::PortDesc::PortEntry);
	for (int i = 0; i < count; i++)
		ports[TcgUids::PortsBase + discovery.port->portEntry[i].portIdentifier] =
				discovery.port->portEntry[i].portLocked;
	return ports;
}

void swap(char* x, char *y) {
	*x ^= *y;
	*y ^= *x;
	*x ^= *y;
}

static const char * fipsDocs =
		"Read the FIPS Compliance Descriptor from the drive.\n"
				"Returns None if FIPS Compliance Descriptor was not found.\n"
				"Returns a dictionary when FIPS compliant with values from the \n"
				"TCG Security Compliance structure with the following keys/values:\n"
				"  standard           - \'FIPS 140-2\' or \'FIPS 140-3\'\n"
				"  securityLevel      - Security level value\n"
				"  hardwareVersion    - The hardware version string\n"
				"  descriptorVersion  - Descriptor version string\n"
				"  moduleName         - Module name\n";
object Sed::getFipsCompliance() {
	char buffer[2048];
	try {
		int rv;
		{
			ScopedGILRelease unlockGIL;
			rv = transport->receive(SeaTransport::SECURITY_COMPLIANCE_INFO,
					buffer, sizeof(buffer));
		}
		if (!rv) {
			beint32_t * lptr = (beint32_t *) buffer;
			uint32_t length = *lptr;
			uint16_t i;
			for (unsigned ofs = 4; ofs < length;) {
				FipsComplianceDescriptor * desc =
						(FipsComplianceDescriptor *) (buffer + ofs);
				if (desc->type != 1) {
					desc->type = htobe16(desc->type);
					desc->length = htobe32(desc->length);
					for (i = 0; i < 128; i = i + 2) {
						swap(&desc->hardwareVersion[i],
								&desc->hardwareVersion[i + 1]);
						swap(&desc->descVersion[i], &desc->descVersion[i + 1]);
					}
					for (i = 0; i < 256; i = i + 2)
						swap(&desc->moduleName[i], &desc->moduleName[i + 1]);
				}
				if (desc->type == 1) {
					dict fipsInfo;
					char* temp_p = NULL;
					char* replace_p = NULL;
					char replaceval = '0';
					replace_p = &replaceval;
					if (desc->relatedStandard == FIPS_140_2)
						fipsInfo["standard"] = "FIPS 140-2";
					else if (desc->relatedStandard == FIPS_140_3)
						fipsInfo["standard"] = "FIPS 140-3";
					else
						fipsInfo["standard"] = "Unknown";

					fipsInfo["securityLevel"] = desc->securityLevel;
					//Replace extended ascii characters
					for (temp_p = &desc->hardwareVersion[0]; *temp_p != '\0'; temp_p++)
					{
						if ((int(*temp_p) > 127) || (int(*temp_p) < 0)) {
							*temp_p = *replace_p;
						}
					}
					str hwver(desc->hardwareVersion);
					fipsInfo["hardwareVersion"] = hwver.rstrip();
					for (temp_p = &desc->descVersion[0]; *temp_p != '\0'; temp_p++)
					{
						if ((int(*temp_p) > 127) || (int(*temp_p) < 0)) {
							*temp_p = *replace_p;
						}
					}
					for (temp_p = &desc->moduleName[0]; *temp_p != '\0'; temp_p++)
					{
						if ((int(*temp_p) > 127) || (int(*temp_p) < 0)) {
							*temp_p = *replace_p;
						}
					}
					fipsInfo["descriptorVersion"] = desc->descVersion;
					fipsInfo["moduleName"] = desc->moduleName;
					return fipsInfo;
				}
				ofs += desc->length;
			}
		}
	} catch (TcgError & e) {
		logger.error("%s",e.what());
		PyErr_SetString(PyExc_RuntimeError, e.what());
	}
	return object();
}

static const char * fipsAMDocs =
		"Retrieves current discovery level 0 flag representing the device is operating in FIPS approved mode\n"
				"for devices reporting this state.";
bool Sed::getFipsApprovedMode() {
	discovery.refresh(transport);
	return discovery.locking && discovery.locking->fipsApprovedMode;
}

// Helper routine used to encode function parameters.
// Arguments:
//   p 		- The TCG packet encoding the parameter.
//   o 		- The Python object representing the type/value to encode.
//   name 	- The optional parameter name to encode.
static void encodeParameter(Packet * p, object o, std::string name) {
	if (name.empty()) {
		if (o == object())	// None
				{
			p->encodeToken(EmptyAtom);
			return;
		}
		extract<tuple> tup(o);
		if (tup.check()) {
			tuple t = tup();// tuple used to encode named parameters
			extract<string> asName(t[0]);
			if (asName.check())
			{
				string new_string = extract<string> (str(t[0]));
				encodeParameter(p, t[1], new_string);
			}
			else					// Opal style ID/value pair
			{
				extract<int> asInt(t[0]);
				if (asInt.check()) {
					p->encodeToken(StartName);
					p->encodeAtom(asInt());
					encodeParameter(p, t[1], "");
					p->encodeToken(EndName);
				}
			}
			return;
		}
	}
	extract<string> strParm(o);
	if (strParm.check()) {
		if (!name.empty())
			p->addNamedParameter(name, strParm());
		else
			p->addParameter(strParm());
		return;
	}
	extract<uint64_t> intParm(o);
	if (intParm.check()) {
		if (!name.empty())
			p->addNamedParameter(name, intParm);
		else
			p->addParameter(intParm);
		return;
	}
	extract<list> listParm(o);
	if (listParm.check()) {
		if (!name.empty()) {
			p->encodeToken(StartName);
			p->encodeAtom(name.data(), name.size());
		}
		Packet * p2 = p->addList();
		list theList = listParm();
		for (int i = 0; i < len(theList); i++)
			encodeParameter(p2, theList[i],"");
		p2->pop();
		if (!name.empty())
			p->encodeToken(EndName);
	}
}

static const char * namedParms[] = { "sp", "authas", "timeout", "noClose",
		"useTls", "deferClose" };

static  int sizeparms = 6;

static bool isKnownParameter(string &key) {
	for (int i = 0; i < sizeparms; i++)
		if (!strcasecmp(key.c_str(), namedParms[i]))
			return true;
	return false;
}

// Retrieve the plain text from a credential parameter.
static string parseCredential(object ob) {
	if (PyObject_HasAttrString(ob.ptr(), "plainText"))
		return extract<string>(ob.attr("plainText"));

	extract<string> asString(ob);
	if (asString.check())
		return asString();

	string obs = extract<string>(str(ob));
	throw TcgError("Invalid credential: %s", obs.c_str());
}

static const char * invokeDocs =
		"def invoke(self, obId, methodId, *vargs, **kwargs):\n"
				"Low level TCG method invocation."
				"  Positional arguments:\n"
				"    obId     - Uid or known object names.  Uid may be in integer or string form.\n"
				"    methodId - Uid or known method names.\n"
				"    <vargs>	  - Unnamed method parameters including:\n"
				"        value          - Specified value is inserted into the argument list.\n"
				"        [args]         - Insert StartList, <args>, EndList into parameters.\n"
				"        (name, value)  - Insert StartName <name> <value> EndName into parameters.\n"
				"\n"
				"  Named arguments:\n"
				"    sp         - Optional SP.  SP defaults to one inferred by obId or authority.\n"
				"    authAs     - Tuple of (authority, credential).\n"
				"                 authority may be Uid or name.  Default is Anybody.\n"
				"                 credential may be a string or an object with the property 'plainText'.\n"
				"                 If authority is not Anybody and credential is not supplied,\n"
				"                 credential is assumed to be mSID.\n"
				"    timeout    - timeout of response in ms.  Default is 1000ms.\n"
				"    noNamed    - Do not provide a named parameter list if parameter is supplied.  Value is not used.\n"
				"     noClose    - Do not instruct drive to close the session if parameter is supplied, but clear session handle (Session handle is cleared)\n"
				"    useTls     - Override use of a Tls session.  By default, Tls is used when the authority is not Anybody.\n"
				"    deferClose - Do not append a CloseSession token with method call, an additional transaction is used to close the session.\n"
				"                 This is to avoid problems with TLS sessions being closed prior to method completion.Not implemented\n"
				"    <other kwargs>\n"
				"               - Named method parameters.\n"
				"\n"
				"Returns:\n"
				"    StatusCode - One of the StatusCode enumeration values.\n"
				"  On Success:\n"
				"    rvs	        - Unnamed return values (list).\n"
				"    kwrvs      - Named return values (dict)\n"
				"  On Fail:\n"
				"    msg        - Possible error description.\n"
				"    None       - Tuple filler\n";
tuple Sed::invoke(tuple argv, dict kwargs) {
	Sed * self = extract<Sed *>(argv[0]);
	try {
		Uid obId = self->objectIds(argv[1]);
		Uid methodId = self->methodIds(argv[2]);
		list keys = kwargs.keys();
		Uid authority = TcgUids::Authorities::Anybody;
		string authName;
		object credentials;
		Uid sp;

		if (obId == 0) {
			string name = extract<string>(str(argv[1]));
			throw TcgError("Invalid TCG objectId: %s", name.c_str());
		}
		if (methodId == 0) {
			string name = extract<string>(str(argv[2]));
			throw TcgError("Invalid TCG methodId: %s", name.c_str());
		}
		if (keys.contains("authAs")) {
			object authAso = kwargs.get("authAs");
			extract<tuple> asTuple(authAso);
			if (asTuple.check()) {
				tuple authAs = asTuple();
				authority = self->authIds(authAs[0]);
				authName = extract<string>(authAs[0]);
				if (len(authAs) > 1)
					credentials = authAs[1];
			} else {
				authName = extract<string>(authAso);
				authority = self->authIds(authAso);
			}
			if (authority == 0) {
				string name = extract<string>(str(authAso));
				throw TcgError("Invalid TCG authority: %s", name.c_str());
			}
			if (credentials == object()) {
				credentials = str(self->getmSID());
			}
		}
		bool useTls = false;
		if (self->tlsEnabled) {
			if (keys.contains("useTls"))
				useTls = extract<bool>(kwargs.get("useTls"));
			else
				useTls = authority != TcgUids::Authorities::Anybody;
		}
		if (keys.contains("sp"))
			sp = self->spIds(kwargs.get("sp"));
		else
			sp = self->getSp(obId, authority);
		if (sp == 0)
			throw TcgError("Invalid SP");

		unsigned timeout = 0;
		if (keys.contains("timeout"))
			timeout = extract<unsigned>(kwargs.get("timeout"));
		else
			timeout = self->respTimeout;
		ScopedSession session(self, sp, timeout, useTls);
		if (authority != TcgUids::Authorities::Anybody) {
			while (!session.authenticate(authority,
					parseCredential(credentials))) {
				self->logger.debug("Failed to authenticate as %s",
						authName.c_str());
				object self = argv[0];
				credentials = call_method<object>(self.ptr(),
						"_failedCredentials", authName, credentials);
				if (credentials == object())
					return make_tuple(NOT_AUTHORIZED, credentials, credentials);
			}
		}
		FunctionCall * call = session.call(obId, methodId);
		ssize_t i;
		for (i = 3; i < len(argv); i++)
			encodeParameter(call, argv[i],"");

		if (!keys.contains("noNamed")) {
			ParameterList * addlParms = call->addList();
			ParameterList * namedParms = 0;
			for (i = 0; i < len(keys); i++) {
				string key = extract<string>(keys[i]);
				if (isKnownParameter(key))
					continue;
				if (!namedParms)
					namedParms = addlParms->addList();
				encodeParameter(namedParms, kwargs.get(keys[i]), key.c_str());
			}
			if (namedParms)
				namedParms->pop();
			addlParms->pop();
		}

		Results results;
		int rv = session.invoke(results, !keys.contains("deferClose"));
		if (keys.contains("noClose"))
			session.clearSession();
		return make_tuple(rv, results.returnedValues,
				results.returnedNamedValues);
	} catch (TcgError & err) {
		self->logger.error("%s",err.what());
		return make_tuple(FAIL, err.what(), object());
	} catch (...) {
		handle_exception();
	}
	return make_tuple(FAIL);
}

// Low-level check PIN primative.
bool Sed::checkPIN(object auth, object cred) {
	Uid authority = authIds(auth);
	Uid sp = getSp(0, authority);
	try {
		ScopedSession session(this, sp, respTimeout, tlsEnabled);

		string credentials = parseCredential(cred);

		return session.authenticate(authority, credentials, true);
	} catch (TcgError & e) {
		logger.error("%s",e.what());
	}
	return false;
}

object Sed::getCipherSuites() {
#if defined(TCG_TLS) && !defined(_WINDOWS)
	if (discovery.tls) {
		list suites;
		Discovery::SecureMsgDesc * l0tls = discovery.tls;
		Discovery::SMCS * l0CipherSuite =
				reinterpret_cast<Discovery::SMCS *>(l0tls->sps + l0tls->spCount);
		SupportedSuites & ssuites = TlsSession::supportedSuites();
		for (unsigned ndx = 0; ndx < l0CipherSuite->count; ndx++) {
			if (ssuites.supports(l0CipherSuite->suites[ndx]))
				suites.append(l0CipherSuite->suites[ndx]);
		}
		if (len(suites) > 0)
			return suites;
	}
#endif
	return object();
}

static const char * usePskDocs =
		"Configure the TLS PSK cipher suite to be used for communications.\n"
				"This must be set for an interface to utilize TLS.\n"
				"Parameters:\n"
				"  uid          - The Tls Entry UID used for the Tls psk_identity field."
				"  cipherSuite	- The Cipher Suite to use as defined by the\n"
				"               tcgapi.PskCipherSuites enumeration.\n"
				"               None, to stop TLS communications.\n"
				"  psk          - The Pre-Shared Key to use.\n"
				"  psk2         - Optional PSK to use for the LockingSP";
void Sed::usePsk(string uid, object cipherSuite, object key, object key2) {
#if defined(TCG_TLS) && !defined(_WINDOWS)
	if (tlsCreds) {
		destroyCreds();
	}
	if (key == object()) {
		tlsEnabled = false;
		tlsParameters = -1;
	} else {
		if (uid.size() != 8) {
			PyErr_SetString(PyExc_RuntimeError, "Invalid UID specified");
			return;
		}
		tlsCreds[0] = new TlsCredentials(uid, extract<string>(key));
		tlsCreds[1] =
				(key2 == object()) ?
						tlsCreds[0] :
						new TlsCredentials(uid, extract<string>(key2));
		tlsEnabled = true;
		TlsSession::supportedSuites().supports(cipherSuites.Value(cipherSuite),
				&tlsParameters);
	}
#endif
}

object Sed::getCurrentCipherSuite() {
#if !defined(_WINDOWS)
	if (tlsParameters < 0)
		return object();

	unsigned sscode = TlsSession::supportedSuites().index2cipherSuite(
			tlsParameters);
	return str(cipherSuites.Name(sscode));
#else
	return object();
#endif
}

object Sed::l0discovery() {
	struct enumDisc: public DescriptorEnum {
		dict results;
		void operator()(const Discovery::DescHdr * hdr, const void * data) {
			uint16_t ndx = hdr->featureCode;
			results[ndx] = str((const char *) data, hdr->length);
		}
		virtual void hdr(const Discovery::Hdr * hdr) {
			results["hdr"] = str((const char *) hdr, hdr->length);
		}
	};
	enumDisc r;
	discovery.enumDescriptors(r);
	return r.results;
}

bool Sed::getDebugPackets() {
	return Session::dumpPackets;
}

void Sed::setDebugPackets(bool val) {
	Session::dumpPackets = val;
}



static const char * maxlbaDocs = "Retrieve drive's maximum addressable LBA";
static const char * wwnDocs = "Retrieve drive's world wide name.";
static const char * fipsDATADocs = "Retrieves the FIPS operating mode of a drive through ATA Identify data";
BOOST_PYTHON_MEMBER_FUNCTION_OVERLOADS(ifaceReset, Sed::interfaceReset, 0, 1)
BOOST_PYTHON_MEMBER_FUNCTION_OVERLOADS(usePSK, Sed::usePsk, 0, 4)
BOOST_PYTHON_MODULE(pysed)
{
	PyEval_InitThreads();
	register_exception_translator<TcgError>(&translate);
#if !defined(_WINDOWS)
	register_exception_translator<gnutls::exception>(&translateTls);
#endif
	to_python_converter<beint32_t, beint32_to_python>();
	to_python_converter<beint64_t, beint64_to_python>();
	docstring_options doc_options;
	doc_options.disable_py_signatures();
	class_<Sed>("Sed", sedDocs, init<string, object, object, dict>())
			.add_property("SSC", 				&Sed::getSSC,				sscDocs)
			.add_property("mSID", 				&Sed::getmSID,				msidDocs)
			.add_property("hasLockedRange", 	&Sed::getHasLockedRange,	hasLockedRangeDocs)
			.add_property("isEnterprise", 		&Sed::getIsEnterprise,		isEnterpriseDocs)
			.add_property("maxLba", 			&Sed::getMaxLba,			maxlbaDocs)
			.add_property("wwn", 				&Sed::getWwn,				wwnDocs)
			.add_property("fipsidentifydata", 	&Sed::getfipsdata,			fipsDATADocs)
			.add_property("lifeCycle", 			&Sed::getLifeCycle,			lifeCycleDocs)
			.add_property("ports", 				&Sed::getPorts,				portsDocs)
			.add_property("fipsApprovedMode", 	&Sed::getFipsApprovedMode,	fipsAMDocs)
			.add_property("_debugPackets",      &Sed::getDebugPackets, 	&Sed::setDebugPackets,	"Dump TCG packets in debug log")

			.def_readwrite("timeout",   &Sed::respTimeout, "Response timeout in ms")
			.def("invoke", 				raw_function(&Sed::invoke, 3),			invokeDocs)
			.def("_checkPIN", 			&Sed::checkPIN)
			.def("fipsCompliance", 		&Sed::getFipsCompliance,	fipsDocs)
			.def("tcgReset", 			&Sed::stackReset, "Reset the TCG stack")
			.def("interfaceReset", 		&Sed::interfaceReset,
					ifaceReset(args("level"), "Perform an interface reset")
					)
			.def("_cipherSuites",		&Sed::getCipherSuites)
			.def("usePsk",				&Sed::usePsk,
					usePSK(args("uid", "cipherSuite", "key"), usePskDocs)
					)
			.add_property("currentCipherSuite",		&Sed::getCurrentCipherSuite)
			.def("_l0", &Sed::l0discovery, "Dictionary of raw l0 discovery descriptors")
			;
		enum_<Tcg::StatusCode>("StatusCode")
			.value("Success", 				SUCCESSCODE)
			.value("NotAuthorized", 		NOT_AUTHORIZED)
			.value("Obsolete", 				OBSOLETECODE)
			.value("Busy",         			SP_BUSY)
			.value("Failed",         		SP_FAILED)
			.value("Disabled",         		SP_DISABLED)
			.value("Frozen",         		SP_FROZEN)
			.value("NoSessionsAvailable",   NO_SESSIONS_AVAILABLE)
			.value("UniquenessConflict",    UNIQUENESS_CONFLICT)
			.value("InsufficientSpace",     INSUFFICIENT_SPACE)
			.value("InsufficientRows",      INSUFFICIENT_ROWS)
			.value("InvalidParameter",      INVALID_PARAMETER)
			.value("TperMalfunction",       TPER_MALFUNCTION)
			.value("TransactionFailure",    TRANSACTION_FAILURE)
			.value("ResponseOverflow",      RESPONSE_OVERFLOW)
			.value("AuthorityLockedOut",    AUTHORITY_LOCKED_OUT)
			.value("Fail",  		 		FAIL)
			.value("Timeout",				TIMEOUT)
			.export_values();
	}
