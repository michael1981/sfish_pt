# This script was automatically generated from the dsa-1185
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2009 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004-2009 Tenable Network Security, Inc.

if (! defined_func('bn_random')) exit(0);

include('compat.inc');

if (description) {
 script_id(22727);
 script_version("$Revision: 1.5 $");
 script_xref(name: "DSA", value: "1185");
 script_cve_id("CVE-2006-2937", "CVE-2006-2940", "CVE-2006-3738", "CVE-2006-4343");

 script_set_attribute(attribute:'synopsis', value: 
'The remote host is missing the DSA-1185 security update');
 script_set_attribute(attribute: 'description', value:
'The fix used to correct CVE-2006-2940 introduced code that could lead to
the use of uninitialized memory.  Such use is likely to cause the
application using the openssl library to crash, and has the potential to
allow an attacker to cause the execution of arbitrary code.
For reference please find below the original advisory text:
Multiple vulnerabilities have been discovered in the OpenSSL
cryptographic software package that could allow an attacker to launch
a denial of service attack by exhausting system resources or crashing
processes on a victim\'s computer.
CVE-2006-2937
	Dr S N Henson of the OpenSSL core team and Open Network
	Security recently developed an ASN1 test suite for NISCC
	(www.niscc.gov.uk). When the test suite was run against
	OpenSSL two denial of service vulnerabilities were discovered.
	During the parsing of certain invalid ASN1 structures an error
	condition is mishandled. This can result in an infinite loop
	which consumes system memory.
	Any code which uses OpenSSL to parse ASN1 data from untrusted
	sources is affected. This includes SSL servers which enable
	client authentication and S/MIME applications.
CVE-2006-3738
	Tavis Ormandy and Will Drewry of the Google Security Team
	discovered a buffer overflow in SSL_get_shared_ciphers utility
	function, used by some applications such as exim and mysql.  An
	attacker could send a list of ciphers that would overrun a
	buffer.
CVE-2006-4343
	Tavis Ormandy and Will Drewry of the Google Security Team
	discovered a possible DoS in the sslv2 client code.  Where a
	client application uses OpenSSL to make a SSLv2 connection to
	a malicious server that server could cause the client to
	crash.
CVE-2006-2940
	Dr S N Henson of the OpenSSL core team and Open Network
	Security recently developed an ASN1 test suite for NISCC
	(www.niscc.gov.uk). When the test suite was run against
	OpenSSL a DoS was discovered.
	Certain types of public key can take disproportionate amounts
	of time to process. This could be used by an attacker in a
	denial of service attack.
For the stable distribution (sarge) these problems have been fixed in
version 0.9.7e-3sarge4.
For the unstable and testing distributions (sid and etch,
respectively), these problems will be fixed in version 0.9.7k-3 of the
openssl097 compatibility libraries, and version 0.9.8c-3 of the
openssl package.
');
 script_set_attribute(attribute: 'see_also', value: 
'http://www.debian.org/security/2006/dsa-1185');
 script_set_attribute(attribute: 'solution', value: 
'The Debian project recommends that you upgrade your openssl package.');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C');
script_end_attributes();

 script_copyright(english: "This script is (C) 2009 Tenable Network Security, Inc.");
 script_name(english: "[DSA1185] DSA-1185-2 openssl");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-1185-2 openssl");
 exit(0);
}

include("debian_package.inc");

if ( ! get_kb_item("Host/Debian/dpkg-l") ) exit(1, "Could not obtain the list of packages");

deb_check(prefix: 'libssl-dev', release: '3.1', reference: '0.9.7e-3sarge4');
deb_check(prefix: 'libssl0.9.7', release: '3.1', reference: '0.9.7e-3sarge4');
deb_check(prefix: 'openssl', release: '3.1', reference: '0.9.7e-3sarge4');
if (deb_report_get()) security_hole(port: 0, extra:deb_report_get());
else exit(0, "Host is not affected");
