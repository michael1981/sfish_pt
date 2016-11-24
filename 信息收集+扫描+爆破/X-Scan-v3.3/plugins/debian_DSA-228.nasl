# This script was automatically generated from the dsa-228
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2009 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004-2009 Tenable Network Security, Inc.

if (! defined_func('bn_random')) exit(0);

include('compat.inc');

if (description) {
 script_id(15065);
 script_version("$Revision: 1.11 $");
 script_xref(name: "DSA", value: "228");
 script_cve_id("CVE-2003-0031", "CVE-2003-0032");
 script_bugtraq_id(6510, 6512);

 script_set_attribute(attribute:'synopsis', value: 
'The remote host is missing the DSA-228 security update');
 script_set_attribute(attribute: 'description', value:
'Ilia Alshanetsky discovered several buffer overflows in libmcrypt, a
decryption and encryption library, that originates from improper or
lacking input validation.  By passing input which is longer than
expected to a number of functions (multiple functions are affected)
the user can successfully make libmcrypt crash and may be able to insert
arbitrary, malicious code which will be executed under the user
libmcrypt runs as, e.g. inside a web server.
Another vulnerability exists in the way libmcrypt loads algorithms via
libtool.  When different algorithms are loaded dynamically, each time
an algorithm is loaded a small part of memory is leaked.  In a
persistent environment (web server) this could lead to a memory
exhaustion attack that will exhaust all available memory by launching
repeated requests at an application utilizing the mcrypt library.
For the current stable distribution (woody) these problems have been
fixed in version 2.5.0-1woody1.
The old stable distribution (potato) does not contain libmcrypt packages.
');
 script_set_attribute(attribute: 'see_also', value: 
'http://www.debian.org/security/2003/dsa-228');
 script_set_attribute(attribute: 'solution', value: 
'The Debian project recommends that you upgrade your libmcrypt packages.');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P');
script_end_attributes();

 script_copyright(english: "This script is (C) 2009 Tenable Network Security, Inc.");
 script_name(english: "[DSA228] DSA-228-1 libmcrypt");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-228-1 libmcrypt");
 exit(0);
}

include("debian_package.inc");

if ( ! get_kb_item("Host/Debian/dpkg-l") ) exit(1, "Could not obtain the list of packages");

deb_check(prefix: 'libmcrypt-dev', release: '3.0', reference: '2.5.0-1woody1');
deb_check(prefix: 'libmcrypt4', release: '3.0', reference: '2.5.0-1woody1');
deb_check(prefix: 'libmcrypt', release: '3.0', reference: '2.5.0-1woody1');
if (deb_report_get()) security_hole(port: 0, extra:deb_report_get());
else exit(0, "Host is not affected");
