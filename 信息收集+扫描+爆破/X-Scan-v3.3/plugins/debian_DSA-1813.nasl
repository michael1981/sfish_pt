# This script was automatically generated from the dsa-1813
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2009 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004-2009 Tenable Network Security, Inc.

if (! defined_func('bn_random')) exit(0);

include('compat.inc');

if (description) {
 script_id(39334);
 script_version("$Revision: 1.1 $");
 script_xref(name: "DSA", value: "1813");
 script_cve_id("CVE-2009-0547", "CVE-2009-0582", "CVE-2009-0587");

 script_set_attribute(attribute:'synopsis', value: 
'The remote host is missing the DSA-1813 security update');
 script_set_attribute(attribute: 'description', value:
'Several vulnerabilities have been found in evolution-data-server, the
database backend server for the evolution groupware suite. The Common
Vulnerabilities and Exposures project identifies the following problems:
CVE-2009-0587
It was discovered that evolution-data-server is prone to integer
overflows triggered by large base64 strings.
CVE-2009-0547
Joachim Breitner discovered that S/MIME signatures are not verified
properly, which can lead to spoofing attacks.
CVE-2009-0582
It was discovered that NTLM authentication challenge packets are not
validated properly when using the NTLM authentication method, which
could lead to an information disclosure or a denial of service.
For the oldstable distribution (etch), these problems have been fixed in
version 1.6.3-5etch2.
For the stable distribution (lenny), these problems have been fixed in
version 2.22.3-1.1+lenny1.
');
 script_set_attribute(attribute: 'see_also', value: 
'http://www.debian.org/security/2009/dsa-1813');
 script_set_attribute(attribute: 'solution', value: 
'The Debian project recommends that you upgrade your evolution-data-server packages.');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P');
script_end_attributes();

 script_copyright(english: "This script is (C) 2009 Tenable Network Security, Inc.");
 script_name(english: "[DSA1813] DSA-1813-1 evolution-data-server");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-1813-1 evolution-data-server");
 exit(0);
}

include("debian_package.inc");

if ( ! get_kb_item("Host/Debian/dpkg-l") ) exit(1, "Could not obtain the list of packages");

deb_check(prefix: 'evolution-data-server', release: '4.0', reference: '1.6.3-5etch2');
deb_check(prefix: 'evolution-data-server-common', release: '4.0', reference: '1.6.3-5etch2');
deb_check(prefix: 'evolution-data-server-dbg', release: '4.0', reference: '1.6.3-5etch2');
deb_check(prefix: 'evolution-data-server-dev', release: '4.0', reference: '1.6.3-5etch2');
deb_check(prefix: 'libcamel1.2-8', release: '4.0', reference: '1.6.3-5etch2');
deb_check(prefix: 'libcamel1.2-dev', release: '4.0', reference: '1.6.3-5etch2');
deb_check(prefix: 'libebook1.2-5', release: '4.0', reference: '1.6.3-5etch2');
deb_check(prefix: 'libebook1.2-dev', release: '4.0', reference: '1.6.3-5etch2');
deb_check(prefix: 'libecal1.2-6', release: '4.0', reference: '1.6.3-5etch2');
deb_check(prefix: 'libecal1.2-dev', release: '4.0', reference: '1.6.3-5etch2');
deb_check(prefix: 'libedata-book1.2-2', release: '4.0', reference: '1.6.3-5etch2');
deb_check(prefix: 'libedata-book1.2-dev', release: '4.0', reference: '1.6.3-5etch2');
deb_check(prefix: 'libedata-cal1.2-5', release: '4.0', reference: '1.6.3-5etch2');
deb_check(prefix: 'libedata-cal1.2-dev', release: '4.0', reference: '1.6.3-5etch2');
deb_check(prefix: 'libedataserver1.2-7', release: '4.0', reference: '1.6.3-5etch2');
deb_check(prefix: 'libedataserver1.2-dev', release: '4.0', reference: '1.6.3-5etch2');
deb_check(prefix: 'libedataserverui1.2-6', release: '4.0', reference: '1.6.3-5etch2');
deb_check(prefix: 'libedataserverui1.2-dev', release: '4.0', reference: '1.6.3-5etch2');
deb_check(prefix: 'libegroupwise1.2-10', release: '4.0', reference: '1.6.3-5etch2');
deb_check(prefix: 'libegroupwise1.2-dev', release: '4.0', reference: '1.6.3-5etch2');
deb_check(prefix: 'libexchange-storage1.2-1', release: '4.0', reference: '1.6.3-5etch2');
deb_check(prefix: 'libexchange-storage1.2-dev', release: '4.0', reference: '1.6.3-5etch2');
deb_check(prefix: 'evolution-data-server', release: '5.0', reference: '2.22.3-1.1+lenny1');
deb_check(prefix: 'evolution-data-server-common', release: '5.0', reference: '2.22.3-1.1+lenny1');
deb_check(prefix: 'evolution-data-server-dbg', release: '5.0', reference: '2.22.3-1.1+lenny1');
deb_check(prefix: 'evolution-data-server-dev', release: '5.0', reference: '2.22.3-1.1+lenny1');
deb_check(prefix: 'libcamel1.2-11', release: '5.0', reference: '2.22.3-1.1+lenny1');
deb_check(prefix: 'libcamel1.2-dev', release: '5.0', reference: '2.22.3-1.1+lenny1');
deb_check(prefix: 'libebook1.2-9', release: '5.0', reference: '2.22.3-1.1+lenny1');
deb_check(prefix: 'libebook1.2-dev', release: '5.0', reference: '2.22.3-1.1+lenny1');
deb_check(prefix: 'libecal1.2-7', release: '5.0', reference: '2.22.3-1.1+lenny1');
deb_check(prefix: 'libecal1.2-dev', release: '5.0', reference: '2.22.3-1.1+lenny1');
deb_check(prefix: 'libedata-book1.2-2', release: '5.0', reference: '2.22.3-1.1+lenny1');
deb_check(prefix: 'libedata-book1.2-dev', release: '5.0', reference: '2.22.3-1.1+lenny1');
deb_check(prefix: 'libedata-cal1.2-6', release: '5.0', reference: '2.22.3-1.1+lenny1');
deb_check(prefix: 'libedata-cal1.2-dev', release: '5.0', reference: '2.22.3-1.1+lenny1');
deb_check(prefix: 'libedataserver1.2-9', release: '5.0', reference: '2.22.3-1.1+lenny1');
deb_check(prefix: 'libedataserver1.2-dev', release: '5.0', reference: '2.22.3-1.1+lenny1');
deb_check(prefix: 'libedataserverui1.2-8', release: '5.0', reference: '2.22.3-1.1+lenny1');
deb_check(prefix: 'libedataserverui1.2-dev', release: '5.0', reference: '2.22.3-1.1+lenny1');
deb_check(prefix: 'libegroupwise1.2-13', release: '5.0', reference: '2.22.3-1.1+lenny1');
deb_check(prefix: 'libegroupwise1.2-dev', release: '5.0', reference: '2.22.3-1.1+lenny1');
deb_check(prefix: 'libexchange-storage1.2-3', release: '5.0', reference: '2.22.3-1.1+lenny1');
deb_check(prefix: 'libexchange-storage1.2-dev', release: '5.0', reference: '2.22.3-1.1+lenny1');
deb_check(prefix: 'libgdata-google1.2-1', release: '5.0', reference: '2.22.3-1.1+lenny1');
deb_check(prefix: 'libgdata-google1.2-dev', release: '5.0', reference: '2.22.3-1.1+lenny1');
deb_check(prefix: 'libgdata1.2-1', release: '5.0', reference: '2.22.3-1.1+lenny1');
deb_check(prefix: 'libgdata1.2-dev', release: '5.0', reference: '2.22.3-1.1+lenny1');
if (deb_report_get()) security_hole(port: 0, extra:deb_report_get());
else exit(0, "Host is not affected");
