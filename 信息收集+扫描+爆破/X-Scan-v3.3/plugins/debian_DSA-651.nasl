# This script was automatically generated from the dsa-651
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2009 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004-2009 Tenable Network Security, Inc.

if (! defined_func('bn_random')) exit(0);

include('compat.inc');

if (description) {
 script_id(16235);
 script_version("$Revision: 1.8 $");
 script_xref(name: "DSA", value: "651");
 script_cve_id("CVE-2005-0094", "CVE-2005-0095");

 script_set_attribute(attribute:'synopsis', value: 
'The remote host is missing the DSA-651 security update');
 script_set_attribute(attribute: 'description', value:
'Several vulnerabilities have been discovered in Squid, the internet
object cache, the popular WWW proxy cache.  The Common Vulnerabilities
and Exposures Project identifies the following vulnerabilities:
    "infamous41md" discovered a buffer overflow in the parser for
    Gopher responses which will lead to memory corruption and usually
    crash Squid.
    "infamous41md" discovered an integer overflow in the receiver of
    WCCP (Web Cache Communication Protocol) messages.  An attacker
    could send a specially crafted UDP datagram that will cause Squid
    to crash.
For the stable distribution (woody) these problems have been fixed in
version 2.4.6-2woody5.
');
 script_set_attribute(attribute: 'see_also', value: 
'http://www.debian.org/security/2005/dsa-651');
 script_set_attribute(attribute: 'solution', value: 
'The Debian project recommends that you upgrade your squid package.');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P');
script_end_attributes();

 script_copyright(english: "This script is (C) 2009 Tenable Network Security, Inc.");
 script_name(english: "[DSA651] DSA-651-1 squid");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-651-1 squid");
 exit(0);
}

include("debian_package.inc");

if ( ! get_kb_item("Host/Debian/dpkg-l") ) exit(1, "Could not obtain the list of packages");

deb_check(prefix: 'squid', release: '3.0', reference: '2.4.6-2woody5');
deb_check(prefix: 'squid-cgi', release: '3.0', reference: '2.4.6-2woody5');
deb_check(prefix: 'squidclient', release: '3.0', reference: '2.4.6-2woody5');
if (deb_report_get()) security_warning(port: 0, extra:deb_report_get());
else exit(0, "Host is not affected");
