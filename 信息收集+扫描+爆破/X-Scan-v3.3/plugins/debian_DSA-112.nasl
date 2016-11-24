# This script was automatically generated from the dsa-112
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2009 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004-2009 Tenable Network Security, Inc.

if (! defined_func('bn_random')) exit(0);

include('compat.inc');

if (description) {
 script_id(14949);
 script_version("$Revision: 1.9 $");
 script_xref(name: "DSA", value: "112");
 script_cve_id("CVE-2002-0239");

 script_set_attribute(attribute:'synopsis', value: 
'The remote host is missing the DSA-112 security update');
 script_set_attribute(attribute: 'description', value:
'A set of buffer overflow problems have been found in hanterm, a Hangul
terminal for X11 derived from xterm, that will read and display Korean
characters in its terminal window.  The font handling code in hanterm
uses hard limited string variables but didn\'t check for boundaries.
This problem can be exploited by a malicious user to gain access to
the utmp group which is able to write the wtmp and utmp files.  These
files record login and logout activities.
This problem has been fixed in version 3.3.1p17-5.2 for the stable
Debian distribution.  A fixed package for the current testing/unstable
distribution is not yet available but will have a version number
higher than 3.3.1p18-6.1.
');
 script_set_attribute(attribute: 'see_also', value: 
'http://www.debian.org/security/2002/dsa-112');
 script_set_attribute(attribute: 'solution', value: 
'The Debian project recommends that you upgrade your hanterm packages immediately if you
have them installed.');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C');
script_end_attributes();

 script_copyright(english: "This script is (C) 2009 Tenable Network Security, Inc.");
 script_name(english: "[DSA112] DSA-112-1 hanterm");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-112-1 hanterm");
 exit(0);
}

include("debian_package.inc");

if ( ! get_kb_item("Host/Debian/dpkg-l") ) exit(1, "Could not obtain the list of packages");

deb_check(prefix: 'hanterm', release: '2.2', reference: '3.3.1p17-5.2');
if (deb_report_get()) security_hole(port: 0, extra:deb_report_get());
else exit(0, "Host is not affected");
