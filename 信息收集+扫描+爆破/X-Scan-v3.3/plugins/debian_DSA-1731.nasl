# This script was automatically generated from the dsa-1731
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2009 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004-2009 Tenable Network Security, Inc.

if (! defined_func('bn_random')) exit(0);

include('compat.inc');

if (description) {
 script_id(35762);
 script_version("$Revision: 1.2 $");
 script_xref(name: "DSA", value: "1731");
 script_cve_id("CVE-2008-4395");

 script_set_attribute(attribute:'synopsis', value: 
'The remote host is missing the DSA-1731 security update');
 script_set_attribute(attribute: 'description', value:
'Anders Kaseorg discovered that ndiswrapper suffers from buffer overflows
via specially crafted wireless network traffic, due to incorrectly
handling long ESSIDs. This could lead to the execution of arbitrary
code.
For the oldstable distribution (etch), this problem has been fixed in
version 1.28-1+etch1.
For the stable distribution (lenny), this problem has been fixed in
version 1.53-2, which was already included in the lenny release.
');
 script_set_attribute(attribute: 'see_also', value: 
'http://www.debian.org/security/2009/dsa-1731');
 script_set_attribute(attribute: 'solution', value: 
'Read http://www.debian.org/security/2009/dsa-1731
and install the recommended updated packages.');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:A/AC:L/Au:N/C:C/I:C/A:C');
script_end_attributes();

 script_copyright(english: "This script is (C) 2009 Tenable Network Security, Inc.");
 script_name(english: "[DSA1731] DSA-1731-1 ndiswrapper");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-1731-1 ndiswrapper");
 exit(0);
}

include("debian_package.inc");

if ( ! get_kb_item("Host/Debian/dpkg-l") ) exit(1, "Could not obtain the list of packages");

deb_check(prefix: 'ndiswrapper-common', release: '4.0', reference: '1.28-1+etch1');
deb_check(prefix: 'ndiswrapper-source', release: '4.0', reference: '1.28-1+etch1');
deb_check(prefix: 'ndiswrapper-utils-1.9', release: '4.0', reference: '1.28-1+etch1');
deb_check(prefix: 'ndiswrapper', release: '4.0', reference: '1.28-1+etch1');
if (deb_report_get()) security_hole(port: 0, extra:deb_report_get());
else exit(0, "Host is not affected");
