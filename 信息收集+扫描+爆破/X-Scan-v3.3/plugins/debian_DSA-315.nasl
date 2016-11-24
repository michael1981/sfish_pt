# This script was automatically generated from the dsa-315
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2009 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004-2009 Tenable Network Security, Inc.

if (! defined_func('bn_random')) exit(0);

include('compat.inc');

if (description) {
 script_id(15152);
 script_version("$Revision: 1.9 $");
 script_xref(name: "DSA", value: "315");
 script_cve_id("CVE-2003-0433");
 script_bugtraq_id(7877);

 script_set_attribute(attribute:'synopsis', value: 
'The remote host is missing the DSA-315 security update');
 script_set_attribute(attribute: 'description', value:
'Bas Wijnen discovered that the gnocatan server is vulnerable to
several buffer overflows which could be exploited to execute arbitrary
code on the server system.
For the stable distribution (woody), this problem has been fixed in
version 0.6.1-5woody2.
The old stable distribution (potato) does not contain a gnocatan package.
');
 script_set_attribute(attribute: 'see_also', value: 
'http://www.debian.org/security/2003/dsa-315');
 script_set_attribute(attribute: 'solution', value: 
'Read http://www.debian.org/security/2003/dsa-315
and install the recommended updated packages.');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P');
script_end_attributes();

 script_copyright(english: "This script is (C) 2009 Tenable Network Security, Inc.");
 script_name(english: "[DSA315] DSA-315-1 gnocatan");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-315-1 gnocatan");
 exit(0);
}

include("debian_package.inc");

if ( ! get_kb_item("Host/Debian/dpkg-l") ) exit(1, "Could not obtain the list of packages");

deb_check(prefix: 'gnocatan-client', release: '3.0', reference: '0.6.1-5woody2');
deb_check(prefix: 'gnocatan-data', release: '3.0', reference: '0.6.1-5woody2');
deb_check(prefix: 'gnocatan-help', release: '3.0', reference: '0.6.1-5woody2');
deb_check(prefix: 'gnocatan-server', release: '3.0', reference: '0.6.1-5woody2');
deb_check(prefix: 'gnocatan', release: '3.0', reference: '0.6.1-5woody2');
if (deb_report_get()) security_hole(port: 0, extra:deb_report_get());
else exit(0, "Host is not affected");
