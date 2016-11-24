# This script was automatically generated from the dsa-873
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2009 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004-2009 Tenable Network Security, Inc.

if (! defined_func('bn_random')) exit(0);

include('compat.inc');

if (description) {
 script_id(22739);
 script_version("$Revision: 1.6 $");
 script_xref(name: "DSA", value: "873");
 script_cve_id("CVE-2005-2177");
 script_bugtraq_id(14168);

 script_set_attribute(attribute:'synopsis', value: 
'The remote host is missing the DSA-873 security update');
 script_set_attribute(attribute: 'description', value:
'A security vulnerability has been found in Net-SNMP releases that
could allow a denial of service attack against Net-SNMP agents that
have opened a stream based protocol (e.g. TCP but not UDP).  By default,
Net-SNMP does not open a TCP port.
The old stable distribution (woody) does not contain a net-snmp package.
For the stable distribution (sarge) this problem has been fixed in
version 5.1.2-6.2.
');
 script_set_attribute(attribute: 'see_also', value: 
'http://www.debian.org/security/2005/dsa-873');
 script_set_attribute(attribute: 'solution', value: 
'The Debian project recommends that you upgrade your net-snmp package.');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P');
script_end_attributes();

 script_copyright(english: "This script is (C) 2009 Tenable Network Security, Inc.");
 script_name(english: "[DSA873] DSA-873-1 net-snmp");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-873-1 net-snmp");
 exit(0);
}

include("debian_package.inc");

if ( ! get_kb_item("Host/Debian/dpkg-l") ) exit(1, "Could not obtain the list of packages");

deb_check(prefix: 'libsnmp-base', release: '3.1', reference: '5.1.2-6.2');
deb_check(prefix: 'libsnmp-perl', release: '3.1', reference: '5.1.2-6.2');
deb_check(prefix: 'libsnmp5', release: '3.1', reference: '5.1.2-6.2');
deb_check(prefix: 'libsnmp5-dev', release: '3.1', reference: '5.1.2-6.2');
deb_check(prefix: 'snmp', release: '3.1', reference: '5.1.2-6.2');
deb_check(prefix: 'snmpd', release: '3.1', reference: '5.1.2-6.2');
deb_check(prefix: 'tkmib', release: '3.1', reference: '5.1.2-6.2');
deb_check(prefix: 'net-snmp', release: '3.1', reference: '5.1.2-6.2');
if (deb_report_get()) security_warning(port: 0, extra:deb_report_get());
else exit(0, "Host is not affected");
