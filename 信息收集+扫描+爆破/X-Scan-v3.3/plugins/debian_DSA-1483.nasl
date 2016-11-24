# This script was automatically generated from the dsa-1483
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2009 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004-2009 Tenable Network Security, Inc.

if (! defined_func('bn_random')) exit(0);

include('compat.inc');

if (description) {
 script_id(30223);
 script_version("$Revision: 1.4 $");
 script_xref(name: "DSA", value: "1483");
 script_cve_id("CVE-2007-5846");

 script_set_attribute(attribute:'synopsis', value: 
'The remote host is missing the DSA-1483 security update');
 script_set_attribute(attribute: 'description', value:
'The SNMP agent (snmp_agent.c) in net-snmp before 5.4.1 allows remote
attackers to cause a denial of service (CPU and memory consumption)
via a GETBULK request with a large max-repeaters value.
For the stable distribution (etch), this problem has been fixed in
version 5.2.3-7etch2.
For the unstable and testing distributions (sid and lenny,
respectively), this problem has been fixed in version 5.4.1~dfsg-2.
');
 script_set_attribute(attribute: 'see_also', value: 
'http://www.debian.org/security/2008/dsa-1483');
 script_set_attribute(attribute: 'solution', value: 
'The Debian project recommends that you upgrade your net-snmp package.');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C');
script_end_attributes();

 script_copyright(english: "This script is (C) 2009 Tenable Network Security, Inc.");
 script_name(english: "[DSA1483] DSA-1483-1 net-snmp");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-1483-1 net-snmp");
 exit(0);
}

include("debian_package.inc");

if ( ! get_kb_item("Host/Debian/dpkg-l") ) exit(1, "Could not obtain the list of packages");

deb_check(prefix: 'libsnmp-base', release: '4.0', reference: '5.2.3-7etch2');
deb_check(prefix: 'libsnmp-perl', release: '4.0', reference: '5.2.3-7etch2');
deb_check(prefix: 'libsnmp9', release: '4.0', reference: '5.2.3-7etch2');
deb_check(prefix: 'libsnmp9-dev', release: '4.0', reference: '5.2.3-7etch2');
deb_check(prefix: 'snmp', release: '4.0', reference: '5.2.3-7etch2');
deb_check(prefix: 'snmpd', release: '4.0', reference: '5.2.3-7etch2');
deb_check(prefix: 'tkmib', release: '4.0', reference: '5.2.3-7etch2');
deb_check(prefix: 'net-snmp', release: '4.0', reference: '5.2.3-7etch2');
if (deb_report_get()) security_hole(port: 0, extra:deb_report_get());
else exit(0, "Host is not affected");
