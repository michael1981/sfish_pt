# This script was automatically generated from the dsa-1013
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2009 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004-2009 Tenable Network Security, Inc.

if (! defined_func('bn_random')) exit(0);

include('compat.inc');

if (description) {
 script_id(22555);
 script_version("$Revision: 1.6 $");
 script_xref(name: "DSA", value: "1013");
 script_cve_id("CVE-2006-0050");

 script_set_attribute(attribute:'synopsis', value: 
'The remote host is missing the DSA-1013 security update');
 script_set_attribute(attribute: 'description', value:
'Will Aoki discovered that snmptrapfmt, a configurable snmp trap
handler daemon for snmpd, does not prevent overwriting existing files
when writing to a temporary log file.
For the old stable distribution (woody) this problem has been fixed in
version 1.03woody1.
For the stable distribution (sarge) this problem has been fixed in
version 1.08sarge1.
');
 script_set_attribute(attribute: 'see_also', value: 
'http://www.debian.org/security/2006/dsa-1013');
 script_set_attribute(attribute: 'solution', value: 
'The Debian project recommends that you upgrade your snmptrapfmt package.');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:L/AC:H/Au:N/C:N/I:P/A:N');
script_end_attributes();

 script_copyright(english: "This script is (C) 2009 Tenable Network Security, Inc.");
 script_name(english: "[DSA1013] DSA-1013-1 snmptrapfmt");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-1013-1 snmptrapfmt");
 exit(0);
}

include("debian_package.inc");

if ( ! get_kb_item("Host/Debian/dpkg-l") ) exit(1, "Could not obtain the list of packages");

deb_check(prefix: 'snmptrapfmt', release: '3.0', reference: '1.03woody1');
deb_check(prefix: 'snmptrapfmt', release: '3.1', reference: '1.08sarge1');
if (deb_report_get()) security_note(port: 0, extra:deb_report_get());
else exit(0, "Host is not affected");
