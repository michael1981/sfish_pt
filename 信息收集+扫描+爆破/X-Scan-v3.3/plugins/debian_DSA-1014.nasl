# This script was automatically generated from the dsa-1014
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2009 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004-2009 Tenable Network Security, Inc.

if (! defined_func('bn_random')) exit(0);

include('compat.inc');

if (description) {
 script_id(22556);
 script_version("$Revision: 1.6 $");
 script_xref(name: "DSA", value: "1014");
 script_cve_id("CVE-2004-2043");
 script_bugtraq_id(10446);

 script_set_attribute(attribute:'synopsis', value: 
'The remote host is missing the DSA-1014 security update');
 script_set_attribute(attribute: 'description', value:
'Aviram Jenik and Damyan Ivanov discovered a buffer overflow in
firebird2, an RDBMS based on InterBase 6.0 code, that allows remote
attackers to crash.
The old stable distribution (woody) does not contain firebird2 packages.
For the stable distribution (sarge) this problem has been fixed in
version 1.5.1-4sarge1.
');
 script_set_attribute(attribute: 'see_also', value: 
'http://www.debian.org/security/2006/dsa-1014');
 script_set_attribute(attribute: 'solution', value: 
'The Debian project recommends that you upgrade your firebird2 packages.');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P');
script_end_attributes();

 script_copyright(english: "This script is (C) 2009 Tenable Network Security, Inc.");
 script_name(english: "[DSA1014] DSA-1014-1 firebird2");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-1014-1 firebird2");
 exit(0);
}

include("debian_package.inc");

if ( ! get_kb_item("Host/Debian/dpkg-l") ) exit(1, "Could not obtain the list of packages");

deb_check(prefix: 'firebird2-classic-server', release: '3.1', reference: '1.5.1-4sarge1');
deb_check(prefix: 'firebird2-dev', release: '3.1', reference: '1.5.1-4sarge1');
deb_check(prefix: 'firebird2-examples', release: '3.1', reference: '1.5.1-4sarge1');
deb_check(prefix: 'firebird2-server-common', release: '3.1', reference: '1.5.1-4sarge1');
deb_check(prefix: 'firebird2-super-server', release: '3.1', reference: '1.5.1-4sarge1');
deb_check(prefix: 'firebird2-utils-classic', release: '3.1', reference: '1.5.1-4sarge1');
deb_check(prefix: 'firebird2-utils-super', release: '3.1', reference: '1.5.1-4sarge1');
deb_check(prefix: 'libfirebird2-classic', release: '3.1', reference: '1.5.1-4sarge1');
deb_check(prefix: 'libfirebird2-super', release: '3.1', reference: '1.5.1-4sarge1');
deb_check(prefix: 'firebird2', release: '3.1', reference: '1.5.1-4sarge1');
if (deb_report_get()) security_warning(port: 0, extra:deb_report_get());
else exit(0, "Host is not affected");
