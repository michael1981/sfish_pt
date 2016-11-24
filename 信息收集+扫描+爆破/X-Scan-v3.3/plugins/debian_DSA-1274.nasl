# This script was automatically generated from the dsa-1274
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2009 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004-2009 Tenable Network Security, Inc.

if (! defined_func('bn_random')) exit(0);

include('compat.inc');

if (description) {
 script_id(25008);
 script_version("$Revision: 1.4 $");
 script_xref(name: "DSA", value: "1274");
 script_cve_id("CVE-2007-1536");
 script_bugtraq_id(23021);

 script_set_attribute(attribute:'synopsis', value: 
'The remote host is missing the DSA-1274 security update');
 script_set_attribute(attribute: 'description', value:
'An integer underflow bug has been found in the file_printf function in
file, a tool to determine file types based analysis of file content.
The bug could allow an attacker to execute arbitrary code by inducing a
local user to examine a specially crafted file that triggers a buffer
overflow.
For the stable distribution (sarge), this problem has been fixed in
version 4.12-1sarge1.
For the upcoming stable distribution (etch), this problem has been fixed in
version 4.17-5etch1.
');
 script_set_attribute(attribute: 'see_also', value: 
'http://www.debian.org/security/2007/dsa-1274');
 script_set_attribute(attribute: 'solution', value: 
'The Debian project recommends that you upgrade your file package.');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C');
script_end_attributes();

 script_copyright(english: "This script is (C) 2009 Tenable Network Security, Inc.");
 script_name(english: "[DSA1274] DSA-1274-1 file");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-1274-1 file");
 exit(0);
}

include("debian_package.inc");

if ( ! get_kb_item("Host/Debian/dpkg-l") ) exit(1, "Could not obtain the list of packages");

deb_check(prefix: 'file', release: '', reference: '4.17-5etch1');
deb_check(prefix: 'libmagic-dev', release: '', reference: '4.17-5etch1');
deb_check(prefix: 'libmagic1', release: '', reference: '4.17-5etch1');
deb_check(prefix: 'python-magic', release: '', reference: '4.17-5etch1');
deb_check(prefix: 'file', release: '3.1', reference: '4.12-1sarge1');
deb_check(prefix: 'libmagic-dev', release: '3.1', reference: '4.12-1sarge1');
deb_check(prefix: 'libmagic1', release: '3.1', reference: '4.12-1sarge1');
deb_check(prefix: 'file', release: '4.0', reference: '4.17-5etch1');
if (deb_report_get()) security_hole(port: 0, extra:deb_report_get());
else exit(0, "Host is not affected");
