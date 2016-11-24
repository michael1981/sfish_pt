# This script was automatically generated from the dsa-1761
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2009 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004-2009 Tenable Network Security, Inc.

if (! defined_func('bn_random')) exit(0);

include('compat.inc');

if (description) {
 script_id(36084);
 script_version("$Revision: 1.2 $");
 script_xref(name: "DSA", value: "1761");
 script_cve_id("CVE-2009-1171");

 script_set_attribute(attribute:'synopsis', value: 
'The remote host is missing the DSA-1761 security update');
 script_set_attribute(attribute: 'description', value:
'Christian J. Eibl discovered that the TeX filter of Moodle, a web-based
course management system, doesn\'t check user input for certain TeX commands
which allows an attacker to include and display the content of arbitrary system
files.
Note that this doesn\'t affect installations that only use the mimetex
environment.
For the oldstable distribution (etch), this problem has been fixed in
version 1.6.3-2+etch3.
For the stable distribution (lenny), this problem has been fixed in
version 1.8.2.dfsg-3+lenny2.
');
 script_set_attribute(attribute: 'see_also', value: 
'http://www.debian.org/security/2009/dsa-1761');
 script_set_attribute(attribute: 'solution', value: 
'The Debian project recommends that you upgrade your moodle packages.');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:M/Au:N/C:P/I:N/A:N');
script_end_attributes();

 script_copyright(english: "This script is (C) 2009 Tenable Network Security, Inc.");
 script_name(english: "[DSA1761] DSA-1761-1 moodle");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-1761-1 moodle");
 exit(0);
}

include("debian_package.inc");

if ( ! get_kb_item("Host/Debian/dpkg-l") ) exit(1, "Could not obtain the list of packages");

deb_check(prefix: 'moodle', release: '4.0', reference: '1.6.3-2+etch3');
deb_check(prefix: 'moodle', release: '5.0', reference: '1.8.2.dfsg-3+lenny2');
if (deb_report_get()) security_warning(port: 0, extra:deb_report_get());
else exit(0, "Host is not affected");
