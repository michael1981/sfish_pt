# This script was automatically generated from the dsa-1762
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2009 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004-2009 Tenable Network Security, Inc.

if (! defined_func('bn_random')) exit(0);

include('compat.inc');

if (description) {
 script_id(36076);
 script_version("$Revision: 1.3 $");
 script_xref(name: "DSA", value: "1762");
 script_cve_id("CVE-2008-1036");

 script_set_attribute(attribute:'synopsis', value: 
'The remote host is missing the DSA-1762 security update');
 script_set_attribute(attribute: 'description', value:
'It was discovered that icu, the internal components for Unicode, did
not properly sanitise invalid encoded data, which could lead to crosssite scripting attacks.
For the oldstable distribution (etch), this problem has been fixed in
version 3.6-2etch2.
For the stable distribution (lenny), this problem has been fixed in
version 3.8.1-3+lenny1.
');
 script_set_attribute(attribute: 'see_also', value: 
'http://www.debian.org/security/2009/dsa-1762');
 script_set_attribute(attribute: 'solution', value: 
'The Debian project recommends that you upgrade your icu packages.');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N');
script_end_attributes();

 script_copyright(english: "This script is (C) 2009 Tenable Network Security, Inc.");
 script_name(english: "[DSA1762] DSA-1762-1 icu");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-1762-1 icu");
 exit(0);
}

include("debian_package.inc");

if ( ! get_kb_item("Host/Debian/dpkg-l") ) exit(1, "Could not obtain the list of packages");

deb_check(prefix: 'icu-doc', release: '4.0', reference: '3.6-2etch2');
deb_check(prefix: 'libicu36', release: '4.0', reference: '3.6-2etch2');
deb_check(prefix: 'libicu36-dev', release: '4.0', reference: '3.6-2etch2');
deb_check(prefix: 'icu-doc', release: '5.0', reference: '3.8.1-3+lenny1');
deb_check(prefix: 'lib32icu-dev', release: '5.0', reference: '3.8.1-3+lenny1');
deb_check(prefix: 'lib32icu38', release: '5.0', reference: '3.8.1-3+lenny1');
deb_check(prefix: 'libicu-dev', release: '5.0', reference: '3.8.1-3+lenny1');
deb_check(prefix: 'libicu38', release: '5.0', reference: '3.8.1-3+lenny1');
deb_check(prefix: 'libicu38-dbg', release: '5.0', reference: '3.8.1-3+lenny1');
deb_check(prefix: 'icu', release: '4.0', reference: '3.6-2etch2');
deb_check(prefix: 'icu', release: '5.0', reference: '3.8.1-3+lenny1');
if (deb_report_get()) security_warning(port: 0, extra:deb_report_get());
else exit(0, "Host is not affected");
