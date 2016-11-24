# This script was automatically generated from the dsa-1178
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2009 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004-2009 Tenable Network Security, Inc.

if (! defined_func('bn_random')) exit(0);

include('compat.inc');

if (description) {
 script_id(22720);
 script_version("$Revision: 1.6 $");
 script_xref(name: "DSA", value: "1178");
 script_cve_id("CVE-2006-3467");

 script_set_attribute(attribute:'synopsis', value: 
'The remote host is missing the DSA-1178 security update');
 script_set_attribute(attribute: 'description', value:
'It was discovered that an integer overflow in freetype\'s PCF font code
may lead to denial of service and potential execution of arbitrary code.
For the stable distribution (sarge) this problem has been fixed in
version 2.1.7-6.
');
 script_set_attribute(attribute: 'see_also', value: 
'http://www.debian.org/security/2006/dsa-1178');
 script_set_attribute(attribute: 'solution', value: 
'The Debian project recommends that you upgrade your freetype package.');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P');
script_end_attributes();

 script_copyright(english: "This script is (C) 2009 Tenable Network Security, Inc.");
 script_name(english: "[DSA1178] DSA-1178-1 freetype");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-1178-1 freetype");
 exit(0);
}

include("debian_package.inc");

if ( ! get_kb_item("Host/Debian/dpkg-l") ) exit(1, "Could not obtain the list of packages");

deb_check(prefix: 'freetype2-demos', release: '3.1', reference: '2.1.7-6');
deb_check(prefix: 'libfreetype6', release: '3.1', reference: '2.1.7-6');
deb_check(prefix: 'libfreetype6-dev', release: '3.1', reference: '2.1.7-6');
deb_check(prefix: 'freetype', release: '3.1', reference: '2.1.7-6');
if (deb_report_get()) security_hole(port: 0, extra:deb_report_get());
else exit(0, "Host is not affected");
