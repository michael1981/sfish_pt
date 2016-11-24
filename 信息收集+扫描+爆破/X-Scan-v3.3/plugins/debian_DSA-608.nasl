# This script was automatically generated from the dsa-608
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2009 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004-2009 Tenable Network Security, Inc.

if (! defined_func('bn_random')) exit(0);

include('compat.inc');

if (description) {
 script_id(15953);
 script_version("$Revision: 1.8 $");
 script_xref(name: "DSA", value: "608");
 script_cve_id("CVE-2004-0999", "CVE-2004-1095");
 script_bugtraq_id(11556);

 script_set_attribute(attribute:'synopsis', value: 
'The remote host is missing the DSA-608 security update');
 script_set_attribute(attribute: 'description', value:
'Several vulnerabilities have been discovered in zgv, an SVGAlib
graphics viewer for the i386 architecture.  The Common Vulnerabilities
and Exposures Project identifies the following problems:
    "infamous41md" discovered multiple
    integer overflows in zgv.  Remote exploitation of an integer
    overflow vulnerability could allow the execution of arbitrary
    code.
    Mikulas Patocka discovered that malicious multiple-image (e.g.
    animated) GIF images can cause a segmentation fault in zgv.
For the stable distribution (woody) these problems have been fixed in
version 5.5-3woody1.
');
 script_set_attribute(attribute: 'see_also', value: 
'http://www.debian.org/security/2004/dsa-608');
 script_set_attribute(attribute: 'solution', value: 
'The Debian project recommends that you upgrade your zgv package immediately.');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C');
script_end_attributes();

 script_copyright(english: "This script is (C) 2009 Tenable Network Security, Inc.");
 script_name(english: "[DSA608] DSA-608-1 zgv");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-608-1 zgv");
 exit(0);
}

include("debian_package.inc");

if ( ! get_kb_item("Host/Debian/dpkg-l") ) exit(1, "Could not obtain the list of packages");

deb_check(prefix: 'zgv', release: '3.0', reference: '5.5-3woody2');
deb_check(prefix: 'zgv', release: '3.0', reference: '5.5-3woody1');
if (deb_report_get()) security_hole(port: 0, extra:deb_report_get());
else exit(0, "Host is not affected");
