# This script was automatically generated from the dsa-621
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2009 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004-2009 Tenable Network Security, Inc.

if (! defined_func('bn_random')) exit(0);

include('compat.inc');

if (description) {
 script_id(16074);
 script_version("$Revision: 1.8 $");
 script_xref(name: "DSA", value: "621");
 script_cve_id("CVE-2004-1125");

 script_set_attribute(attribute:'synopsis', value: 
'The remote host is missing the DSA-621 security update');
 script_set_attribute(attribute: 'description', value:
'An iDEFENSE security researcher discovered a buffer overflow in xpdf,
the Portable Document Format (PDF) suite.  Similar code is present in
the PDF processing part of CUPS.  A maliciously crafted PDF file could
exploit this problem, leading to the execution of arbitrary code.
For the stable distribution (woody) this problem has been fixed in
version 1.1.14-5woody11.
');
 script_set_attribute(attribute: 'see_also', value: 
'http://www.debian.org/security/2004/dsa-621');
 script_set_attribute(attribute: 'solution', value: 
'The Debian project recommends that you upgrade your cupsys packages.');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C');
script_end_attributes();

 script_copyright(english: "This script is (C) 2009 Tenable Network Security, Inc.");
 script_name(english: "[DSA621] DSA-621-1 cupsys");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-621-1 cupsys");
 exit(0);
}

include("debian_package.inc");

if ( ! get_kb_item("Host/Debian/dpkg-l") ) exit(1, "Could not obtain the list of packages");

deb_check(prefix: 'cupsys', release: '3.0', reference: '1.1.14-5woody11');
deb_check(prefix: 'cupsys-bsd', release: '3.0', reference: '1.1.14-5woody11');
deb_check(prefix: 'cupsys-client', release: '3.0', reference: '1.1.14-5woody11');
deb_check(prefix: 'cupsys-pstoraster', release: '3.0', reference: '1.1.14-5woody11');
deb_check(prefix: 'libcupsys2', release: '3.0', reference: '1.1.14-5woody11');
deb_check(prefix: 'libcupsys2-dev', release: '3.0', reference: '1.1.14-5woody11');
if (deb_report_get()) security_hole(port: 0, extra:deb_report_get());
else exit(0, "Host is not affected");
