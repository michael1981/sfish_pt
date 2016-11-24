# This script was automatically generated from the dsa-676
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2009 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004-2009 Tenable Network Security, Inc.

if (! defined_func('bn_random')) exit(0);

include('compat.inc');

if (description) {
 script_id(16380);
 script_version("$Revision: 1.6 $");
 script_xref(name: "DSA", value: "676");
 script_cve_id("CVE-2005-0074");

 script_set_attribute(attribute:'synopsis', value: 
'The remote host is missing the DSA-676 security update');
 script_set_attribute(attribute: 'description', value:
'Erik Sjölund discovered a buffer overflow in pcdsvgaview, an SVGA
PhotoCD viewer.  xpcd-svga is part of xpcd and uses svgalib to display
graphics on the Linux console for which root permissions are required.
A malicious user could overflow a fixed-size buffer and may cause the
program to execute arbitrary code with elevated privileges.
For the stable distribution (woody) this problem has been fixed in
version 2.08-8woody3.
');
 script_set_attribute(attribute: 'see_also', value: 
'http://www.debian.org/security/2005/dsa-676');
 script_set_attribute(attribute: 'solution', value: 
'The Debian project recommends that you upgrade your xpcd-svga package immediately.');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C');
script_end_attributes();

 script_copyright(english: "This script is (C) 2009 Tenable Network Security, Inc.");
 script_name(english: "[DSA676] DSA-676-1 xpcd");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-676-1 xpcd");
 exit(0);
}

include("debian_package.inc");

if ( ! get_kb_item("Host/Debian/dpkg-l") ) exit(1, "Could not obtain the list of packages");

deb_check(prefix: 'xpcd', release: '3.0', reference: '2.08-8woody3');
deb_check(prefix: 'xpcd-gimp', release: '3.0', reference: '2.08-8woody3');
deb_check(prefix: 'xpcd-svga', release: '3.0', reference: '2.08-8woody3');
if (deb_report_get()) security_hole(port: 0, extra:deb_report_get());
else exit(0, "Host is not affected");
