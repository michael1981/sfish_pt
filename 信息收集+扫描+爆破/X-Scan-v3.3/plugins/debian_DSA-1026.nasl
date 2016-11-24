# This script was automatically generated from the dsa-1026
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2009 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004-2009 Tenable Network Security, Inc.

if (! defined_func('bn_random')) exit(0);

include('compat.inc');

if (description) {
 script_id(22568);
 script_version("$Revision: 1.6 $");
 script_xref(name: "DSA", value: "1026");
 script_cve_id("CVE-2005-1849", "CVE-2005-2096");

 script_set_attribute(attribute:'synopsis', value: 
'The remote host is missing the DSA-1026 security update');
 script_set_attribute(attribute: 'description', value:
'Markus Oberhumer discovered a flaw in the way zlib, a library used for
file compression and decompression, handles invalid input. This flaw can
cause programs which use zlib to crash when opening an invalid file.
A further error in the way zlib handles the inflation of certain
compressed files can cause a program which uses zlib to crash when opening
an invalid file.
sash, the stand-alone shell, links statically against zlib, and was
thus affected by these problems.
The old stable distribution (woody) isn\'t affected by these problems.
For the stable distribution (sarge) these problems have been fixed in
version 3.7-5sarge1.
');
 script_set_attribute(attribute: 'see_also', value: 
'http://www.debian.org/security/2006/dsa-1026');
 script_set_attribute(attribute: 'solution', value: 
'The Debian project recommends that you upgrade your sash package.');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P');
script_end_attributes();

 script_copyright(english: "This script is (C) 2009 Tenable Network Security, Inc.");
 script_name(english: "[DSA1026] DSA-1026-1 sash");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-1026-1 sash");
 exit(0);
}

include("debian_package.inc");

if ( ! get_kb_item("Host/Debian/dpkg-l") ) exit(1, "Could not obtain the list of packages");

deb_check(prefix: 'sash', release: '3.1', reference: '3.7-5sarge1');
if (deb_report_get()) security_hole(port: 0, extra:deb_report_get());
else exit(0, "Host is not affected");
