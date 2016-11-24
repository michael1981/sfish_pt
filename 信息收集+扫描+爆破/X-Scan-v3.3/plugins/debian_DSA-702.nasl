# This script was automatically generated from the dsa-702
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2009 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004-2009 Tenable Network Security, Inc.

if (! defined_func('bn_random')) exit(0);

include('compat.inc');

if (description) {
 script_id(17673);
 script_version("$Revision: 1.8 $");
 script_xref(name: "DSA", value: "702");
 script_cve_id("CVE-2005-0397", "CVE-2005-0759", "CVE-2005-0760", "CVE-2005-0762");
 script_bugtraq_id(12875);

 script_set_attribute(attribute:'synopsis', value: 
'The remote host is missing the DSA-702 security update');
 script_set_attribute(attribute: 'description', value:
'Several vulnerabilities have been discovered in ImageMagick, a
commonly used image manipulation library.  These problems can be
exploited by a carefully crafted graphic image.  The Common
Vulnerabilities and Exposures project identifies the following
problems:
    Tavis Ormandy discovered a format string vulnerability in the
    filename handling code which allows a remote attacker to cause a
    denial of service and possibly execute arbitrary code.
    Andrei Nigmatulin discovered a denial of service condition which
    can be caused by an invalid tag in a TIFF image.
    Andrei Nigmatulin discovered that the TIFF decoder is vulnerable
    to accessing memory out of bounds which will result in a
    segmentation fault.
    Andrei Nigmatulin discovered a buffer overflow in the SGI parser
    which allows a remote attacker to execute arbitrary code via a
    specially crafted SGI image file.
For the stable distribution (woody) these problems have been fixed in
version 5.4.4.5-1woody6.
');
 script_set_attribute(attribute: 'see_also', value: 
'http://www.debian.org/security/2005/dsa-702');
 script_set_attribute(attribute: 'solution', value: 
'The Debian project recommends that you upgrade your imagemagick package.');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P');
script_end_attributes();

 script_copyright(english: "This script is (C) 2009 Tenable Network Security, Inc.");
 script_name(english: "[DSA702] DSA-702-1 imagemagick");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-702-1 imagemagick");
 exit(0);
}

include("debian_package.inc");

if ( ! get_kb_item("Host/Debian/dpkg-l") ) exit(1, "Could not obtain the list of packages");

deb_check(prefix: 'imagemagick', release: '3.0', reference: '5.4.4.5-1woody6');
deb_check(prefix: 'libmagick5', release: '3.0', reference: '5.4.4.5-1woody6');
deb_check(prefix: 'libmagick5-dev', release: '3.0', reference: '5.4.4.5-1woody6');
deb_check(prefix: 'perlmagick', release: '3.0', reference: '5.4.4.5-1woody6');
if (deb_report_get()) security_hole(port: 0, extra:deb_report_get());
else exit(0, "Host is not affected");
