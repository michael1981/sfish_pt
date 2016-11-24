# This script was automatically generated from the dsa-593
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2009 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004-2009 Tenable Network Security, Inc.

if (! defined_func('bn_random')) exit(0);

include('compat.inc');

if (description) {
 script_id(15728);
 script_version("$Revision: 1.8 $");
 script_xref(name: "DSA", value: "593");
 script_cve_id("CVE-2004-0981");

 script_set_attribute(attribute:'synopsis', value: 
'The remote host is missing the DSA-593 security update');
 script_set_attribute(attribute: 'description', value:
'A vulnerability has been reported for ImageMagick, a commonly used
image manipulation library.  Due to a boundary error within the EXIF
parsing routine, a specially crafted graphic image could lead to the
execution of arbitrary code.
For the stable distribution (woody) this problem has been fixed in
version 5.4.4.5-1woody4.
');
 script_set_attribute(attribute: 'see_also', value: 
'http://www.debian.org/security/2004/dsa-593');
 script_set_attribute(attribute: 'solution', value: 
'The Debian project recommends that you upgrade your imagemagick packages.');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C');
script_end_attributes();

 script_copyright(english: "This script is (C) 2009 Tenable Network Security, Inc.");
 script_name(english: "[DSA593] DSA-593-1 imagemagick");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-593-1 imagemagick");
 exit(0);
}

include("debian_package.inc");

if ( ! get_kb_item("Host/Debian/dpkg-l") ) exit(1, "Could not obtain the list of packages");

deb_check(prefix: 'imagemagick', release: '3.0', reference: '5.4.4.5-1woody4');
deb_check(prefix: 'libmagick5', release: '3.0', reference: '5.4.4.5-1woody4');
deb_check(prefix: 'libmagick5-dev', release: '3.0', reference: '5.4.4.5-1woody4');
deb_check(prefix: 'perlmagick', release: '3.0', reference: '5.4.4.5-1woody4');
if (deb_report_get()) security_hole(port: 0, extra:deb_report_get());
else exit(0, "Host is not affected");
