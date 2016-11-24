# This script was automatically generated from the dsa-1260
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2009 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004-2009 Tenable Network Security, Inc.

if (! defined_func('bn_random')) exit(0);

include('compat.inc');

if (description) {
 script_id(24347);
 script_version("$Revision: 1.6 $");
 script_xref(name: "DSA", value: "1260");
 script_cve_id("CVE-2007-0770");

 script_set_attribute(attribute:'synopsis', value: 
'The remote host is missing the DSA-1260 security update');
 script_set_attribute(attribute: 'description', value:
'Vladimir Nadvornik discovered that the fix for a vulnerability in the
PALM decoder of Imagemagick, a collection of image manipulation programs,
was ineffective. To avoid confusion a new CVE ID has been assigned;
the original issue was tracked as CVE-2006-5456.
For the stable distribution (sarge) this problem has been fixed in
version 6:6.0.6.2-2.9.
For the upcoming stable distribution (etch) this problem has been
fixed in version 7:6.2.4.5.dfsg1-0.14.
');
 script_set_attribute(attribute: 'see_also', value: 
'http://www.debian.org/security/2007/dsa-1260');
 script_set_attribute(attribute: 'solution', value: 
'The Debian project recommends that you upgrade your imagemagick packages.');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C');
script_end_attributes();

 script_copyright(english: "This script is (C) 2009 Tenable Network Security, Inc.");
 script_name(english: "[DSA1260] DSA-1260-1 imagemagick");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-1260-1 imagemagick");
 exit(0);
}

include("debian_package.inc");

if ( ! get_kb_item("Host/Debian/dpkg-l") ) exit(1, "Could not obtain the list of packages");

deb_check(prefix: 'imagemagick', release: '3.1', reference: '6.0.6.2-2.9');
deb_check(prefix: 'libmagick6', release: '3.1', reference: '6.0.6.2-2.9');
deb_check(prefix: 'libmagick6-dev', release: '3.1', reference: '6.0.6.2-2.9');
deb_check(prefix: 'perlmagick', release: '3.1', reference: '6.0.6.2-2.9');
deb_check(prefix: 'imagemagick', release: '4.0', reference: '6.2.4.5.dfsg1-0.14');
if (deb_report_get()) security_hole(port: 0, extra:deb_report_get());
else exit(0, "Host is not affected");
