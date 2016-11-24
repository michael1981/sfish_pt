# This script was automatically generated from the dsa-547
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2009 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004-2009 Tenable Network Security, Inc.

if (! defined_func('bn_random')) exit(0);

include('compat.inc');

if (description) {
 script_id(15384);
 script_version("$Revision: 1.11 $");
 script_xref(name: "DSA", value: "547");
 script_cve_id("CVE-2004-0827");

 script_set_attribute(attribute:'synopsis', value: 
'The remote host is missing the DSA-547 security update');
 script_set_attribute(attribute: 'description', value:
'Marcus Meissner from SUSE has discovered several buffer overflows in
the ImageMagick graphics library.  An attacker could create a
malicious image or video file in AVI, BMP, or DIB format that could
crash the reading process.  It might be possible that carefully
crafted images could also allow to execute arbitrary code with the
capabilities of the invoking process.
For the stable distribution (woody) this problem has been fixed in
version 5.4.4.5-1woody3.
');
 script_set_attribute(attribute: 'see_also', value: 
'http://www.debian.org/security/2004/dsa-547');
 script_set_attribute(attribute: 'solution', value: 
'The Debian project recommends that you upgrade your imagemagick packages.');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P');
script_end_attributes();

 script_copyright(english: "This script is (C) 2009 Tenable Network Security, Inc.");
 script_name(english: "[DSA547] DSA-547-1 imagemagick");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-547-1 imagemagick");
 exit(0);
}

include("debian_package.inc");

if ( ! get_kb_item("Host/Debian/dpkg-l") ) exit(1, "Could not obtain the list of packages");

deb_check(prefix: 'imagemagick', release: '3.0', reference: '5.4.4.5-1woody3');
deb_check(prefix: 'libmagick5', release: '3.0', reference: '5.4.4.5-1woody3');
deb_check(prefix: 'libmagick5-dev', release: '3.0', reference: '5.4.4.5-1woody3');
deb_check(prefix: 'perlmagick', release: '3.0', reference: '5.4.4.5-1woody3');
if (deb_report_get()) security_hole(port: 0, extra:deb_report_get());
else exit(0, "Host is not affected");
