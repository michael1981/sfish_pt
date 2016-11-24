# This script was automatically generated from the dsa-190
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2009 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004-2009 Tenable Network Security, Inc.

if (! defined_func('bn_random')) exit(0);

include('compat.inc');

if (description) {
 script_id(15027);
 script_version("$Revision: 1.8 $");
 script_xref(name: "DSA", value: "190");
 script_cve_id("CVE-2002-1277");

 script_set_attribute(attribute:'synopsis', value: 
'The remote host is missing the DSA-190 security update');
 script_set_attribute(attribute: 'description', value:
'Al Viro found a problem in the image handling code use in Window Maker,
a popular NEXTSTEP like window manager. When creating an image it would
allocate a buffer by multiplying the image width and height, but did not
check for an overflow. This makes it possible to overflow the buffer.
This could be exploited by using specially crafted image files (for
example when previewing themes).
This problem has been fixed in version 0.80.0-4.1 for the current stable
distribution (woody).  Packages for the mipsel architecture are not yet
available.
');
 script_set_attribute(attribute: 'see_also', value: 
'http://www.debian.org/security/2002/dsa-190');
 script_set_attribute(attribute: 'solution', value: 
'Read http://www.debian.org/security/2002/dsa-190
and install the recommended updated packages.');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P');
script_end_attributes();

 script_copyright(english: "This script is (C) 2009 Tenable Network Security, Inc.");
 script_name(english: "[DSA190] DSA-190-1 wmaker");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-190-1 wmaker");
 exit(0);
}

include("debian_package.inc");

if ( ! get_kb_item("Host/Debian/dpkg-l") ) exit(1, "Could not obtain the list of packages");

deb_check(prefix: 'libwings-dev', release: '3.0', reference: '0.80.0-4.1');
deb_check(prefix: 'libwmaker0-dev', release: '3.0', reference: '0.80.0-4.1');
deb_check(prefix: 'libwraster2', release: '3.0', reference: '0.80.0-4.1');
deb_check(prefix: 'libwraster2-dev', release: '3.0', reference: '0.80.0-4.1');
deb_check(prefix: 'wmaker', release: '3.0', reference: '0.80.0-4.1');
if (deb_report_get()) security_hole(port: 0, extra:deb_report_get());
else exit(0, "Host is not affected");
