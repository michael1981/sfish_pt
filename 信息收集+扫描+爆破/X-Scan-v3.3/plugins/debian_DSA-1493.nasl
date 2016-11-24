# This script was automatically generated from the dsa-1493
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2009 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004-2009 Tenable Network Security, Inc.

if (! defined_func('bn_random')) exit(0);

include('compat.inc');

if (description) {
 script_id(30232);
 script_version("$Revision: 1.6 $");
 script_xref(name: "DSA", value: "1493");
 script_cve_id("CVE-2007-6697", "CVE-2008-0544");

 script_set_attribute(attribute:'synopsis', value: 
'The remote host is missing the DSA-1493 security update');
 script_set_attribute(attribute: 'description', value:
'Several local/remote vulnerabilities have been discovered in the image
loading library for the Simple DirectMedia Layer 1.2. The Common
Vulnerabilities and Exposures project identifies the following problems:
CVE-2007-6697
    Gynvael Coldwind discovered a buffer overflow in GIF image parsing,
    which could result in denial of service and potentially the
    execution of arbitrary code.
CVE-2008-0544
    It was discovered that a buffer overflow in IFF ILBM image parsing
    could result in denial of service and potentially the execution of
    arbitrary code.
For the old stable distribution (sarge), these problems have been fixed
in version 1.2.4-1etch1. Due to a copy &amp; paste error <q>etch1</q> was appended
to the version number instead of <q>sarge1</q>. Since the update is otherwise
technically correct, the update was not rebuilt on the buildd network.
For the stable distribution (etch), these problems have been fixed in
version 1.2.5-2+etch1.
');
 script_set_attribute(attribute: 'see_also', value: 
'http://www.debian.org/security/2008/dsa-1493');
 script_set_attribute(attribute: 'solution', value: 
'The Debian project recommends that you upgrade your sdl-image1.');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C');
script_end_attributes();

 script_copyright(english: "This script is (C) 2009 Tenable Network Security, Inc.");
 script_name(english: "[DSA1493] DSA-1493-2 sdl-image1.2");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-1493-2 sdl-image1.2");
 exit(0);
}

include("debian_package.inc");

if ( ! get_kb_item("Host/Debian/dpkg-l") ) exit(1, "Could not obtain the list of packages");

deb_check(prefix: 'libsdl-image1.2', release: '3.1', reference: '1.2.4-1etch1');
deb_check(prefix: 'libsdl-image1.2-dev', release: '3.1', reference: '1.2.4-1etch1');
deb_check(prefix: 'libsdl-image1.2', release: '4.0', reference: '1.2.5-2+etch1');
deb_check(prefix: 'libsdl-image1.2-dev', release: '4.0', reference: '1.2.5-2+etch1');
deb_check(prefix: 'sdl-image1.2', release: '4.0', reference: '1.2.5-2+etch1');
if (deb_report_get()) security_hole(port: 0, extra:deb_report_get());
else exit(0, "Host is not affected");
