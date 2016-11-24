# This script was automatically generated from the dsa-763
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2009 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004-2009 Tenable Network Security, Inc.

if (! defined_func('bn_random')) exit(0);

include('compat.inc');

if (description) {
 script_id(19257);
 script_version("$Revision: 1.7 $");
 script_xref(name: "DSA", value: "763");
 script_cve_id("CVE-2005-1849");

 script_set_attribute(attribute:'synopsis', value: 
'The remote host is missing the DSA-763 security update');
 script_set_attribute(attribute: 'description', value:
'Markus Oberhumer discovered a flaw in the way zlib, a library used for
file compression and decompression, handles invalid input. This flaw can
cause programs which use zlib to crash when opening an invalid file.
This problem does not affect the old stable distribution (woody).
For the current stable distribution (sarge), this problem has been fixed
in version 1.2.2-4.sarge.2.
');
 script_set_attribute(attribute: 'see_also', value: 
'http://www.debian.org/security/2005/dsa-763');
 script_set_attribute(attribute: 'solution', value: 
'The Debian project recommends that you upgrade your zlib package.');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P');
script_end_attributes();

 script_copyright(english: "This script is (C) 2009 Tenable Network Security, Inc.");
 script_name(english: "[DSA763] DSA-763-1 zlib");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-763-1 zlib");
 exit(0);
}

include("debian_package.inc");

if ( ! get_kb_item("Host/Debian/dpkg-l") ) exit(1, "Could not obtain the list of packages");

deb_check(prefix: 'lib64z1', release: '3.1', reference: '1.2.2-4.sarge.2');
deb_check(prefix: 'lib64z1-dev', release: '3.1', reference: '1.2.2-4.sarge.2');
deb_check(prefix: 'zlib-bin', release: '3.1', reference: '1.2.2-4.sarge.2');
deb_check(prefix: 'zlib1g', release: '3.1', reference: '1.2.2-4.sarge.2');
deb_check(prefix: 'zlib1g-dev', release: '3.1', reference: '1.2.2-4.sarge.2');
deb_check(prefix: 'zlib', release: '3.1', reference: '1.2.2-4.sarge.2');
if (deb_report_get()) security_warning(port: 0, extra:deb_report_get());
else exit(0, "Host is not affected");
