# This script was automatically generated from the dsa-740
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2009 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004-2009 Tenable Network Security, Inc.

if (! defined_func('bn_random')) exit(0);

include('compat.inc');

if (description) {
 script_id(18632);
 script_version("$Revision: 1.7 $");
 script_xref(name: "DSA", value: "740");
 script_cve_id("CVE-2005-2096");

 script_set_attribute(attribute:'synopsis', value: 
'The remote host is missing the DSA-740 security update');
 script_set_attribute(attribute: 'description', value:
'An error in the way zlib handles the inflation of certain compressed
files can cause a program which uses zlib to crash when opening an
invalid file. 
This problem does not affect the old stable distribution (woody).
For the stable distribution (sarge), this problem has been fixed in
version 1.2.2-4.sarge.1.
');
 script_set_attribute(attribute: 'see_also', value: 
'http://www.debian.org/security/2005/dsa-740');
 script_set_attribute(attribute: 'solution', value: 
'The Debian project recommends that you upgrade your zlib package.');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P');
script_end_attributes();

 script_copyright(english: "This script is (C) 2009 Tenable Network Security, Inc.");
 script_name(english: "[DSA740] DSA-740-1 zlib");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-740-1 zlib");
 exit(0);
}

include("debian_package.inc");

if ( ! get_kb_item("Host/Debian/dpkg-l") ) exit(1, "Could not obtain the list of packages");

deb_check(prefix: 'lib64z1', release: '3.1', reference: '1.2.2-4.sarge.1');
deb_check(prefix: 'lib64z1-dev', release: '3.1', reference: '1.2.2-4.sarge.1');
deb_check(prefix: 'zlib-bin', release: '3.1', reference: '1.2.2-4.sarge.1');
deb_check(prefix: 'zlib1g', release: '3.1', reference: '1.2.2-4.sarge.1');
deb_check(prefix: 'zlib1g-dev', release: '3.1', reference: '1.2.2-4.sarge.1');
deb_check(prefix: 'zlib', release: '3.1', reference: '1.2.2-4.sarge.1');
if (deb_report_get()) security_hole(port: 0, extra:deb_report_get());
else exit(0, "Host is not affected");
