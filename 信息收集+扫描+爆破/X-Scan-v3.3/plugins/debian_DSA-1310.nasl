# This script was automatically generated from the dsa-1310
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2009 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004-2009 Tenable Network Security, Inc.

if (! defined_func('bn_random')) exit(0);

include('compat.inc');

if (description) {
 script_id(25532);
 script_version("$Revision: 1.5 $");
 script_xref(name: "DSA", value: "1310");
 script_cve_id("CVE-2006-4168");

 script_set_attribute(attribute:'synopsis', value: 
'The remote host is missing the DSA-1310 security update');
 script_set_attribute(attribute: 'description', value:
'A vulnerability has been discovered in libexif, a library to parse EXIF
files, which allows denial of service and possible execution of arbitrary
code via malformed EXIF data.
For the old-stable distribution (sarge), this problem has been fixed
in version 0.6.9-6sarge1.
For the stable distribution (etch), this problem has been fixed in version
0.6.13-5etch1.
');
 script_set_attribute(attribute: 'see_also', value: 
'http://www.debian.org/security/2007/dsa-1310');
 script_set_attribute(attribute: 'solution', value: 
'The Debian project recommends that you upgrade your libexif package.');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P');
script_end_attributes();

 script_copyright(english: "This script is (C) 2009 Tenable Network Security, Inc.");
 script_name(english: "[DSA1310] DSA-1310-1 libexif");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-1310-1 libexif");
 exit(0);
}

include("debian_package.inc");

if ( ! get_kb_item("Host/Debian/dpkg-l") ) exit(1, "Could not obtain the list of packages");

deb_check(prefix: 'libexif-dev', release: '3.1', reference: '0.6.9-6sarge1');
deb_check(prefix: 'libexif10', release: '3.1', reference: '0.6.9-6sarge1');
deb_check(prefix: 'libexif-dev', release: '4.0', reference: '0.6.13-5etch1');
deb_check(prefix: 'libexif12', release: '4.0', reference: '0.6.13-5etch1');
deb_check(prefix: 'libexif', release: '4.0', reference: '0.6.13-5etch1');
if (deb_report_get()) security_warning(port: 0, extra:deb_report_get());
else exit(0, "Host is not affected");
