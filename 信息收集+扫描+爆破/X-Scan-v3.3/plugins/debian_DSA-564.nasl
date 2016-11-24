# This script was automatically generated from the dsa-564
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2009 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004-2009 Tenable Network Security, Inc.

if (! defined_func('bn_random')) exit(0);

include('compat.inc');

if (description) {
 script_id(15662);
 script_version("$Revision: 1.8 $");
 script_xref(name: "DSA", value: "564");
 script_cve_id("CVE-2004-0805");

 script_set_attribute(attribute:'synopsis', value: 
'The remote host is missing the DSA-564 security update');
 script_set_attribute(attribute: 'description', value:
'Davide Del Vecchio discovered a vulnerability in mpg123, a popular (but
non-free) MPEG layer 1/2/3 audio player.  A malicious MPEG layer 2/3
file could cause the header checks in mpg123 to fail, which could in
turn allow arbitrary code to be executed with the privileges of the
user running mpg123.
For the stable distribution (woody) this problem has been fixed in
version 0.59r-13woody3.
');
 script_set_attribute(attribute: 'see_also', value: 
'http://www.debian.org/security/2004/dsa-564');
 script_set_attribute(attribute: 'solution', value: 
'The Debian project recommends that you upgrade your mpg123 package.');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P');
script_end_attributes();

 script_copyright(english: "This script is (C) 2009 Tenable Network Security, Inc.");
 script_name(english: "[DSA564] DSA-564-1 mpg123");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-564-1 mpg123");
 exit(0);
}

include("debian_package.inc");

if ( ! get_kb_item("Host/Debian/dpkg-l") ) exit(1, "Could not obtain the list of packages");

deb_check(prefix: 'mpg123', release: '3.0', reference: '0.59r-13woody3');
deb_check(prefix: 'mpg123-esd', release: '3.0', reference: '0.59r-13woody3');
deb_check(prefix: 'mpg123-nas', release: '3.0', reference: '0.59r-13woody3');
deb_check(prefix: 'mpg123-oss-3dnow', release: '3.0', reference: '0.59r-13woody3');
deb_check(prefix: 'mpg123-oss-i486', release: '3.0', reference: '0.59r-13woody3');
if (deb_report_get()) security_hole(port: 0, extra:deb_report_get());
else exit(0, "Host is not affected");
