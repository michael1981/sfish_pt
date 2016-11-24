# This script was automatically generated from the 849-1 Ubuntu Security Notice
# It is released under the Nessus Script Licence.
# Ubuntu Security Notices are (C) 2005 Canonical, Inc.
# USN2nasl Convertor is (C) 2005 Tenable Network Security, Inc.
# See http://www.ubuntulinux.org/usn/
# Ubuntu(R) is a registered trademark of Canonical, Inc.

if (! defined_func("bn_random")) exit(0);
include('compat.inc');

if (description) {
script_id(42167);
script_version("$Revision: 1.1 $");
script_copyright("Ubuntu Security Notice (C) 2009 Canonical, Inc. / NASL script (C) 2009 Tenable Network Security, Inc.");
script_category(ACT_GATHER_INFO);
script_family(english: "Ubuntu Local Security Checks");
script_dependencies("ssh_get_info.nasl");
script_require_keys("Host/Ubuntu", "Host/Ubuntu/release", "Host/Debian/dpkg-l");

script_xref(name: "USN", value: "849-1");
script_summary(english:"libsndfile vulnerabilities");
script_name(english:"USN849-1 : libsndfile vulnerabilities");
script_set_attribute(attribute:'synopsis', value: 'These remote packages are missing security patches :
- libsndfile1 
- libsndfile1-dev 
- sndfile-programs 
');
script_set_attribute(attribute:'description', value: 'Tobias Klein discovered a heap-based buffer overflow in libsndfile. If a
user or automated system processed a crafted VOC file, an attacker could
cause a denial of service via application crash, or possibly execute
arbitrary code with the privileges of the user invoking the program.
(CVE-2009-1788)

Erik de Castro Lopo discovered a similar heap-based buffer overflow when
processing AIFF files. If a user or automated system processed a crafted
AIFF file, an attacker could cause a denial of service via application
crash, or possibly execute arbitrary code with the privileges of the user
invoking the program. (CVE-2009-1791)');
script_set_attribute(attribute:'solution', value: 'Upgrade to : 
- libsndfile1-1.0.17-4ubuntu1.1 (Ubuntu 9.04)
- libsndfile1-dev-1.0.17-4ubuntu1.1 (Ubuntu 9.04)
- sndfile-programs-1.0.17-4ubuntu1.1 (Ubuntu 9.04)
');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C');
script_end_attributes();

script_cve_id("CVE-2009-1788","CVE-2009-1791");
exit(0);
}

include('ubuntu.inc');

if ( ! get_kb_item('Host/Ubuntu/release') ) exit(1, 'Could not gather the list of packages');

extrarep = NULL;

found = ubuntu_check(osver: "9.04", pkgname: "libsndfile1", pkgver: "1.0.17-4ubuntu1.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libsndfile1-',found,' is vulnerable in Ubuntu 9.04
Upgrade it to libsndfile1-1.0.17-4ubuntu1.1
');
}
found = ubuntu_check(osver: "9.04", pkgname: "libsndfile1-dev", pkgver: "1.0.17-4ubuntu1.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libsndfile1-dev-',found,' is vulnerable in Ubuntu 9.04
Upgrade it to libsndfile1-dev-1.0.17-4ubuntu1.1
');
}
found = ubuntu_check(osver: "9.04", pkgname: "sndfile-programs", pkgver: "1.0.17-4ubuntu1.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package sndfile-programs-',found,' is vulnerable in Ubuntu 9.04
Upgrade it to sndfile-programs-1.0.17-4ubuntu1.1
');
}

if (w) { security_hole(port: 0, extra: extrarep); }
else exit(0, "Host is not vulnerable");
