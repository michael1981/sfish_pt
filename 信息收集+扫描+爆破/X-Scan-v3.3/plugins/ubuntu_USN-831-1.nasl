# This script was automatically generated from the 831-1 Ubuntu Security Notice
# It is released under the Nessus Script Licence.
# Ubuntu Security Notices are (C) 2005 Canonical, Inc.
# USN2nasl Convertor is (C) 2005 Tenable Network Security, Inc.
# See http://www.ubuntulinux.org/usn/
# Ubuntu(R) is a registered trademark of Canonical, Inc.

if (! defined_func("bn_random")) exit(0);
include('compat.inc');

if (description) {
script_id(40982);
script_version("$Revision: 1.1 $");
script_copyright("Ubuntu Security Notice (C) 2009 Canonical, Inc. / NASL script (C) 2009 Tenable Network Security, Inc.");
script_category(ACT_GATHER_INFO);
script_family(english: "Ubuntu Local Security Checks");
script_dependencies("ssh_get_info.nasl");
script_require_keys("Host/Ubuntu", "Host/Ubuntu/release", "Host/Debian/dpkg-l");

script_xref(name: "USN", value: "831-1");
script_summary(english:"openexr vulnerabilities");
script_name(english:"USN831-1 : openexr vulnerabilities");
script_set_attribute(attribute:'synopsis', value: 'These remote packages are missing security patches :
- libopenexr-dev 
- libopenexr2ldbl 
- libopenexr6 
- openexr 
');
script_set_attribute(attribute:'description', value: 'Drew Yao discovered several flaws in the way OpenEXR handled certain
malformed EXR image files. If a user were tricked into opening a crafted
EXR image file, an attacker could cause a denial of service via application
crash, or possibly execute arbitrary code with the privileges of the user
invoking the program. (CVE-2009-1720, CVE-2009-1721)

It was discovered that OpenEXR did not properly handle certain malformed
EXR image files. If a user were tricked into opening a crafted EXR image
file, an attacker could cause a denial of service via application crash, or
possibly execute arbitrary code with the privileges of the user invoking
the program. This issue only affected Ubuntu 8.04 LTS. (CVE-2009-1722)');
script_set_attribute(attribute:'solution', value: 'Upgrade to : 
- libopenexr-dev-1.6.1-3ubuntu1.9.04.1 (Ubuntu 9.04)
- libopenexr2ldbl-1.2.2-4.4ubuntu1.1 (Ubuntu 8.04)
- libopenexr6-1.6.1-3ubuntu1.9.04.1 (Ubuntu 9.04)
- openexr-1.6.1-3ubuntu1.9.04.1 (Ubuntu 9.04)
');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P');
script_end_attributes();

script_cve_id("CVE-2009-1720","CVE-2009-1721","CVE-2009-1722");
exit(0);
}

include('ubuntu.inc');

if ( ! get_kb_item('Host/Ubuntu/release') ) exit(1, 'Could not gather the list of packages');

extrarep = NULL;

found = ubuntu_check(osver: "9.04", pkgname: "libopenexr-dev", pkgver: "1.6.1-3ubuntu1.9.04.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libopenexr-dev-',found,' is vulnerable in Ubuntu 9.04
Upgrade it to libopenexr-dev-1.6.1-3ubuntu1.9.04.1
');
}
found = ubuntu_check(osver: "8.04", pkgname: "libopenexr2ldbl", pkgver: "1.2.2-4.4ubuntu1.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libopenexr2ldbl-',found,' is vulnerable in Ubuntu 8.04
Upgrade it to libopenexr2ldbl-1.2.2-4.4ubuntu1.1
');
}
found = ubuntu_check(osver: "9.04", pkgname: "libopenexr6", pkgver: "1.6.1-3ubuntu1.9.04.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libopenexr6-',found,' is vulnerable in Ubuntu 9.04
Upgrade it to libopenexr6-1.6.1-3ubuntu1.9.04.1
');
}
found = ubuntu_check(osver: "9.04", pkgname: "openexr", pkgver: "1.6.1-3ubuntu1.9.04.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package openexr-',found,' is vulnerable in Ubuntu 9.04
Upgrade it to openexr-1.6.1-3ubuntu1.9.04.1
');
}

if (w) { security_hole(port: 0, extra: extrarep); }
else exit(0, "Host is not vulnerable");
