# This script was automatically generated from the 693-1 Ubuntu Security Notice
# It is released under the Nessus Script Licence.
# Ubuntu Security Notices are (C) 2005 Canonical, Inc.
# USN2nasl Convertor is (C) 2005 Tenable Network Security, Inc.
# See http://www.ubuntulinux.org/usn/
# Ubuntu(R) is a registered trademark of Canonical, Inc.

if (! defined_func("bn_random")) exit(0);
include('compat.inc');

if (description) {
script_id(36761);
script_version("$Revision: 1.1 $");
script_copyright("Ubuntu Security Notice (C) 2009 Canonical, Inc. / NASL script (C) 2009 Tenable Network Security, Inc.");
script_category(ACT_GATHER_INFO);
script_family(english: "Ubuntu Local Security Checks");
script_dependencies("ssh_get_info.nasl");
script_require_keys("Host/Ubuntu", "Host/Ubuntu/release", "Host/Debian/dpkg-l");

script_xref(name: "USN", value: "693-1");
script_summary(english:"LittleCMS vulnerability");
script_name(english:"USN693-1 : LittleCMS vulnerability");
script_set_attribute(attribute:'synopsis', value: 'These remote packages are missing security patches :
- liblcms-utils 
- liblcms1 
- liblcms1-dev 
- python-liblcms 
');
script_set_attribute(attribute:'description', value: 'It was discovered that certain gamma operations in lcms were not
correctly bounds-checked.  If a user or automated system were tricked into
processing a malicious image, a remote attacker could crash applications
linked against liblcms1, leading to a denial of service, or possibly
execute arbitrary code with user privileges.');
script_set_attribute(attribute:'solution', value: 'Upgrade to : 
- liblcms-utils-1.16-10ubuntu0.1 (Ubuntu 8.10)
- liblcms1-1.16-10ubuntu0.1 (Ubuntu 8.10)
- liblcms1-dev-1.16-10ubuntu0.1 (Ubuntu 8.10)
- python-liblcms-1.16-10ubuntu0.1 (Ubuntu 8.10)
');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C');
script_end_attributes();

script_cve_id("CVE-2008-5317");
exit(0);
}

include('ubuntu.inc');

if ( ! get_kb_item('Host/Ubuntu/release') ) exit(1, 'Could not gather the list of packages');

extrarep = NULL;

found = ubuntu_check(osver: "8.10", pkgname: "liblcms-utils", pkgver: "1.16-10ubuntu0.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package liblcms-utils-',found,' is vulnerable in Ubuntu 8.10
Upgrade it to liblcms-utils-1.16-10ubuntu0.1
');
}
found = ubuntu_check(osver: "8.10", pkgname: "liblcms1", pkgver: "1.16-10ubuntu0.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package liblcms1-',found,' is vulnerable in Ubuntu 8.10
Upgrade it to liblcms1-1.16-10ubuntu0.1
');
}
found = ubuntu_check(osver: "8.10", pkgname: "liblcms1-dev", pkgver: "1.16-10ubuntu0.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package liblcms1-dev-',found,' is vulnerable in Ubuntu 8.10
Upgrade it to liblcms1-dev-1.16-10ubuntu0.1
');
}
found = ubuntu_check(osver: "8.10", pkgname: "python-liblcms", pkgver: "1.16-10ubuntu0.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package python-liblcms-',found,' is vulnerable in Ubuntu 8.10
Upgrade it to python-liblcms-1.16-10ubuntu0.1
');
}

if (w) { security_hole(port: 0, extra: extrarep); }
else exit(0, "Host is not vulnerable");
