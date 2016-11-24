# This script was automatically generated from the 533-1 Ubuntu Security Notice
# It is released under the Nessus Script Licence.
# Ubuntu Security Notices are (C) 2005 Canonical, Inc.
# USN2nasl Convertor is (C) 2005 Tenable Network Security, Inc.
# See http://www.ubuntulinux.org/usn/
# Ubuntu(R) is a registered trademark of Canonical, Inc.

if (! defined_func("bn_random")) exit(0);
include('compat.inc');

if (description) {
script_id(28139);
script_version("$Revision: 1.3 $");
script_copyright("Ubuntu Security Notice (C) 2009 Canonical, Inc. / NASL script (C) 2009 Tenable Network Security, Inc.");
script_category(ACT_GATHER_INFO);
script_family(english: "Ubuntu Local Security Checks");
script_dependencies("ssh_get_info.nasl");
script_require_keys("Host/Ubuntu", "Host/Ubuntu/release", "Host/Debian/dpkg-l");

script_xref(name: "USN", value: "533-1");
script_summary(english:"util-linux vulnerability");
script_name(english:"USN533-1 : util-linux vulnerability");
script_set_attribute(attribute:'synopsis', value: 'These remote packages are missing security patches :
- bsdutils 
- mount 
- util-linux 
- util-linux-locales 
');
script_set_attribute(attribute:'description', value: 'Ludwig Nussel discovered that mount and umount did not properly
drop privileges when using helper programs. Local attackers may be
able to bypass security restrictions and gain root privileges using
programs such as mount.nfs or mount.cifs.');
script_set_attribute(attribute:'solution', value: 'Upgrade to : 
- bsdutils-2.12r-17ubuntu2.1 (Ubuntu 7.04)
- mount-2.12r-17ubuntu2.1 (Ubuntu 7.04)
- util-linux-2.12r-17ubuntu2.1 (Ubuntu 7.04)
- util-linux-locales-2.12r-17ubuntu2.1 (Ubuntu 7.04)
');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:L/AC:M/Au:N/C:C/I:C/A:C');
script_end_attributes();

script_cve_id("CVE-2007-5191");
exit(0);
}

include('ubuntu.inc');

if ( ! get_kb_item('Host/Ubuntu/release') ) exit(1, 'Could not gather the list of packages');

extrarep = NULL;

found = ubuntu_check(osver: "7.04", pkgname: "bsdutils", pkgver: "2.12r-17ubuntu2.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package bsdutils-',found,' is vulnerable in Ubuntu 7.04
Upgrade it to bsdutils-2.12r-17ubuntu2.1
');
}
found = ubuntu_check(osver: "7.04", pkgname: "mount", pkgver: "2.12r-17ubuntu2.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package mount-',found,' is vulnerable in Ubuntu 7.04
Upgrade it to mount-2.12r-17ubuntu2.1
');
}
found = ubuntu_check(osver: "7.04", pkgname: "util-linux", pkgver: "2.12r-17ubuntu2.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package util-linux-',found,' is vulnerable in Ubuntu 7.04
Upgrade it to util-linux-2.12r-17ubuntu2.1
');
}
found = ubuntu_check(osver: "7.04", pkgname: "util-linux-locales", pkgver: "2.12r-17ubuntu2.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package util-linux-locales-',found,' is vulnerable in Ubuntu 7.04
Upgrade it to util-linux-locales-2.12r-17ubuntu2.1
');
}

if (w) { security_warning(port: 0, extra: extrarep); }
else exit(0, "Host is not vulnerable");
