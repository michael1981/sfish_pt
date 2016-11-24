# This script was automatically generated from the 541-1 Ubuntu Security Notice
# It is released under the Nessus Script Licence.
# Ubuntu Security Notices are (C) 2005 Canonical, Inc.
# USN2nasl Convertor is (C) 2005 Tenable Network Security, Inc.
# See http://www.ubuntulinux.org/usn/
# Ubuntu(R) is a registered trademark of Canonical, Inc.

if (! defined_func("bn_random")) exit(0);
include('compat.inc');

if (description) {
script_id(28209);
script_version("$Revision: 1.3 $");
script_copyright("Ubuntu Security Notice (C) 2009 Canonical, Inc. / NASL script (C) 2009 Tenable Network Security, Inc.");
script_category(ACT_GATHER_INFO);
script_family(english: "Ubuntu Local Security Checks");
script_dependencies("ssh_get_info.nasl");
script_require_keys("Host/Ubuntu", "Host/Ubuntu/release", "Host/Debian/dpkg-l");

script_xref(name: "USN", value: "541-1");
script_summary(english:"Emacs vulnerability");
script_name(english:"USN541-1 : Emacs vulnerability");
script_set_attribute(attribute:'synopsis', value: 'These remote packages are missing security patches :
- emacs 
- emacs22 
- emacs22-bin-common 
- emacs22-common 
- emacs22-el 
- emacs22-gtk 
- emacs22-nox 
');
script_set_attribute(attribute:'description', value: 'Drake Wilson discovered that Emacs did not correctly handle the safe
mode of "enable-local-variables". If a user were tricked into opening
a specially crafted file while "enable-local-variables" was set to the
non-default ":safe", a remote attacker could execute arbitrary commands
with the user\'s privileges.');
script_set_attribute(attribute:'solution', value: 'Upgrade to : 
- emacs-22.1-0ubuntu5.1 (Ubuntu 7.10)
- emacs22-22.1-0ubuntu5.1 (Ubuntu 7.10)
- emacs22-bin-common-22.1-0ubuntu5.1 (Ubuntu 7.10)
- emacs22-common-22.1-0ubuntu5.1 (Ubuntu 7.10)
- emacs22-el-22.1-0ubuntu5.1 (Ubuntu 7.10)
- emacs22-gtk-22.1-0ubuntu5.1 (Ubuntu 7.10)
- emacs22-nox-22.1-0ubuntu5.1 (Ubuntu 7.10)
');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:L/AC:M/Au:N/C:N/I:C/A:C');
script_end_attributes();

script_cve_id("CVE-2007-5795");
exit(0);
}

include('ubuntu.inc');

if ( ! get_kb_item('Host/Ubuntu/release') ) exit(1, 'Could not gather the list of packages');

extrarep = NULL;

found = ubuntu_check(osver: "7.10", pkgname: "emacs", pkgver: "22.1-0ubuntu5.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package emacs-',found,' is vulnerable in Ubuntu 7.10
Upgrade it to emacs-22.1-0ubuntu5.1
');
}
found = ubuntu_check(osver: "7.10", pkgname: "emacs22", pkgver: "22.1-0ubuntu5.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package emacs22-',found,' is vulnerable in Ubuntu 7.10
Upgrade it to emacs22-22.1-0ubuntu5.1
');
}
found = ubuntu_check(osver: "7.10", pkgname: "emacs22-bin-common", pkgver: "22.1-0ubuntu5.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package emacs22-bin-common-',found,' is vulnerable in Ubuntu 7.10
Upgrade it to emacs22-bin-common-22.1-0ubuntu5.1
');
}
found = ubuntu_check(osver: "7.10", pkgname: "emacs22-common", pkgver: "22.1-0ubuntu5.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package emacs22-common-',found,' is vulnerable in Ubuntu 7.10
Upgrade it to emacs22-common-22.1-0ubuntu5.1
');
}
found = ubuntu_check(osver: "7.10", pkgname: "emacs22-el", pkgver: "22.1-0ubuntu5.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package emacs22-el-',found,' is vulnerable in Ubuntu 7.10
Upgrade it to emacs22-el-22.1-0ubuntu5.1
');
}
found = ubuntu_check(osver: "7.10", pkgname: "emacs22-gtk", pkgver: "22.1-0ubuntu5.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package emacs22-gtk-',found,' is vulnerable in Ubuntu 7.10
Upgrade it to emacs22-gtk-22.1-0ubuntu5.1
');
}
found = ubuntu_check(osver: "7.10", pkgname: "emacs22-nox", pkgver: "22.1-0ubuntu5.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package emacs22-nox-',found,' is vulnerable in Ubuntu 7.10
Upgrade it to emacs22-nox-22.1-0ubuntu5.1
');
}

if (w) { security_warning(port: 0, extra: extrarep); }
else exit(0, "Host is not vulnerable");
