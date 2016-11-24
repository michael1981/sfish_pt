# This script was automatically generated from the 504-1 Ubuntu Security Notice
# It is released under the Nessus Script Licence.
# Ubuntu Security Notices are (C) 2005 Canonical, Inc.
# USN2nasl Convertor is (C) 2005 Tenable Network Security, Inc.
# See http://www.ubuntulinux.org/usn/
# Ubuntu(R) is a registered trademark of Canonical, Inc.

if (! defined_func("bn_random")) exit(0);
include('compat.inc');

if (description) {
script_id(28108);
script_version("$Revision: 1.3 $");
script_copyright("Ubuntu Security Notice (C) 2009 Canonical, Inc. / NASL script (C) 2009 Tenable Network Security, Inc.");
script_category(ACT_GATHER_INFO);
script_family(english: "Ubuntu Local Security Checks");
script_dependencies("ssh_get_info.nasl");
script_require_keys("Host/Ubuntu", "Host/Ubuntu/release", "Host/Debian/dpkg-l");

script_xref(name: "USN", value: "504-1");
script_summary(english:"Emacs vulnerability");
script_name(english:"USN504-1 : Emacs vulnerability");
script_set_attribute(attribute:'synopsis', value: 'These remote packages are missing security patches :
- emacs 
- emacs-el 
- emacs-nox 
- emacs21 
- emacs21-bin-common 
- emacs21-common 
- emacs21-el 
- emacs21-nox 
');
script_set_attribute(attribute:'description', value: 'Hendrik Tews discovered that emacs21 did not correctly handle certain
GIF images.  By tricking a user into opening a specially crafted GIF,
a remote attacker could cause emacs21 to crash, resulting in a denial
of service.');
script_set_attribute(attribute:'solution', value: 'Upgrade to : 
- emacs-21.4a+1-2ubuntu1.1 (Ubuntu 7.04)
- emacs-el-21.4a+1-2ubuntu1.1 (Ubuntu 7.04)
- emacs-nox-21.4a+1-2ubuntu1.1 (Ubuntu 7.04)
- emacs21-21.4a+1-2ubuntu1.1 (Ubuntu 7.04)
- emacs21-bin-common-21.4a+1-2ubuntu1.1 (Ubuntu 7.04)
- emacs21-common-21.4a+1-2ubuntu1.1 (Ubuntu 7.04)
- emacs21-el-21.4a+1-2ubuntu1.1 (Ubuntu 7.04)
- emacs21-nox-21.4a+1-2ubuntu1.1 (Ubuntu 7.04)
');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C');
script_end_attributes();

script_cve_id("CVE-2007-2833");
exit(0);
}

include('ubuntu.inc');

if ( ! get_kb_item('Host/Ubuntu/release') ) exit(1, 'Could not gather the list of packages');

extrarep = NULL;

found = ubuntu_check(osver: "7.04", pkgname: "emacs", pkgver: "21.4a+1-2ubuntu1.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package emacs-',found,' is vulnerable in Ubuntu 7.04
Upgrade it to emacs-21.4a+1-2ubuntu1.1
');
}
found = ubuntu_check(osver: "7.04", pkgname: "emacs-el", pkgver: "21.4a+1-2ubuntu1.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package emacs-el-',found,' is vulnerable in Ubuntu 7.04
Upgrade it to emacs-el-21.4a+1-2ubuntu1.1
');
}
found = ubuntu_check(osver: "7.04", pkgname: "emacs-nox", pkgver: "21.4a+1-2ubuntu1.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package emacs-nox-',found,' is vulnerable in Ubuntu 7.04
Upgrade it to emacs-nox-21.4a+1-2ubuntu1.1
');
}
found = ubuntu_check(osver: "7.04", pkgname: "emacs21", pkgver: "21.4a+1-2ubuntu1.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package emacs21-',found,' is vulnerable in Ubuntu 7.04
Upgrade it to emacs21-21.4a+1-2ubuntu1.1
');
}
found = ubuntu_check(osver: "7.04", pkgname: "emacs21-bin-common", pkgver: "21.4a+1-2ubuntu1.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package emacs21-bin-common-',found,' is vulnerable in Ubuntu 7.04
Upgrade it to emacs21-bin-common-21.4a+1-2ubuntu1.1
');
}
found = ubuntu_check(osver: "7.04", pkgname: "emacs21-common", pkgver: "21.4a+1-2ubuntu1.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package emacs21-common-',found,' is vulnerable in Ubuntu 7.04
Upgrade it to emacs21-common-21.4a+1-2ubuntu1.1
');
}
found = ubuntu_check(osver: "7.04", pkgname: "emacs21-el", pkgver: "21.4a+1-2ubuntu1.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package emacs21-el-',found,' is vulnerable in Ubuntu 7.04
Upgrade it to emacs21-el-21.4a+1-2ubuntu1.1
');
}
found = ubuntu_check(osver: "7.04", pkgname: "emacs21-nox", pkgver: "21.4a+1-2ubuntu1.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package emacs21-nox-',found,' is vulnerable in Ubuntu 7.04
Upgrade it to emacs21-nox-21.4a+1-2ubuntu1.1
');
}

if (w) { security_hole(port: 0, extra: extrarep); }
else exit(0, "Host is not vulnerable");
