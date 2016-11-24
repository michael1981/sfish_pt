# This script was automatically generated from the 607-1 Ubuntu Security Notice
# It is released under the Nessus Script Licence.
# Ubuntu Security Notices are (C) 2005 Canonical, Inc.
# USN2nasl Convertor is (C) 2005 Tenable Network Security, Inc.
# See http://www.ubuntulinux.org/usn/
# Ubuntu(R) is a registered trademark of Canonical, Inc.

if (! defined_func("bn_random")) exit(0);
include('compat.inc');

if (description) {
script_id(32187);
script_version("$Revision: 1.3 $");
script_copyright("Ubuntu Security Notice (C) 2009 Canonical, Inc. / NASL script (C) 2009 Tenable Network Security, Inc.");
script_category(ACT_GATHER_INFO);
script_family(english: "Ubuntu Local Security Checks");
script_dependencies("ssh_get_info.nasl");
script_require_keys("Host/Ubuntu", "Host/Ubuntu/release", "Host/Debian/dpkg-l");

script_xref(name: "USN", value: "607-1");
script_summary(english:"Emacs vulnerabilities");
script_name(english:"USN607-1 : Emacs vulnerabilities");
script_set_attribute(attribute:'synopsis', value: 'These remote packages are missing security patches :
- emacs 
- emacs-el 
- emacs-nox 
- emacs21 
- emacs21-bin-common 
- emacs21-common 
- emacs21-el 
- emacs21-nox 
- emacs22 
- emacs22-bin-common 
- emacs22-common 
- emacs22-el 
- emacs22-gtk 
- emacs22-nox 
');
script_set_attribute(attribute:'description', value: 'It was discovered that Emacs did not account for precision when formatting
integers. If a user were tricked into opening a specially crafted file, an
attacker could cause a denial of service or possibly other unspecified
actions. This issue does not affect Ubuntu 8.04. (CVE-2007-6109)

Steve Grubb discovered that the vcdiff script as included in Emacs created
temporary files in an insecure way when used with SCCS. Local users could
exploit a race condition to create or overwrite files with the privileges
of the user invoking the program. (CVE-2008-1694)');
script_set_attribute(attribute:'solution', value: 'Upgrade to : 
- emacs-22.1-0ubuntu10.1 (Ubuntu 8.04)
- emacs-el-21.4a+1-5ubuntu4.1 (Ubuntu 7.10)
- emacs-nox-21.4a+1-5ubuntu4.1 (Ubuntu 7.10)
- emacs21-21.4a+1-5.3ubuntu1.1 (Ubuntu 8.04)
- emacs21-bin-common-21.4a+1-5.3ubuntu1.1 (Ubuntu 8.04)
- emacs21-common-21.4a+1-5.3ubuntu1.1 (Ubuntu 8.04)
- emacs21-el-21.4a+1-5.3ubuntu1.1 (Ubuntu 8.04)
- emacs21-nox-21.4a+1-5.3ubuntu1.1 (Ubuntu 8.04)
- emacs22-22.1-0ubuntu10.1 (Ubuntu 8.04)
- emacs22-bin-common-22.1-0ubuntu10.1 (Ubuntu 8.04)
- emacs22-common-22.1-0ubu
[...]');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C');
script_end_attributes();

script_cve_id("CVE-2007-6109","CVE-2008-1694");
exit(0);
}

include('ubuntu.inc');

if ( ! get_kb_item('Host/Ubuntu/release') ) exit(1, 'Could not gather the list of packages');

extrarep = NULL;

found = ubuntu_check(osver: "8.04", pkgname: "emacs", pkgver: "22.1-0ubuntu10.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package emacs-',found,' is vulnerable in Ubuntu 8.04
Upgrade it to emacs-22.1-0ubuntu10.1
');
}
found = ubuntu_check(osver: "7.10", pkgname: "emacs-el", pkgver: "21.4a+1-5ubuntu4.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package emacs-el-',found,' is vulnerable in Ubuntu 7.10
Upgrade it to emacs-el-21.4a+1-5ubuntu4.1
');
}
found = ubuntu_check(osver: "7.10", pkgname: "emacs-nox", pkgver: "21.4a+1-5ubuntu4.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package emacs-nox-',found,' is vulnerable in Ubuntu 7.10
Upgrade it to emacs-nox-21.4a+1-5ubuntu4.1
');
}
found = ubuntu_check(osver: "8.04", pkgname: "emacs21", pkgver: "21.4a+1-5.3ubuntu1.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package emacs21-',found,' is vulnerable in Ubuntu 8.04
Upgrade it to emacs21-21.4a+1-5.3ubuntu1.1
');
}
found = ubuntu_check(osver: "8.04", pkgname: "emacs21-bin-common", pkgver: "21.4a+1-5.3ubuntu1.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package emacs21-bin-common-',found,' is vulnerable in Ubuntu 8.04
Upgrade it to emacs21-bin-common-21.4a+1-5.3ubuntu1.1
');
}
found = ubuntu_check(osver: "8.04", pkgname: "emacs21-common", pkgver: "21.4a+1-5.3ubuntu1.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package emacs21-common-',found,' is vulnerable in Ubuntu 8.04
Upgrade it to emacs21-common-21.4a+1-5.3ubuntu1.1
');
}
found = ubuntu_check(osver: "8.04", pkgname: "emacs21-el", pkgver: "21.4a+1-5.3ubuntu1.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package emacs21-el-',found,' is vulnerable in Ubuntu 8.04
Upgrade it to emacs21-el-21.4a+1-5.3ubuntu1.1
');
}
found = ubuntu_check(osver: "8.04", pkgname: "emacs21-nox", pkgver: "21.4a+1-5.3ubuntu1.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package emacs21-nox-',found,' is vulnerable in Ubuntu 8.04
Upgrade it to emacs21-nox-21.4a+1-5.3ubuntu1.1
');
}
found = ubuntu_check(osver: "8.04", pkgname: "emacs22", pkgver: "22.1-0ubuntu10.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package emacs22-',found,' is vulnerable in Ubuntu 8.04
Upgrade it to emacs22-22.1-0ubuntu10.1
');
}
found = ubuntu_check(osver: "8.04", pkgname: "emacs22-bin-common", pkgver: "22.1-0ubuntu10.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package emacs22-bin-common-',found,' is vulnerable in Ubuntu 8.04
Upgrade it to emacs22-bin-common-22.1-0ubuntu10.1
');
}
found = ubuntu_check(osver: "8.04", pkgname: "emacs22-common", pkgver: "22.1-0ubuntu10.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package emacs22-common-',found,' is vulnerable in Ubuntu 8.04
Upgrade it to emacs22-common-22.1-0ubuntu10.1
');
}
found = ubuntu_check(osver: "8.04", pkgname: "emacs22-el", pkgver: "22.1-0ubuntu10.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package emacs22-el-',found,' is vulnerable in Ubuntu 8.04
Upgrade it to emacs22-el-22.1-0ubuntu10.1
');
}
found = ubuntu_check(osver: "8.04", pkgname: "emacs22-gtk", pkgver: "22.1-0ubuntu10.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package emacs22-gtk-',found,' is vulnerable in Ubuntu 8.04
Upgrade it to emacs22-gtk-22.1-0ubuntu10.1
');
}
found = ubuntu_check(osver: "8.04", pkgname: "emacs22-nox", pkgver: "22.1-0ubuntu10.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package emacs22-nox-',found,' is vulnerable in Ubuntu 8.04
Upgrade it to emacs22-nox-22.1-0ubuntu10.1
');
}

if (w) { security_hole(port: 0, extra: extrarep); }
else exit(0, "Host is not vulnerable");
