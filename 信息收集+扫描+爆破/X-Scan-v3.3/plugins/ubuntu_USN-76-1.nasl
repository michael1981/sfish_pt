# This script was automatically generated from the 76-1 Ubuntu Security Notice
# It is released under the Nessus Script Licence.
# Ubuntu Security Notices are (C) 2005 Canonical, Inc.
# USN2nasl Convertor is (C) 2005 Tenable Network Security, Inc.
# See http://www.ubuntulinux.org/usn/
# Ubuntu(R) is a registered trademark of Canonical, Inc.

if (! defined_func("bn_random")) exit(0);
include('compat.inc');

if (description) {
script_id(20698);
script_version("$Revision: 1.5 $");
script_copyright("Ubuntu Security Notice (C) 2009 Canonical, Inc. / NASL script (C) 2009 Tenable Network Security, Inc.");
script_category(ACT_GATHER_INFO);
script_family(english: "Ubuntu Local Security Checks");
script_dependencies("ssh_get_info.nasl");
script_require_keys("Host/Ubuntu", "Host/Ubuntu/release", "Host/Debian/dpkg-l");

script_xref(name: "USN", value: "76-1");
script_summary(english:"emacs21 vulnerability");
script_name(english:"USN76-1 : emacs21 vulnerability");
script_set_attribute(attribute:'synopsis', value: 'These remote packages are missing security patches :
- emacs21 
- emacs21-bin-common 
- emacs21-common 
- emacs21-el 
- emacs21-nox 
');
script_set_attribute(attribute:'description', value: 'Max Vozeler discovered a format string vulnerability in the "movemail"
utility of Emacs. By sending specially crafted packets, a malicious
POP3 server could cause a buffer overflow, which could have been
exploited to execute arbitrary code with the privileges of the user
and the "mail" group (since "movemail" is installed as "setgid mail").');
script_set_attribute(attribute:'solution', value: 'Upgrade to : 
- emacs21-21.3+1-5ubuntu4.2 (Ubuntu 4.10)
- emacs21-bin-common-21.3+1-5ubuntu4.2 (Ubuntu 4.10)
- emacs21-common-21.3+1-5ubuntu4.2 (Ubuntu 4.10)
- emacs21-el-21.3+1-5ubuntu4.2 (Ubuntu 4.10)
- emacs21-nox-21.3+1-5ubuntu4.2 (Ubuntu 4.10)
');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P');
script_end_attributes();

script_cve_id("CVE-2005-0100");
exit(0);
}

include('ubuntu.inc');

if ( ! get_kb_item('Host/Ubuntu/release') ) exit(1, 'Could not gather the list of packages');

extrarep = NULL;

found = ubuntu_check(osver: "4.10", pkgname: "emacs21", pkgver: "21.3+1-5ubuntu4.2");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package emacs21-',found,' is vulnerable in Ubuntu 4.10
Upgrade it to emacs21-21.3+1-5ubuntu4.2
');
}
found = ubuntu_check(osver: "4.10", pkgname: "emacs21-bin-common", pkgver: "21.3+1-5ubuntu4.2");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package emacs21-bin-common-',found,' is vulnerable in Ubuntu 4.10
Upgrade it to emacs21-bin-common-21.3+1-5ubuntu4.2
');
}
found = ubuntu_check(osver: "4.10", pkgname: "emacs21-common", pkgver: "21.3+1-5ubuntu4.2");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package emacs21-common-',found,' is vulnerable in Ubuntu 4.10
Upgrade it to emacs21-common-21.3+1-5ubuntu4.2
');
}
found = ubuntu_check(osver: "4.10", pkgname: "emacs21-el", pkgver: "21.3+1-5ubuntu4.2");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package emacs21-el-',found,' is vulnerable in Ubuntu 4.10
Upgrade it to emacs21-el-21.3+1-5ubuntu4.2
');
}
found = ubuntu_check(osver: "4.10", pkgname: "emacs21-nox", pkgver: "21.3+1-5ubuntu4.2");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package emacs21-nox-',found,' is vulnerable in Ubuntu 4.10
Upgrade it to emacs21-nox-21.3+1-5ubuntu4.2
');
}

if (w) { security_hole(port: 0, extra: extrarep); }
else exit(0, "Host is not vulnerable");
