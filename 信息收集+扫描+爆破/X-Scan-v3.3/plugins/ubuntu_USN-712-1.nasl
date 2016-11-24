# This script was automatically generated from the 712-1 Ubuntu Security Notice
# It is released under the Nessus Script Licence.
# Ubuntu Security Notices are (C) 2005 Canonical, Inc.
# USN2nasl Convertor is (C) 2005 Tenable Network Security, Inc.
# See http://www.ubuntulinux.org/usn/
# Ubuntu(R) is a registered trademark of Canonical, Inc.

if (! defined_func("bn_random")) exit(0);
include('compat.inc');

if (description) {
script_id(38044);
script_version("$Revision: 1.1 $");
script_copyright("Ubuntu Security Notice (C) 2009 Canonical, Inc. / NASL script (C) 2009 Tenable Network Security, Inc.");
script_category(ACT_GATHER_INFO);
script_family(english: "Ubuntu Local Security Checks");
script_dependencies("ssh_get_info.nasl");
script_require_keys("Host/Ubuntu", "Host/Ubuntu/release", "Host/Debian/dpkg-l");

script_xref(name: "USN", value: "712-1");
script_summary(english:"vim vulnerabilities");
script_name(english:"USN712-1 : vim vulnerabilities");
script_set_attribute(attribute:'synopsis', value: 'These remote packages are missing security patches :
- vim 
- vim-common 
- vim-dbg 
- vim-doc 
- vim-full 
- vim-gnome 
- vim-gtk 
- vim-gui-common 
- vim-nox 
- vim-perl 
- vim-python 
- vim-ruby 
- vim-runtime 
- vim-tcl 
- vim-tiny 
');
script_set_attribute(attribute:'description', value: 'Jan Minar discovered that Vim did not properly sanitize inputs before invoking
the execute or system functions inside Vim scripts. If a user were tricked
into running Vim scripts with a specially crafted input, an attacker could
execute arbitrary code with the privileges of the user invoking the program.
(CVE-2008-2712)

Ben Schmidt discovered that Vim did not properly escape characters when
performing keyword or tag lookups. If a user were tricked into running specially
crafted commands, an attacker could execute arbitrary code with the privileges
of the user invoking the program. (CVE-2008-4101)');
script_set_attribute(attribute:'solution', value: 'Upgrade to : 
- vim-7.1.314-3ubuntu3.1 (Ubuntu 8.10)
- vim-common-7.1.314-3ubuntu3.1 (Ubuntu 8.10)
- vim-dbg-7.1.314-3ubuntu3.1 (Ubuntu 8.10)
- vim-doc-7.1.314-3ubuntu3.1 (Ubuntu 8.10)
- vim-full-7.1.314-3ubuntu3.1 (Ubuntu 8.10)
- vim-gnome-7.1.314-3ubuntu3.1 (Ubuntu 8.10)
- vim-gtk-7.1.314-3ubuntu3.1 (Ubuntu 8.10)
- vim-gui-common-7.1.314-3ubuntu3.1 (Ubuntu 8.10)
- vim-nox-7.1.314-3ubuntu3.1 (Ubuntu 8.10)
- vim-perl-7.1.314-3ubuntu3.1 (Ubuntu 8.10)
- vim-python-7.1.314-3ubuntu3.1 (Ubuntu 8.10)
- vim-ruby-
[...]');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C');
script_end_attributes();

script_cve_id("CVE-2008-2712","CVE-2008-4101");
exit(0);
}

include('ubuntu.inc');

if ( ! get_kb_item('Host/Ubuntu/release') ) exit(1, 'Could not gather the list of packages');

extrarep = NULL;

found = ubuntu_check(osver: "8.10", pkgname: "vim", pkgver: "7.1.314-3ubuntu3.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package vim-',found,' is vulnerable in Ubuntu 8.10
Upgrade it to vim-7.1.314-3ubuntu3.1
');
}
found = ubuntu_check(osver: "8.10", pkgname: "vim-common", pkgver: "7.1.314-3ubuntu3.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package vim-common-',found,' is vulnerable in Ubuntu 8.10
Upgrade it to vim-common-7.1.314-3ubuntu3.1
');
}
found = ubuntu_check(osver: "8.10", pkgname: "vim-dbg", pkgver: "7.1.314-3ubuntu3.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package vim-dbg-',found,' is vulnerable in Ubuntu 8.10
Upgrade it to vim-dbg-7.1.314-3ubuntu3.1
');
}
found = ubuntu_check(osver: "8.10", pkgname: "vim-doc", pkgver: "7.1.314-3ubuntu3.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package vim-doc-',found,' is vulnerable in Ubuntu 8.10
Upgrade it to vim-doc-7.1.314-3ubuntu3.1
');
}
found = ubuntu_check(osver: "8.10", pkgname: "vim-full", pkgver: "7.1.314-3ubuntu3.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package vim-full-',found,' is vulnerable in Ubuntu 8.10
Upgrade it to vim-full-7.1.314-3ubuntu3.1
');
}
found = ubuntu_check(osver: "8.10", pkgname: "vim-gnome", pkgver: "7.1.314-3ubuntu3.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package vim-gnome-',found,' is vulnerable in Ubuntu 8.10
Upgrade it to vim-gnome-7.1.314-3ubuntu3.1
');
}
found = ubuntu_check(osver: "8.10", pkgname: "vim-gtk", pkgver: "7.1.314-3ubuntu3.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package vim-gtk-',found,' is vulnerable in Ubuntu 8.10
Upgrade it to vim-gtk-7.1.314-3ubuntu3.1
');
}
found = ubuntu_check(osver: "8.10", pkgname: "vim-gui-common", pkgver: "7.1.314-3ubuntu3.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package vim-gui-common-',found,' is vulnerable in Ubuntu 8.10
Upgrade it to vim-gui-common-7.1.314-3ubuntu3.1
');
}
found = ubuntu_check(osver: "8.10", pkgname: "vim-nox", pkgver: "7.1.314-3ubuntu3.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package vim-nox-',found,' is vulnerable in Ubuntu 8.10
Upgrade it to vim-nox-7.1.314-3ubuntu3.1
');
}
found = ubuntu_check(osver: "8.10", pkgname: "vim-perl", pkgver: "7.1.314-3ubuntu3.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package vim-perl-',found,' is vulnerable in Ubuntu 8.10
Upgrade it to vim-perl-7.1.314-3ubuntu3.1
');
}
found = ubuntu_check(osver: "8.10", pkgname: "vim-python", pkgver: "7.1.314-3ubuntu3.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package vim-python-',found,' is vulnerable in Ubuntu 8.10
Upgrade it to vim-python-7.1.314-3ubuntu3.1
');
}
found = ubuntu_check(osver: "8.10", pkgname: "vim-ruby", pkgver: "7.1.314-3ubuntu3.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package vim-ruby-',found,' is vulnerable in Ubuntu 8.10
Upgrade it to vim-ruby-7.1.314-3ubuntu3.1
');
}
found = ubuntu_check(osver: "8.10", pkgname: "vim-runtime", pkgver: "7.1.314-3ubuntu3.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package vim-runtime-',found,' is vulnerable in Ubuntu 8.10
Upgrade it to vim-runtime-7.1.314-3ubuntu3.1
');
}
found = ubuntu_check(osver: "8.10", pkgname: "vim-tcl", pkgver: "7.1.314-3ubuntu3.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package vim-tcl-',found,' is vulnerable in Ubuntu 8.10
Upgrade it to vim-tcl-7.1.314-3ubuntu3.1
');
}
found = ubuntu_check(osver: "8.10", pkgname: "vim-tiny", pkgver: "7.1.314-3ubuntu3.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package vim-tiny-',found,' is vulnerable in Ubuntu 8.10
Upgrade it to vim-tiny-7.1.314-3ubuntu3.1
');
}

if (w) { security_hole(port: 0, extra: extrarep); }
else exit(0, "Host is not vulnerable");
