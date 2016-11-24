# This script was automatically generated from the 154-1 Ubuntu Security Notice
# It is released under the Nessus Script Licence.
# Ubuntu Security Notices are (C) 2005 Canonical, Inc.
# USN2nasl Convertor is (C) 2005 Tenable Network Security, Inc.
# See http://www.ubuntulinux.org/usn/
# Ubuntu(R) is a registered trademark of Canonical, Inc.

if (! defined_func("bn_random")) exit(0);
include('compat.inc');

if (description) {
script_id(20555);
script_version("$Revision: 1.5 $");
script_copyright("Ubuntu Security Notice (C) 2009 Canonical, Inc. / NASL script (C) 2009 Tenable Network Security, Inc.");
script_category(ACT_GATHER_INFO);
script_family(english: "Ubuntu Local Security Checks");
script_dependencies("ssh_get_info.nasl");
script_require_keys("Host/Ubuntu", "Host/Ubuntu/release", "Host/Debian/dpkg-l");

script_xref(name: "USN", value: "154-1");
script_summary(english:"vim vulnerability");
script_name(english:"USN154-1 : vim vulnerability");
script_set_attribute(attribute:'synopsis', value: 'These remote packages are missing security patches :
- kvim 
- kvim-perl 
- kvim-python 
- kvim-tcl 
- vim 
- vim-common 
- vim-doc 
- vim-gnome 
- vim-gtk 
- vim-lesstif 
- vim-perl 
- vim-python 
- vim-tcl 
');
script_set_attribute(attribute:'description', value: 'Georgi Guninski discovered that it was possible to construct Vim
modelines that execute arbitrary shell commands by wrapping them in
glob() or expand() function calls. If an attacker tricked an user to
open a file with a specially crafted modeline, he could exploit this
to execute arbitrary commands with the user\'s privileges.');
script_set_attribute(attribute:'solution', value: 'Upgrade to : 
- kvim-6.3-046+1ubuntu7.1 (Ubuntu 5.04)
- kvim-perl-6.3-046+1ubuntu7.1 (Ubuntu 5.04)
- kvim-python-6.3-046+1ubuntu7.1 (Ubuntu 5.04)
- kvim-tcl-6.3-046+1ubuntu7.1 (Ubuntu 5.04)
- vim-6.3-046+1ubuntu7.1 (Ubuntu 5.04)
- vim-common-6.3-046+1ubuntu7.1 (Ubuntu 5.04)
- vim-doc-6.3-046+1ubuntu7.1 (Ubuntu 5.04)
- vim-gnome-6.3-046+1ubuntu7.1 (Ubuntu 5.04)
- vim-gtk-6.3-046+1ubuntu7.1 (Ubuntu 5.04)
- vim-lesstif-6.3-046+1ubuntu7.1 (Ubuntu 5.04)
- vim-perl-6.3-046+1ubuntu7.1 (Ubuntu 5.04)
- vim-python-6
[...]');
script_set_attribute(attribute: 'risk_factor', value: 'High');
script_end_attributes();

exit(0);
}

include('ubuntu.inc');

if ( ! get_kb_item('Host/Ubuntu/release') ) exit(1, 'Could not gather the list of packages');

extrarep = NULL;

found = ubuntu_check(osver: "5.04", pkgname: "kvim", pkgver: "6.3-046+1ubuntu7.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package kvim-',found,' is vulnerable in Ubuntu 5.04
Upgrade it to kvim-6.3-046+1ubuntu7.1
');
}
found = ubuntu_check(osver: "5.04", pkgname: "kvim-perl", pkgver: "6.3-046+1ubuntu7.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package kvim-perl-',found,' is vulnerable in Ubuntu 5.04
Upgrade it to kvim-perl-6.3-046+1ubuntu7.1
');
}
found = ubuntu_check(osver: "5.04", pkgname: "kvim-python", pkgver: "6.3-046+1ubuntu7.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package kvim-python-',found,' is vulnerable in Ubuntu 5.04
Upgrade it to kvim-python-6.3-046+1ubuntu7.1
');
}
found = ubuntu_check(osver: "5.04", pkgname: "kvim-tcl", pkgver: "6.3-046+1ubuntu7.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package kvim-tcl-',found,' is vulnerable in Ubuntu 5.04
Upgrade it to kvim-tcl-6.3-046+1ubuntu7.1
');
}
found = ubuntu_check(osver: "5.04", pkgname: "vim", pkgver: "6.3-046+1ubuntu7.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package vim-',found,' is vulnerable in Ubuntu 5.04
Upgrade it to vim-6.3-046+1ubuntu7.1
');
}
found = ubuntu_check(osver: "5.04", pkgname: "vim-common", pkgver: "6.3-046+1ubuntu7.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package vim-common-',found,' is vulnerable in Ubuntu 5.04
Upgrade it to vim-common-6.3-046+1ubuntu7.1
');
}
found = ubuntu_check(osver: "5.04", pkgname: "vim-doc", pkgver: "6.3-046+1ubuntu7.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package vim-doc-',found,' is vulnerable in Ubuntu 5.04
Upgrade it to vim-doc-6.3-046+1ubuntu7.1
');
}
found = ubuntu_check(osver: "5.04", pkgname: "vim-gnome", pkgver: "6.3-046+1ubuntu7.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package vim-gnome-',found,' is vulnerable in Ubuntu 5.04
Upgrade it to vim-gnome-6.3-046+1ubuntu7.1
');
}
found = ubuntu_check(osver: "5.04", pkgname: "vim-gtk", pkgver: "6.3-046+1ubuntu7.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package vim-gtk-',found,' is vulnerable in Ubuntu 5.04
Upgrade it to vim-gtk-6.3-046+1ubuntu7.1
');
}
found = ubuntu_check(osver: "5.04", pkgname: "vim-lesstif", pkgver: "6.3-046+1ubuntu7.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package vim-lesstif-',found,' is vulnerable in Ubuntu 5.04
Upgrade it to vim-lesstif-6.3-046+1ubuntu7.1
');
}
found = ubuntu_check(osver: "5.04", pkgname: "vim-perl", pkgver: "6.3-046+1ubuntu7.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package vim-perl-',found,' is vulnerable in Ubuntu 5.04
Upgrade it to vim-perl-6.3-046+1ubuntu7.1
');
}
found = ubuntu_check(osver: "5.04", pkgname: "vim-python", pkgver: "6.3-046+1ubuntu7.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package vim-python-',found,' is vulnerable in Ubuntu 5.04
Upgrade it to vim-python-6.3-046+1ubuntu7.1
');
}
found = ubuntu_check(osver: "5.04", pkgname: "vim-tcl", pkgver: "6.3-046+1ubuntu7.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package vim-tcl-',found,' is vulnerable in Ubuntu 5.04
Upgrade it to vim-tcl-6.3-046+1ubuntu7.1
');
}

if (w) { security_hole(port: 0, extra: extrarep); }
else exit(0, "Host is not vulnerable");
