# This script was automatically generated from the 463-1 Ubuntu Security Notice
# It is released under the Nessus Script Licence.
# Ubuntu Security Notices are (C) 2005 Canonical, Inc.
# USN2nasl Convertor is (C) 2005 Tenable Network Security, Inc.
# See http://www.ubuntulinux.org/usn/
# Ubuntu(R) is a registered trademark of Canonical, Inc.

if (! defined_func("bn_random")) exit(0);
include('compat.inc');

if (description) {
script_id(28063);
script_version("$Revision: 1.3 $");
script_copyright("Ubuntu Security Notice (C) 2009 Canonical, Inc. / NASL script (C) 2009 Tenable Network Security, Inc.");
script_category(ACT_GATHER_INFO);
script_family(english: "Ubuntu Local Security Checks");
script_dependencies("ssh_get_info.nasl");
script_require_keys("Host/Ubuntu", "Host/Ubuntu/release", "Host/Debian/dpkg-l");

script_xref(name: "USN", value: "463-1");
script_summary(english:"vim vulnerability");
script_name(english:"USN463-1 : vim vulnerability");
script_set_attribute(attribute:'synopsis', value: 'These remote packages are missing security patches :
- vim 
- vim-common 
- vim-doc 
- vim-full 
- vim-gnome 
- vim-gtk 
- vim-gui-common 
- vim-perl 
- vim-python 
- vim-ruby 
- vim-runtime 
- vim-tcl 
- vim-tiny 
');
script_set_attribute(attribute:'description', value: 'Tomas Golembiovsky discovered that some vim commands were accidentally
allowed in modelines.  By tricking a user into opening a specially
crafted file in vim, an attacker could execute arbitrary code with user
privileges.');
script_set_attribute(attribute:'solution', value: 'Upgrade to : 
- vim-7.0-164+1ubuntu7.1 (Ubuntu 7.04)
- vim-common-7.0-164+1ubuntu7.1 (Ubuntu 7.04)
- vim-doc-7.0-164+1ubuntu7.1 (Ubuntu 7.04)
- vim-full-7.0-164+1ubuntu7.1 (Ubuntu 7.04)
- vim-gnome-7.0-164+1ubuntu7.1 (Ubuntu 7.04)
- vim-gtk-7.0-164+1ubuntu7.1 (Ubuntu 7.04)
- vim-gui-common-7.0-164+1ubuntu7.1 (Ubuntu 7.04)
- vim-perl-7.0-164+1ubuntu7.1 (Ubuntu 7.04)
- vim-python-7.0-164+1ubuntu7.1 (Ubuntu 7.04)
- vim-ruby-7.0-164+1ubuntu7.1 (Ubuntu 7.04)
- vim-runtime-7.0-164+1ubuntu7.1 (Ubuntu 7.04)
- vim-
[...]');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:H/Au:N/C:C/I:C/A:C');
script_end_attributes();

script_cve_id("CVE-2007-2438");
exit(0);
}

include('ubuntu.inc');

if ( ! get_kb_item('Host/Ubuntu/release') ) exit(1, 'Could not gather the list of packages');

extrarep = NULL;

found = ubuntu_check(osver: "7.04", pkgname: "vim", pkgver: "7.0-164+1ubuntu7.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package vim-',found,' is vulnerable in Ubuntu 7.04
Upgrade it to vim-7.0-164+1ubuntu7.1
');
}
found = ubuntu_check(osver: "7.04", pkgname: "vim-common", pkgver: "7.0-164+1ubuntu7.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package vim-common-',found,' is vulnerable in Ubuntu 7.04
Upgrade it to vim-common-7.0-164+1ubuntu7.1
');
}
found = ubuntu_check(osver: "7.04", pkgname: "vim-doc", pkgver: "7.0-164+1ubuntu7.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package vim-doc-',found,' is vulnerable in Ubuntu 7.04
Upgrade it to vim-doc-7.0-164+1ubuntu7.1
');
}
found = ubuntu_check(osver: "7.04", pkgname: "vim-full", pkgver: "7.0-164+1ubuntu7.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package vim-full-',found,' is vulnerable in Ubuntu 7.04
Upgrade it to vim-full-7.0-164+1ubuntu7.1
');
}
found = ubuntu_check(osver: "7.04", pkgname: "vim-gnome", pkgver: "7.0-164+1ubuntu7.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package vim-gnome-',found,' is vulnerable in Ubuntu 7.04
Upgrade it to vim-gnome-7.0-164+1ubuntu7.1
');
}
found = ubuntu_check(osver: "7.04", pkgname: "vim-gtk", pkgver: "7.0-164+1ubuntu7.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package vim-gtk-',found,' is vulnerable in Ubuntu 7.04
Upgrade it to vim-gtk-7.0-164+1ubuntu7.1
');
}
found = ubuntu_check(osver: "7.04", pkgname: "vim-gui-common", pkgver: "7.0-164+1ubuntu7.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package vim-gui-common-',found,' is vulnerable in Ubuntu 7.04
Upgrade it to vim-gui-common-7.0-164+1ubuntu7.1
');
}
found = ubuntu_check(osver: "7.04", pkgname: "vim-perl", pkgver: "7.0-164+1ubuntu7.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package vim-perl-',found,' is vulnerable in Ubuntu 7.04
Upgrade it to vim-perl-7.0-164+1ubuntu7.1
');
}
found = ubuntu_check(osver: "7.04", pkgname: "vim-python", pkgver: "7.0-164+1ubuntu7.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package vim-python-',found,' is vulnerable in Ubuntu 7.04
Upgrade it to vim-python-7.0-164+1ubuntu7.1
');
}
found = ubuntu_check(osver: "7.04", pkgname: "vim-ruby", pkgver: "7.0-164+1ubuntu7.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package vim-ruby-',found,' is vulnerable in Ubuntu 7.04
Upgrade it to vim-ruby-7.0-164+1ubuntu7.1
');
}
found = ubuntu_check(osver: "7.04", pkgname: "vim-runtime", pkgver: "7.0-164+1ubuntu7.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package vim-runtime-',found,' is vulnerable in Ubuntu 7.04
Upgrade it to vim-runtime-7.0-164+1ubuntu7.1
');
}
found = ubuntu_check(osver: "7.04", pkgname: "vim-tcl", pkgver: "7.0-164+1ubuntu7.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package vim-tcl-',found,' is vulnerable in Ubuntu 7.04
Upgrade it to vim-tcl-7.0-164+1ubuntu7.1
');
}
found = ubuntu_check(osver: "7.04", pkgname: "vim-tiny", pkgver: "7.0-164+1ubuntu7.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package vim-tiny-',found,' is vulnerable in Ubuntu 7.04
Upgrade it to vim-tiny-7.0-164+1ubuntu7.1
');
}

if (w) { security_hole(port: 0, extra: extrarep); }
else exit(0, "Host is not vulnerable");
