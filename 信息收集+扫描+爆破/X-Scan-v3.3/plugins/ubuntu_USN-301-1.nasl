# This script was automatically generated from the 301-1 Ubuntu Security Notice
# It is released under the Nessus Script Licence.
# Ubuntu Security Notices are (C) 2005 Canonical, Inc.
# USN2nasl Convertor is (C) 2005 Tenable Network Security, Inc.
# See http://www.ubuntulinux.org/usn/
# Ubuntu(R) is a registered trademark of Canonical, Inc.

if (! defined_func("bn_random")) exit(0);
include('compat.inc');

if (description) {
script_id(27876);
script_version("$Revision: 1.3 $");
script_copyright("Ubuntu Security Notice (C) 2009 Canonical, Inc. / NASL script (C) 2009 Tenable Network Security, Inc.");
script_category(ACT_GATHER_INFO);
script_family(english: "Ubuntu Local Security Checks");
script_dependencies("ssh_get_info.nasl");
script_require_keys("Host/Ubuntu", "Host/Ubuntu/release", "Host/Debian/dpkg-l");

script_xref(name: "USN", value: "301-1");
script_summary(english:"kdm vulnerability");
script_name(english:"USN301-1 : kdm vulnerability");
script_set_attribute(attribute:'synopsis', value: 'These remote packages are missing security patches :
- kappfinder 
- kate 
- kcontrol 
- kdebase 
- kdebase-bin 
- kdebase-data 
- kdebase-dev 
- kdebase-doc 
- kdebase-doc-html 
- kdebase-kio-plugins 
- kdepasswd 
- kdeprint 
- kdesktop 
- kdm 
- kfind 
- khelpcenter 
- kicker 
- klipper 
- kmenuedit 
- konqueror 
- konqueror-nsplugins 
- konsole 
- kpager 
- kpersonalizer 
- ksmserver 
- ksplash 
- ksysguard 
- ksysguardd 
- ktip 
- kwin 
- libkonq4 
- libkonq4-dev 
- xfonts-konsole 
');
script_set_attribute(attribute:'description', value: 'Ludwig Nussel discovered that kdm managed the ~/.dmrc file in an
insecure way. By performing a symlink attack, a local user could
exploit this to read arbitrary files on the system, like private files
of other users, /etc/shadow, and similarly sensitive data.');
script_set_attribute(attribute:'solution', value: 'Upgrade to : 
- kappfinder-3.5.2-0ubuntu27 (Ubuntu 6.06)
- kate-3.5.2-0ubuntu27 (Ubuntu 6.06)
- kcontrol-3.5.2-0ubuntu27 (Ubuntu 6.06)
- kdebase-3.5.2-0ubuntu27 (Ubuntu 6.06)
- kdebase-bin-3.5.2-0ubuntu27 (Ubuntu 6.06)
- kdebase-data-3.5.2-0ubuntu27 (Ubuntu 6.06)
- kdebase-dev-3.5.2-0ubuntu27 (Ubuntu 6.06)
- kdebase-doc-3.5.2-0ubuntu27 (Ubuntu 6.06)
- kdebase-doc-html-3.5.2-0ubuntu27 (Ubuntu 6.06)
- kdebase-kio-plugins-3.5.2-0ubuntu27 (Ubuntu 6.06)
- kdepasswd-3.5.2-0ubuntu27 (Ubuntu 6.06)
- kdeprint-3.5.2
[...]');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:L/AC:H/Au:N/C:C/I:N/A:N');
script_end_attributes();

script_cve_id("CVE-2006-2449");
exit(0);
}

include('ubuntu.inc');

if ( ! get_kb_item('Host/Ubuntu/release') ) exit(1, 'Could not gather the list of packages');

extrarep = NULL;

found = ubuntu_check(osver: "6.06", pkgname: "kappfinder", pkgver: "3.5.2-0ubuntu27");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package kappfinder-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to kappfinder-3.5.2-0ubuntu27
');
}
found = ubuntu_check(osver: "6.06", pkgname: "kate", pkgver: "3.5.2-0ubuntu27");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package kate-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to kate-3.5.2-0ubuntu27
');
}
found = ubuntu_check(osver: "6.06", pkgname: "kcontrol", pkgver: "3.5.2-0ubuntu27");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package kcontrol-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to kcontrol-3.5.2-0ubuntu27
');
}
found = ubuntu_check(osver: "6.06", pkgname: "kdebase", pkgver: "3.5.2-0ubuntu27");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package kdebase-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to kdebase-3.5.2-0ubuntu27
');
}
found = ubuntu_check(osver: "6.06", pkgname: "kdebase-bin", pkgver: "3.5.2-0ubuntu27");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package kdebase-bin-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to kdebase-bin-3.5.2-0ubuntu27
');
}
found = ubuntu_check(osver: "6.06", pkgname: "kdebase-data", pkgver: "3.5.2-0ubuntu27");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package kdebase-data-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to kdebase-data-3.5.2-0ubuntu27
');
}
found = ubuntu_check(osver: "6.06", pkgname: "kdebase-dev", pkgver: "3.5.2-0ubuntu27");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package kdebase-dev-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to kdebase-dev-3.5.2-0ubuntu27
');
}
found = ubuntu_check(osver: "6.06", pkgname: "kdebase-doc", pkgver: "3.5.2-0ubuntu27");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package kdebase-doc-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to kdebase-doc-3.5.2-0ubuntu27
');
}
found = ubuntu_check(osver: "6.06", pkgname: "kdebase-doc-html", pkgver: "3.5.2-0ubuntu27");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package kdebase-doc-html-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to kdebase-doc-html-3.5.2-0ubuntu27
');
}
found = ubuntu_check(osver: "6.06", pkgname: "kdebase-kio-plugins", pkgver: "3.5.2-0ubuntu27");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package kdebase-kio-plugins-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to kdebase-kio-plugins-3.5.2-0ubuntu27
');
}
found = ubuntu_check(osver: "6.06", pkgname: "kdepasswd", pkgver: "3.5.2-0ubuntu27");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package kdepasswd-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to kdepasswd-3.5.2-0ubuntu27
');
}
found = ubuntu_check(osver: "6.06", pkgname: "kdeprint", pkgver: "3.5.2-0ubuntu27");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package kdeprint-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to kdeprint-3.5.2-0ubuntu27
');
}
found = ubuntu_check(osver: "6.06", pkgname: "kdesktop", pkgver: "3.5.2-0ubuntu27");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package kdesktop-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to kdesktop-3.5.2-0ubuntu27
');
}
found = ubuntu_check(osver: "6.06", pkgname: "kdm", pkgver: "3.5.2-0ubuntu27");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package kdm-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to kdm-3.5.2-0ubuntu27
');
}
found = ubuntu_check(osver: "6.06", pkgname: "kfind", pkgver: "3.5.2-0ubuntu27");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package kfind-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to kfind-3.5.2-0ubuntu27
');
}
found = ubuntu_check(osver: "6.06", pkgname: "khelpcenter", pkgver: "3.5.2-0ubuntu27");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package khelpcenter-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to khelpcenter-3.5.2-0ubuntu27
');
}
found = ubuntu_check(osver: "6.06", pkgname: "kicker", pkgver: "3.5.2-0ubuntu27");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package kicker-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to kicker-3.5.2-0ubuntu27
');
}
found = ubuntu_check(osver: "6.06", pkgname: "klipper", pkgver: "3.5.2-0ubuntu27");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package klipper-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to klipper-3.5.2-0ubuntu27
');
}
found = ubuntu_check(osver: "6.06", pkgname: "kmenuedit", pkgver: "3.5.2-0ubuntu27");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package kmenuedit-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to kmenuedit-3.5.2-0ubuntu27
');
}
found = ubuntu_check(osver: "6.06", pkgname: "konqueror", pkgver: "3.5.2-0ubuntu27");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package konqueror-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to konqueror-3.5.2-0ubuntu27
');
}
found = ubuntu_check(osver: "6.06", pkgname: "konqueror-nsplugins", pkgver: "3.5.2-0ubuntu27");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package konqueror-nsplugins-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to konqueror-nsplugins-3.5.2-0ubuntu27
');
}
found = ubuntu_check(osver: "6.06", pkgname: "konsole", pkgver: "3.5.2-0ubuntu27");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package konsole-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to konsole-3.5.2-0ubuntu27
');
}
found = ubuntu_check(osver: "6.06", pkgname: "kpager", pkgver: "3.5.2-0ubuntu27");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package kpager-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to kpager-3.5.2-0ubuntu27
');
}
found = ubuntu_check(osver: "6.06", pkgname: "kpersonalizer", pkgver: "3.5.2-0ubuntu27");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package kpersonalizer-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to kpersonalizer-3.5.2-0ubuntu27
');
}
found = ubuntu_check(osver: "6.06", pkgname: "ksmserver", pkgver: "3.5.2-0ubuntu27");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package ksmserver-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to ksmserver-3.5.2-0ubuntu27
');
}
found = ubuntu_check(osver: "6.06", pkgname: "ksplash", pkgver: "3.5.2-0ubuntu27");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package ksplash-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to ksplash-3.5.2-0ubuntu27
');
}
found = ubuntu_check(osver: "6.06", pkgname: "ksysguard", pkgver: "3.5.2-0ubuntu27");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package ksysguard-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to ksysguard-3.5.2-0ubuntu27
');
}
found = ubuntu_check(osver: "6.06", pkgname: "ksysguardd", pkgver: "3.5.2-0ubuntu27");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package ksysguardd-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to ksysguardd-3.5.2-0ubuntu27
');
}
found = ubuntu_check(osver: "6.06", pkgname: "ktip", pkgver: "3.5.2-0ubuntu27");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package ktip-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to ktip-3.5.2-0ubuntu27
');
}
found = ubuntu_check(osver: "6.06", pkgname: "kwin", pkgver: "3.5.2-0ubuntu27");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package kwin-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to kwin-3.5.2-0ubuntu27
');
}
found = ubuntu_check(osver: "6.06", pkgname: "libkonq4", pkgver: "3.5.2-0ubuntu27");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libkonq4-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to libkonq4-3.5.2-0ubuntu27
');
}
found = ubuntu_check(osver: "6.06", pkgname: "libkonq4-dev", pkgver: "3.5.2-0ubuntu27");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libkonq4-dev-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to libkonq4-dev-3.5.2-0ubuntu27
');
}
found = ubuntu_check(osver: "5.10", pkgname: "xfonts-konsole", pkgver: "3.4.3-0ubuntu7");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package xfonts-konsole-',found,' is vulnerable in Ubuntu 5.10
Upgrade it to xfonts-konsole-3.4.3-0ubuntu7
');
}

if (w) { security_warning(port: 0, extra: extrarep); }
else exit(0, "Host is not vulnerable");
