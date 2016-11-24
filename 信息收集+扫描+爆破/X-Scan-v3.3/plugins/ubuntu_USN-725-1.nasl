# This script was automatically generated from the 725-1 Ubuntu Security Notice
# It is released under the Nessus Script Licence.
# Ubuntu Security Notices are (C) 2005 Canonical, Inc.
# USN2nasl Convertor is (C) 2005 Tenable Network Security, Inc.
# See http://www.ubuntulinux.org/usn/
# Ubuntu(R) is a registered trademark of Canonical, Inc.

if (! defined_func("bn_random")) exit(0);
include('compat.inc');

if (description) {
script_id(37810);
script_version("$Revision: 1.1 $");
script_copyright("Ubuntu Security Notice (C) 2009 Canonical, Inc. / NASL script (C) 2009 Tenable Network Security, Inc.");
script_category(ACT_GATHER_INFO);
script_family(english: "Ubuntu Local Security Checks");
script_dependencies("ssh_get_info.nasl");
script_require_keys("Host/Ubuntu", "Host/Ubuntu/release", "Host/Debian/dpkg-l");

script_xref(name: "USN", value: "725-1");
script_summary(english:"kdepim vulnerability");
script_name(english:"USN725-1 : kdepim vulnerability");
script_set_attribute(attribute:'synopsis', value: 'These remote packages are missing security patches :
- akregator 
- kaddressbook 
- kalarm 
- kandy 
- karm 
- kdepim 
- kdepim-dbg 
- kdepim-dev 
- kdepim-doc 
- kdepim-doc-html 
- kdepim-kfile-plugins 
- kdepim-kio-plugins 
- kdepim-kresources 
- kdepim-wizards 
- kitchensync 
- kleopatra 
- kmail 
- kmailcvt 
- knode 
- knotes 
- kode 
- konsolekalendar 
- kontact 
- korganizer 
- korn 
- kpilot 
- ksync 
- ktnef 
- libindex0 
- libindex0-dev 
- libkcal2-dev 
- libkcal2b 
- libkdepim1-dev 
- libkdepim1a
[...]');
script_set_attribute(attribute:'description', value: 'It was discovered that Kmail did not adequately prevent execution of arbitrary
code when a user clicked on a URL to an executable within an HTML mail. If a
user clicked on a malicious URL and chose to execute the file, a remote
attacker could execute arbitrary code with user privileges. This update changes
KMail\'s behavior to instead launch a helper program to view the file if the
user chooses to execute such a link.');
script_set_attribute(attribute:'solution', value: 'Upgrade to : 
- akregator-3.5.7enterprise20070926-0ubuntu2.2 (Ubuntu 7.10)
- kaddressbook-3.5.7enterprise20070926-0ubuntu2.2 (Ubuntu 7.10)
- kalarm-3.5.7enterprise20070926-0ubuntu2.2 (Ubuntu 7.10)
- kandy-3.5.7enterprise20070926-0ubuntu2.2 (Ubuntu 7.10)
- karm-3.5.7enterprise20070926-0ubuntu2.2 (Ubuntu 7.10)
- kdepim-3.5.7enterprise20070926-0ubuntu2.2 (Ubuntu 7.10)
- kdepim-dbg-3.5.7enterprise20070926-0ubuntu2.2 (Ubuntu 7.10)
- kdepim-dev-3.5.7enterprise20070926-0ubuntu2.2 (Ubuntu 7.10)
- kdepim-doc-3.5.7e
[...]');
script_set_attribute(attribute: 'risk_factor', value: 'High');
script_end_attributes();

exit(0);
}

include('ubuntu.inc');

if ( ! get_kb_item('Host/Ubuntu/release') ) exit(1, 'Could not gather the list of packages');

extrarep = NULL;

found = ubuntu_check(osver: "7.10", pkgname: "akregator", pkgver: "3.5.7enterprise20070926-0ubuntu2.2");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package akregator-',found,' is vulnerable in Ubuntu 7.10
Upgrade it to akregator-3.5.7enterprise20070926-0ubuntu2.2
');
}
found = ubuntu_check(osver: "7.10", pkgname: "kaddressbook", pkgver: "3.5.7enterprise20070926-0ubuntu2.2");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package kaddressbook-',found,' is vulnerable in Ubuntu 7.10
Upgrade it to kaddressbook-3.5.7enterprise20070926-0ubuntu2.2
');
}
found = ubuntu_check(osver: "7.10", pkgname: "kalarm", pkgver: "3.5.7enterprise20070926-0ubuntu2.2");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package kalarm-',found,' is vulnerable in Ubuntu 7.10
Upgrade it to kalarm-3.5.7enterprise20070926-0ubuntu2.2
');
}
found = ubuntu_check(osver: "7.10", pkgname: "kandy", pkgver: "3.5.7enterprise20070926-0ubuntu2.2");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package kandy-',found,' is vulnerable in Ubuntu 7.10
Upgrade it to kandy-3.5.7enterprise20070926-0ubuntu2.2
');
}
found = ubuntu_check(osver: "7.10", pkgname: "karm", pkgver: "3.5.7enterprise20070926-0ubuntu2.2");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package karm-',found,' is vulnerable in Ubuntu 7.10
Upgrade it to karm-3.5.7enterprise20070926-0ubuntu2.2
');
}
found = ubuntu_check(osver: "7.10", pkgname: "kdepim", pkgver: "3.5.7enterprise20070926-0ubuntu2.2");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package kdepim-',found,' is vulnerable in Ubuntu 7.10
Upgrade it to kdepim-3.5.7enterprise20070926-0ubuntu2.2
');
}
found = ubuntu_check(osver: "7.10", pkgname: "kdepim-dbg", pkgver: "3.5.7enterprise20070926-0ubuntu2.2");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package kdepim-dbg-',found,' is vulnerable in Ubuntu 7.10
Upgrade it to kdepim-dbg-3.5.7enterprise20070926-0ubuntu2.2
');
}
found = ubuntu_check(osver: "7.10", pkgname: "kdepim-dev", pkgver: "3.5.7enterprise20070926-0ubuntu2.2");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package kdepim-dev-',found,' is vulnerable in Ubuntu 7.10
Upgrade it to kdepim-dev-3.5.7enterprise20070926-0ubuntu2.2
');
}
found = ubuntu_check(osver: "7.10", pkgname: "kdepim-doc", pkgver: "3.5.7enterprise20070926-0ubuntu2.2");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package kdepim-doc-',found,' is vulnerable in Ubuntu 7.10
Upgrade it to kdepim-doc-3.5.7enterprise20070926-0ubuntu2.2
');
}
found = ubuntu_check(osver: "7.10", pkgname: "kdepim-doc-html", pkgver: "3.5.7enterprise20070926-0ubuntu2.2");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package kdepim-doc-html-',found,' is vulnerable in Ubuntu 7.10
Upgrade it to kdepim-doc-html-3.5.7enterprise20070926-0ubuntu2.2
');
}
found = ubuntu_check(osver: "7.10", pkgname: "kdepim-kfile-plugins", pkgver: "3.5.7enterprise20070926-0ubuntu2.2");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package kdepim-kfile-plugins-',found,' is vulnerable in Ubuntu 7.10
Upgrade it to kdepim-kfile-plugins-3.5.7enterprise20070926-0ubuntu2.2
');
}
found = ubuntu_check(osver: "7.10", pkgname: "kdepim-kio-plugins", pkgver: "3.5.7enterprise20070926-0ubuntu2.2");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package kdepim-kio-plugins-',found,' is vulnerable in Ubuntu 7.10
Upgrade it to kdepim-kio-plugins-3.5.7enterprise20070926-0ubuntu2.2
');
}
found = ubuntu_check(osver: "7.10", pkgname: "kdepim-kresources", pkgver: "3.5.7enterprise20070926-0ubuntu2.2");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package kdepim-kresources-',found,' is vulnerable in Ubuntu 7.10
Upgrade it to kdepim-kresources-3.5.7enterprise20070926-0ubuntu2.2
');
}
found = ubuntu_check(osver: "7.10", pkgname: "kdepim-wizards", pkgver: "3.5.7enterprise20070926-0ubuntu2.2");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package kdepim-wizards-',found,' is vulnerable in Ubuntu 7.10
Upgrade it to kdepim-wizards-3.5.7enterprise20070926-0ubuntu2.2
');
}
found = ubuntu_check(osver: "7.10", pkgname: "kitchensync", pkgver: "3.5.7enterprise20070926-0ubuntu2.2");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package kitchensync-',found,' is vulnerable in Ubuntu 7.10
Upgrade it to kitchensync-3.5.7enterprise20070926-0ubuntu2.2
');
}
found = ubuntu_check(osver: "7.10", pkgname: "kleopatra", pkgver: "3.5.7enterprise20070926-0ubuntu2.2");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package kleopatra-',found,' is vulnerable in Ubuntu 7.10
Upgrade it to kleopatra-3.5.7enterprise20070926-0ubuntu2.2
');
}
found = ubuntu_check(osver: "7.10", pkgname: "kmail", pkgver: "3.5.7enterprise20070926-0ubuntu2.2");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package kmail-',found,' is vulnerable in Ubuntu 7.10
Upgrade it to kmail-3.5.7enterprise20070926-0ubuntu2.2
');
}
found = ubuntu_check(osver: "7.10", pkgname: "kmailcvt", pkgver: "3.5.7enterprise20070926-0ubuntu2.2");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package kmailcvt-',found,' is vulnerable in Ubuntu 7.10
Upgrade it to kmailcvt-3.5.7enterprise20070926-0ubuntu2.2
');
}
found = ubuntu_check(osver: "7.10", pkgname: "knode", pkgver: "3.5.7enterprise20070926-0ubuntu2.2");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package knode-',found,' is vulnerable in Ubuntu 7.10
Upgrade it to knode-3.5.7enterprise20070926-0ubuntu2.2
');
}
found = ubuntu_check(osver: "7.10", pkgname: "knotes", pkgver: "3.5.7enterprise20070926-0ubuntu2.2");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package knotes-',found,' is vulnerable in Ubuntu 7.10
Upgrade it to knotes-3.5.7enterprise20070926-0ubuntu2.2
');
}
found = ubuntu_check(osver: "7.10", pkgname: "kode", pkgver: "3.5.7enterprise20070926-0ubuntu2.2");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package kode-',found,' is vulnerable in Ubuntu 7.10
Upgrade it to kode-3.5.7enterprise20070926-0ubuntu2.2
');
}
found = ubuntu_check(osver: "7.10", pkgname: "konsolekalendar", pkgver: "3.5.7enterprise20070926-0ubuntu2.2");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package konsolekalendar-',found,' is vulnerable in Ubuntu 7.10
Upgrade it to konsolekalendar-3.5.7enterprise20070926-0ubuntu2.2
');
}
found = ubuntu_check(osver: "7.10", pkgname: "kontact", pkgver: "3.5.7enterprise20070926-0ubuntu2.2");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package kontact-',found,' is vulnerable in Ubuntu 7.10
Upgrade it to kontact-3.5.7enterprise20070926-0ubuntu2.2
');
}
found = ubuntu_check(osver: "7.10", pkgname: "korganizer", pkgver: "3.5.7enterprise20070926-0ubuntu2.2");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package korganizer-',found,' is vulnerable in Ubuntu 7.10
Upgrade it to korganizer-3.5.7enterprise20070926-0ubuntu2.2
');
}
found = ubuntu_check(osver: "7.10", pkgname: "korn", pkgver: "3.5.7enterprise20070926-0ubuntu2.2");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package korn-',found,' is vulnerable in Ubuntu 7.10
Upgrade it to korn-3.5.7enterprise20070926-0ubuntu2.2
');
}
found = ubuntu_check(osver: "7.10", pkgname: "kpilot", pkgver: "3.5.7enterprise20070926-0ubuntu2.2");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package kpilot-',found,' is vulnerable in Ubuntu 7.10
Upgrade it to kpilot-3.5.7enterprise20070926-0ubuntu2.2
');
}
found = ubuntu_check(osver: "6.06", pkgname: "ksync", pkgver: "3.5.2-0ubuntu6.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package ksync-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to ksync-3.5.2-0ubuntu6.1
');
}
found = ubuntu_check(osver: "7.10", pkgname: "ktnef", pkgver: "3.5.7enterprise20070926-0ubuntu2.2");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package ktnef-',found,' is vulnerable in Ubuntu 7.10
Upgrade it to ktnef-3.5.7enterprise20070926-0ubuntu2.2
');
}
found = ubuntu_check(osver: "7.10", pkgname: "libindex0", pkgver: "3.5.7enterprise20070926-0ubuntu2.2");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libindex0-',found,' is vulnerable in Ubuntu 7.10
Upgrade it to libindex0-3.5.7enterprise20070926-0ubuntu2.2
');
}
found = ubuntu_check(osver: "7.10", pkgname: "libindex0-dev", pkgver: "3.5.7enterprise20070926-0ubuntu2.2");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libindex0-dev-',found,' is vulnerable in Ubuntu 7.10
Upgrade it to libindex0-dev-3.5.7enterprise20070926-0ubuntu2.2
');
}
found = ubuntu_check(osver: "7.10", pkgname: "libkcal2-dev", pkgver: "3.5.7enterprise20070926-0ubuntu2.2");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libkcal2-dev-',found,' is vulnerable in Ubuntu 7.10
Upgrade it to libkcal2-dev-3.5.7enterprise20070926-0ubuntu2.2
');
}
found = ubuntu_check(osver: "7.10", pkgname: "libkcal2b", pkgver: "3.5.7enterprise20070926-0ubuntu2.2");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libkcal2b-',found,' is vulnerable in Ubuntu 7.10
Upgrade it to libkcal2b-3.5.7enterprise20070926-0ubuntu2.2
');
}
found = ubuntu_check(osver: "7.10", pkgname: "libkdepim1-dev", pkgver: "3.5.7enterprise20070926-0ubuntu2.2");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libkdepim1-dev-',found,' is vulnerable in Ubuntu 7.10
Upgrade it to libkdepim1-dev-3.5.7enterprise20070926-0ubuntu2.2
');
}
found = ubuntu_check(osver: "7.10", pkgname: "libkdepim1a", pkgver: "3.5.7enterprise20070926-0ubuntu2.2");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libkdepim1a-',found,' is vulnerable in Ubuntu 7.10
Upgrade it to libkdepim1a-3.5.7enterprise20070926-0ubuntu2.2
');
}
found = ubuntu_check(osver: "7.10", pkgname: "libkgantt0", pkgver: "3.5.7enterprise20070926-0ubuntu2.2");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libkgantt0-',found,' is vulnerable in Ubuntu 7.10
Upgrade it to libkgantt0-3.5.7enterprise20070926-0ubuntu2.2
');
}
found = ubuntu_check(osver: "7.10", pkgname: "libkgantt0-dev", pkgver: "3.5.7enterprise20070926-0ubuntu2.2");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libkgantt0-dev-',found,' is vulnerable in Ubuntu 7.10
Upgrade it to libkgantt0-dev-3.5.7enterprise20070926-0ubuntu2.2
');
}
found = ubuntu_check(osver: "7.10", pkgname: "libkleopatra1", pkgver: "3.5.7enterprise20070926-0ubuntu2.2");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libkleopatra1-',found,' is vulnerable in Ubuntu 7.10
Upgrade it to libkleopatra1-3.5.7enterprise20070926-0ubuntu2.2
');
}
found = ubuntu_check(osver: "7.10", pkgname: "libkleopatra1-dev", pkgver: "3.5.7enterprise20070926-0ubuntu2.2");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libkleopatra1-dev-',found,' is vulnerable in Ubuntu 7.10
Upgrade it to libkleopatra1-dev-3.5.7enterprise20070926-0ubuntu2.2
');
}
found = ubuntu_check(osver: "7.10", pkgname: "libkmime2", pkgver: "3.5.7enterprise20070926-0ubuntu2.2");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libkmime2-',found,' is vulnerable in Ubuntu 7.10
Upgrade it to libkmime2-3.5.7enterprise20070926-0ubuntu2.2
');
}
found = ubuntu_check(osver: "7.10", pkgname: "libkpimexchange1", pkgver: "3.5.7enterprise20070926-0ubuntu2.2");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libkpimexchange1-',found,' is vulnerable in Ubuntu 7.10
Upgrade it to libkpimexchange1-3.5.7enterprise20070926-0ubuntu2.2
');
}
found = ubuntu_check(osver: "7.10", pkgname: "libkpimexchange1-dev", pkgver: "3.5.7enterprise20070926-0ubuntu2.2");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libkpimexchange1-dev-',found,' is vulnerable in Ubuntu 7.10
Upgrade it to libkpimexchange1-dev-3.5.7enterprise20070926-0ubuntu2.2
');
}
found = ubuntu_check(osver: "7.10", pkgname: "libkpimidentities1", pkgver: "3.5.7enterprise20070926-0ubuntu2.2");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libkpimidentities1-',found,' is vulnerable in Ubuntu 7.10
Upgrade it to libkpimidentities1-3.5.7enterprise20070926-0ubuntu2.2
');
}
found = ubuntu_check(osver: "7.10", pkgname: "libksieve0", pkgver: "3.5.7enterprise20070926-0ubuntu2.2");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libksieve0-',found,' is vulnerable in Ubuntu 7.10
Upgrade it to libksieve0-3.5.7enterprise20070926-0ubuntu2.2
');
}
found = ubuntu_check(osver: "7.10", pkgname: "libksieve0-dev", pkgver: "3.5.7enterprise20070926-0ubuntu2.2");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libksieve0-dev-',found,' is vulnerable in Ubuntu 7.10
Upgrade it to libksieve0-dev-3.5.7enterprise20070926-0ubuntu2.2
');
}
found = ubuntu_check(osver: "7.10", pkgname: "libktnef1", pkgver: "3.5.7enterprise20070926-0ubuntu2.2");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libktnef1-',found,' is vulnerable in Ubuntu 7.10
Upgrade it to libktnef1-3.5.7enterprise20070926-0ubuntu2.2
');
}
found = ubuntu_check(osver: "7.10", pkgname: "libktnef1-dev", pkgver: "3.5.7enterprise20070926-0ubuntu2.2");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libktnef1-dev-',found,' is vulnerable in Ubuntu 7.10
Upgrade it to libktnef1-dev-3.5.7enterprise20070926-0ubuntu2.2
');
}
found = ubuntu_check(osver: "7.10", pkgname: "libmimelib1-dev", pkgver: "3.5.7enterprise20070926-0ubuntu2.2");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libmimelib1-dev-',found,' is vulnerable in Ubuntu 7.10
Upgrade it to libmimelib1-dev-3.5.7enterprise20070926-0ubuntu2.2
');
}
found = ubuntu_check(osver: "7.10", pkgname: "libmimelib1c2a", pkgver: "3.5.7enterprise20070926-0ubuntu2.2");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libmimelib1c2a-',found,' is vulnerable in Ubuntu 7.10
Upgrade it to libmimelib1c2a-3.5.7enterprise20070926-0ubuntu2.2
');
}
found = ubuntu_check(osver: "7.10", pkgname: "networkstatus", pkgver: "3.5.7enterprise20070926-0ubuntu2.2");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package networkstatus-',found,' is vulnerable in Ubuntu 7.10
Upgrade it to networkstatus-3.5.7enterprise20070926-0ubuntu2.2
');
}
found = ubuntu_check(osver: "7.10", pkgname: "networkstatus-dev", pkgver: "3.5.7enterprise20070926-0ubuntu2.2");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package networkstatus-dev-',found,' is vulnerable in Ubuntu 7.10
Upgrade it to networkstatus-dev-3.5.7enterprise20070926-0ubuntu2.2
');
}

if (w) { security_hole(port: 0, extra: extrarep); }
else exit(0, "Host is not vulnerable");
