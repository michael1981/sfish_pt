# This script was automatically generated from the 409-1 Ubuntu Security Notice
# It is released under the Nessus Script Licence.
# Ubuntu Security Notices are (C) 2005 Canonical, Inc.
# USN2nasl Convertor is (C) 2005 Tenable Network Security, Inc.
# See http://www.ubuntulinux.org/usn/
# Ubuntu(R) is a registered trademark of Canonical, Inc.

if (! defined_func("bn_random")) exit(0);
include('compat.inc');

if (description) {
script_id(27997);
script_version("$Revision: 1.3 $");
script_copyright("Ubuntu Security Notice (C) 2009 Canonical, Inc. / NASL script (C) 2009 Tenable Network Security, Inc.");
script_category(ACT_GATHER_INFO);
script_family(english: "Ubuntu Local Security Checks");
script_dependencies("ssh_get_info.nasl");
script_require_keys("Host/Ubuntu", "Host/Ubuntu/release", "Host/Debian/dpkg-l");

script_xref(name: "USN", value: "409-1");
script_summary(english:"ksirc vulnerability");
script_name(english:"USN409-1 : ksirc vulnerability");
script_set_attribute(attribute:'synopsis', value: 'These remote packages are missing security patches :
- dcoprss 
- kdenetwork 
- kdenetwork-dbg 
- kdenetwork-dev 
- kdenetwork-doc-html 
- kdenetwork-filesharing 
- kdenetwork-kfile-plugins 
- kdict 
- kdnssd 
- kget 
- knewsticker 
- kopete 
- kpf 
- kppp 
- krdc 
- krfb 
- ksirc 
- ktalkd 
- kwifimanager 
- librss1 
- librss1-dev 
- lisa 
');
script_set_attribute(attribute:'description', value: 'Federico L. Bossi Bonin discovered a Denial of Service vulnerability
in ksirc. By sending a special response packet, a malicious IRC server
could crash ksirc.');
script_set_attribute(attribute:'solution', value: 'Upgrade to : 
- dcoprss-3.5.5-0ubuntu1.1 (Ubuntu 6.10)
- kdenetwork-3.5.5-0ubuntu1.1 (Ubuntu 6.10)
- kdenetwork-dbg-3.5.5-0ubuntu1.1 (Ubuntu 6.10)
- kdenetwork-dev-3.5.5-0ubuntu1.1 (Ubuntu 6.10)
- kdenetwork-doc-html-3.5.5-0ubuntu1.1 (Ubuntu 6.10)
- kdenetwork-filesharing-3.5.5-0ubuntu1.1 (Ubuntu 6.10)
- kdenetwork-kfile-plugins-3.5.5-0ubuntu1.1 (Ubuntu 6.10)
- kdict-3.5.5-0ubuntu1.1 (Ubuntu 6.10)
- kdnssd-3.5.5-0ubuntu1.1 (Ubuntu 6.10)
- kget-3.5.5-0ubuntu1.1 (Ubuntu 6.10)
- knewsticker-3.5.5-0ubuntu1.1 (
[...]');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:M/Au:N/C:N/I:N/A:P');
script_end_attributes();

script_cve_id("CVE-2006-6811");
exit(0);
}

include('ubuntu.inc');

if ( ! get_kb_item('Host/Ubuntu/release') ) exit(1, 'Could not gather the list of packages');

extrarep = NULL;

found = ubuntu_check(osver: "6.10", pkgname: "dcoprss", pkgver: "3.5.5-0ubuntu1.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package dcoprss-',found,' is vulnerable in Ubuntu 6.10
Upgrade it to dcoprss-3.5.5-0ubuntu1.1
');
}
found = ubuntu_check(osver: "6.10", pkgname: "kdenetwork", pkgver: "3.5.5-0ubuntu1.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package kdenetwork-',found,' is vulnerable in Ubuntu 6.10
Upgrade it to kdenetwork-3.5.5-0ubuntu1.1
');
}
found = ubuntu_check(osver: "6.10", pkgname: "kdenetwork-dbg", pkgver: "3.5.5-0ubuntu1.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package kdenetwork-dbg-',found,' is vulnerable in Ubuntu 6.10
Upgrade it to kdenetwork-dbg-3.5.5-0ubuntu1.1
');
}
found = ubuntu_check(osver: "6.10", pkgname: "kdenetwork-dev", pkgver: "3.5.5-0ubuntu1.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package kdenetwork-dev-',found,' is vulnerable in Ubuntu 6.10
Upgrade it to kdenetwork-dev-3.5.5-0ubuntu1.1
');
}
found = ubuntu_check(osver: "6.10", pkgname: "kdenetwork-doc-html", pkgver: "3.5.5-0ubuntu1.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package kdenetwork-doc-html-',found,' is vulnerable in Ubuntu 6.10
Upgrade it to kdenetwork-doc-html-3.5.5-0ubuntu1.1
');
}
found = ubuntu_check(osver: "6.10", pkgname: "kdenetwork-filesharing", pkgver: "3.5.5-0ubuntu1.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package kdenetwork-filesharing-',found,' is vulnerable in Ubuntu 6.10
Upgrade it to kdenetwork-filesharing-3.5.5-0ubuntu1.1
');
}
found = ubuntu_check(osver: "6.10", pkgname: "kdenetwork-kfile-plugins", pkgver: "3.5.5-0ubuntu1.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package kdenetwork-kfile-plugins-',found,' is vulnerable in Ubuntu 6.10
Upgrade it to kdenetwork-kfile-plugins-3.5.5-0ubuntu1.1
');
}
found = ubuntu_check(osver: "6.10", pkgname: "kdict", pkgver: "3.5.5-0ubuntu1.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package kdict-',found,' is vulnerable in Ubuntu 6.10
Upgrade it to kdict-3.5.5-0ubuntu1.1
');
}
found = ubuntu_check(osver: "6.10", pkgname: "kdnssd", pkgver: "3.5.5-0ubuntu1.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package kdnssd-',found,' is vulnerable in Ubuntu 6.10
Upgrade it to kdnssd-3.5.5-0ubuntu1.1
');
}
found = ubuntu_check(osver: "6.10", pkgname: "kget", pkgver: "3.5.5-0ubuntu1.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package kget-',found,' is vulnerable in Ubuntu 6.10
Upgrade it to kget-3.5.5-0ubuntu1.1
');
}
found = ubuntu_check(osver: "6.10", pkgname: "knewsticker", pkgver: "3.5.5-0ubuntu1.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package knewsticker-',found,' is vulnerable in Ubuntu 6.10
Upgrade it to knewsticker-3.5.5-0ubuntu1.1
');
}
found = ubuntu_check(osver: "6.06", pkgname: "kopete", pkgver: "3.5.2-0ubuntu6.3");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package kopete-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to kopete-3.5.2-0ubuntu6.3
');
}
found = ubuntu_check(osver: "6.10", pkgname: "kpf", pkgver: "3.5.5-0ubuntu1.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package kpf-',found,' is vulnerable in Ubuntu 6.10
Upgrade it to kpf-3.5.5-0ubuntu1.1
');
}
found = ubuntu_check(osver: "6.10", pkgname: "kppp", pkgver: "3.5.5-0ubuntu1.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package kppp-',found,' is vulnerable in Ubuntu 6.10
Upgrade it to kppp-3.5.5-0ubuntu1.1
');
}
found = ubuntu_check(osver: "6.10", pkgname: "krdc", pkgver: "3.5.5-0ubuntu1.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package krdc-',found,' is vulnerable in Ubuntu 6.10
Upgrade it to krdc-3.5.5-0ubuntu1.1
');
}
found = ubuntu_check(osver: "6.10", pkgname: "krfb", pkgver: "3.5.5-0ubuntu1.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package krfb-',found,' is vulnerable in Ubuntu 6.10
Upgrade it to krfb-3.5.5-0ubuntu1.1
');
}
found = ubuntu_check(osver: "6.10", pkgname: "ksirc", pkgver: "3.5.5-0ubuntu1.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package ksirc-',found,' is vulnerable in Ubuntu 6.10
Upgrade it to ksirc-3.5.5-0ubuntu1.1
');
}
found = ubuntu_check(osver: "6.10", pkgname: "ktalkd", pkgver: "3.5.5-0ubuntu1.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package ktalkd-',found,' is vulnerable in Ubuntu 6.10
Upgrade it to ktalkd-3.5.5-0ubuntu1.1
');
}
found = ubuntu_check(osver: "6.10", pkgname: "kwifimanager", pkgver: "3.5.5-0ubuntu1.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package kwifimanager-',found,' is vulnerable in Ubuntu 6.10
Upgrade it to kwifimanager-3.5.5-0ubuntu1.1
');
}
found = ubuntu_check(osver: "6.10", pkgname: "librss1", pkgver: "3.5.5-0ubuntu1.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package librss1-',found,' is vulnerable in Ubuntu 6.10
Upgrade it to librss1-3.5.5-0ubuntu1.1
');
}
found = ubuntu_check(osver: "5.10", pkgname: "librss1-dev", pkgver: "3.4.3-0ubuntu1.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package librss1-dev-',found,' is vulnerable in Ubuntu 5.10
Upgrade it to librss1-dev-3.4.3-0ubuntu1.1
');
}
found = ubuntu_check(osver: "6.10", pkgname: "lisa", pkgver: "3.5.5-0ubuntu1.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package lisa-',found,' is vulnerable in Ubuntu 6.10
Upgrade it to lisa-3.5.5-0ubuntu1.1
');
}

if (w) { security_warning(port: 0, extra: extrarep); }
else exit(0, "Host is not vulnerable");
