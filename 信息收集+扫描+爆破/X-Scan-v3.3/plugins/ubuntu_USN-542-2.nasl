# This script was automatically generated from the 542-2 Ubuntu Security Notice
# It is released under the Nessus Script Licence.
# Ubuntu Security Notices are (C) 2005 Canonical, Inc.
# USN2nasl Convertor is (C) 2005 Tenable Network Security, Inc.
# See http://www.ubuntulinux.org/usn/
# Ubuntu(R) is a registered trademark of Canonical, Inc.

if (! defined_func("bn_random")) exit(0);
include('compat.inc');

if (description) {
script_id(28249);
script_version("$Revision: 1.3 $");
script_copyright("Ubuntu Security Notice (C) 2009 Canonical, Inc. / NASL script (C) 2009 Tenable Network Security, Inc.");
script_category(ACT_GATHER_INFO);
script_family(english: "Ubuntu Local Security Checks");
script_dependencies("ssh_get_info.nasl");
script_require_keys("Host/Ubuntu", "Host/Ubuntu/release", "Host/Debian/dpkg-l");

script_xref(name: "USN", value: "542-2");
script_summary(english:"koffice vulnerabilities");
script_name(english:"USN542-2 : koffice vulnerabilities");
script_set_attribute(attribute:'synopsis', value: 'These remote packages are missing security patches :
- karbon 
- kchart 
- kexi 
- kformula 
- kivio 
- kivio-data 
- koffice 
- koffice-data 
- koffice-dbg 
- koffice-dev 
- koffice-doc 
- koffice-doc-html 
- koffice-libs 
- koshell 
- kplato 
- kpresenter 
- kpresenter-data 
- krita 
- krita-data 
- kspread 
- kthesaurus 
- kugar 
- kword 
- kword-data 
');
script_set_attribute(attribute:'description', value: 'USN-542-1 fixed a vulnerability in poppler. This update provides the
corresponding updates for KWord, part of KOffice.

Original advisory details:

 Secunia Research discovered several vulnerabilities in poppler. If a
 user were tricked into loading a specially crafted PDF file, a remote
 attacker could cause a denial of service or possibly execute arbitrary
 code with the user\'s privileges in applications linked against poppler.');
script_set_attribute(attribute:'solution', value: 'Upgrade to : 
- karbon-1.6.3-0ubuntu5.1 (Ubuntu 7.10)
- kchart-1.6.3-0ubuntu5.1 (Ubuntu 7.10)
- kexi-1.6.3-0ubuntu5.1 (Ubuntu 7.10)
- kformula-1.6.3-0ubuntu5.1 (Ubuntu 7.10)
- kivio-1.6.3-0ubuntu5.1 (Ubuntu 7.10)
- kivio-data-1.6.3-0ubuntu5.1 (Ubuntu 7.10)
- koffice-1.6.3-0ubuntu5.1 (Ubuntu 7.10)
- koffice-data-1.6.3-0ubuntu5.1 (Ubuntu 7.10)
- koffice-dbg-1.6.3-0ubuntu5.1 (Ubuntu 7.10)
- koffice-dev-1.6.3-0ubuntu5.1 (Ubuntu 7.10)
- koffice-doc-1.6.3-0ubuntu5.1 (Ubuntu 7.10)
- koffice-doc-html-1.6.3-0ubuntu
[...]');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C');
script_end_attributes();

script_cve_id("CVE-2007-4352","CVE-2007-5392","CVE-2007-5393");
exit(0);
}

include('ubuntu.inc');

if ( ! get_kb_item('Host/Ubuntu/release') ) exit(1, 'Could not gather the list of packages');

extrarep = NULL;

found = ubuntu_check(osver: "7.10", pkgname: "karbon", pkgver: "1.6.3-0ubuntu5.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package karbon-',found,' is vulnerable in Ubuntu 7.10
Upgrade it to karbon-1.6.3-0ubuntu5.1
');
}
found = ubuntu_check(osver: "7.10", pkgname: "kchart", pkgver: "1.6.3-0ubuntu5.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package kchart-',found,' is vulnerable in Ubuntu 7.10
Upgrade it to kchart-1.6.3-0ubuntu5.1
');
}
found = ubuntu_check(osver: "7.10", pkgname: "kexi", pkgver: "1.6.3-0ubuntu5.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package kexi-',found,' is vulnerable in Ubuntu 7.10
Upgrade it to kexi-1.6.3-0ubuntu5.1
');
}
found = ubuntu_check(osver: "7.10", pkgname: "kformula", pkgver: "1.6.3-0ubuntu5.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package kformula-',found,' is vulnerable in Ubuntu 7.10
Upgrade it to kformula-1.6.3-0ubuntu5.1
');
}
found = ubuntu_check(osver: "7.10", pkgname: "kivio", pkgver: "1.6.3-0ubuntu5.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package kivio-',found,' is vulnerable in Ubuntu 7.10
Upgrade it to kivio-1.6.3-0ubuntu5.1
');
}
found = ubuntu_check(osver: "7.10", pkgname: "kivio-data", pkgver: "1.6.3-0ubuntu5.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package kivio-data-',found,' is vulnerable in Ubuntu 7.10
Upgrade it to kivio-data-1.6.3-0ubuntu5.1
');
}
found = ubuntu_check(osver: "7.10", pkgname: "koffice", pkgver: "1.6.3-0ubuntu5.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package koffice-',found,' is vulnerable in Ubuntu 7.10
Upgrade it to koffice-1.6.3-0ubuntu5.1
');
}
found = ubuntu_check(osver: "7.10", pkgname: "koffice-data", pkgver: "1.6.3-0ubuntu5.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package koffice-data-',found,' is vulnerable in Ubuntu 7.10
Upgrade it to koffice-data-1.6.3-0ubuntu5.1
');
}
found = ubuntu_check(osver: "7.10", pkgname: "koffice-dbg", pkgver: "1.6.3-0ubuntu5.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package koffice-dbg-',found,' is vulnerable in Ubuntu 7.10
Upgrade it to koffice-dbg-1.6.3-0ubuntu5.1
');
}
found = ubuntu_check(osver: "7.10", pkgname: "koffice-dev", pkgver: "1.6.3-0ubuntu5.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package koffice-dev-',found,' is vulnerable in Ubuntu 7.10
Upgrade it to koffice-dev-1.6.3-0ubuntu5.1
');
}
found = ubuntu_check(osver: "7.10", pkgname: "koffice-doc", pkgver: "1.6.3-0ubuntu5.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package koffice-doc-',found,' is vulnerable in Ubuntu 7.10
Upgrade it to koffice-doc-1.6.3-0ubuntu5.1
');
}
found = ubuntu_check(osver: "7.10", pkgname: "koffice-doc-html", pkgver: "1.6.3-0ubuntu5.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package koffice-doc-html-',found,' is vulnerable in Ubuntu 7.10
Upgrade it to koffice-doc-html-1.6.3-0ubuntu5.1
');
}
found = ubuntu_check(osver: "7.10", pkgname: "koffice-libs", pkgver: "1.6.3-0ubuntu5.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package koffice-libs-',found,' is vulnerable in Ubuntu 7.10
Upgrade it to koffice-libs-1.6.3-0ubuntu5.1
');
}
found = ubuntu_check(osver: "7.10", pkgname: "koshell", pkgver: "1.6.3-0ubuntu5.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package koshell-',found,' is vulnerable in Ubuntu 7.10
Upgrade it to koshell-1.6.3-0ubuntu5.1
');
}
found = ubuntu_check(osver: "7.10", pkgname: "kplato", pkgver: "1.6.3-0ubuntu5.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package kplato-',found,' is vulnerable in Ubuntu 7.10
Upgrade it to kplato-1.6.3-0ubuntu5.1
');
}
found = ubuntu_check(osver: "7.10", pkgname: "kpresenter", pkgver: "1.6.3-0ubuntu5.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package kpresenter-',found,' is vulnerable in Ubuntu 7.10
Upgrade it to kpresenter-1.6.3-0ubuntu5.1
');
}
found = ubuntu_check(osver: "7.10", pkgname: "kpresenter-data", pkgver: "1.6.3-0ubuntu5.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package kpresenter-data-',found,' is vulnerable in Ubuntu 7.10
Upgrade it to kpresenter-data-1.6.3-0ubuntu5.1
');
}
found = ubuntu_check(osver: "7.10", pkgname: "krita", pkgver: "1.6.3-0ubuntu5.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package krita-',found,' is vulnerable in Ubuntu 7.10
Upgrade it to krita-1.6.3-0ubuntu5.1
');
}
found = ubuntu_check(osver: "7.10", pkgname: "krita-data", pkgver: "1.6.3-0ubuntu5.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package krita-data-',found,' is vulnerable in Ubuntu 7.10
Upgrade it to krita-data-1.6.3-0ubuntu5.1
');
}
found = ubuntu_check(osver: "7.10", pkgname: "kspread", pkgver: "1.6.3-0ubuntu5.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package kspread-',found,' is vulnerable in Ubuntu 7.10
Upgrade it to kspread-1.6.3-0ubuntu5.1
');
}
found = ubuntu_check(osver: "7.10", pkgname: "kthesaurus", pkgver: "1.6.3-0ubuntu5.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package kthesaurus-',found,' is vulnerable in Ubuntu 7.10
Upgrade it to kthesaurus-1.6.3-0ubuntu5.1
');
}
found = ubuntu_check(osver: "7.10", pkgname: "kugar", pkgver: "1.6.3-0ubuntu5.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package kugar-',found,' is vulnerable in Ubuntu 7.10
Upgrade it to kugar-1.6.3-0ubuntu5.1
');
}
found = ubuntu_check(osver: "7.10", pkgname: "kword", pkgver: "1.6.3-0ubuntu5.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package kword-',found,' is vulnerable in Ubuntu 7.10
Upgrade it to kword-1.6.3-0ubuntu5.1
');
}
found = ubuntu_check(osver: "7.10", pkgname: "kword-data", pkgver: "1.6.3-0ubuntu5.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package kword-data-',found,' is vulnerable in Ubuntu 7.10
Upgrade it to kword-data-1.6.3-0ubuntu5.1
');
}

if (w) { security_hole(port: 0, extra: extrarep); }
else exit(0, "Host is not vulnerable");
